"""Integration tests inside the built add-on image, with disposable /data.

Run only in a fresh container:
  docker run --rm --network none -v "$PWD/tests:/tests:ro" \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
    --entrypoint python3 IMAGE /tests/test_fail2ban.py

Real Vaultwarden, Nginx, Fail2ban, SQLite, logrotate and s6-supervise are used.
Only bashio's Supervisor option access is replaced; no external network,
production volume, credentials, host firewall changes or NET_ADMIN are used.
"""

import gzip
import http.client
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import time
import unittest
import urllib.parse


DATA = Path("/data/fail2ban")
LOG = DATA / "vaultwarden.log"
MAP = DATA / "banned.map"
JAIL = "vaultwarden-cfm"
SCRIPTS = Path("/etc/s6-overlay/s6-rc.d")


def command(*args, check=True):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=20)
    if check and result.returncode:
        raise AssertionError(f"{args!r} exited {result.returncode}:\n{result.stdout}")
    return result.stdout.strip()


def wait_for(predicate, description, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (OSError, sqlite3.Error, AssertionError):
            pass
        time.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {description}")


class Fail2banIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Refuse to run against any previously initialized data directory.
        data = Path("/data")
        data.mkdir(exist_ok=True)
        if any(data.iterdir()):
            raise RuntimeError("Tests require an empty disposable /data directory")
        Path("/data/config.json").write_text("{}\n")
        Path("/data/options.json").write_text("{}\n")
        DATA.mkdir()
        cls.outputs = []
        cls.nginx = cls.fail2ban = cls.supervisor = None
        cls.addClassCleanup(cls.cleanup)
        for script in SCRIPTS.glob("*/run"):
            command("bash", "-n", str(script))
        command("bash", "-n", "/usr/local/bin/vaultwarden-reset-ban-map")
        cls.environment = dict(os.environ, BASH_ENV="/tmp/test-bashio.sh",
                               FAIL2BAN_TEST_ENABLED="true",
                               LOGIN_RATELIMIT_MAX_BURST="1000",
                               LOGIN_RATELIMIT_SECONDS="1",
                               SIGNUPS_ALLOWED="false")
        Path("/tmp/test-bashio.sh").write_text("""
bashio::config.true() { [[ "$1" == fail2ban_enabled && "$FAIL2BAN_TEST_ENABLED" == true ]]; }
bashio::config() {
    case "$1" in
        fail2ban_maxretry) echo 10 ;;
        fail2ban_findtime) echo 600 ;;
        fail2ban_bantime) echo -1 ;;
        *) return 1 ;;
    esac
}
bashio::config.has_value() { return 1; }
bashio::config.require.ssl() { :; }
bashio::fs.file_exists() { [[ -f "$1" ]]; }
bashio::net.wait_for() { :; }
bashio::log.info() { echo "$*"; }
bashio::log.warning() { echo "$*"; }
bashio::log.error() { echo "$*" >&2; }
bashio::exit.nok() { echo "$*" >&2; exit 1; }
""")
        # Only test clients use loopback addresses. Production keeps the
        # package's normal self-IP exemptions.
        Path("/etc/fail2ban/jail.d/zz-test-loopback.local").write_text(
            "[DEFAULT]\nignoreself = false\nignoreip =\n")
        # Exercise the production Vaultwarden run script under real S6 so
        # logrotate's production s6-svc SIGHUP command is tested as well.
        service = Path("/run/service/vaultwarden")
        service.mkdir(parents=True, exist_ok=True)
        (service / "run").write_text(
            "#!/bin/bash\nexec bash /etc/s6-overlay/s6-rc.d/vaultwarden/run\n")
        (service / "run").chmod(0o755)
        cls.supervisor = cls.spawn("vaultwarden", ["/command/s6-supervise", str(service)])
        wait_for(lambda: cls.http("/alive", port=80)[0] == 200, "Vaultwarden")
        command("bash", str(SCRIPTS / "init-nginx/run"))
        command("nginx", "-t")
        cls.nginx = cls.spawn("nginx", ["nginx"])
        wait_for(lambda: cls.http("/alive")[0] == 200, "Nginx")
        cls.start_fail2ban()
        print(command("dpkg-query", "-W", "fail2ban", "nginx", "logrotate"), flush=True)

    @classmethod
    def spawn(cls, name, args):
        output = open(f"/tmp/test-{name}.log", "a")
        cls.outputs.append(output)
        return subprocess.Popen(args, env=cls.environment, stdout=output,
                                stderr=subprocess.STDOUT)

    @classmethod
    def start_fail2ban(cls):
        cls.fail2ban = cls.spawn("fail2ban", ["bash", str(SCRIPTS / "fail2ban/run")])
        wait_for(lambda: "Currently banned" in cls.client("status", JAIL),
                 "Fail2ban jail")

    @classmethod
    def client(cls, *args):
        return command("fail2ban-client", *args)

    @classmethod
    def http(cls, path, ip="127.0.0.2", port=7277, body=None, headers=None):
        host = "::1" if ":" in ip else "127.0.0.1"
        conn = http.client.HTTPConnection(host, port, timeout=3,
                                          source_address=(ip, 0))
        try:
            conn.request("POST" if body is not None else "GET", path,
                         body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read().decode()
        finally:
            conn.close()

    @classmethod
    def login(cls, ip, username="nobody@example.invalid", headers=None):
        form = urllib.parse.urlencode({
            "grant_type": "password", "username": username,
            "password": "synthetic-invalid-password",
            "scope": "api offline_access", "client_id": "web",
            "deviceType": "10", "deviceIdentifier": "test-device",
            "deviceName": "Disposable integration test",
        })
        return cls.http("/identity/connect/token", ip=ip, body=form,
                        headers={"Content-Type": "application/x-www-form-urlencoded",
                                 **(headers or {})})

    @classmethod
    def kill_fail2ban(cls):
        cls.fail2ban.kill()
        cls.fail2ban.wait(timeout=10)

    def assert_access(self, ip, status):
        wait_for(lambda: self.http("/alive", ip=ip)[0] == status,
                 f"HTTP {status} from {ip}")

    def wait_persisted(self, ip):
        def exists():
            with sqlite3.connect(DATA / "fail2ban.sqlite3") as db:
                return db.execute("SELECT 1 FROM bips WHERE ip = ?", (ip,)).fetchone()
        wait_for(exists, f"SQLite ban for {ip}")

    def test_01_threshold_headers_and_manual_unban(self):
        ip = "127.0.0.10"
        self.assertEqual(self.client("get", JAIL, "maxretry"), "10")
        self.assertEqual(self.client("get", JAIL, "findtime"), "600")
        self.assertEqual(self.client("get", JAIL, "bantime"), "-1")
        for _ in range(9):
            self.assertEqual(self.login(ip, headers={
                "X-Real-IP": "203.0.113.99",
                "X-Forwarded-For": "203.0.113.99",
            })[0], 400)
        # Wait until the polling backend has consumed the first nine errors.
        wait_for(lambda: re.search(r"Total failed:\s+9\b", self.client("status", JAIL)),
                 "nine failures")
        self.assert_access(ip, 200)
        self.assertEqual(self.login(ip)[0], 400)
        self.assert_access(ip, 403)
        self.assert_access("127.0.0.11", 200)
        self.assertNotIn("203.0.113.99", MAP.read_text())
        self.assertIn(f"IP: {ip}. Username:", LOG.read_text())
        self.client("set", JAIL, "unbanip", ip)
        self.assert_access(ip, 200)
        self.assertNotIn(ip, MAP.read_text())
        # The explicit unban must survive restoration from the database.
        self.kill_fail2ban()
        self.start_fail2ban()
        time.sleep(2)
        self.assert_access(ip, 200)
        self.assertNotIn(ip, MAP.read_text())
        self.assertNotIn(ip, self.client("get", JAIL, "banip"))

    def test_02_username_cannot_select_victim_ip(self):
        ip = "127.0.0.20"
        victim = "203.0.113.42"
        username = ("Username or password is incorrect. Try again. "
                    f"IP: {victim}. Username: injected")
        for _ in range(10):
            self.assertEqual(self.login(ip, username)[0], 400)
        self.assert_access(ip, 403)
        self.assertNotIn(victim, self.client("get", JAIL, "banip"))
        self.assertNotIn(victim, MAP.read_text())
        self.client("set", JAIL, "unbanip", ip)
        # A full log-looking string inside a different logger must not match.
        forged = ("[vaultwarden::api::identity][ERROR] "
                  "Username or password is incorrect. Try again. "
                  f"IP: {victim}. Username: injected")
        with LOG.open("a") as stream:
            for _ in range(10):
                stream.write(time.strftime("[%Y-%m-%d %H:%M:%S]") +
                             "[other::logger][ERROR] " + forged + "\n")
        time.sleep(2)
        self.assertNotIn(victim, self.client("get", JAIL, "banip"))

    def test_03_ipv6(self):
        for _ in range(10):
            self.assertEqual(self.login("::1")[0], 400)
        self.assert_access("::1", 403)
        self.assert_access("127.0.0.30", 200)
        self.client("set", JAIL, "unbanip", "::1")
        self.assert_access("::1", 200)

    def test_04_crash_restores_each_permanent_ban_once(self):
        ip = "127.0.0.40"
        self.client("set", JAIL, "banip", ip)
        self.assert_access(ip, 403)
        self.wait_persisted(ip)
        for _ in range(2):
            self.kill_fail2ban()
            self.assertIn(ip, MAP.read_text())  # SIGKILL did not flush the map.
            self.start_fail2ban()
            wait_for(lambda: ip in self.client("get", JAIL, "banip"),
                     "restored permanent ban")
            self.assert_access(ip, 403)
            self.assertEqual(MAP.read_text().count(ip), 1)
            command("nginx", "-t")
        self.client("set", JAIL, "unbanip", ip)
        self.assert_access(ip, 200)

    def test_05_expired_ban_is_removed_after_crash(self):
        ip = "127.0.0.50"
        self.client("set", JAIL, "bantime", "3")
        self.client("set", JAIL, "banip", ip)
        self.wait_persisted(ip)
        self.kill_fail2ban()
        time.sleep(4)
        self.start_fail2ban()
        self.assert_access(ip, 200)
        self.assertNotIn(ip, MAP.read_text())
        self.assertNotIn(ip, self.client("get", JAIL, "banip"))

    def test_06_rotation_reopens_and_bounds_archives(self):
        config = "/etc/logrotate-vaultwarden.conf"
        state = str(DATA / "logrotate.status")
        # The configured size threshold, not --force, must trigger rotation.
        with LOG.open("a") as stream:
            stream.write("rotation-size-test\n" * 620000)
        command("logrotate", "--state", state, config)
        self.assertTrue(Path(str(LOG) + ".1").exists())
        self.assertLess(LOG.stat().st_size, 1024 * 1024)
        self.assertEqual(LOG.stat().st_mode & 0o777, 0o600)
        # The real Rust process must reopen its logger after S6 sends SIGHUP.
        self.assertEqual(self.login("127.0.0.60", "after-rotation@example.invalid")[0], 400)
        wait_for(lambda: "after-rotation@example.invalid" in LOG.read_text(),
                 "Vaultwarden log reopen")
        for index in range(4):
            with LOG.open("a") as stream:
                stream.write(f"retention-check-{index}\n")
            command("logrotate", "--force", "--state", state, config)
        self.assertTrue(Path(str(LOG) + ".3.gz").exists())
        self.assertFalse(Path(str(LOG) + ".4.gz").exists())
        with gzip.open(str(LOG) + ".3.gz", "rt") as archive:
            self.assertIn("retention-check-", archive.read())
        # Polling must follow the replacement file and keep detecting failures.
        for _ in range(10):
            self.assertEqual(self.login("127.0.0.61")[0], 400)
        self.assert_access("127.0.0.61", 403)
        self.client("set", JAIL, "unbanip", "127.0.0.61")

    def test_07_disabled_reenabled_and_boot_cleanup(self):
        ip = "127.0.0.70"
        self.client("set", JAIL, "banip", ip)
        self.wait_persisted(ip)
        self.kill_fail2ban()
        # Exercise the disabled branch: it must not start a jail.
        disabled_env = dict(self.environment, FAIL2BAN_TEST_ENABLED="false")
        disabled = subprocess.Popen(["bash", str(SCRIPTS / "fail2ban/run")],
                                    env=disabled_env)
        try:
            time.sleep(0.2)
            self.assertIsNone(disabled.poll())
            command("/usr/local/bin/vaultwarden-reset-ban-map", "--reload")
            self.assert_access(ip, 200)
            self.assertEqual(MAP.read_text(), "")
        finally:
            disabled.terminate()
            disabled.wait(timeout=10)
        self.start_fail2ban()
        self.assert_access(ip, 403)
        self.client("set", JAIL, "unbanip", ip)
        # A subsequent Nginx boot must discard even an invalid map.
        self.kill_fail2ban()
        self.nginx.terminate()
        self.nginx.wait(timeout=10)
        MAP.write_text("invalid stale map\n")
        shutil.copy("/etc/nginx/servers/direct.conf",
                    "/etc/nginx/servers/direct.disabled")
        command("bash", str(SCRIPTS / "init-nginx/run"))
        self.assertEqual(MAP.read_text(), "")
        command("nginx", "-t")
        type(self).nginx = self.spawn("nginx", ["nginx"])
        self.assert_access(ip, 200)
        self.start_fail2ban()
        self.assertNotIn(ip, self.client("get", JAIL, "banip"))

    @classmethod
    def cleanup(cls):
        # Always expose diagnostics in CI, including when an assertion fails.
        for name in ("fail2ban", "nginx", "vaultwarden"):
            path = Path(f"/tmp/test-{name}.log")
            if path.exists():
                print(f"\n--- {name}: last 60 diagnostic lines ---")
                print("\n".join(path.read_text().splitlines()[-60:]))
        if cls.fail2ban and cls.fail2ban.poll() is None:
            cls.fail2ban.terminate()
            cls.fail2ban.wait(timeout=10)
        if cls.nginx and cls.nginx.poll() is None:
            cls.nginx.terminate()
            cls.nginx.wait(timeout=10)
        if cls.supervisor:
            command("/command/s6-svc", "-dx", "/run/service/vaultwarden", check=False)
            cls.supervisor.wait(timeout=10)
        for output in cls.outputs:
            output.close()


if __name__ == "__main__":
    # These scripts are invoked with bash in the fixture, so export the stub
    # for command() as well as the separately supervised processes.
    os.environ["BASH_ENV"] = "/tmp/test-bashio.sh"
    os.environ["FAIL2BAN_TEST_ENABLED"] = "true"
    unittest.main(verbosity=2)
