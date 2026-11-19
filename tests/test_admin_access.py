"""Admin ACL unit tests and disposable-container Nginx/Vaultwarden tests.

Run locally for validation tests; run inside the built image for HTTP/HTTPS.
Never mount production /data. No credentials or external network are needed.
"""

import http.client
import ipaddress
import json
import os
from pathlib import Path
import runpy
import ssl
import subprocess
import tempfile
import time
import unittest


CONTAINER = Path("/opt/vaultwarden").is_file()
HELPER = (Path("/usr/local/bin/vaultwarden-admin-access") if CONTAINER else
          Path(__file__).resolve().parents[1] / "rootfs/usr/local/bin/vaultwarden-admin-access")
MODULE = runpy.run_path(str(HELPER))
SCRIPTS = Path("/etc/s6-overlay/s6-rc.d")


class AdminOptions(unittest.TestCase):
    def render(self, networks, enabled=True):
        return MODULE["render"]({"admin_restriction_enabled": enabled,
                                 "admin_allowed_networks": networks})

    def test_defaults_and_disabled_recovery(self):
        self.assertIn("allow all;", MODULE["render"]({}))
        self.assertIn("allow all;", self.render(["invalid"], enabled=False))

    def test_user_subnet_and_multiple_address_families(self):
        result = self.render(["192.168.2.0/23", "10.8.0.5", "fd12:3456::/64",
                              "2001:db8::1", "192.168.2.184/23"])
        self.assertEqual(result.count("allow 192.168.2.0/23;"), 1)
        self.assertIn("allow 10.8.0.5/32;", result)
        self.assertIn("allow fd12:3456::/64;", result)
        self.assertIn("allow 2001:db8::1/128;", result)
        self.assertTrue(result.endswith("deny all;\n"))
        network = ipaddress.ip_network(result.splitlines()[1].split()[1][:-1])
        for address in ("192.168.2.1", "192.168.2.184", "192.168.3.254"):
            self.assertIn(ipaddress.ip_address(address), network)
        for address in ("192.168.1.254", "192.168.4.1"):
            self.assertNotIn(ipaddress.ip_address(address), network)

    def test_empty_or_missing_list_denies_everyone(self):
        self.assertEqual(self.render([]), MODULE["DENY_ALL"])
        self.assertEqual(MODULE["render"]({"admin_restriction_enabled": True}),
                         MODULE["DENY_ALL"])

    def test_invalid_addresses_and_directive_injection(self):
        for entry in ("", "all", "localhost", "192.168.2.0/33", "::/129",
                      "127.0.0.1;\nallow all;", "127.0.0.1 #", "fe80::1%eth0",
                      "unix:", 123, None, {"ip": "127.0.0.1"}):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                self.render([entry])

    def test_invalid_types(self):
        for value in ("true", "false", 0, 1, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.render([], enabled=value)
        for value in ("192.168.2.0/23", None, {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.render(value)
        with self.assertRaises(ValueError):
            MODULE["render"]([])

    def test_failed_configuration_removes_old_allow_all(self):
        with tempfile.TemporaryDirectory() as directory:
            options, output = Path(directory) / "options.json", Path(directory) / "acl.conf"
            for content in ("{", '{"admin_restriction_enabled": "false"}',
                            '{"admin_restriction_enabled": true, "admin_allowed_networks": ["all"]}'):
                options.write_text(content, encoding="utf-8")
                output.write_text("allow all;\n", encoding="utf-8")
                with self.subTest(content=content), self.assertRaises(ValueError):
                    MODULE["configure"](options, output)
                self.assertEqual(output.read_text(), MODULE["DENY_ALL"])
            options.unlink()
            with self.assertRaises(OSError):
                MODULE["configure"](options, output)
            self.assertEqual(output.read_text(), MODULE["DENY_ALL"])


@unittest.skipUnless(CONTAINER, "requires the built add-on image")
class AdminIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = Path("/data")
        data.mkdir(exist_ok=True)
        if any(data.iterdir()):
            raise RuntimeError("Tests require an empty disposable /data directory")
        cls.nginx = cls.vaultwarden = None
        cls.outputs = []
        cls.addClassCleanup(cls.cleanup)
        cls.templates = {path: path.read_text() for path in
                         Path("/etc/nginx/servers").glob("*.disabled")}
        cls.environment = dict(os.environ, BASH_ENV="/tmp/admin-test-bashio.sh",
                               ADMIN_TOKEN="disposable-integration-test-token",
                               SIGNUPS_ALLOWED="false")
        Path("/data/config.json").write_text("{}\n")
        Path("/data/options.json").write_text("{}\n")
        Path(cls.environment["BASH_ENV"]).write_text('''
bashio::config.true() {
    python3 -c 'import json,sys; sys.exit(json.load(open("/data/options.json")).get(sys.argv[1]) is not True)' "$1"
}
bashio::config() {
    python3 -c 'import json,sys; print(json.load(open("/data/options.json"))[sys.argv[1]])' "$1"
}
bashio::config.has_value() { return 1; }
bashio::config.require.ssl() { :; }
bashio::fs.file_exists() { [[ -f "$1" ]]; }
bashio::log.info() { echo "$*"; }
bashio::log.warning() { echo "$*"; }
bashio::log.error() { echo "$*" >&2; }
bashio::exit.nok() { echo "$*" >&2; exit 1; }
''')
        Path("/ssl").mkdir(exist_ok=True)
        cls.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", "/ssl/test.key", "-out", "/ssl/test.crt",
                    "-days", "1", "-subj", "/CN=localhost")
        cls.vaultwarden = cls.spawn("vaultwarden", ["bash", str(SCRIPTS / "vaultwarden/run")])
        cls.wait_for(lambda: cls.http("/alive", port=80)[0] == 200)
        if cls.http("/admin", port=80)[0] != 200:
            raise AssertionError("The real Vaultwarden admin login must be enabled")

    @classmethod
    def command(cls, *args, check=True):
        result = subprocess.run(args, env=cls.environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        if check and result.returncode:
            raise AssertionError(f"{args!r}: {result.stdout}")
        return result

    @classmethod
    def spawn(cls, name, args):
        output = open(f"/tmp/admin-test-{name}.log", "a")
        cls.outputs.append(output)
        return subprocess.Popen(args, env=cls.environment, stdout=output, stderr=subprocess.STDOUT)

    @staticmethod
    def wait_for(predicate):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.1)
        raise AssertionError("Timed out waiting for service response")

    @staticmethod
    def http(path, ip="127.0.0.2", tls=False, port=7277, headers=None, method="GET"):
        host = "::1" if ":" in ip else "127.0.0.1"
        kwargs = {"timeout": 3, "source_address": (ip, 0)}
        if tls:
            # Only the disposable test certificate is self-signed.
            kwargs["context"] = ssl._create_unverified_context()
        connection = (http.client.HTTPSConnection if tls else http.client.HTTPConnection)(host, port, **kwargs)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    @classmethod
    def stop_nginx(cls):
        if cls.nginx and cls.nginx.poll() is None:
            cls.nginx.terminate()
            cls.nginx.wait(timeout=10)
        cls.nginx = None

    @classmethod
    def configure(cls, enabled=True, networks=None, tls=False, omit=False):
        cls.stop_nginx()
        for path, content in cls.templates.items():
            path.write_text(content)
        options = {"ssl": tls, "certfile": "test.crt", "keyfile": "test.key"}
        if not omit:
            options.update(admin_restriction_enabled=enabled,
                           admin_allowed_networks=networks if networks is not None else ["127.0.0.0/30"])
        Path("/data/options.json").write_text(json.dumps(options))
        cls.command("bash", str(SCRIPTS / "init-nginx/run"))
        cls.command("nginx", "-t")
        cls.nginx = cls.spawn("nginx", ["nginx"])
        cls.wait_for(lambda: cls.http("/alive", tls=tls)[0] == 200)

    def test_01_disabled_and_existing_options(self):
        for tls in (False, True):
            for omit in (False, True):
                with self.subTest(tls=tls, omit=omit):
                    self.configure(enabled=False, tls=tls, omit=omit)
                    for ip in ("127.0.0.2", "127.0.0.4", "::1"):
                        self.assertEqual(self.http("/admin", ip=ip, tls=tls)[0], 200)

    def test_02_cidr_boundaries_and_public_vault(self):
        for tls in (False, True):
            with self.subTest(tls=tls):
                self.configure(tls=tls)
                for ip in ("127.0.0.2", "127.0.0.3"):
                    self.assertEqual(self.http("/admin", ip=ip, tls=tls)[0], 200)
                for ip in ("127.0.0.4", "::1"):
                    self.assertEqual(self.http("/admin", ip=ip, tls=tls)[0], 403)
                    for path in ("/", "/alive", "/api/config"):
                        self.assertEqual(self.http(path, ip=ip, tls=tls)[0], 200)
                    self.assertEqual(self.http("/identity/connect/token", ip=ip, tls=tls, method="POST")[0],
                                     self.http("/identity/connect/token", port=80, method="POST")[0])

    def test_03_admin_variants_methods_and_spoofed_headers(self):
        paths = ("/admin", "/admin/", "/admin/config", "/admin/users", "/admin?test=1",
                 "/%61dmin", "/admin%2fconfig", "//admin", "/x/../admin", "/ADMIN",
                 "/admin//users", "/prefix/admin", "/prefix/admin/config")
        for tls in (False, True):
            self.configure(tls=tls)
            for path in paths:
                with self.subTest(tls=tls, path=path):
                    self.assertEqual(self.http(path, ip="127.0.0.4", tls=tls, headers={
                        "X-Real-IP": "127.0.0.2", "X-Forwarded-For": "127.0.0.2",
                        "Forwarded": "for=127.0.0.2"})[0], 403)
            for method in ("POST", "HEAD", "OPTIONS", "DELETE"):
                self.assertEqual(self.http("/admin/config", ip="127.0.0.4", tls=tls, method=method)[0], 403)

    def test_04_multiple_networks_and_ipv6_allowlist(self):
        for tls in (False, True):
            self.configure(networks=["127.0.0.2", "127.0.0.8/30", "::1/128"], tls=tls)
            for ip in ("127.0.0.2", "127.0.0.9", "::1"):
                self.assertEqual(self.http("/admin", ip=ip, tls=tls)[0], 200)
            self.assertEqual(self.http("/admin", ip="127.0.0.4", tls=tls)[0], 403)

    def test_05_empty_list_denies_admin_only(self):
        for tls in (False, True):
            self.configure(networks=[], tls=tls)
            for ip in ("127.0.0.2", "::1"):
                self.assertEqual(self.http("/admin", ip=ip, tls=tls)[0], 403)
                self.assertEqual(self.http("/alive", ip=ip, tls=tls)[0], 200)

    def test_06_restart_disable_reenable_and_changed_networks(self):
        for enabled, networks, expected in ((True, ["127.0.0.2"], 403),
                                            (False, ["invalid"], 200),
                                            (True, ["127.0.0.4"], 200),
                                            (True, ["127.0.0.2"], 403)):
            self.configure(enabled=enabled, networks=networks)
            self.assertEqual(self.http("/admin", ip="127.0.0.4")[0], expected)

    def test_07_fail2ban_still_blocks_allowed_admin(self):
        self.configure(networks=["127.0.0.2"])
        self.assertEqual(self.http("/admin")[0], 200)
        Path("/data/fail2ban/banned.map").write_text('"127.0.0.2" 1;\n')
        self.command("nginx", "-t")
        self.command("nginx", "-s", "reload")
        self.wait_for(lambda: self.http("/admin")[0] == 403)
        self.assertEqual(self.http("/alive")[0], 403)
        self.assertEqual(self.http("/alive", ip="127.0.0.4")[0], 200)

    def test_08_invalid_settings_abort_initialization(self):
        self.configure(enabled=False)
        self.stop_nginx()
        Path("/data/options.json").write_text(json.dumps({
            "admin_restriction_enabled": True,
            "admin_allowed_networks": ["127.0.0.1; allow all;"]}))
        result = self.command("bash", str(SCRIPTS / "init-nginx/run"), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid admin access configuration", result.stdout)
        self.assertEqual(Path("/etc/nginx/includes/admin-allow.conf").read_text(), MODULE["DENY_ALL"])

    @classmethod
    def cleanup(cls):
        cls.stop_nginx()
        if cls.vaultwarden and cls.vaultwarden.poll() is None:
            cls.vaultwarden.terminate()
            cls.vaultwarden.wait(timeout=10)
        for output in cls.outputs:
            output.close()
        for name in ("nginx", "vaultwarden"):
            path = Path(f"/tmp/admin-test-{name}.log")
            if path.exists():
                print(f"\n{name}: last 30 diagnostic lines\n" + "\n".join(path.read_text().splitlines()[-30:]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
