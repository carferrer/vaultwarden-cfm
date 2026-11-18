# Fail2ban integration coverage

The PR CI builds and loads each architecture's add-on image without publishing
it, then runs `test_fail2ban.py` in a fresh container with no external network
and no host data volume. The test refuses a nonempty /data directory.

The suite uses the packaged Fail2ban and nginx-block-map action, the actual
Vaultwarden executable, Nginx, SQLite, logrotate and s6-supervise. It invokes
the production initialization and service scripts. A Bash fixture substitutes
only bashio's Supervisor option access and readiness helpers; each real service
is checked separately for readiness. Loopback exemptions and login rate limits
are adjusted only in this disposable fixture.

## Assertions

- Shell syntax of service scripts and the map-reset helper.
- Nginx configuration validation and service startup.
- Real invalid logins with spoofed forwarding headers: nine failures remain
  accessible, the tenth within 600 seconds gives HTTP 403; another IP works.
- Explicit unban clears Nginx and remains cleared after Fail2ban restarts.
- A username containing a forged error message cannot select another IP.
  A forged identity prefix inside another logger's message is ignored.
- IPv6 invalid logins, ban and unban.
- Permanent SQLite bans survive repeated Fail2ban SIGKILL/restart cycles with
  exactly one map entry per IP and valid Nginx configuration.
- A finite ban that expires while Fail2ban is down leaves no stale map entry.
- Disabled/re-enabled recovery and Nginx initialization with a corrupt old map.
- Rotation at the real 10 MiB threshold, 0600 creation, three retained archives,
  compression, real Vaultwarden SIGHUP/reopen and detection after rotation.

## Run

Build the Dockerfile locally, then run:

```sh
docker build -t vaultwarden-pr-test .
docker run --rm --network none -v "$PWD/tests:/tests:ro" \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
  --entrypoint python3 vaultwarden-pr-test /tests/test_fail2ban.py
```

No production credentials are needed. The login attempts use nonexistent
accounts and synthetic passwords. Test service diagnostics and package
versions are printed in CI logs.

Docker's none driver disables IPv6 by default. The two namespaced sysctls
enable only the test container's IPv6 loopback; no host network setting changes.

## Remaining environment checks

These component tests do not start the complete Home Assistant Supervisor/S6
dependency tree, reproduce a physical Home Assistant restart, or validate
public routing/NAT and external reverse proxies. Confirm those on an isolated
Home Assistant instance with an alternate administration path before deployment.
The rotation threshold is checked once per minute, so peak disk usage can exceed
10 MiB between checks. Map restoration briefly removes HTTP bans while the
SQLite tickets are reapplied.
