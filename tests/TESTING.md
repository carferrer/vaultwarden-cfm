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

The jail starts at the log's end on restart. This prevents delayed log-cursor
checkpoints from replaying pre-unban failures after a crash. Active SQLite
bans are still restored, but attempts logged while the jail is stopped are not
counted.

## Admin network restriction

`test_admin_access.py` runs in a second fresh container in the same amd64 and
aarch64 CI jobs. It invokes production Nginx initialization, both listener
templates and the real Vaultwarden admin login. Only Supervisor Bashio calls
are substituted; the ACL helper reads the real disposable `/data/options.json`.
A temporary self-signed certificate exercises HTTPS without production keys.

Coverage:

- Six portable unit tests: defaults, disable/recovery, the 192.168.2.0/23
  boundaries, multiple IPv4/IPv6 networks, host addresses, normalization,
  duplicates, empty lists, invalid types/addresses, directive injection and
  stale ACL cleanup after invalid or missing options.
- Eight integration tests: HTTP/HTTPS with restriction on/off or options absent;
  allowed/denied IPv4 CIDR boundaries; explicit IPv6 allowance and default denial;
  multiple networks; empty-list denial; real admin login access and public
  vault/API forwarding; normalized/encoded admin URLs, subpaths and path
  prefixes; HTTP methods and spoofed forwarding headers; restart/disable/
  re-enable/network changes; coexistence with the Fail2ban map; invalid settings
  aborting initialization.

Run locally with `python tests/test_admin_access.py` for the six unit tests
(the eight container tests are skipped). For complete coverage, use the Docker
command above with `/tests/test_admin_access.py` as its final argument. Never
mount an existing data directory.

The live socket tests use disposable loopback CIDRs, not a simulated public
router or the user's physical LAN. The exact configured /23 is validated by
the unit tests. HTTPS tests disable verification only for their generated
self-signed test certificate. Supervisor form rendering/options persistence,
real certificate validation, LAN/WAN/NAT/VPN routing, authenticated vault sync
and a full Home Assistant restart remain manual checks. See the README for
activation and recovery instructions.
