Open source password management solution.

## About

Bitwarden is an open-source password manager that can store sensitive
information such as website credentials in an encrypted vault.

The Bitwarden platform offers a variety of client applications including
a web interface, desktop applications, browser extensions and mobile apps.

This app is based upon the lightweight and opensource
implementation, allowing you to self-host
this amazing password manager.

Password theft is a serious problem. The websites and apps that you use are
under attack every day. Security breaches occur and your passwords are stolen.
When you reuse the same passwords everywhere hackers can easily access your
email, bank, and other important accounts. USE A PASSWORD MANAGER!



## Optional Fail2ban protection (experimental)

This add-on can detect repeated incorrect passwords in Vaultwarden logs and deny
the source IP in its bundled Nginx proxy without granting `NET_ADMIN` to the
Home Assistant container. **The feature is disabled by default.**

Add-on options:

```yaml
fail2ban_enabled: false
fail2ban_maxretry: 5
fail2ban_findtime: 600
fail2ban_bantime: 3600
```

The deployment should have direct NAT forwarding to port 7277. Nginx reads the
client's actual peer IP using `$remote_addr`; if placed behind another proxy,
configure trusted real-IP handling first or you may block the proxy itself.

When enabled, Vaultwarden's `[ERROR] Username or password is incorrect`
messages are written to `/data/fail2ban/vaultwarden.log` and matched by a
Fail2ban jail. An `nginx-block-map` action maintains
`/data/fail2ban/banned.map`, causing Nginx to return HTTP 403 for blocked
addresses. The Fail2ban state database is persisted in `/data/fail2ban`.

### Verify before production deployment

1. Verify the add-on image builds on **both amd64 and aarch64** and runs with
   Home Assistant's S6 service manager.
2. With the option disabled, verify HTTPS and a valid login still work.
3. Enable the option; confirm both `nginx -t` and
   `fail2ban-client status vaultwarden-cfm` succeed.
4. From a **separate test IP**, attempt five deliberately incorrect passwords
   for a test account within ten minutes. Confirm a ban with
   `fail2ban-client status vaultwarden-cfm` and HTTP 403 from that test IP.
   Verify a different IP is unaffected.
5. Test unblocking with
   `fail2ban-client set vaultwarden-cfm unbanip TEST_IP`, and confirm Nginx
   accepts the previously blocked address again.
6. Verify that a restart and toggling `fail2ban_enabled: false` do not cause
   accidental lockout. Do not test against your only administrator connection.

**Recovery:** If access is lost, disable Fail2ban in the add-on options and
restart the add-on. This clears the Nginx ban map at initialization. Maintain
a local Home Assistant administration path.

**Limits:** This is an application-layer HTTP 403, **not** a network-level
firewall ban. Only documented password-failure messages are covered; admin,
TOTP, other authentication errors, and general HTTP probing require further
filters. Review the log rotation strategy before keeping the protection
enabled for long periods. A strong master password and 2FA remain essential.
