# Configuration reference

## Configuration file

The default location is `/etc/network-relay/relay.toml` (change it with `network-relay serve --config path`). The format is TOML. For a complete example, see [`deploy/relay.example.toml`](../deploy/relay.example.toml).

- A misspelled key is reported as an error, not silently ignored.
- After editing, check with `network-relay serve --check` first, then apply with `systemctl reload network-relay`.
- The file contains password hashes; set its mode to `600`.

### Top level

| Key | Default | Description |
|---|---|---|
| `listen` | `"[::]:443"` | Address and port to listen on. HTTP/3 on UDP, HTTP/2 and HTTP/1.1 on TCP, on the same port. `[::]` accepts both IPv4 and IPv6. Needs a restart after a change |
| `log_dir` | not set | Directory where logs are also saved as files; must be a full path, such as `"/var/log/network-relay"`. One file per hour, kept for 24 hours. When not set, logs go only to the journal |

### `[tls]` (required)

| Key | Default | Description |
|---|---|---|
| `cert` | — | Certificate chain file, certbot's `fullchain.pem` |
| `key` | — | Private key file, certbot's `privkey.pem` |
| `reload_interval_days` | not set | Reread the certificate files every this many days (1 to 7). When not set, they are reread every day at 3 a.m. (system time zone). `systemctl reload` also rereads them immediately |

The name on the certificate must be the domain the devices connect to. If reading a new certificate fails (a corrupt file, for example), the old one stays in use and a warning is logged. A warning is also logged when the certificate expires within 14 days.

### `[web]` (optional)

| Key | Default | Description |
|---|---|---|
| `root` | — | Directory of the decoy website; it must contain `index.html` |
| `headers` | none | Extra response headers, for example `Content-Security-Policy = "default-src 'self'"` under `[web.headers]` |

- Every request without a password is answered by this website: existing files are returned; missing paths return `index.html` (like a single-page app); CONNECT requests get a 404 with `index.html`.
- Exception: missing files under `/.well-known/` return an empty 404, because those paths have fixed meanings (RFC 8615).
- Files and directories starting with `.` are not served, except the `.well-known` directory.
- File symlinks may only point to public files inside the website; directory symlinks are not followed. Links pointing outside the directory or to hidden files are not published.
- A field in `headers` with the same name overrides the default; `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `Keep-Alive`, `Proxy-Connection`, `TE` and `Trailer` cannot be set, because the protocol implementation manages them.
- The directory is read into memory as a whole at startup and on reload (at most 1000 files, 64 MiB); after changing files, reload for them to take effect.
- Without `[web]`, all such requests get 404.
- `.mobileconfig` files are served with the profile content type (`application/x-apple-aspen-config`), so Safari offers to install them. `network-relay profile --publish` puts profiles here.

### `[relay]` (optional)

| Key | Default | Description |
|---|---|---|
| `udp_template` | `"/.well-known/masque/udp/{target_host}/{target_port}/"` | Path part of the CONNECT-UDP URI template (RFC 9298 §2). It must contain `{target_host}` and `{target_port}`, and requests expanded from it must parse back to the original target (for example, an unnamed `?{target_host}` in the query cannot be parsed back and is rejected). Profiles must use the same template (`network-relay profile --udp-template`). Usually left alone |
| `blocked_destinations` | see below | Address ranges devices may not reach. Every address a domain resolves to is checked; IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are checked as IPv4 addresses |
| `blocked_ports` | `[25]` | Ports devices may not reach, on both TCP and UDP. 25 is the mail port; blocking it keeps the server from being used to send spam |
| `connect_timeout_secs` | `10` | Timeout for connecting to a target TCP service (1 to 120) |
| `udp_idle_timeout_secs` | `300` | How long a UDP flow may go without data in either direction before it is closed (120 to 3600; RFC 4787 requires at least 2 minutes) |
| `max_tunnels` | `20000` | Limit on TCP connections and UDP flows relayed at the same time, across all users. New requests beyond it get 503. Needs a restart after a change |

Default `blocked_destinations`: the local host (`127.0.0.0/8`, `::1`), unspecified addresses, private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), carrier-grade NAT (`100.64.0.0/10`), link-local (`169.254.0.0/16`, including cloud providers' metadata service `169.254.169.254`; `fe80::/10`), multicast, reserved addresses, documentation and test addresses, IPv4-mapped addresses, and the local-use NAT64 prefix. See the example configuration for the complete list.

- To let devices reach the network the server is on (a NAS at home, say), remove the corresponding range from the list. **Do not empty it entirely**: devices could then reach services on the server itself that listen only on 127.0.0.1.
- Refused requests get 403, with the reason in the `Proxy-Status` header (`destination_ip_prohibited` or `http_request_denied`).

### `[debug]` (optional)

| Key | Default | Description |
|---|---|---|
| `log_requests` | `false` | Log one line per proxy request (CONNECT or Upgrade): HTTP version, method, `:protocol`, target, path and all request headers (`Authorization` shows only the user name). Refused requests are logged with the reason. Use it to find out what devices actually send; it is noisy, so turn it off afterwards |

### `[[user]]` (may appear more than once)

| Key | Description |
|---|---|
| `name` | User name: 1 to 64 letters, digits, `-`, `_` or `.`, not starting with `.` |
| `password_hash` | The Argon2id hash printed by `network-relay passwd` |

- One user per device, so disabling a device means deleting only its section.
- After a reload, ongoing connections of users who were deleted or whose password changed are disconnected immediately.
- With no users at all, the relay is just a website, and a warning is logged at startup.

## reload and restart

| What changed | How to apply it |
|---|---|
| `[[user]]`, `[relay]` (except `max_tunnels`), `[debug]`, `[web]`, certificate files | `systemctl reload network-relay`; existing connections are not affected (except for deleted users) |
| `listen`, `max_tunnels`, `log_dir`, the file paths and `reload_interval_days` in `[tls]` | `systemctl restart network-relay`; all devices disconnect and reconnect automatically |

If parsing or validating the configuration fails, the reload does not take effect and the reason is logged. If reading the website fails, the old website is kept and other valid configuration changes still apply; if updating the certificate fails, the old certificate is kept.

## Commands

Every command has `--help`.

### `network-relay serve`

Runs the relay. This is what systemd uses.

| Option | Description |
|---|---|
| `-c`, `--config path` | Configuration file, default `/etc/network-relay/relay.toml` |
| `--check` | Only check that the configuration, certificate and website can be read, then exit. An expired or not-yet-valid certificate is an error (a normal start only warns, so that a later renewal can fix it automatically) |

The environment variable `RUST_LOG=debug` shows more detailed logs (the start and end of every relayed connection).

### `network-relay passwd`

Creates a user: a random password (144 random bits) and its hash.

| Option | Description |
|---|---|
| `--name name` | User name |
| `--stdin` | Instead of generating a random password, read your own from standard input (at least 12 characters) |

### `network-relay profile`

Generates a profile (`.mobileconfig`) for iPhone, iPad and Mac.

| Option | Description |
|---|---|
| `--host domain` | The relay's domain (the name on the certificate) |
| `--user name` | User name |
| `--password password` | Password; if omitted, it is prompted for when the command runs (recommended: it stays out of the shell history) |
| `--port port` | Needed when not 443 |
| `--match-domain domain` | This domain and its subdomains go through the relay. Can be given more than once; when neither this nor `--match-fqdn` is given, all traffic goes through the relay (except exclusions) |
| `--exclude-domain domain` | This domain and its subdomains do not go through the relay. Can be given more than once |
| `--match-fqdn hostname` | Only this exact host name goes through the relay, not its subdomains. Can be given more than once; supported from iOS 18.4 and macOS 15.4 |
| `--exclude-fqdn hostname` | Exclude exactly this host name, not its subdomains. Can be given more than once; supported from iOS 18.4 and macOS 15.4 |
| `--ui-toggle-enabled [true/false]` | Whether the user may turn the relay off in Settings; supported from iOS/macOS 26. When omitted, the system default `true` applies; the flag alone means `true` |
| `--allow-dns-failover [true/false]` | Whether the device may fall back to the default system DNS resolver; supported from iOS/macOS 26. When omitted, the system default `false` applies; the flag alone means `true` |
| `--relay-uuid UUID` | The Relay UUID used for managed app routing; user enrollment requires it. It must match the app association configured in MDM; Apple does not offer this key on macOS |
| `--name name` | Name shown in Settings, default the domain |
| `--udp-template path` | If `relay.udp_template` was changed, give the same value |
| `--no-http3` | Use HTTP/2 (TCP) only. Worth trying on networks that block UDP |
| `--no-http2` | Use HTTP/3 only |
| `-o`, `--out file` | Save to this file, default `domain-user.mobileconfig` (mode 600) |
| `--publish` | Put it in the `[web] root` directory with a random file name and mode 600, and print the download link. It can be downloaded only after `systemctl reload`; after installing, delete it and reload again |
| `--config path` | Which configuration file `--publish` reads, default `/etc/network-relay/relay.toml` |

What the profile contains:

- One `com.apple.relay.managed` payload (iOS 17 and macOS 14 or later; can be installed by hand, no supervision needed).
- `HTTP3RelayURL` and `HTTP2RelayURL` are both URI templates, such as `https://relay.qolita.com/.well-known/masque/udp/{target_host}/{target_port}/`.
- `AdditionalHTTPHeaderFields` holds `Authorization: Basic ...`, which the device sends with every request. **So the profile contains the password**; do not hand it to others.
- The identifier is the domain and the user name joined with a dot: a profile regenerated for the same domain and user replaces the old one when installed. This means a dot in the user name can "join up" with the domain: domain `relay.example` with user `com.alice` gives the same identifier as domain `relay.example.com` with user `alice`, and whichever is installed later replaces the other. When installing several relays on the same device, do not use dotted user names like this. (The way the identifier is built stays unchanged so that profiles already installed can still be replaced.)
- New options are written into the profile only when given explicitly. Choose them according to the device's OS version: for example, a configuration that uses only `--match-fqdn` does not suit older systems that do not support that key. Domains are converted to lower case and trailing dots are removed.
- DNS failover lets the device use the local network's system DNS; to keep DNS going through the relay at all times, leave the default.
- Saving and overwriting both use atomic replacement with a mode-600 temporary file, and symlinks are never overwritten. Generate published files as the user that runs the relay service, so that the service can read them.

For example, to relay only `api.example.com` while letting the user turn the relay off by hand (the device needs iOS/macOS 26 or later):

```bash
network-relay profile --host relay.example.com --user iphone --match-fqdn api.example.com --ui-toggle-enabled true
```

### `network-relay check`

Tests a running relay the way a device would: on each of HTTP/3, HTTP/2 and HTTP/1.1 it tests TCP once (fetching a web page through a CONNECT request) and UDP once (a DNS query through CONNECT-UDP), then confirms that CONNECT without a password gets 404. Exits with 0 when everything passes.

| Option | Default | Description |
|---|---|---|
| `--server domain` | — | The relay's domain |
| `--address IP` | resolve the domain | Connect directly to this IP (can be given more than once) |
| `--port port` | `443` | |
| `--user name` | — | |
| `--password password` | prompted for | |
| `--tcp-target host:port` | `example.com:80` | Website reached through the TCP relay (sends one HTTP request and shows the first line of the response) |
| `--udp-target host:port` | `1.1.1.1:53` | DNS server queried through the UDP relay |
| `--dns-name domain` | `example.com` | Name to query |
| `--udp-template path` | default template | If `relay.udp_template` was changed, give the same value |
| `--ca file` | system root certificates | Trust only this CA (for testing) |
| `--timeout seconds` | `10` | Timeout for each step |
