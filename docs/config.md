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
| `cert` | — | Certificate chain file (`/etc/network-relay/tls/fullchain.pem`, the hook's copy of certbot's `fullchain.pem`) |
| `key` | — | Private key file. The relay runs as user `network-relay`, which cannot read certbot's `privkey.pem`; point this at the copy that `deploy/certbot-hook.sh` keeps in `/etc/network-relay/tls` |
| `reload_interval_days` | not set | Reread the certificate files every this many days (1 to 7). When not set, they are reread every day at 3 a.m. (system time zone). `systemctl reload` also rereads them immediately |
| `client_certificates` | `false` | Ask TLS clients for a certificate (optional for them), so that users with a `certificate_sha256` can authenticate without a password. Off by default, because a website that asks for client certificates is unusual and can make a browser offer its user a certificate to choose. Needs a restart after a change |

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
- `.mobileconfig` files are served with the profile content type (`application/x-apple-aspen-config`), so Safari offers to install them.
- Profiles from `network-relay profile --publish` go to the hidden `.publish` directory inside `root`. Each is served at `/<its name>` once, and only within 15 minutes of being written; after that the address shows the website like any other, even across reloads. They carry credentials, so delete them afterwards (the next `--publish` also removes expired ones).

### `[relay]` (optional)

Network buffer capacity is also admitted against one shared budget: half the smallest detected host or visible ancestor cgroup memory limit. Each TCP/QUIC client connection reserves up to 8 MiB; each tunnel reserves 16 MiB for transport, capsule queues and target socket buffers. The reservations are conservative capacity estimates, not process RSS measurements. All reservations are refunded on cancellation and closure. Raising `max_connections` or `max_tunnels` does not bypass this budget. At 1 GiB, the default tunnel limit is 16; at 4 GiB, 64. Website snapshots, password hashing and other process overhead need the remaining memory. Capacity and throughput should be measured for your workload before deploying at scale.

| Key | Default | Description |
|---|---|---|
| `udp_template` | `"/.well-known/masque/udp/{target_host}/{target_port}/"` | Path part of the CONNECT-UDP URI template (RFC 9298 §2). It must contain `{target_host}` and `{target_port}`, and requests expanded from it must parse back to the original target (for example, an unnamed `?{target_host}` in the query cannot be parsed back and is rejected). Profiles must use the same template (`network-relay profile --udp-template`). Usually left alone |
| `blocked_destinations` | see below | Address ranges devices may not reach. Every address a domain resolves to is checked. IPv6 addresses that carry an IPv4 address are checked by that IPv4 address as well: IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible, NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`) and Teredo (`2001::/32`, both the server and the client address) |
| `block_own_addresses` | `true` | Also block every address of this server's network interfaces, its public addresses included, which the list cannot know. Read again at most every 10 seconds. If they cannot be read, every destination is refused rather than risk reaching the server itself |
| `blocked_ports` | `[25]` | Ports devices may not reach, on both TCP and UDP. 25 is the mail port; blocking it keeps the server from being used to send spam |
| `connect_timeout_secs` | `10` | Timeout for connecting to a target TCP service (1 to 120) |
| `udp_idle_timeout_secs` | `300` | How long a UDP flow may go without data in either direction before it is closed (120 to 3600; RFC 4787 requires at least 2 minutes) |
| `max_tunnels` | from memory | Limit on TCP connections and UDP flows relayed at the same time, across all users. When not set: a quarter of available host/container memory at 16 MiB per tunnel, between 1 and 20000 (32 if memory cannot be detected). New requests beyond it get 503. Needs a restart after a change |
| `max_tunnels_per_user` | `512` | The same limit for one user, so that one device, or stolen credentials, cannot take every slot. Beyond it: 503 with `connection_limit_reached` |
| `max_bytes_per_second_per_user` | `0` (unlimited) | Payload bytes per second one user may relay, both directions and all tunnels together, after a burst of 128 KiB. TCP tunnels slow down; UDP packets over the budget are dropped |
| `max_udp_packets_per_second_per_user` | `0` (unlimited) | UDP packets per second one user may relay, both directions together, after a burst of 1024 |
| `max_connections` | `16384` | Client connections (TCP and QUIC) open at once. Connections beyond it are closed right away; QUIC ones are refused before their handshake. Needs a restart after a change |
| `max_connections_per_ip` | `64` | The same limit per IPv4 address or IPv6 /64. Needs a restart after a change |
| `idle_timeout_secs` | `300` | Close a client connection after this many seconds without an open request (30 to 3600). A connection that has not authenticated any request gets 30 seconds |

Default `blocked_destinations`: the local host (`127.0.0.0/8`, `::1`), unspecified addresses, private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), carrier-grade NAT (`100.64.0.0/10`), link-local (`169.254.0.0/16`, including cloud providers' metadata service `169.254.169.254`; `fe80::/10`), multicast, reserved addresses, benchmarking, documentation and test addresses (including `3fff::/20`), the deprecated 6to4 relay anycast range, ORCHID, SRv6 SIDs (`5f00::/16`), IPv4-mapped addresses, and the local-use NAT64 prefix. See the example configuration for the complete list.

- To let devices reach the network the server is on (a NAS at home, say), remove the corresponding range from the list. **Do not empty it entirely**: devices could then reach services on the server itself that listen only on 127.0.0.1.
- The server's own public address is not in the list; `block_own_addresses` covers it. Addresses that reach the server some other way (a floating IP that is not configured on an interface, a load balancer) must be added to the list by hand.
- Refused requests get the reason in the `Proxy-Status` header (RFC 9209): a blocked address is `destination_ip_prohibited` with 502, a blocked port `http_request_denied` with 403.

### `[debug]` (optional)

| Key | Default | Description |
|---|---|---|
| `log_requests` | `false` | Log one line per proxy request (CONNECT or Upgrade): HTTP version, method, `:protocol`, target, path and all request headers (`Authorization` shows only the user name). Refused requests are logged with the reason. Use it to find out what devices actually send; it is noisy, so turn it off afterwards |

### `[[user]]` (may appear more than once)

| Key | Description |
|---|---|
| `name` | User name: 1 to 64 letters, digits, `-`, `_` or `.`, not starting with `.` |
| `password_hash` | The hash printed by `network-relay passwd`: `$pbkdf2-sha256$...` for a generated password, `$argon2id$...` for a chosen one |
| `certificate_sha256` | The SHA-256 fingerprint of the user's client certificate, printed by `network-relay identity`. Needs `[tls] client_certificates = true`. A user needs a `password_hash`, a `certificate_sha256`, or both |
| `expires` | When the account stops working, in RFC 3339 (`2027-01-31T00:00:00Z`, quoted or not). Its open tunnels are closed then |

- One user per device, so disabling a device means deleting only its section.
- After a reload, ongoing connections of users who were deleted or whose credentials changed are disconnected immediately. Verified credentials of users that did not change stay cached, so a reload does not make every device verify again.
- With no users at all, the relay is just a website, and a warning is logged at startup.

Generated passwords (`passwd` without `--stdin`) are 144 random bits, so they get a fast hash (PBKDF2-SHA256, 1000 rounds), which protects them as well as a slow hash protects a chosen password and costs the server almost nothing to check. Chosen passwords get Argon2id. Argon2id hashes may use at most 64 MiB, 10 passes and 4 lanes, so that one check cannot tie up the server.

Checking new credentials is limited: about one attempt per second per client address (IPv4 address or IPv6 /64, after a burst of 30) and four at a time per connection. Credentials that already passed cost nothing: they stay cached as long as they are used, and stay bound to the connection that used them. A device opening many tunnels at once with new credentials waits for one check, not one each.

#### Client certificates

Instead of a password, a device can prove itself with a certificate:

```bash
network-relay identity --name ipad                     # writes ipad.p12, prints its password and fingerprint
network-relay profile --host relay.example.com --user ipad --identity ipad.p12
```

Put the printed `certificate_sha256` in the user's section and `client_certificates = true` under `[tls]`, then restart. The profile carries the certificate and key in a `com.apple.security.pkcs12` payload that the relay payload refers to with `PayloadCertificateUUID`; the device asks for the PKCS#12 password when it is installed (unless `--embed-identity-password` puts it in the profile), so the profile file alone does not give the key away. The certificate is self-signed and valid for 825 days (`--days`); the relay trusts exactly the fingerprints in its configuration, not a CA.

## reload and restart

| What changed | How to apply it |
|---|---|
| `[[user]]`, `[relay]` (except the settings below), `[debug]`, `[web]`, certificate files | `systemctl reload network-relay`; existing connections are not affected (except for deleted users) |
| `listen`, `log_dir`, `max_tunnels`, `max_connections`, `max_connections_per_ip`, the file paths, `reload_interval_days` and `client_certificates` in `[tls]` | `systemctl restart network-relay`; all devices disconnect and reconnect automatically |

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

Logs are written by a separate thread. If the journal or the log directory cannot keep up, lines are dropped rather than slowing the relay down. Failed authentications are logged at most about five times a second, with a count of those left out.

### `network-relay passwd`

Creates a user: a random password (144 random bits) and its hash.

| Option | Description |
|---|---|
| `--name name` | User name |
| `--stdin` | Instead of generating a random password, read your own from standard input (at least 12 characters); it gets an Argon2id hash |
| `--fast-hash` | With `--stdin`: the password read is itself a random secret of at least 24 characters (from a password manager, say), so it gets the fast hash |
| `--expires time` | Add an `expires` line (RFC 3339) |

### `network-relay identity`

Creates a client certificate for a user: an ECDSA P-256 key and a self-signed certificate (CN = the user name, for client authentication), packed into a PKCS#12 file that Apple devices accept. It prints the file's random password and the `[[user]]` lines with the fingerprint.

| Option | Description |
|---|---|
| `--name name` | User name |
| `--days days` | Validity, default 825 |
| `-o`, `--out file` | Default `name.p12`, mode 600 |

### `network-relay profile`

Generates a profile (`.mobileconfig`) for iPhone, iPad and Mac.

| Option | Description |
|---|---|
| `--host domain` | The relay's domain (the name on the certificate) |
| `--user name` | User name |
| `--password password` | Password; if omitted, it is prompted for when the command runs (recommended: on the command line it is visible to other users of the machine and lands in the shell history, and a warning says so). Not asked for when `--identity` is given; with both, the profile carries both |
| `--identity file.p12` | Authenticate with this client certificate (from `network-relay identity`) |
| `--embed-identity-password` | Put the PKCS#12 password (asked for) into the profile; without it the device asks for it during installation |
| `--ddm` | Write a declarative device management declaration (JSON) for an MDM server instead of a `.mobileconfig` |
| `--identity-asset id` | With `--ddm`: the identifier of the MDM's identity asset declaration to authenticate with |
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
| `--publish` | Put it in `.publish` under the `[web] root` directory with a random name and mode 600, and print the link. After `systemctl reload`, the link works once, within 15 minutes; delete the file afterwards |
| `--config path` | Which configuration file `--publish` reads, default `/etc/network-relay/relay.toml` |

What the profile contains:

- One `com.apple.relay.managed` payload (iOS 17 and macOS 14 or later; can be installed by hand, no supervision needed).
- `HTTP3RelayURL` and `HTTP2RelayURL` are both URI templates, such as `https://relay.qolita.com/.well-known/masque/udp/{target_host}/{target_port}/`.
- With a password, `AdditionalHTTPHeaderFields` holds `Authorization: Basic ...`, which the device sends with every request. **So the profile contains the password**; do not hand it to others. With a client certificate instead, it holds no secret except the encrypted PKCS#12.
- Profiles are not signed. To sign one with your own certificate, so that the device shows who it is from: `openssl smime -sign -signer cert.pem -inkey key.pem -certfile chain.pem -nodetach -outform der -in relay.mobileconfig -out relay-signed.mobileconfig` (on a Mac, `security cms -S -N "certificate name" -i relay.mobileconfig -o relay-signed.mobileconfig`).
- The identifier is the domain and the user name joined with a dot: a profile regenerated for the same domain and user replaces the old one when installed. This means a dot in the user name can "join up" with the domain: domain `relay.example` with user `com.alice` gives the same identifier as domain `relay.example.com` with user `alice`, and whichever is installed later replaces the other. When installing several relays on the same device, do not use dotted user names like this. (The way the identifier is built stays unchanged so that profiles already installed can still be replaced.)
- New options are written into the profile only when given explicitly. Choose them according to the device's OS version: for example, a configuration that uses only `--match-fqdn` does not suit older systems that do not support that key. Domains are converted to lower case and trailing dots are removed.
- DNS failover lets the device use the local network's system DNS; to keep DNS going through the relay at all times, leave the default.
- Saving and overwriting both use atomic replacement with a mode-600 temporary file, and symlinks are never overwritten. A published file gets the owner of the `.publish` directory, so that the relay, which runs as user `network-relay`, can read it even when root runs the command.

Warnings are printed for choices that may not do what was meant: `UIToggleEnabled` false (a relay that is down cannot be switched off), only `--match-fqdn` (older systems do not know the key), and excluded host names that are not under any matched domain (Apple ignores them).

`--ddm` writes a `com.apple.configuration.network.relay` declaration (`Type`, `Identifier`, `ServerToken`, `Payload`) with the same relays and rules. With `--identity-asset`, the relay authenticates with that identity asset (`IdentityAssetReference`) and the declaration holds no password; otherwise it carries the `Authorization` header like the profile.

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
| `--client-cert file`, `--client-key file` | none | Present this client certificate and key (PEM) |
| `--timeout seconds` | `10` | Timeout for each step |
