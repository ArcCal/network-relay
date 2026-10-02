# Changelog

## Unreleased

- When loading the website, the file actually opened is checked, so a parent directory swapped for a symlink between the check and the open cannot expose files outside the site.
- HTTP/1.1 requests with no `Host` or more than one `Host` get 400 (RFC 9112 §3.2, RFC 9298 §3.2).
- If a request expanded from `relay.udp_template` does not parse back to the original target, configuration loading and profile generation fail outright instead of silently treating UDP requests as website requests.
- `serve --check` reports an error for a certificate that has expired or is not yet valid.
- Installer: `--cert`/`--key` are saved as given (Let's Encrypt `live/` symlinks are not resolved); an upgrade keeps the existing installation's certificate setup instead of suddenly switching to certbot; a `--cert`/`--key` that differs from the existing configuration is refused rather than silently ignored; the startup check accepts any HTTP response (without `[web]` the home page is a 404); `procps` is installed.
- The one-step installer also supports Debian 12 (bookworm) x86_64.
- The installer's `apt-get` waits for the dpkg lock (up to 30 minutes), so it no longer fails outright on a freshly booted VPS that is running automatic updates.
- CI: in the arm64 tests, child processes started by tests also find the dynamic linker through qemu.
- `passwd --stdin`, `profile` and `check` no longer echo the password when prompting for it in a terminal.
- The error code used when a UDP flow ends early now depends on the cause: a malformed message, a failed target socket, and cancellation or revocation use `H3_MESSAGE_ERROR`/`PROTOCOL_ERROR`, `H3_CONNECT_ERROR`/`CONNECT_ERROR` and `H3_REQUEST_CANCELLED`/`CANCEL` respectively; previously all were treated as malformed messages.
- On an HTTP/3 TCP tunnel, datagrams received after the device has sent FIN are silently dropped (RFC 9297 §2.1) instead of resetting the stream.
- HTTP/1.1 `Connection` and `Upgrade` are parsed as token lists; HTTP/2 rejects a `Date` on responses.
- Added `deploy/global-profile.py`: builds a `.mobileconfig` from a service domain list (`deploy/domains/global-services.txt`) and the gfwlist, using only the standard library and `network-relay profile`; it has automated tests.
- If the listener or certificate-reload task exits unexpectedly, the process now exits with an error (and systemd restarts it) instead of carrying on with a listener missing; signal handlers are registered before the listeners start.
- A reload no longer gives the decoy website's 404 to requests that are in their first authentication and whose user did not change; failed authentication results can no longer evict authenticated entries from the cache.
- Dangling or looping symlinks in the website directory no longer make the whole website fail to load.
- The HTTP/1.1 request header buffer is limited to 64 KiB (previously hyper's default of about 400 KiB), close to the 32 KiB header limit of HTTP/2 and HTTP/3.
- In environments without IPv6 loopback, the no-fragmentation test skips its IPv6 part; added a regression test that successful HTTP/1.1 responses carry no framing headers.
- Added a source-build installer for Debian 13 x64: automatic certificates, renewal, systemd, configuration import, self-check and rollback on startup failure; ships a Google/AI/X domain preset, and the private device profile is generated separately and never added to the repository.
- Fixed cancellation after HTTP/2 half-close, idle HTTP/3 STOP_SENDING, connection loss, and user revocation while the response is blocked by flow control, so target connections and tunnel slots are released promptly.
- Trailing HEADERS on CONNECT are rejected as the protocols require; fixed empty HTTP/3 DATA being taken as the end of the stream and truncated DATA being taken as a normal close. The local patches to dependencies and their origin are recorded in `vendor/*/PATCH.md`.
- Large capsules with an unknown UDP context are discarded as a stream; a closed write side is no longer treated as ordinary packet loss, blocked write tasks exit within a bound, and a steady stream of incoming packets no longer holds off cancellation and timeouts.
- Fixed matching errors when a URI template separator appears in the host name; tightened validation of configuration, Argon2 hashes, and profile XML and domain names.
- The website no longer exposes files outside its directory or hidden files through file symlinks, and reads are bounded in size; custom response headers cannot override protocol framing fields, and legitimate overrides do not produce duplicate headers.
- The self-check now has timeouts for DNS, HTTP/3 connection setup and writes, and tries the next address after a TLS handshake failure; DNS queries validate label and total length.
- Profiles gain `--match-fqdn`, `--exclude-fqdn`, `--ui-toggle-enabled`, `--allow-dns-failover` and `--relay-uuid`, and domains, ports and UUIDs are validated.
- Fixed authentication and connection races while a user is deleted or their password is changed; limited the number of distinct credentials waiting for authentication, cleaned up waiters when a request is cancelled, and kept the hashing slot until the hash has really finished.
- HTTP/2 manages flow control and stream resets directly, maps target TCP errors to `CONNECT_ERROR`, and keeps normal half-close.
- HTTP/3 uses QUIC DATAGRAM only when datagrams were negotiated at both the HTTP and the QUIC layer, and capsules otherwise; a datagram received on a non-UDP request gets `H3_DATAGRAM_ERROR`.
- Fixed handling of oversized UDP payloads, large unknown capsules, forbidden request headers on capsule requests, and query templates mixing literals and variables. Target UDP sockets on Linux explicitly forbid IP fragmentation.
- Saving, publishing and overwriting profiles all write atomically with mode 600 and refuse symlink targets.
- Added regression tests for protocol error codes, capsule fallback, empty UDP packets, file permissions and more; verification on real Apple devices is still pending.

## 0.1.0

First release.

- **Relay server**: TCP relaying (classic CONNECT) and UDP relaying (CONNECT-UDP, RFC 9298) over HTTP/3 (UDP 443), HTTP/2 and HTTP/1.1 (TCP 443), implemented the way Apple's network relay uses them.
- **Authentication**: user name and password (HTTP Basic, `Authorization` or `Proxy-Authorization`); the server stores only Argon2id hashes; authentication results are cached; users deleted in a reload are disconnected immediately.
- **Decoy website**: requests without a password see an ordinary website; missing files under `/.well-known/` get 404.
- **Destination restrictions**: internal networks, the server itself, metadata services and similar addresses are blocked by default, checking every address a domain resolves to; port 25 is blocked by default.
- **Error information**: failed requests that passed authentication carry `Proxy-Status` (RFC 9209).
- **`network-relay profile`**: generates profiles for iPhone, iPad and Mac, which can be put straight on the decoy website and installed by opening them in Safari (`--publish`).
- **`network-relay check`**: tests TCP and UDP relaying over all three HTTP versions.
- **`network-relay passwd`**: creates users and passwords.
- systemd unit (keeping only the permission to bind port 443), sysctl settings for UDP buffers, GitHub Actions builds for x86_64 and arm64.
- Interoperability tested with curl and quic-go's masque-go; **not yet tested on real Apple devices**.
