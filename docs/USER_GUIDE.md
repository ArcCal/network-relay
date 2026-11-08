# Network Relay practical user guide

This guide covers the standalone Rust server, Apple's built-in Network Relay
profiles, and the additional applications shipped in this repository. Start
with the standard server and one test device. The experimental WARP server and
the NF/RS desktop clients have different requirements and validation status.

Commands are examples to run deliberately on your own systems. Replace
`relay.example.com`, `203.0.113.10`, SSH account names and paths before use.
`203.0.113.10` is a documentation address, not a working server.

## Contents

- [Choose the right component](#choose-the-right-component)
- [Deployment checklist](#deployment-checklist)
- [Install the standard server](#install-the-standard-server)
- [Understand the configuration](#understand-the-configuration)
- [Create and install device profiles](#create-and-install-device-profiles)
- [Verify the complete path](#verify-the-complete-path)
- [Routine administration](#routine-administration)
- [Upgrade, stop and remove](#upgrade-stop-and-remove)
- [Use the NF and RS desktop clients](#use-the-nf-and-rs-desktop-clients)
- [Use the experimental WARP-egress server](#use-the-experimental-warp-egress-server)
- [Troubleshooting](#troubleshooting)
- [Tests and evidence](#tests-and-evidence)

## Choose the right component

| Component | What it does | Choose it when |
| --- | --- | --- |
| Root `network-relay` server | Authenticated TCP CONNECT and UDP CONNECT-UDP over HTTP/1.1, HTTP/2 and HTTP/3; ordinary website for other requests | You want a standalone server for Apple profiles or compatible relay clients |
| Apple `.mobileconfig` profile | Configures the operating system's built-in relay feature | You want domain-based routing without installing a client application |
| [Network Relay NF](../network-relay-nf/README.md) | Separate macOS SOCKS5 application, using Apple Network.framework for production sockets/TLS/QUIC | You want applications to use an explicit local SOCKS proxy and can meet its current macOS/SDK requirements |
| [Network Relay RS](../network-relay-rs/README.md) | Separate Rust/AppKit macOS SOCKS5 application, using Tokio/rustls/Quinn | You want the independent Rust desktop client or its headless mode |
| [Network Relay CF MASQUE](../network-relay-cf-masque/README.md) | Separate experimental relay server whose forwarded traffic and DNS must leave through WARP | You specifically need WARP egress and accept the live-service validation gap |

The root server's current package version is `1.5.0`; it is not the same
program as the similarly named desktop applications. Read the version of the
binary actually installed:

```bash
network-relay --version
```

The standard server connects to allowed destinations from the VPS. It does not
create a TUN interface, forward raw IP packets or install full-device VPN routes.
Apple's "all traffic" relay profile is still an application/OS relay mechanism:
ICMP is outside its protocol, and applications using their own networking paths
may bypass it. It is not interchangeable with a CONNECT-IP VPN.

The Caddy implementation is a separate project:
[caddy-network-relay](https://github.com/ArcCal/caddy-network-relay). Password
hashes and the client-facing relay protocol are compatible, but its service,
configuration, TLS management and reload rules differ.

## Deployment checklist

Prepare these before installing:

1. A domain pointing at the server's reachable public address. If using
   Cloudflare DNS, select **DNS only**, not the HTTP reverse proxy.
2. A fixed or reserved public address. An incorrect AAAA record can break
   clients even when the A record is correct; remove or correct an unreachable
   AAAA record.
3. TCP 443 for HTTP/1.1/HTTP/2, UDP 443 for HTTP/3, and TCP 80 if using the
   installer's HTTP certificate challenge. DNS-based certificate validation is
   a separate documented option, not a reason to close port 80 in HTTP-challenge
   deployments.
4. Working SSH access. Keep your SSH port allowed in both the provider firewall
   and the host firewall. Provider firewalls are not configured by the installer.
5. Exclusive use of the required TCP/UDP listener ports. Existing nginx, Caddy,
   other proxies or QUIC services may already own them.
6. Debian 12/13 x86_64 with systemd for the automatic installer. Use manual
   deployment for other distributions or arm64. Allow roughly 2 GiB RAM/swap and
   3 GiB free disk when compiling, and more if building additional applications.

Useful checks **on the VPS**:

```bash
cat /etc/os-release
```

```bash
uname -m
```

```bash
getent ahosts relay.example.com
```

```bash
ss -lntup
```

Do not diagnose server DNS exclusively through a desktop running a fake-IP
proxy. A successful test from the VPS also does not establish that a device on
another network can reach it.

## Install the standard server

### Recommended automatic source installation

For this private repository, download files in a browser signed into an account
with repository access, or use your already-authenticated GitHub CLI. Anonymous
raw-file requests may return 404.

Download both current files from the repository root:

- [network-relay-install-from-source.sh](../network-relay-install-from-source.sh)
- [network-relay-install-from-source.sh.sha256](../network-relay-install-from-source.sh.sha256)

Verify on a Mac:

```bash
shasum -a 256 -c network-relay-install-from-source.sh.sha256
```

Or verify on Linux:

```bash
sha256sum -c network-relay-install-from-source.sh.sha256
```

An `OK` result is required. Upload the script from your computer:

```bash
scp network-relay-install-from-source.sh root@203.0.113.10:/tmp/
```

Then connect to the VPS and run as root:

```bash
sudo bash /tmp/network-relay-install-from-source.sh --domain relay.example.com --user iphone
```

The script contains its source payload; it does not need a source ZIP or a
GitHub credential on the VPS. It installs prerequisites, builds the server,
obtains a certificate, writes the service and configuration, gathers domain
lists, generates a private profile and runs checks. It changes packages,
service files, certificate-renewal configuration and, when UFW is already
active, host port allowances. Read
[the Debian deployment guide](deploy-debian13.md) for all installer options.
Run `bash SCRIPT --help` before choosing nondefault paths or certificate modes.

The current installer generates a **selective HTTP/2-only Apple profile**.
UDP applications still use CONNECT-UDP, carried in capsules over HTTP/2. The
server retains its HTTP/3 and HTTP/1.1 listeners for other clients.

Normal domain gathering combines the bundled base list, gfwlist and eighteen
service lists. A required source failure stops generation; it is not permission
to install an empty match list. The resulting profile must be reinstalled on
devices after later rule changes.

The installer either writes the credential-bearing profile to the selected
private output path or prints a random one-use website link valid for fifteen
minutes. The profile is the recoverable copy of its generated account password.
Install it promptly, then remove residual profile files. Do not paste profile
contents or installation output containing credentials into support requests.

### Use an executable built elsewhere

[network-relay-install.sh](../network-relay-install.sh) and
[its checksum](../network-relay-install.sh.sha256) accept an existing Linux
x86_64 executable. Upload it as `/tmp/network-relay`, verify the script and run:

```bash
sudo bash /tmp/network-relay-install.sh --domain relay.example.com --user iphone --binary /tmp/network-relay
```

The script does not turn a macOS executable into a Linux executable. The binary
must match the server architecture, runtime ABI and source used by the installer.
The [Mac-to-VPS deployment guide](manual-mac-cloudflare-dns.md) covers building
elsewhere and DNS-based certificate issuance.

Release `1.5` currently provides source archives rather than a manually uploaded
server binary. Check the actual Release asset list before choosing a download;
the existence of older binaries under earlier releases does not make them the
current server. The current root installers and source build are the dependable
starting points.

### Manual build and deployment

From a source checkout with Rust/Cargo and a native compiler/linker installed:

```bash
cargo build --locked --release --bin network-relay
```

```bash
./target/release/network-relay --version
```

Use [deploy.md](deploy.md) for creating the service account, installing the
binary, obtaining certificates and copying the
[systemd service](../deploy/network-relay.service). Use the committed lockfile
and vendored HTTP/3 patches; replacing their dependencies casually changes the
tested transport implementation. A successful cross-build is not a native
runtime test.

To build Linux x64 and arm64 server binaries for upload instead, run
`bash build-linux-servers-on-linux.sh` on Debian 13 or Ubuntu 26.04; it
installs what it needs and writes all three servers (network-relay,
network-relay-cf-masque and caddy-network-relay), logs and `SHA256SUMS` to a new
`relay-servers-*` folder. The [build scripts](../README.md#build-scripts)
section lists every build script. Each invocation downloads complete current
sources into a new timestamped `/tmp` directory; temporary sources, intermediate
files and build caches are removed on exit, while artifacts and logs remain.

The supplied service runs as `network-relay` with only low-port bind capability;
normal forwarding does not require `CAP_NET_ADMIN`. Installation itself requires
administrative privileges. Certbot's root-only key must be copied with the
provided renewal hook into the service-readable TLS directory; do not make the
original private key world-readable.

## Understand the configuration

The default path is `/etc/network-relay/relay.toml`. Start from
[relay.example.toml](../deploy/relay.example.toml); the complete field reference
is [config.md](config.md). For an IPv4 listener, the essential structure is:

```toml
listen = "0.0.0.0:443"

[tls]
cert = "/etc/network-relay/tls/fullchain.pem"
key = "/etc/network-relay/tls/privkey.pem"

[web]
root = "/var/www/relay"

[[user]]
name = "iphone"
password_hash = "REPLACE_WITH_THE_COMPLETE_HASH_FROM_NETWORK_RELAY_PASSWD"
```

This is a template, not a runnable configuration until real certificate files,
website `index.html` and the generated hash exist. Omitted relay settings retain
the safe defaults. Generate the actual user entry:

```bash
network-relay passwd --name iphone
```

Copy its complete `[[user]]` section into the configuration and keep the password
for profile generation. Use one account per device. Generated secrets use the
fast PBKDF2 format intended for high-entropy passwords; `passwd --stdin` accepts
a chosen password of at least twelve characters and hashes it with Argon2id.
Do not use `--fast-hash` for an ordinary human-chosen password.

| Setting | Default or practical meaning |
| --- | --- |
| `listen` | `[::]:443`; the server supports dual-stack listening and IPv4 fallback on hosts without IPv6. Choose an explicit IPv4 address when appropriate |
| `relay.udp_template` | `/.well-known/masque/udp/{target_host}/{target_port}/`; client profile and server must agree |
| `relay.blocked_destinations` | Blocks private, loopback, link-local, documentation and other special addresses; all DNS results are checked |
| `relay.block_own_addresses` | `true`; also blocks the server's own interface addresses |
| `relay.blocked_ports` | `[25]`, for both TCP and UDP |
| `relay.connect_timeout_secs` | `10`; bounded target connection attempts |
| `relay.udp_idle_timeout_secs` | `300`; accepted range 120-3600 seconds |
| `relay.max_tunnels` | Derived from available host/container memory unless explicitly set; this bounds admission, not total process RSS |
| `relay.max_tunnels_per_user` | `512` |
| Per-user byte/UDP packet rates | `0` means unlimited; excess TCP waits, excess UDP drops |
| `relay.max_connections_per_ip` | `64`; IPv6 clients are grouped by /64 |
| `debug.log_requests` | `false`; enable briefly for diagnosis, then disable |

Do not copy a test fixture's `blocked_destinations = []` and
`block_own_addresses = false` into an Internet-facing deployment. Those settings
can expose local services and cloud metadata to anyone holding relay credentials.
Domain policy here is destination safety policy; selective **client routing**
belongs in the Apple profile.

All relative filesystem paths resolve from the process's working directory.
Use absolute configuration, certificate, key and website paths in a service.

Validate without opening the network service:

```bash
sudo -u network-relay /usr/local/bin/network-relay serve --config /etc/network-relay/relay.toml --check
```

This checks configuration, readable certificate/key and website. It does not
test public DNS, certificate issuance, firewall reachability or device routing.
Unlike normal startup's warning, `--check` rejects expired/not-yet-valid
certificates.

## Create and install device profiles

### Start with one explicit domain

This limits the first experiment to a domain and its subdomains and preserves
the supported user switch:

Run on the VPS as root (the output path is root's private directory):

```bash
sudo network-relay profile --host relay.example.com --user iphone --no-http3 --match-domain example.com --ui-toggle-enabled true --out /root/iphone.mobileconfig
```

Type the account password at the prompt. Prefer the prompt to `--password`,
which exposes the secret in command arguments and shell history.

| Option | Effect |
| --- | --- |
| `--match-domain example.com` | Relays that domain and subdomains; repeat for more domains |
| `--exclude-domain relay.example.com` | Excludes that domain/subdomains from this relay configuration |
| `--match-fqdn api.example.com` | Exact hostname only; requires iOS 18.4/macOS 15.4 or later |
| No `--match-domain` or `--match-fqdn` | **All eligible traffic**, subject to exclusions; an empty list is not "relay nothing" |
| `--no-http3` | Writes HTTP/2 only; useful when UDP transport is blocked |
| `--no-http2` | Writes HTTP/3 only; do not combine with `--no-http3` |
| `--port N` / `--udp-template PATH` | Must match the server listener/template |
| `--ui-toggle-enabled true` | Allows the device's supported relay toggle; iOS/macOS 26+ |
| `--allow-dns-failover true` | Explicitly permits the device's system DNS fallback on supported OS versions; omit to retain the default |

The basic managed relay profile requires iOS/iPadOS 17 or macOS 14 or newer.
Exact-FQDN fields need newer versions. Do not create an exact-FQDN-only profile
for an OS that ignores the field: it can change the intended selection scope.
DDM output (`--ddm`, with appropriate identity-asset options) targets OS 27+
managed deployments and is separate from manually installing a mobileconfig.
Generated structures have parser coverage; real MDM/DDM acceptance remains a
separate check.

The source-list installer normalizes registered roots using bundled ICANN suffix
data. This can widen one shared-hosting/CDN hostname to a parent used by unrelated
services. Its processing also drops unsupported regex/IP/process/exception rules
and widens path rules to domains. Read
[domain-list behavior](../deploy/domains/README.md) before treating imported
lists as exact replicas of their source rule engines.

### Install privately

Download the file to your computer using SSH/SCP, then use AirDrop or another
private transfer method to the device. On iPhone/iPad, install it through the
downloaded profile screen in Settings. On macOS, open it and complete installation
under System Settings's device-management/profile section. Labels vary by OS.

Remove obsolete relay profiles first. A replacement for the same host and user
uses the same identifier; unrelated profiles can remain active together and
interfere. Avoid dotted usernames that can collide with a host/user-derived
profile identifier when administering multiple relays.

The mobileconfig contains recoverable credentials, even if its Basic header
looks encoded. Keep output permissions private, never put it in the ordinary
website root, and remove download/server copies after installation. One-time
publication limits URL use and time; it does not delete the underlying file.
Removing the profile on the device is the recovery path when an unwanted
all-traffic rule or unavailable relay prevents access. Setting the supported
toggle to false intentionally removes the simpler toggle-based escape route.

### Optional certificate authentication

`network-relay identity --name ipad` creates an encrypted PKCS#12 identity and
prints its fingerprint and password. Add the fingerprint to that user's
`certificate_sha256`, enable `[tls] client_certificates = true`, restart, and
generate the profile with `--identity FILE.p12`. The same user can have a
password, a certificate, or both. Protect both the PKCS#12 and generated profile;
embedding its password removes the extra installation-time secret.

This is implemented functionality, not established Apple-device acceptance.
Use the [configuration reference](config.md#client-certificates) and test one
device before relying on it. Changing the TLS certificate-request setting needs
a restart and can make ordinary browsers offer client certificates.

## Verify the complete path

Run these checks in order; each answers a different question.

1. **Local configuration:** run `serve --check` as the service user.
2. **Service/listeners:** inspect `systemctl status network-relay --no-pager`
   and `ss -lntup`. Check both TCP and UDP if using H3.
3. **Local end-to-end relay:** run the self-check against loopback while keeping
   the real TLS hostname:

   ```bash
   network-relay check --server relay.example.com --address 127.0.0.1 --user iphone
   ```

4. **External reachability:** run the same check on another machine, without
   `--address 127.0.0.1` or with the actual public address. A working local check
   cannot certify provider firewall/NAT/inbound routing.
5. **Actual device selection:** install the profile, disable competing VPN/proxy
   applications for the experiment, access a matched domain, and correlate
   temporary server request logs. Also check an unmatched/excluded domain.
6. **Separate TCP and UDP:** the self-check's TCP web fetch and UDP DNS query
   test different forwarding paths. A successful webpage alone proves neither
   UDP forwarding nor the exact profile routing policy.

`check` tests TCP and UDP over all three HTTP versions and anonymous rejection.
Its defaults fetch `example.com:80`, query `1.1.1.1:53` for `example.com`, and
allow ten seconds per step. Select `--tcp-target`, `--udp-target`, `--dns-name`
or `--timeout SECONDS` when your allowed destination/network policy requires it.
An intentionally H2-only deployment can have an H3 diagnostic failure without
invalidating H2, but investigate failures in the protocol you intend to use.

An HTTP response from the ordinary website is only a website test. Likewise,
an IP-check webpage may be outside a selective profile's match list. Use an
observed matched destination rather than treating any working browser page as
proof of relay use.

## Routine administration

### Paths and commands

| Item | Standard location or command |
| --- | --- |
| Executable | `/usr/local/bin/network-relay` |
| Configuration | `/etc/network-relay/relay.toml` |
| Service | `network-relay.service`, running as `network-relay` |
| Service-readable TLS copies | `/etc/network-relay/tls/` |
| Website | `/var/www/relay/` |
| Journal | `journalctl -u network-relay -n 100 --no-pager` |
| Optional hourly log files | Configured absolute `log_dir`; 24-hour retention |

### Change settings safely

Back up the configuration with restrictive permissions. Edit it, run
`serve --check` as the service user, and only then reload or restart.

```bash
sudo systemctl reload network-relay
```

Reload applies users, destination policy, most timeouts/budgets, website content
and the current certificate. Deleted/changed credentials, expired users and
newly forbidden destinations revoke affected tunnels; do not promise existing
sessions survive a security-policy change. Invalid replacement configuration is
logged and the current configuration is kept.

Restart for changes to `listen`, `log_dir`, `max_tunnels`, `max_connections`,
`max_connections_per_ip`, or TLS settings including file paths,
`client_certificates` and `reload_interval_days`:

```bash
sudo systemctl restart network-relay
```

A successful SIGHUP with a warning about restart-only fields does not mean those
fields took effect. Read the journal after either operation. The server rereads
certificate files daily at 03:00 in the host's timezone by default; this is
separate from Certbot actually renewing and copying those files.

### Add, revoke or rotate a device

Create a unique account using `passwd --name ipad`, add its printed section,
validate and reload. Generate a separate profile for that user.

To rotate a password, replace the existing hash instead of appending a duplicate
user section. Validate/reload, regenerate the profile with the new password and
reinstall it on the device. For a lost device or exposed profile, revoke its
account immediately; changing only a local profile file does not revoke the
server credential. An `expires` timestamp can provide a fixed account lifetime.

### Collect a useful incident report

Record binary version, OS/architecture, selected transport, sanitized
configuration, service status, timestamps and the exact failed check. Enable
`[debug] log_requests = true` briefly and reload if destination evidence is
needed. Turn it off afterwards. Logs can still expose usernames and destination
metadata even when authentication headers are redacted, and the values of other
header fields, including any custom ones a profile adds. Do not share passwords,
full mobileconfig files, private keys or WARP enrollment material.

## Upgrade, stop and remove

Keep a known-good binary plus private configuration backup. Use a current
installer/source bundle, not an old extracted payload with a new outer filename.
Read its `--help` and [deployment instructions](deploy-debian13.md) for upgrade
and profile-refresh behavior; installer-generated profiles and already-installed
device profiles are separate objects.

For a manual upgrade, build a candidate from the intended source with `--locked`,
run that candidate's `serve --check` against the installed configuration under
the service account, then replace the binary and restart during a planned
interruption. If startup fails, restore the saved binary/configuration, restart
and repeat the external check. Do not assume that an installer failure always
left a working service; inspect the reported rollback and systemd state.

To stop accepting relay traffic and disable boot startup:

```bash
sudo systemctl disable --now network-relay
```

Normal stop requests bounded graceful shutdown (a five-second tunnel drain),
then listeners and connections close. A crash also closes its process-owned
sockets; systemd's `Restart=on-failure` may restart it. Stopping the server does
not remove Apple device profiles, package installations, certificates or host
firewall allowances. Matching device traffic may stop working until the profile
is disabled/removed or a server returns.

For full removal, first remove/disable device profiles, stop/disable the service,
then remove this service's binary/unit and run `systemctl daemon-reload`. Archive
or delete its private configuration, TLS copies and profile files deliberately.
Remove only the renewal hook, website, account and firewall rules that belong
exclusively to this installation. Do not remove shared Certbot certificates,
other websites or SSH allowances as a blanket cleanup step.

## Use the NF and RS desktop clients

These applications expose SOCKS, not an automatic full-device VPN. Configure
each application that should use the proxy, or use its explicit proxy option.
The common default listener is `127.0.0.1:1080`; run only one app on that address
or choose different ports. Remote relay credentials authenticate the server
connection, not local applications connecting to the default no-auth SOCKS port.

### Network Relay NF

Current build target: Apple silicon, macOS 27+, full Xcode with SDK 27+, and
stable Rust supporting edition 2024. From the repository root:

```bash
cd network-relay-nf &&
bash build-macos.sh &&
open 'dist/Network Relay NF.app'
```

Enter relay domain, optional server IP, username and password. Start with forced
HTTP/2 for an easily isolated check. An IP override changes the socket address;
the domain still controls TLS verification. The private settings directory is
`~/Library/Application Support/NetworkRelayNF/`; an older misspelled
`NetworkRealyNF` directory is read only for migration when the new file is absent.

"Relay Connected" means an authenticated request was admitted, not that every
Internet destination works. Test payload forwarding separately:

```bash
curl -I --noproxy '' --proxy socks5h://127.0.0.1:1080 --connect-timeout 10 --max-time 30 https://example.com/
```

Use `socks5h` so curl sends destination hostnames to the proxy. Choosing a saved
server in the sidebar or settings, or another transport, applies at once and
restarts this client's connections; a newly added or imported server must be
saved before it can be chosen. Adding or importing a server never connects by
itself. The minus (-) button deletes the selected server after a confirmation;
deleting the connected server moves the connection to the next one in the list.
The application does not switch failed proxy traffic to a direct connection. The current NF
local SOCKS profile supports only no authentication; Kerberos/GSS-API is not
available. See the application's
[specification](../network-relay-nf/docs/SPEC.md) for its deliberately limited
SOCKS protocol scope.

### Network Relay RS

Build on an Apple silicon Mac with macOS 27+ and Xcode/Command Line Tools. The
manifests require at least Rust 1.88; the locked build is recorded with Rust
1.99, so prefer the documented tested toolchain. Start from the repository
root in a fresh terminal:

```bash
cd network-relay-rs &&
bash build-macos.sh &&
open 'dist/Network Relay RS.app'
```

RS has its own private settings at
`~/Library/Application Support/NetworkRelayRS/configuration.json`. It can
explicitly import NF-compatible TOML; it does not automatically rewrite NF's
settings. A password-free export is not a credential backup. Server and
transport choices, Save and the minus (-) button behave as in NF. Servers,
Application Settings and All Settings exports from either app import into the
other through the matching Import menu item, and server exports into RS headless
`--config`, without losing fields.

The packaged executable also has a headless mode:

```bash
'dist/Network Relay RS.app/Contents/MacOS/network-relay-rs' --config /absolute/path/client.toml --transport h2 --duration 60 --log-level detailed
```

Allowed transport choices are `auto`, `h3`, `h2` and `http/1.1`. `auto` has
tested QUIC-to-TCP fallback; a forced transport isolates that protocol instead.
Headless mode does not load/save GUI settings. `--ca-file` adds a test CA while
retaining certificate-name verification; it is not an insecure mode.

Both app build scripts create ad-hoc-signed local bundles, not notarized public
releases. They build a fresh temporary checkout and keep final products in the
invoking app's output directories. `build-macos-gui-clients-on-macos.sh` in the
repository root builds both apps from a fresh checkout in one run. Follow their [NF build guide](../network-relay-nf/docs/BUILD-AND-OBSERVE.md)
and [RS build guide](../network-relay-rs/docs/BUILD-AND-OBSERVE.md) for fresh-source
procedures, signing observations and TCP/UDP acceptance. Do not infer native Mac
runtime success from a Linux model or transport test.

## Use the experimental WARP-egress server

This is a separate application under `network-relay-cf-masque/`. It is this
server, built from the same code with the same settings, users and commands,
but it forwards business TCP, UDP and server-side DNS through a userspace
stack and WARP. It does not create a host TUN or use the VPS as a fallback
exit. Existing client profiles carry relay credentials; WARP enrollment
secrets stay on the server.

Use the same Rust toolchain as this server, a native compiler/linker and the
[dedicated configuration guide](../network-relay-cf-masque/docs/CONFIGURATION.md).
From that application's directory:

```bash
bash scripts/build.sh
mkdir -p config
chmod 700 config
cp examples/relay.toml config/relay.toml
chmod 600 config/relay.toml
```

Edit the single file, which is this server's configuration file plus a
`[warp]` table, to include the relay's actual TLS paths, users, listen address
and existing MASQUE enrollment material under `[warp.registration]`. There is
no other configuration file.
An API token or WireGuard key alone is insufficient. The application does not
enroll or refresh the device. Default IPv4 H2 egress needs the enrolled P-256
PKCS#8 private key, endpoint public-key pin and tunnel IPv4 address. IPv6 is
optional: without `tunnel_ipv6` or `endpoint_v6` the server prints a warning
when it starts and keeps running IPv4 only. Select WARP `transport = "h2"` or `"h3"` explicitly; ingress H1/H2/H3
selection is independent.

```bash
./target/release/network-relay-cf-masque serve --config config/relay.toml --check
```

```bash
RUST_LOG=info ./target/release/network-relay-cf-masque serve --config config/relay.toml
```

`--check` validates local material only. Normal startup must establish WARP
before opening ingress. Terminal WARP loss fails flows (H3_CONNECT_ERROR or
HTTP/2 CONNECT_ERROR), drains connections and exits nonzero;
there is no implicit reconnect, transport downgrade, direct exit or local DNS
fallback. A supervisor can start a fresh process. Changing WARP settings needs
a restart; ordinary relay reloads do not reconfigure the active egress.

The [status record](../network-relay-cf-masque/docs/STATUS.md) reports the
synthetic WARP peer, client-core and held-flow tests of the current code;
earlier real WARP attempts failed before an exit-IP check. This is an
experimental option, not an established live Cloudflare deployment recipe.

Its stack has a shared **64-socket** budget, including DNS and connecting/closing
TCP sockets. Reserve capacity rather than copying the standard kernel-backed
server's large tunnel limit. At the default MTU 1280, UDP payloads are limited
to 1252 bytes for IPv4 and 1232 for IPv6; oversize datagrams are dropped without
fragmentation or a native-VPS fallback. These limits can affect DNS/application
traffic even when a small connectivity probe succeeds.

## Troubleshooting

| Symptom | Check first | Next action |
| --- | --- | --- |
| Installer cannot fetch a private file | Download authentication and exact filename | Use a signed-in browser/GitHub CLI; never place access tokens into a public command or profile |
| Apt appears idle | Package-manager lock owner and installer output | Automatic updates may hold the lock; wait rather than deleting lock files |
| Compile ends with `Killed` / signal 9 | RAM/swap, disk and kernel OOM log | Build elsewhere or provide resources; use serial build before increasing jobs |
| Service cannot bind | `ss -lntup`, configured listen address | Resolve the conflicting TCP and UDP services; do not assume stopping only a TCP web server frees UDP |
| Certificate issuance fails | Public A/AAAA, DNS-only record, inbound challenge ports | Correct DNS/firewall or use the documented DNS-challenge method |
| `serve --check` cannot read the key | Service-user permissions and renewal-copy hook | Fix ownership/group access to the copied key, without exposing Certbot's root key |
| Website works, relay does not | Account/profile credential, CONNECT logs, destination policy | A website response does not test relay authentication or forwarding |
| Wrong password looks like a 404 | Profile versus server hash, user spelling/expiry | This can be intentional cover-site behavior; regenerate/replace the profile after rotation |
| H2 works, H3 fails | UDP 443 on provider and host, network UDP policy | Use an H2-only profile while diagnosing the actual QUIC path |
| Local check passes, device fails | Public address reachability, competing proxies and installed profiles | Repeat from an external network, then observe a matched device destination |
| Only some domains unexpectedly relay | Generated match list, root-domain widening, OS support | Inspect the profile as private data; compare exact-domain versus subdomain rules |
| Everything relays unexpectedly | Empty match list, unsupported exact-FQDN-only settings | Remove the profile, regenerate explicit supported match domains and reinstall |
| Destination returns 403 / policy denial | Special/private address, own-address or blocked port | Keep defaults unless the private destination is an explicit requirement with a restricted trust boundary |
| 503 / connection limit | Tunnel/user/connection counts and configured ceilings | Close unnecessary sessions, investigate load and size budgets from staging evidence |
| UDP loses packets under load | Per-user packet/byte limits, MTU, idle lifetime | UDP excess is dropped by design; TCP success does not establish UDP losslessness |
| Password change has no effect | Duplicate entries, validation, reload journal | Replace one hash, validate/reload and update the device profile |
| NF/RS fails to listen | Existing `127.0.0.1:1080` owner | Stop the competing proxy or change this app's listener |
| Client says connected but an origin fails | Separate allowed TCP and UDP payload tests | Admission/readiness is weaker than end-to-end reachability |
| WARP variant never opens listener | WARP configuration, pin, endpoint and egress startup log | Its startup is fail-closed; `--check` success is not live WARP success |

## Tests and evidence

The following are existing recorded results or reproducible procedures, not
tests newly executed while writing this guide. Historical reports describe their
own source/toolchain/environment; use the current code and lockfiles when
repeating them rather than attributing an older run to a new build.

| Area | Recorded evidence | Practical limit |
| --- | --- | --- |
| Root Rust server | [Protocol/interoperability review](review-2026-10-06.md): 153 unit + 64 integration tests in debug/release, 34 deployment tests; Go/curl independent clients and short churn/cleanup observations | Linux/local fixtures; not complete Apple-system or WAN acceptance |
| Earlier independent protocol work | [Standards/interoperability review](review-2026-10-05.md) | Its environment had no IPv6; a pass does not establish IPv6/NAT64 deployment behavior |
| Root CI intent | [build workflow](../.github/workflows/build.yml) | Workflow configuration is a test recipe, not proof that the current checkout ran it |
| NF | [Current status](../network-relay-nf/docs/STATUS.md), [native evidence](../network-relay-nf/docs/evidence/native-mac-20261011.md) | User-reported native H2 successes and H3 repair confirmation are distinct from a complete current native matrix; Linux bridge tests do not execute Network.framework |
| RS | [Current status](../network-relay-rs/docs/STATUS.md) | Production Rust transport passed both-server local matrices and short H3 stability checks; AppKit packaging/GUI and sustained remote Mac acceptance remain separate |
| WARP variant | [Status](../network-relay-cf-masque/docs/STATUS.md), [validation](../network-relay-cf-masque/docs/VALIDATION.md) | Synthetic WARP peers and soak do not establish live Cloudflare interoperability |

For root server development, the documented baseline checks include:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 -m unittest discover -s tests -p test_deploy.py -v
```

Independent client fixtures also require Go, OpenSSL and a suitable curl build:

```bash
cargo build --locked
python3 tests/interop/run.py
```

Read the fixture's requirements before interpreting skips. The root CI tests
the vendored HTTP/3 transport separately; an ordinary `cargo test` does not
automatically reproduce every external client or vendor test. Native Apple
profiles, Wi-Fi/cellular changes, public certificate renewal, IPv6/NAT64 and
long-running production traffic still require deployment-specific acceptance.

For architecture, consult [design.md](design.md). For individual fields and
helper flags, consult [config.md](config.md) and each installed command's
`--help`. When prose and a differently versioned binary disagree, first establish
the exact source/build identity rather than mixing commands from several builds.
