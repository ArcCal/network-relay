# Network Relay CF MASQUE

An experimental Network Relay server with **mandatory Cloudflare WARP MASQUE
egress**. It is network-relay, the server in the parent directory, with one
difference: every tunnel's TCP, UDP and server-side DNS traffic passes through
a userspace TCP/IP stack into WARP instead of the host's own network. Existing
Network Relay clients use ordinary authenticated HTTP CONNECT and CONNECT-UDP;
there is no direct fallback and no client protocol change.

network-relay's code is used, not copied: this project depends on the parent
crate (`network-relay = { path = ".." }`) for the whole client-facing server
(HTTP/1.1, HTTP/2 and HTTP/3, authentication, destination rules, limits, the
cover website, reloads), its configuration format and its `passwd`,
`identity`, `profile` and `check` commands, and on its vendored h3. Only the
WARP egress (`crates/warp-egress`), the one-file configuration reader and the
binary's `serve` are its own.

This is experimental software, not a claim of completed live deployment
validation. Its tests use a local synthetic WARP peer; live Cloudflare
attempts have so far failed before any exit-IP check. See
[STATUS.md](docs/STATUS.md) before relying on any capability or stability
claim.

## Architecture

```text
Network Relay clients (NF / RS / Apple profile)
    | TLS + H1/H2/H3, CONNECT / CONNECT-UDP, existing authentication
    v
network-relay's server --- policy-approved addresses ---> network_relay::egress
    | cover website, authentication, policy, limits              |
    |                                                    warp-masque-egress
    |                                                    tunnel DNS + smoltcp
    |                                                            | IP packets
    |                                                            v
    +---------------------------------------------> Cloudflare WARP H2 or H3
                                                                 |
                                                                 v
                                                        WARP Internet exit
```

The only outbound Internet connection opened by `serve` is to the selected
numeric WARP endpoint. The diagnostic `check` command acts as a separate client
connecting to an explicitly selected relay; it is never used to forward
server traffic.

`crates/warp-egress` can be used by other Rust programs; it depends on
network-relay only for the `egress` interface it implements. The
[independent Cargo consumer](examples/reuse) shows how, patching h3 to
network-relay's vendored copy as network-relay does. See the
[crate README](crates/warp-egress/README.md).

## Build

Use the Rust toolchain network-relay builds with and a native C
compiler/linker (required by `ring`).
The test scripts also require Python 3, Rustfmt and Clippy; install the latter
two with `rustup component add rustfmt clippy` if they are missing. The runtime
server target tested here is Linux x86_64. Install the normal system CA package
for HTTPS diagnostic origins. No TUN, host routing changes, registration API
client or `CAP_NET_ADMIN` is required.

From a fresh checkout of `ArcCal/network-relay`:

```bash
cd network-relay/network-relay-cf-masque
bash scripts/build.sh
./target/release/network-relay-cf-masque --version
```

The helper scripts keep Cargo downloads, build outputs and temporary test
files inside this project (the parent crate is compiled from its sources in
place). They do not install toolchains or modify parent files. For cross-compilation, supply a target supported by your installed
compiler/linker:

```bash
bash scripts/build.sh --target x86_64-unknown-linux-gnu
```

The GNU binary requires the target system's compatible glibc. A successful
cross-build does not replace a native target runtime test. Windows support is
not currently claimed.

## Configure and run

Use **one standalone TOML file** for the relay settings, users and WARP
settings; there is no other configuration file. Copy the existing WARP MASQUE
enrollment values into `[warp.registration]` in that file. Everything outside
`[warp]` is network-relay's own configuration format, read and checked by
network-relay's code. A WireGuard configuration
or API access token alone is insufficient. This project does not enroll,
replace or refresh the device. The account's P-256 private key produces the
client identity; the registered endpoint public key pins the WARP server.

```bash
mkdir -p config
chmod 700 config
cp examples/relay.toml config/relay.toml
chmod 600 config/relay.toml
# Edit config/relay.toml: set the relay paths/users and WARP enrollment values.
```

Put your relay certificate/key at the paths in `config/relay.toml`, set the
real listen address, and append existing `[[user]]` entries. TLS certificate
and key files remain ordinary cryptographic assets; they do not require
additional application configuration files. The relay settings and
password/certificate authentication use the standard Network Relay formats.
Relative relay certificate, key and website paths resolve from the process's
working directory, as in the standard server; use absolute paths for a
deployment whose working directory differs from these examples.

Only these WARP fields are required for the default IPv4-only H2 connection:

| Field | Purpose |
| --- | --- |
| `warp.transport = "h2"` | Select the egress mode explicitly; there is no automatic downgrade. |
| `warp.registration.private_key` | Existing enrollment's base64 P-256 PKCS#8 private key. |
| `warp.registration.endpoint_public_key` | Existing enrollment's PEM public key used to verify the WARP endpoint. |
| `warp.registration.tunnel_ipv4` | Existing enrollment's assigned inner IPv4 address. |

`device_id`, `access_token` and `license` are optional account metadata; this
server does not need them to establish the enrolled MASQUE tunnel. DNS defaults
to `1.1.1.1:53` inside WARP, keepalive to 15 seconds, idle timeout to 30 seconds,
and the H2 outer endpoint to `162.159.198.2:443`. Copy account-specific values
from the existing enrollment rather than inventing a private key or server pin.

IPv6 is optional. If `[warp.registration]` lacks `tunnel_ipv6` or
`endpoint_v6`, the server prints a warning naming them when it starts, logs
it, and **keeps running** IPv4 only. Copy them from the enrollment to enable
IPv6, for example:

```toml
tunnel_ipv6 = "2606:4700:110:88ca:7332:13e4:5a18:e3d9"
endpoint_v6 = "[2606:4700:103::2]:0"
```

Without them, IPv6 destinations cannot be reached (they never fall back to the
VPS network) and the H3 tunnel cannot use an IPv6 WARP endpoint. Selecting an
IPv6 outer endpoint (`ipv6_endpoint = true`) is a separate option.

To create a new user, network-relay's `passwd` helper, under this program's
name, prints the password and configuration entry:

```bash
./target/release/network-relay-cf-masque passwd --name iphone
```

Choose WARP `transport = "h2"` or `"h3"` explicitly. Ingress protocols are
independent: selecting WARP H2 does not disable client-facing H3. H3 additionally
needs the enrollment's `endpoint_v4` unless `warp.endpoint` is supplied.
Registered endpoint port zero maps to 443; optional overrides must be numeric
IPs.

```bash
./target/release/network-relay-cf-masque serve \
  --config config/relay.toml --check

RUST_LOG=info ./target/release/network-relay-cf-masque serve \
  --config config/relay.toml
```

`--check` validates local configuration, cryptographic material, relay
certificate and website without connecting to WARP. In normal operation WARP
must connect before ingress listeners open. Terminal WARP loss fails existing
flows (HTTP/3 H3_CONNECT_ERROR, HTTP/2 CONNECT_ERROR), sends GOAWAY, drains
and exits the process with failure. No implicit reconnect, transport
downgrade, DNS fallback or direct egress occurs. A supervisor may start a fresh
process using the same explicitly configured mode. SIGHUP reloads the standard
relay configuration; changing WARP settings requires restarting this process.

Earlier versions also read a separate WARP file (`--warp-config`) and an
enrollment JSON; they are gone. To move such a deployment to one file, see
[CONFIGURATION.md](docs/CONFIGURATION.md).

The optional [systemd template](deploy/network-relay-cf-masque.service) uses a
separate executable, user, service and configuration under
`/opt/network-relay-cf-masque`. It does not replace an existing Network Relay
service. Install this project there, adjust the paths/user ownership, then
install the unit using your normal system administration workflow.
The template uses the default journal logging. A custom `log_dir` needs an
explicitly writable service-owned directory and corresponding systemd access;
the project tree is read-only under this template.

## Existing clients and Apple profiles

NF and RS clients use the same relay host, port, HTTPS certificate name, user,
password and CONNECT-UDP template as before. No new WARP credentials belong in
the client. For an Apple profile that offers only client-facing HTTP/2:

```bash
./target/release/network-relay-cf-masque profile \
  --host relay.example.com --user iphone --no-http3 \
  --match-domain example.com --out config/iphone.mobileconfig
```

Leave out `--password` to use the secret prompt. Add repeatable match/exclude
options exactly as with the standard profile helper. Protect generated
profiles: they may contain passwords. This example's single match domain is
illustrative, not an imported domain list.

## Verification

```bash
bash scripts/test.sh
bash scripts/soak.sh
```

`test.sh` builds the client harnesses, runs this workspace's tests, strict
Clippy and formatting, checks the reuse example, and then runs
network-relay's own tests twice: as network-relay, and with every tunnel of
its HTTP/1.1, HTTP/2 and HTTP/3 integration suite going through an egress
(`NETWORK_RELAY_TEST_EGRESS=loopback`), the code path this server uses.

Run the acceptance/resource workflow on Linux: its memory and descriptor
checks require `/proc`. Native macOS execution is a separate deployment gate.

The WARP tests use an explicitly synthetic WARP peer with ephemeral keys. They
check the actual transport, mTLS and SPKI, WARP framing, packet forwarding,
inner DNS, TCP/UDP, half-close, resets, authentication/revocation, terminal
failure and bounded resources across all six ingress/egress pairings, and the
NF and RS client cores of this repository against the server. This is
distinct from Cloudflare or native Apple GUI/device validation. `soak.sh`
first requires the finite tests to pass, then runs at least one hour of real
elapsed time with held TCP/UDP flows and metrics. Test evidence is written to
`target/evidence`. [VALIDATION.md](docs/VALIDATION.md) records the results.

The NF client core runs with its own Linux bridge for native hooks. This does
not execute Apple Network.framework, the NF GUI or a device profile; those
remain native-device validation gates.

On a machine with usable WARP TCP/UDP connectivity, run each egress mode
separately with the enrolled account:

```bash
source scripts/env.sh
cargo run --locked --example live-warp -- \
  --warp-config config/relay.toml probe
```

`--warp-config` here names the server's one configuration file; only its
`[warp]` table is used. To test H3 separately, select `transport = "h3"` and
add `endpoint_v4` in that same file before repeating the command. Do not
change a running server's WARP settings without restarting it.

The probe resolves through WARP, sends UDP DNS inside it and verifies a
CA-validated HTTPS Cloudflare trace containing `warp=on` or `warp=plus` and a
valid exit IP. It never retries the other egress mode. The real-download helper
requires an independently obtained expected checksum and a minimum size:

```bash
cargo run --locked --example live-warp -- --warp-config config/relay.toml \
  download --url 'https://your-origin.example/known-artifact.bin' \
  --sha256 REPLACE_WITH_VERIFIED_64_HEX_DIGIT_CHECKSUM --min-bytes 67108864
```

It streams without buffering the whole file, checks the exact hash and any
Content-Length, bounds stalled reads and the whole operation, and refuses
redirects. `live-warp soak --seconds 3900` repeatedly probes real egress; it
does not substitute for the separately held-connection soak or prove native
client behavior.

## Design, research and limitations

- [Design](docs/DESIGN.md) and [specification](docs/SPEC.md).
- [Implementation/known limitations](docs/STATUS.md) and
  [validation](docs/VALIDATION.md).
- Four source-pinned [research reports](docs/RESEARCH-CF-EGRESS.md), including
  [relay contract](docs/RESEARCH-RELAY-CONTRACT.md),
  [usque/mihomo](docs/RESEARCH-USQUE-MIHOMO.md), and
  [Xray/sing-box](docs/RESEARCH-XRAY-SINGBOX.md).
- [Licenses](NOTICE.md); the HTTP/3 patches are network-relay's
  ([`../vendor/h3/PATCH.md`](../vendor/h3/PATCH.md)).

The conservative stack limit is 64 total sockets, including DNS and connecting
or closing TCP. UDP packets larger than the current WARP MTU are dropped at
the relay without IP fragmentation (RFC 9298 section 5). At MTU 1280,
IPv4/IPv6 payload ceilings are 1252/1232 bytes. Normal UDP flow remains usable
after a drop. Live account/path behavior, extended stress and native Apple
testing must be evaluated rather than inferred from compilation.
