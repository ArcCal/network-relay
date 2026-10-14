# Network Relay CF MASQUE

An independent experimental Network Relay server with **mandatory Cloudflare
WARP MASQUE egress**. Existing Network Relay clients use ordinary authenticated
HTTP CONNECT and CONNECT-UDP. Their TCP, UDP and server-side DNS traffic passes
through a userspace TCP/IP stack into WARP. There is no direct business-traffic
fallback and no client protocol change.

All project files are contained in this directory. The parent Network Relay,
its clients and Caddy Network Relay are not modified. The frontend is a private
source snapshot; it is not a path dependency on the parent project.

This is experimental software, not a claim of completed live deployment
validation. Local H1/H2/H3 × WARP H2/H3 tests and repeated 64 MiB integrity
checks passed. Live Cloudflare setup in the development cloud environment
failed before any exit-IP check: H2 returned connection refused and H3 timed
out. See [STATUS.md](docs/STATUS.md) and the actual JSON evidence before relying
on any capability or stability claim.

## Architecture

```text
Unchanged Network Relay clients (NF / RS / Apple profile)
    │ TLS + H1/H2/H3, CONNECT / CONNECT-UDP, existing authentication
    ▼
relay-frontend ── policy-approved numeric destinations ── mandatory Egress
    │                                                      │
    │ cover website, authentication, policy, limits         ▼
    │                                                warp-masque-egress
    │                                                tunneled DNS + smoltcp
    │                                                      │ IP packets
    │                                                      ▼
    └───────────────────────────────────────────── Cloudflare WARP H2 or H3
                                                           │
                                                           ▼
                                                   WARP Internet exit
```

The only outbound Internet connection opened by `serve` is to the selected
numeric WARP endpoint. The diagnostic `check` command acts as a separate client
connecting to an explicitly selected relay; it is never used to forward
server traffic.

`crates/warp-egress` is reusable independently of Network Relay. The
[independent Cargo consumer](examples/reuse) builds without any `[patch]`
configuration or dependency on the parent repository. Vendor paths point only
to copies inside this project. See the [crate README](crates/warp-egress/README.md).

## Build

Use Rust 1.99 or newer and a native C compiler/linker (required by `ring`).
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
files inside this project. They do not install toolchains or modify parent
files. For cross-compilation, supply a target supported by your installed
compiler/linker:

```bash
bash scripts/build.sh --target x86_64-unknown-linux-gnu
```

The GNU binary requires the target system's compatible glibc. A successful
cross-build does not replace a native target runtime test. Windows support is
not currently claimed.

## Configure and run

Supply an **existing WARP MASQUE enrollment JSON**. A WireGuard configuration
or API access token alone is insufficient. This project does not enroll,
replace or refresh the device. The account's P-256 private key produces the
client identity; the registered endpoint public key pins the WARP server.

```bash
mkdir -p .secrets config
chmod 700 .secrets config
# Copy your enrollment JSON to .secrets/warp-registration.json.
chmod 600 .secrets/warp-registration.json
cp examples/relay.toml config/relay.toml
cp examples/warp.h2.toml config/warp.toml
```

The registration path in that example is relative to `config/warp.toml` and
therefore resolves to `../.secrets/warp-registration.json`. Put your relay
certificate/key at the paths in `config/relay.toml`, set the real listen
address, and append existing `[[user]]` entries. The relay TOML schema and
password/certificate authentication are the standard Network Relay formats.
Relative relay certificate, key and website paths resolve from the process's
working directory, as in the standard server; use absolute paths for a
deployment whose working directory differs from these examples.

To create a new user, this independent application's helper prints the
password and configuration entry:

```bash
./target/release/network-relay-cf-masque passwd --name iphone
```

Choose WARP `transport = "h2"` or `"h3"` explicitly. Ingress protocols are
independent: selecting WARP H2 does not disable client-facing H3. Registered
endpoint port zero maps to 443; optional overrides must be numeric IPs.

```bash
./target/release/network-relay-cf-masque serve \
  --config config/relay.toml --warp-config config/warp.toml --check

RUST_LOG=info ./target/release/network-relay-cf-masque serve \
  --config config/relay.toml --warp-config config/warp.toml
```

`--check` validates local configuration, cryptographic material, relay
certificate and website without connecting to WARP. In normal operation WARP
must connect before ingress listeners open. Terminal WARP loss fails existing
flows and exits the process with failure. No implicit reconnect, transport
downgrade, DNS fallback or direct egress occurs. A supervisor may start a fresh
process using the same explicitly configured mode. SIGHUP reloads the standard
relay configuration; changing WARP settings requires restarting this process.

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

Run the acceptance/resource workflow on Linux: its memory and descriptor
checks require `/proc`. Native macOS execution is a separate deployment gate;
missing Linux metrics on macOS do not identify a transport failure.

The functional matrix uses an explicitly synthetic WARP peer with ephemeral
keys. It checks the actual transport, mTLS and SPKI, WARP framing, packet
forwarding, inner DNS, TCP/UDP, half-close, resets, authentication/revocation,
terminal failure and bounded resources. This is distinct from Cloudflare or
native Apple GUI/device validation. `soak.sh` first requires functional and
bulk tests to pass, then runs at least one hour of real elapsed time with held
TCP/UDP flows and metrics. Test evidence records the exact executable/source
snapshot; failed and preliminary runs are not called passed.

On a machine with usable WARP TCP/UDP connectivity, run each egress mode
separately with the enrolled account:

```bash
source scripts/env.sh
cargo run --locked --example live-warp -- \
  --warp-config examples/warp.h2.toml probe
cargo run --locked --example live-warp -- \
  --warp-config examples/warp.h3.toml probe
```

The probe resolves through WARP, sends UDP DNS inside it and verifies a
CA-validated HTTPS Cloudflare trace containing `warp=on` or `warp=plus` and a
valid exit IP. It never retries the other egress mode. The real-download helper
requires an independently obtained expected checksum and a minimum size:

```bash
cargo run --locked --example live-warp -- --warp-config config/warp.toml \
  download --url 'https://your-origin.example/known-artifact.bin' \
  --sha256 REPLACE_WITH_VERIFIED_64_HEX_DIGIT_CHECKSUM --min-bytes 67108864
```

It streams without buffering the whole file, checks the exact hash and any
Content-Length, bounds stalled reads and the whole operation, and refuses
redirects. `live-warp soak --seconds 3900` repeatedly probes real egress; it
does not substitute for the separately held-connection soak or prove native
client behavior. See [VALIDATION.md](docs/VALIDATION.md) for outstanding gates.

## Design, research and limitations

- [Design](docs/DESIGN.md) and [specification](docs/SPEC.md).
- [Implementation/known limitations](docs/STATUS.md).
- Four source-pinned [research reports](docs/RESEARCH-CF-EGRESS.md), including
  [relay contract](docs/RESEARCH-RELAY-CONTRACT.md),
  [usque/mihomo](docs/RESEARCH-USQUE-MIHOMO.md), and
  [Xray/sing-box](docs/RESEARCH-XRAY-SINGBOX.md).
- [HTTP/3 patch provenance](docs/H3-PATCH-PROVENANCE.md) and [licenses](NOTICE.md).

The conservative stack limit is 64 total sockets, including DNS and connecting
or closing TCP. UDP packets larger than the current WARP MTU are dropped at
the relay without IP fragmentation, as required by RFC 9298 §3.1. At MTU 1280,
IPv4/IPv6 payload ceilings are 1252/1232 bytes. Normal UDP flow remains usable
after a drop. Live account/path behavior, extended stress and native Apple
testing must be evaluated rather than inferred from compilation.
