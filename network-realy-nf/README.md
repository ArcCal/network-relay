# Network Realy NF

An independent macOS SOCKS5 client for **network-relay** (Rust) and
**caddy-network-relay** (Go/Caddy). The application name intentionally uses
“Realy”. Its window, server list, menu bar, icon, settings, and logs are adapted
from Masque NF. It has its own code, build, bundle identifier and settings store.
The code and documentation are self-contained in `network-realy-nf/` inside
the network-relay repository. No parent-server code or sibling checkout is
required to build it.

**Development status:** the protocol core is implemented. Production socket,
TLS and QUIC operations are supplied by Apple Network.framework. Linux core
checks are available; the macOS application and native server interoperability
have not been built or run in this environment. HTTP/3 remains experimental.
See [implementation status](docs/STATUS.md) before treating this as a release.
“Perfect compatibility” is an acceptance goal, not a result we have established.

- [Design goals and architecture](docs/DESIGN.md)
- [Protocol and application specification](docs/SPEC.md)
- [Completed, suspected, confirmed and missing work](docs/STATUS.md)
- [QUIC investigation and repair handover](docs/QUIC-RESEARCH.md)
- [Validation procedure and evidence](docs/VALIDATION.md)
- [Fresh Mac build, log levels and TCP/UDP observation](docs/BUILD-AND-OBSERVE.md)
- [Source provenance](SOURCE-PROVENANCE.json)

## Build on a Mac

For a fresh checkout, toolchain setup, five log levels and a bounded HTTP/3
observation, follow [BUILD-AND-OBSERVE.md](docs/BUILD-AND-OBSERVE.md). While this
addition is under review, check out `codex/network-realy-nf`; the application is
not yet on `main`.

The initial target follows Masque NF: **Apple silicon, macOS 27+, Xcode with a
macOS 27+ SDK, and stable Rust supporting edition 2024**. Full Xcode is required;
Command Line Tools alone may select an older SDK. The script checks the OS and
SDK before building. Intel and older macOS releases are not supported yet.

From this application directory:

```bash
rustup update stable
cd network-realy-nf # when starting at the network-relay repository root
bash build-macos.sh
open 'dist/Network Realy NF.app'
```

The script runs Rust tests, Swift model tests and native boundary smoke checks,
builds the static core and GUI, creates the icon, and applies an ad-hoc signature.
It produces `dist/NetworkRealyNF-0.1.0-macos-arm64.zip` and its SHA-256 file.
It does not notarize the app. These build instructions still require a first Mac
execution; no downloadable or verified Mac binary is included in this revision.

Enter the relay domain, optional server IP, username and password. Use HTTP/2
for initial testing. The default CONNECT-UDP endpoint is
`/.well-known/masque/udp/{target_host}/{target_port}/`. The domain remains the
TLS certificate name even when a server IP is supplied. The local SOCKS default
is `127.0.0.1:1080`; it may conflict with a running Masque NF instance.

```bash
curl -I --noproxy '' --proxy socks5h://127.0.0.1:1080 \
  --connect-timeout 10 --max-time 30 https://example.com/
```

Switching the selected server or its transport while connected restarts this
app's client automatically and ends existing proxy sessions. Saving an inactive
server does not restart the active one. Creating and saving a blank server keeps
an existing active selection. Application settings are stored separately under
`~/Library/Application Support/NetworkRealyNF/`.

## Portable checks

```bash
cargo test --locked --manifest-path Core/Cargo.toml
python3 scripts/test-interop.py \
  --rust-server /absolute/path/to/network-relay \
  --caddy /absolute/path/to/caddy-with-network-relay
```

The second command starts disposable real server processes and local echo
services, uses a private test CA and random fixture credentials, and tests the
production protocol core over a **test-only rustls/Quinn bridge emulator**.
It does not validate Apple's QUIC implementation. Test credentials, keys and
server configs are kept in a temporary directory and removed afterwards.
Production does not use or link the emulator's rustls/Quinn transport backends.
