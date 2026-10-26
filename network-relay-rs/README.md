# Network Relay RS

Network Relay RS is an independent Rust macOS client for **network-relay** and
**caddy-network-relay**. It reproduces Network Relay NF's server profiles, settings,
menu-bar controls, status, icon and five-level log workflow. Application and
protocol code are Rust. The GUI calls native AppKit through Rust bindings;
Tokio, rustls and Quinn implement the networking. It contains no Swift source
and does not use Network.framework for sockets, TLS or QUIC.

Its complete code, vendored protocol dependencies, build scripts and documents
live in `network-relay-rs/`. Building it does not require another application's
source or change the parent relay server. Its bundle identifier and private
settings store are separate from Network Relay NF.

**Development status:** the production Rust transport passes real local
network-relay and caddy-network-relay TCP/UDP matrices for HTTP/1.1, HTTP/2 and
HTTP/3, plus separate Automatic fallback and 125-second HTTP/3 stability checks.
[STATUS.md](docs/STATUS.md) links exact versions and evidence. A Linux test does
not establish that the macOS GUI has launched or looks identical. Actual Mac
GUI, packaging and long running remote-server acceptance remain explicit release
gates. Complete compatibility is an acceptance requirement, not a claim based
on one connection.

- [Design and independence](docs/DESIGN.md)
- [Application and protocol specification](docs/SPEC.md)
- [Completed work, risks and unverified acceptance](docs/STATUS.md)
- [Fresh Mac build and observation](docs/BUILD-AND-OBSERVE.md)
- [Source provenance](SOURCE-PROVENANCE.json) and [dependency notices](NOTICE.md)

## Build on an Apple silicon Mac

Use macOS 27 or newer, Apple Command Line Tools or Xcode, and current stable
Rust. The manifests require at least Rust 1.88; the locked dependency graph
is tested with Rust 1.99, so an older compiler is not an established build
configuration. From this application directory:

```bash
bash build-macos.sh
open 'dist/Network Relay RS.app'
```

The script runs the selected RS application and core package tests, builds the ARM64 application, packages
the shared icon and applies an ad-hoc signature. It writes a ZIP and SHA-256
file in `dist/`. It does not notarize or install a system service. The full fresh
clone procedure and independent TCP/UDP checks are in
[BUILD-AND-OBSERVE.md](docs/BUILD-AND-OBSERVE.md).

Enter the relay domain, optional IP, username and password. An IP override
changes only the socket endpoint; the domain remains the TLS certificate name.
The default local SOCKS5 address is `127.0.0.1:1080`. Quit an application already
using that port, or select a different port. Switching the selected server or
transport while connected automatically restarts this app's client.

Settings are stored privately at
`~/Library/Application Support/NetworkRelayRS/configuration.json`.
NF-exported TOML can be explicitly imported. This application does not read or
rewrite NF's private settings automatically. Password-free exports leave an
existing matching server password intact.

## Command-line operation

The same Rust executable can run without opening its GUI:

```bash
'dist/Network Relay RS.app/Contents/MacOS/network-relay-rs' \
  --config /absolute/path/to/client.toml --transport h3 --log-level detailed
```

`--config` accepts an NF-compatible TOML export or relay client TOML format;
`--transport` may be `auto`,
`h3`, `h2` or `http/1.1`. `--ca-file` adds an explicit fixture CA for local tests;
it does not disable peer certificate or hostname verification. GUI connections
use normal trusted roots. `--duration SECONDS` bounds a headless observation;
Control-C stops an unbounded run. Headless operation does not load or save the
GUI's private settings. See `--help` for the available options.
`--log-level` selects `errors`, `warnings`, `normal`, `detailed` or `everything`
without changing saved GUI settings. Everything adds Rust I/O event kinds,
resource handles, byte counts and read EOF markers; it does not print packet
payloads, passwords or authentication headers.
The headless importer follows the NF settings profile: one local SOCKS address,
the standard UDP URI template and the default readiness target. It is not a
lossless importer for every lower-level core configuration option.

## Automated checks

```bash
cargo test --locked -p network-relay-rs -p network-relay-rs-core
python3 scripts/test-interop.py \
  --rust-server /absolute/path/to/network-relay \
  --caddy /absolute/path/to/caddy-with-network-relay
```

The interoperability harness starts disposable **real server binaries** and
TCP/UDP echo targets with a private test CA and random fixture credentials.
Unlike NF's emulated native bridge tests, RS uses its production Tokio/rustls/
Quinn transport. Results and exact limitations belong in the acceptance matrix,
including any failed or untested row.
