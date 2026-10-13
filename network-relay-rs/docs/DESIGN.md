# Design goals and architecture

Revision: 0.1.0 development, 2026-10-12.

## Goals

Network Relay RS preserves Network Relay NF's user workflow while removing its
Network.framework transport dependency. The owner requested a separate app,
with separate code and documents under the network-relay repository. Server
code and the existing NF application remain unchanged. Rust implements the
application model, controller, local SOCKS service, HTTP framing, TLS and QUIC.

The visible target is the NF layout and behavior: server profiles, selected
profile, domain and optional IP, credentials, transport picker, local SOCKS
address, connect-on-launch, connection controls, menu-bar access, settings
import/export, About build identity and a selectable five-level log. The shared
icon is copied. AppKit supplies native platform widgets, called directly from
Rust; using native UI widgets does not put transport ownership back into
Network.framework.

Pixel-level appearance and interaction parity require an actual Mac comparison.
Source inspection and non-Mac type checking cannot prove it. The acceptance
status must say which elements were implemented, executed and visually checked.

## Components

| Component | Responsibility |
| --- | --- |
| Rust AppKit UI | Window, tabs, forms, menu bar, file panels and log view; main thread only |
| Rust model | Profiles, validation, private atomic settings storage and explicit NF TOML import/export |
| Rust controller | Start, stop, automatic settings restart, connection status, generation ownership and retained logs |
| Independent Rust core | SOCKS5, authenticated HTTP CONNECT and CONNECT-UDP, Capsule parsing, readiness and retries |
| Tokio | Async runtime, TCP and UDP sockets and address resolution |
| rustls | TLS, certificate verification and ALPN for HTTP/1.1 and HTTP/2 |
| Quinn with rustls | QUIC and HTTP/3 transport, stream ownership and shutdown |
| Vendored h3 | HTTP/3 settings, QPACK, requests and driver integration |
| Independent RS QUIC adapter | Connects h3's transport traits to the bounded Rust/Quinn transport implementation |

The copied core retains its asynchronous transport boundary. Its production
implementation now uses Rust transport primitives. There is no production
Apple network bridge, Swift package, Swift compiler step or native QUIC group.
This replacement changes observable TLS/QUIC behavior and fingerprints; RS
must not be described as sending Apple's Network.framework TLS/QUIC traffic.

The Rust trust-store loader may call the OS to read trusted certificates.
That use of platform trust data does not delegate sockets or TLS to Apple's
network stack. A configured endpoint IP and its expected DNS certificate name
remain separate values. Test CAs are opt-in, and certificate checks remain on.

## Independence and lifecycle

The root Cargo workspace contains the RS application, its own `Core` and the
copied vendored h3 crate. It contains no parent server or sibling application.
It has its own lockfile, copied vendored libraries, `build/` products, `dist/`
bundle, bundle identifier `org.arccal.NetworkRelayRS` and settings directory
`~/Library/Application Support/NetworkRelayRS/`. No symlink into NF or parent
server source is required.

Every start owns its runtime and listeners. Disconnect cancels that instance
before another instance may bind the same address. Selecting a new server or
transport restarts an active instance automatically. Late status messages from
an earlier generation cannot overwrite the new instance. Changes to only log
level, profile display name or inactive profiles do not reconnect.

NF exports are imported only through an explicit user action. RS never loads
NF's private JSON store automatically and never edits it. Imported password-free
profiles preserve a matching existing password; a first import may therefore
require the user to enter credentials before connecting.

## Compatibility target

Each of network-relay and caddy-network-relay must be tested independently.
Classic CONNECT and CONNECT-UDP are the protocol target; CONNECT-IP services
such as masque-server and caddy-masque are separate software and cannot stand
in for a relay pairing. HTTP/1.1, HTTP/2 and HTTP/3, including forced selection,
must preserve authentication, policy decisions, certificate validation, remote
DNS, binary data and TCP half-close semantics.

The protocol matrix uses real server processes with the production Rust
transport. This is stronger transport coverage for RS than NF's Linux emulator,
but it remains separate from macOS GUI/lifecycle and live deployment acceptance.
Short readiness probes are not sustained Internet TCP/UDP tests. A complete
claim requires all release gates in [SPEC.md](SPEC.md) and [STATUS.md](STATUS.md).

## Constraints

Applicable IETF normative requirements and Apple application/platform rules
remain mandatory. A proposed workaround must not make a malformed HTTP request,
relax certificate identity checks, suppress a forced-transport failure or bypass
server destination policy. Network.framework symptoms are reference evidence,
not a reason to import a speculative workaround into Quinn.

No system proxy, routing table, firewall, VPN extension, privileged helper or
service is installed. The app is a local SOCKS client, not an Apple mobileconfig
or a system-wide tunnel. It cannot promise unrestricted compatibility with all
server configurations, mutual-TLS-only deployments or indefinite connection
stability without the corresponding implementation and tests.
