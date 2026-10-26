# Fresh Mac build and observation

This builds **Network Relay RS** on an Apple silicon Mac, including a Mac mini
M1. It does not rebuild or replace NF or either server. macOS 27 or newer and
current stable Rust are the initial target. The manifests declare Rust 1.88 as
their minimum; the locked graph is tested with Rust 1.99, and older toolchains
have not been validated. Unlike NF, no Swift compiler or
macOS 27 Network.framework SDK is required. macOS linking, packaging and GUI
execution must be performed on a Mac; Linux checks do not substitute for them.

## Prepare the tools

Install Apple's Command Line Tools if `xcrun --sdk macosx --show-sdk-path` fails:

```bash
xcode-select --install
```

Full Xcode is also supported. Confirm the active tools and architecture:

```bash
sw_vers
uname -m
xcode-select -p
xcrun --sdk macosx --show-sdk-version
git --version
```

`uname -m` must print `arm64`. If Rustup is absent, install it using the official
installer; skip this command if Rust is already installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

Load Rust and update stable:

```bash
. "$HOME/.cargo/env"
rustup update stable
rustc --version
cargo --version
```

## Download a fresh checkout and build

Authenticate using the normal GitHub credential manager or `gh auth login`
for this private repository. Do not put a token into a clone URL. The commands
below create a new directory and use the RS application branch while its PR is
under review. After merge, `main` can be selected instead. `test -f` deliberately
fails if the chosen revision does not contain RS.

```bash
. "$HOME/.cargo/env"
RS_CHECKOUT="$HOME/Projects/network-relay-rs-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$HOME/Projects"
git clone --branch codex/network-relay-rs --single-branch \
  https://github.com/ArcCal/network-relay.git "$RS_CHECKOUT"
cd "$RS_CHECKOUT/network-relay-rs"
test -f Cargo.toml
mkdir -p build
set -o pipefail
{
  git rev-parse HEAD
  sw_vers
  uname -m
  xcrun --sdk macosx --show-sdk-version
  rustc --version
  cargo --version
} > build/build-environment.txt
bash build-macos.sh 2>&1 | tee build/build-macos.log
```

The build script uses only this app's `build/target` products. It ignores a
previous shell's `CARGO_TARGET_DIR` so another project's cache cannot select the
wrong executable. It runs the locked RS application and core package tests, builds the fixed
`aarch64-apple-darwin` target, creates an `.app`, packages the icon and signs
ad hoc. It writes the application, ZIP and checksum in `dist/`.

Launch only after the build exits successfully:

```bash
open "$PWD/dist/Network Relay RS.app"
```

Optional packaging arguments are `--unsigned` or `--sign 'SIGNING IDENTITY'`.
A local ad-hoc signature is not Developer ID notarization. The app does not
install system proxy settings or require administrator privileges. Startup and
About show build/source metadata. `-dirty` means application source differs from
the commit; `Unknown` means the build did not have Git metadata.

If a compiler, test, linker or signing step fails, preserve `build/build-macos.log`
and `build/build-environment.txt`. Do not launch a binary from an earlier checkout
and count it as this build's result.

## Configure and import

RS uses its own store at
`~/Library/Application Support/NetworkRelayRS/configuration.json`. It does not
automatically copy private NF settings. In NF, export the desired settings as
TOML, then use RS's Import action. With a password-free export, enter missing
passwords in RS before connecting. No server password needs to be pasted into
logs or a bug report.

Alternatively add a server manually: its certificate domain, optional actual
IP, account and transport. An IP override does not replace the certificate name.
Select HTTP/2 first, then test HTTP/3 separately with the same server/account.

Quit any app using `127.0.0.1:1080` or choose another RS SOCKS port. Replace
`1080` in every test command if you change it. A Rust masque-server or
caddy-masque service is CONNECT-IP and is not the target for this app.

## Logs and independent TCP/UDP probes

The Log view provides Everything, Detailed, Normal, Warnings and Errors and
Errors Only, ordered from most detail to least. Select Everything for a short
failure capture; select Detailed for ordinary transport/destination observation.
Follow latest and Latest control scrolling. Copy All and Save export all
retained lines, including messages hidden by the current view. The 5,000-line
buffer is bounded and is not automatically saved to disk.

| Menu level | CLI value | Generated/visible detail |
| --- | --- | --- |
| Everything | `everything` | TRACE through ERROR, including Rust event kind/resource/byte counts and read EOF |
| Detailed | `detailed` | DEBUG through ERROR, including connection, ALPN, transport and destination diagnostics |
| Normal | `normal` | INFO through ERROR, including readiness, disconnect and reconnect |
| Warnings and Errors | `warnings` | WARN and ERROR |
| Errors Only | `errors` | ERROR |

Everything does not print packet bodies, event payloads, passwords or
Authorization headers. Third-party wire traces stay disabled. Backend resource
numbers are local handles, not QUIC stream IDs. Raising verbosity cannot recover
older diagnostics that were not generated.

The executable can also run headless with an NF-compatible export or supported
client TOML. This does not read or save RS's GUI preferences:

```bash
set -o pipefail
'dist/Network Relay RS.app/Contents/MacOS/network-relay-rs' \
  --config /absolute/path/to/client.toml \
  --transport h3 --log-level everything --duration 180 \
  2>&1 | tee build/rs-headless-http3.log
```

Use a real local config path; no password belongs on the command line. Omit
`--duration` for an unbounded observation and use Control-C to stop it. A GUI
and headless instance cannot share the same SOCKS port at the same time.

For each **network-relay** and **caddy-network-relay** profile, select forced
HTTP/2, connect and look for authenticated Relay ready. Then run:

```bash
set -o pipefail
curl --fail --show-error --noproxy '' \
  --proxy socks5h://127.0.0.1:1080 \
  --connect-timeout 10 --max-time 30 \
  -o /dev/null \
  --write-out '\nHTTP=%{http_code} downloaded=%{size_download}\n' \
  https://www.google.com/ 2>&1 | tee rs-http2-tcp.log
python3 scripts/probe-socks-udp.py \
  --proxy-port 1080 --dns-server 1.1.1.1 --name www.google.com \
  2>&1 | tee rs-http2-udp.log
```

These commands work from the `network-relay-rs` directory and do not depend on
variables set in an older Terminal. Successful HTTP status and downloaded bytes
test TCP. `PASS SOCKS UDP` tests the separate UDP association and a real DNS
reply. The HTTP version printed by curl describes the destination website
connection, not the selected outer relay transport; use the RS log for that.
Readiness by itself tests admission only.

Repeat with forced **HTTP/3 (QUIC, UDP)**, keeping endpoint and account unchanged,
and use separate `rs-http3-tcp.log`, `rs-http3-udp.log` and app-log files. Repeat
HTTP/1.1 if that server configuration advertises it. Keep separate filenames
for Rust and Caddy servers. A denied or unreachable DNS destination is not proof
of a client bug; record the effective server policy.

## Stability and GUI acceptance

For each server and forced transport, observe at least ten minutes with idle
and active periods. Re-run TCP and UDP probes after more than 60 seconds and
near the end. Leave transport/settings unchanged during that run. Save the log
before quitting or trimming the buffer. Report any automatic reconnect with
the first error, transport and elapsed time; a manually requested settings
restart is a different event.

Compare RS and NF side by side for window/tab layout, menu-bar behavior, profile
selection, Import/Export, active server/transport changes, password visibility,
log filters, Copy All, Save, Latest and Follow latest. RS must release listeners
before an automatic restart and must not jump to the first server when saving
a blank new draft. The platform controls may render differently across macOS
releases; record any visible parity gap.

Do not share credential-bearing TOML, private keys or Authorization headers.
A useful report contains source/build identity, `sw_vers`, selected transport,
server software revision and binary hash, sanitized app log and separate TCP/
UDP output. A remote soak and Mac GUI comparison are explicit unverified gates
until results have been recorded in [STATUS.md](STATUS.md).
