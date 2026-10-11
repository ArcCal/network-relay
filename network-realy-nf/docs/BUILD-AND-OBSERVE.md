# Fresh Mac build and observation

This guide builds **Network Realy NF**, the CONNECT/CONNECT-UDP client, from a
new checkout. It does not build Masque NF or modify either relay server. The
macOS build and native interoperability cannot run in the Linux cloud environment.
The user has since reported a Mac build/launch and successful SOCKS TCP/UDP probes;
[the recorded evidence](evidence/native-mac-20261011.md) distinguishes these from
the still-incomplete native matrix. A compiler failure is a failed gate.

## Prerequisites

Use an Apple silicon Mac (`arm64`), macOS 27 or newer, full Xcode with a macOS
27 or newer SDK, Git and stable Rust. The reported macOS 27.0.1 system meets the
OS requirement, but its selected SDK and architecture still need checking.

Install Xcode, launch it once to finish its first-run setup, then check:

```bash
sw_vers
uname -m
xcode-select -p
xcodebuild -version
xcrun --sdk macosx --show-sdk-version
```

If Xcode is installed at `/Applications/Xcode.app` but the active developer
directory is Command Line Tools or a different Xcode, select it and recheck:

```bash
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
xcrun --sdk macosx --show-sdk-version
```

If `rustup --version` reports that the command is missing, install Rust through
its official installer. Skip the installer when Rustup is already installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

Load Rust and update the stable toolchain:

```bash
. "$HOME/.cargo/env"
rustup update stable
rustc --version
cargo --version
```

## Download and build

The application is currently in the `codex/network-realy-nf` branch of
`ArcCal/network-relay`, under review in [PR #18](https://github.com/ArcCal/network-relay/pull/18).
Until that PR is merged, cloning `main` will not provide this application. For
this private repository, use an existing GitHub login that can read it. If Git
reports an authentication error, authenticate with GitHub CLI (`gh auth login`,
then `gh auth setup-git`) or your normal Git credential manager; do not put a
token into the clone URL.

Run the following in a new Terminal window. The timestamp creates a new
directory and avoids reusing an old checkout or its build products:

```bash
. "$HOME/.cargo/env"
NF_CHECKOUT="$HOME/Downloads/network-relay-nf-$(date +%Y%m%d-%H%M%S)"
git clone --branch codex/network-realy-nf --single-branch \
  https://github.com/ArcCal/network-relay.git "$NF_CHECKOUT"
cd "$NF_CHECKOUT/network-realy-nf"
export CARGO_TARGET_DIR="$PWD/Core/target"
set -o pipefail
{
  git rev-parse HEAD
  sw_vers
  uname -m
  xcodebuild -version
  xcrun --sdk macosx --show-sdk-version
  rustc --version
  cargo --version
} > build-environment.txt
bash build-macos.sh 2>&1 | tee build-macos.log
```

Run `open` only after the build command exits successfully:

```bash
open "$PWD/dist/Network Realy NF.app"
```

The build runs the Rust tests, Swift model tests and native local boundary smoke
checks before packaging and ad-hoc signing. Ordinary Cargo runs skip the live
server matrix; a passing build therefore does not establish native relay
compatibility. The bundle, ZIP and SHA-256 file are under `dist/`. The startup
log and About view show the source revision and build time. A `-dirty` suffix
means files in this application directory differed from the recorded commit;
a build without Git metadata reports `Unknown`.

If a test, compiler, linker or signature check fails, retain `build-macos.log`
and `build-environment.txt`. Do not launch a binary left over from another
directory and count it as the result of this build. Neither file contains the
server account or password.

The script's default smoke run covers local listener/lifecycle behavior. Its
additional TCP close checks can be run after a successful build:

```bash
./build/native-smoke --close-checks
```

These loopback checks are separate from remote authentication, HTTP/3 and
Internet access. No Mac execution of them is claimed here.

## Log levels and presentation

The Log tab follows the copied Masque NF layout. Its level menu is ordered from
the most detailed to the least detailed:

| Menu entry | Visible severities | Typical use |
| --- | --- | --- |
| Everything | TRACE, DEBUG, INFO, WARN, ERROR | One short failure capture; native resource I/O kinds and byte counts |
| Detailed | DEBUG, INFO, WARN, ERROR | SOCKS connections, relay host/IP, certificate name, ALPN, QUIC SID and parent |
| Normal | INFO, WARN, ERROR | Launch, connection/readiness, disconnect and retry records |
| Warnings and Errors | WARN, ERROR | Failures and warnings |
| Errors Only | ERROR | Fatal/error records; a retry warning can be hidden at this level |

Changing the level takes effect without reconnecting. Higher levels affect
future diagnostic generation; raising the level cannot recover old diagnostics
that were never generated. Changing to a lower level hides previously retained
verbose lines. Untagged diagnostics remain visible at every level. Rust's
warning/error levels also reduce its generated messages; app/native operation
messages can remain in the retained buffer while hidden in the view.

Text is monospaced and selectable. Warnings/errors use the copied orange
highlight; debug/trace are dimmed. **Follow latest** scrolls with new lines;
disable it to read earlier events, or press **Latest** to resume following.
**Copy All** and **Save…** export the entire retained buffer, including levels
hidden by the current menu selection. Save produces a plain-text file at the
location you choose; there is no automatic log directory or disk rotation.

At most 5,000 lines are retained in memory. Old TRACE/DEBUG entries are removed
first when necessary to preserve operation/error records. Important entries are
also bounded. Save a short capture promptly, before a long verbose run trims
it and before quitting the application.

Logs carry UTC timestamps and per-connection `[run=XXXXXXXX]` tags. Starting a
new connection after changing server or transport produces a new run tag.
Logs include destinations and addresses, but do not deliberately print passwords,
Authorization headers, packet bodies or certificate contents. Everything keeps
third-party wire traces disabled because those can contain payloads or credentials.

## Native HTTP/2 baseline

Create one profile for each actual **network-relay** or **caddy-network-relay**
server. A Rust `masque-server` or `caddy-masque` CONNECT-IP service is a different
protocol endpoint and is not the target for this application. Use the relay
domain, its actual IP if needed, server port and that relay's account. The
default UDP template is `/.well-known/masque/udp/{target_host}/{target_port}/`.
The domain remains the TLS certificate name with an IP override.

Quit any other application using `127.0.0.1:1080`, or select another local SOCKS
port and substitute it in the commands below. No system proxy configuration is
required. Network Realy NF uses its own settings directory:
`~/Library/Application Support/NetworkRealyNF/`.

1. Select **HTTP/2 (TCP)** and set the Log tab to **Everything** before connecting.
2. Save the profile and connect. Look for `Native TLS connection ready, ALPN h2`
   and `Relay ready; HTTP/2; authenticated CONNECT-UDP`.
3. Run the TCP web request below from the application source directory.
4. Separately run the SOCKS UDP probe. Save the app log as
   `nf-rust-http2.log` or `nf-caddy-http2.log`, alongside the command output.
5. Repeat independently with the other relay server profile.

```bash
set -o pipefail
curl -I --noproxy '' --proxy socks5h://127.0.0.1:1080 \
  --connect-timeout 10 --max-time 30 https://example.com/ \
  2>&1 | tee nf-http2-curl.log
python3 scripts/probe-socks-udp.py --proxy-port 1080 \
  --dns-server 1.1.1.1 --name example.com \
  2>&1 | tee nf-http2-udp.log
```

For the second server, use distinct filenames to keep both results. HTTP
response headers and exit status zero establish that the TCP request completed.
`PASS SOCKS UDP` reports a matching, nontruncated successful DNS reply through
the association. The probe sends UDP only to the SOCKS relay; it never connects
directly to the DNS server. It uses Python's standard library and does not need
administrator rights. To observe server resolution of a UDP destination name,
repeat with `--dns-server one.one.one.one`.

An allowed reachable DNS endpoint is required. A server's destination policy or
upstream DNS availability can deny the probe; a failure alone does not identify
the client as the cause. The app's idle readiness request admits `1.1.1.1:53`
but sends no DNS query. It cannot establish website or UDP delivery. Conversely,
curl alone does not test UDP. These small observations are not the full
compatibility acceptance matrix.

## One bounded HTTP/3 observation

Keep the same domain, IP, certificate verification and account. Set
**Everything**, select forced **HTTP/3 (QUIC, UDP)** and allow one attempt to
finish. Do not change/save parameters during that attempt. Each initialization
stage has a ten-second budget; a forced flow has a thirty-second outer budget.
Wait for `Relay ready; HTTP/3` or the first natural `Relay session failed` record.
If no outcome appears within about 35 seconds, disconnect and record that
absence. Disconnect after the first failure to avoid collecting endless retries.

Save the retained log immediately as `nf-rust-http3.log` or
`nf-caddy-http3.log`. Useful records include:

- Startup source/build identity and the new run tag.
- `Native QUIC opening`, including host/IP and certificate name.
- `Native QUIC ready` and outgoing/incoming stream SID/parent records.
- `HTTP/3 request HEADERS sent; waiting for response`, including the request SID.
- The natural failure reason, first request-stream receive or readiness record.

Resource numbers identify bridge handles; only metadata **SID** values identify
QUIC streams. QUIC ready and locally sent HEADERS do not prove the peer parsed
or accepted CONNECT. A transient `waiting: Network is down` followed by ready
does not establish a permanently failed network path.

If HTTP/3 reaches readiness, run both TCP and UDP commands again, with filenames
containing `http3`. If it fails, preserve the capture and return to forced
HTTP/2. Selecting the transport while connected automatically restarts this
application and ends its existing SOCKS sessions. This is manual recovery;
Automatic mode's fallback is a separate observation.

No extended QUIC troubleshooting is required for this initial handover. Mark a
failed native HTTP/3 row as **FAIL**, keep HTTP/2 as the baseline, and attach the
evidence to [QUIC-RESEARCH.md](QUIC-RESEARCH.md). Nothing in this guide establishes
that Network.framework has an unavoidable defect or that HTTP/3 is repaired.

For review, retain the build environment/source file, build log, per-server
application log, TCP output and UDP output. Server revision/configuration and
the selected transport complete the record; configuration exports containing
passwords are unnecessary. Record PASS, FAIL and NOT RUN separately, including
whether a second server or transport was not tested.
