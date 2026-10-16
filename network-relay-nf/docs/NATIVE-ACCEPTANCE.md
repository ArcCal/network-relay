# Opt-in native acceptance

This checks the installed **Network Relay NF** GUI on an Apple silicon Mac.
It does not modify or restart either server, change system proxy settings or
exercise a rustls/Quinn substitute. It is an operator procedure, not a claim
that these cases have run in the Linux development environment.

The earlier periodic HTTP/3 disconnect is user-confirmed resolved. Preserve the
existing fixes; a current failure needs its own build and run evidence.

## Record the six independent pairings

Create a result directory for each row, using the **forced** transport in the
GUI. Automatic fallback is a separate seventh case for each server.

| Server | Forced HTTP/1.1 | Forced HTTP/2 | Forced HTTP/3 |
| --- | --- | --- | --- |
| Rust network-relay | NOT RUN | NOT RUN | NOT RUN |
| caddy-network-relay | NOT RUN | NOT RUN | NOT RUN |

Record PASS, FAIL and NOT RUN per case. A historical user report is not a new
current-build pass. Keep these items with each result:

- `build-environment.txt` and successful `build-macos.log` from
  [the fresh build guide](BUILD-AND-OBSERVE.md).
- Startup app/core source revision, build time and executable SHA-256. Verify
  that the app you launched is the app whose executable was hashed.
- Server source revision and SHA-256 of the **running executable**, deployment
  time, endpoint IP, certificate name, relevant policy/idle/admission limits.
  Request these from the server operator; `caddy version` alone identifies the
  Caddy release, not this plugin's source revision. Do not export credentials.
- App logs at Detailed, saved before and after the test, with matching run ID,
  selected server, forced outer transport and remote endpoint. A `curl`
  destination response of `HTTP/2` does not identify the outer transport.
- A UTC timeline, errors, peak connection count and app memory before/after.
  Keep only short Everything captures when needed; the 5,000-line buffer is
  bounded. Store operator evidence outside tracked source files.

## Bounded TCP and UDP observation

Build and launch the current app, select one server and forced transport, then
run from `network-relay-nf/`:

```bash
bash scripts/observe-native.sh rust h2 "$HOME/Desktop/nf-rust-h2-$(date +%Y%m%d-%H%M%S)"
```

For the other rows, change both the GUI and the command labels to `caddy` and/or
`http1`, `h2`, `h3`. Labels are operator metadata, not transport detection. Save
the app log promptly after completion and verify the same server/forced mode
was active throughout. A listener or **Relay Connected** alone is not a pass.

The script performs actual HTTPS transfers through `socks5h` and matched SOCKS
UDP DNS replies for ten minutes, failing on the first failed probe. It records
OS/SDK/source and app executable hash. It never retries through direct access.
Set `NF_PROXY_PORT` for a nondefault local port. `NF_TCP_URL`, `NF_DNS_SERVER`
and `NF_DNS_NAME` can select approved, reachable test targets; a policy denial is
not automatically a client defect. `NF_OBSERVE_SECONDS` is bounded to 60–3,600.
Timing can exceed the requested interval by one bounded request pair.
Set `NF_SERVER_REVISION` and `NF_SERVER_SHA256` from the operator's running-server
record to include them in `environment.txt`; absent values remain NOT_RECORDED.

For an exact large-file check, choose an immutable HTTPS fixture of at least
256 MiB with an independently known SHA-256, then prefix the same command:

```bash
export NF_DOWNLOAD_URL='https://your-controlled-fixture.example/immutable-256MiB.bin'
export NF_DOWNLOAD_SHA256='replace-with-the-64-digit-known-sha256'
bash scripts/observe-native.sh rust h3 "$HOME/Desktop/nf-rust-h3-$(date +%Y%m%d-%H%M%S)"
unset NF_DOWNLOAD_URL NF_DOWNLOAD_SHA256
```

Replace both placeholders. The bulk step has a ten-minute bound, verifies the
whole file hash and records the byte count. Confirm that the recorded size is
at least 256 MiB. Without these two variables it explicitly reports the bulk
case NOT RUN. Successful small requests are not evidence of large-file integrity.

## Cases the observation script cannot certify

Run the following against each pairing with controlled fixtures and keep the
matching client/server timeline. Missing fixtures mean NOT RUN, not PASS.

| Case | Procedure and acceptance |
| --- | --- |
| One long active connection | Keep one SOCKS TCP connection exchanging numbered, verified bytes for at least ten minutes; also exercise UDP. Repeated curl requests do not satisfy this case. Verify no sequence gap, reconnect disguised as continuity or steadily growing resource count. |
| Independent idle and active flows | Hold one established idle SOCKS TCP stream for at least ten minutes while another forwards verified traffic. After at least two probe-renewal intervals, resume the idle stream and verify bytes on the same connection. Record server idle policy; an intentional server idle timeout is not a client regression. |
| Concurrency and cancellation | Exercise more than 64 concurrent TCP/UDP tunnels within the server's configured tunnel limits. Verify bounded outer connections, correct stream isolation, and prompt resource release after cancelling half of the clients. HTTP/1.1 still uses one connection per tunnel. |
| Half-close and destination reset | Against an echo fixture, send bytes, half-close the write side and receive the entire response. Then reset the destination after a known byte count. If the relay exposes abnormal termination, the client must preserve that error. If the relay sends valid TLS close-notify before a raw TCP reset, record that server/TLS boundary separately; do not require NF to invent an error for a clean TLS EOF. Verify exact expected bytes so a truncated file cannot pass. Test both half-close directions. |
| Sleep/wake | During controlled traffic, sleep the Mac for 30 seconds, wake it, and record the existing connection outcome. Old flows may fail; newly opened TCP/UDP flows must work after native reconnection. No stuck UI, crash, hidden direct access or leaked listeners. |
| Network change | While transferring, switch between two available networks and back. Record failed existing flows separately from recovery of new flows; changing networks need not preserve an established TCP stream. Repeat one explicit Disconnect/Connect after recovery. |
| Certificate/account/policy errors | Wrong certificate identity and wrong password must fail securely without direct fallback. A denied business target must not stop unrelated active flows. Select an allowed numeric admission-probe target when the default is denied, and verify the saved target survives restart/import/export. |
| Settings/lifecycle | Switch active server/transport, edit an inactive profile, save a blank new profile, rapidly switch, Disconnect during restart, quit during initialization and reopen the same listener. Confirm independent settings and no stale generation revival. |

Automatic mode must be tested with controlled QUIC unavailability and its own
logs. A manually selected HTTP/2 pass cannot substitute for forced HTTP/3 or
automatic fallback. No native pass is asserted by this checklist or by merely
adding this script.
