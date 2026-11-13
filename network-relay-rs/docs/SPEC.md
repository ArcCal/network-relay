# Application and protocol specification

Revision: 0.1.0 development, 2026-10-12. Requirements are acceptance targets;
[STATUS.md](STATUS.md) records tested implementation and remaining gates.

## Wire protocol

| Forced transport | TCP | UDP | Required server result |
| --- | --- | --- | --- |
| HTTP/1.1 over rustls | Classic CONNECT with authority-form destination | GET with `Connection: Upgrade` and `Upgrade: connect-udp` at the template URI | TCP any 2xx; UDP exactly 101 with Upgrade and Capsule negotiation |
| HTTP/2 over rustls | Classic CONNECT with destination `:authority` | Extended CONNECT with `:protocol = connect-udp` and an expanded HTTPS template | Any 2xx; ENABLE_CONNECT_PROTOCOL; UDP `Capsule-Protocol: ?1` |
| HTTP/3 over Quinn/rustls | Classic CONNECT on a bidirectional request stream | Extended CONNECT with `:protocol = connect-udp` and an expanded HTTPS template | Any 2xx; ENABLE_CONNECT_PROTOCOL; UDP `Capsule-Protocol: ?1` |

Applicable references include RFC 1928, RFC 6570, RFC 9000, RFC 9001, RFC 9110
section 9.3.6, RFC 9113, RFC 9114, RFC 9220, RFC 9297 and RFC 9298. The inherited
RFC 6570 parser supports a restricted template profile; unsupported forms must
be rejected explicitly. The GUI emits
`/.well-known/masque/udp/{target_host}/{target_port}/` and does not provide custom
endpoint editing. Both GUI and headless settings imports currently accept only
that standard endpoint; custom templates are rejected instead of silently
rewritten. The protocol core parser alone supports a wider restricted profile.

Credentials use HTTP Basic `Authorization` at the relay. They must not be sent
to destination applications or included in logs. The app fails a non-success
response before acknowledging SOCKS success. Server policy is authoritative:
a rejected destination is not retried directly. Mutual-TLS-only authentication
is not implemented by this initial app.

Ordinary CONNECT accepts every successful 2xx response, rather than only 200.
The Capsule-Protocol value is parsed as a Structured Fields Boolean, including
valid unknown parameters. A malformed/list value, repeated field or false
value fails. The present client also requires the response field to be present;
RFC 9297 section 3.4 says the peer SHOULD send it, so an otherwise compliant
peer omitting that field may be rejected. Both target-server fixtures send it;
broader omission compatibility has not been implemented or tested.

The optional server IP selects the socket endpoint. The profile domain selects
SNI and the expected certificate identity. With no IP override, domain resolution
selects the endpoint. rustls verifies trust and hostname; production has no
accept-any-certificate option. Explicit CLI `--ca-file` adds a trusted test CA
without disabling normal certificate validation.

## Streams and UDP

TCP transports arbitrary binary bytes. Each direction supports independent
half-close: a local write EOF must permit a later remote response. Cancellation
and an I/O error must release owned drivers and wake blocked opposite pumps;
already buffered response bytes must remain readable before the terminal error.

CONNECT-UDP uses DATAGRAM Capsules with context ID 0 inside the request stream.
An empty UDP payload is valid. Native QUIC DATAGRAM is not negotiated; HTTP/3
UDP forwarding therefore remains reliable and ordered inside that stream.
Unknown capsule types and unsupported contexts are ignored with bounded
buffering. Truncated Capsules fail on EOF. Invalid tunnel headers or trailers
must fail instead of becoming application payload.

The inherited limits are 65,507 bytes for outgoing UDP and 65,240 bytes for a
SOCKS response payload, leaving room for supported address headers. The full
IPv6 UDP maximum is outside the initial profile. Stream pumps use bounded
64 KiB duplex buffers and 16 KiB write chunks. HTTP/2 returns receive credit
only after the consumer accepts bytes.

HTTP/3 reuses a session for independent CONNECT and CONNECT-UDP streams. New
requests stop using a session after GOAWAY; admitted streams keep their driver
and parent connection until released. Session creation and request-stream
capacity waits are bounded. At most four sessions are owned by one client,
including sessions retained by draining flows. A request is not automatically
replayed after HEADERS submission or a response timeout.
Response waiting is bounded at 20 seconds, allowing the relay's default
five-second DNS and ten-second destination-connect budgets. Transport setup
and stream-capacity waits retain their separate ten-second deadlines.

HTTP/2 likewise shares one cached TLS connection for independent CONNECT and
CONNECT-UDP streams, including the readiness probe. A connection that received
GOAWAY or failed is not reused; admitted streams keep it until released.
The client sends a PING every 20 seconds and ends a connection whose PING is
unanswered for 20 seconds, so a path that stopped carrying packets without a
TCP error is replaced for new flows within about 40 seconds.
Because flows share the connection's receive window, that window is the
protocol maximum while each stream keeps its 2 MiB window, so unread flows
cannot stall the others. HTTP/1.1 CONNECT consumes its TLS connection and
still opens one per flow.

## SOCKS5

The local interface is SOCKS5 CONNECT and UDP ASSOCIATE with no authentication.
The default address is `127.0.0.1:1080`. Explicitly selecting a non-loopback
address exposes an unauthenticated proxy. BIND and fragmented SOCKS UDP are
unsupported. Destination DNS names remain names for server-side resolution;
internationalized names must be supplied as ASCII/Punycode.

A UDP association ends with its TCP control connection. Its sender IP must
match the control peer. An advertised sender port is enforced; otherwise the
first valid sender port is pinned. Each association has at most 32 destination
flows, a 16-packet outgoing queue per flow, a 32-packet reply queue and a
120-second inactive-flow timeout. Queue overflow is dropped. Concurrent SOCKS
TCP sessions are capped at 256 and further bounded by the process file descriptor
allowance, with capacity reserved for pending I/O and the application. Temporary
accept-time descriptor exhaustion is retried without terminating the listener.
Per-drop UI counters are not implemented.

## Readiness, transport and retries

Authenticated CONNECT-UDP admission establishes **Relay ready**, not destination
reachability or sustained traffic. The readiness request sends no target UDP
packets. The core renews an idle readiness probe after 60 seconds and refreshes
clean peer EOF without declaring a global relay failure. Independently opened
SOCKS flows retain their own lifetimes. Malformed protocol data and transport
errors remain failures.

Forced HTTP/3 must remain HTTP/3. Automatic mode may try HTTP/3 and fall back to
TCP during connection setup and capability negotiation, before submitting the
CONNECT request; its tests and logs must identify the chosen transport. Silent
fallback must not count as a forced HTTP/3 pass. Short failures use exponential backoff; at
least 30 seconds of admitted readiness resets that backoff. A recurring failure
must remain visible in Normal or higher logs.

## Application parity and isolation

RS has the same functional target as NF: server list and selection, optional
display name, domain/IP, username/password, four transport choices, local listen
address/port, connect-on-launch, connection controls, status/menu-bar access,
settings import/export, About and the copied icon. GUI source and application
logic are Rust; native AppKit is a platform widget layer.

Selecting another server or changing active transport must take effect
automatically. A newly added or imported server takes effect only after Save,
and adding or importing never connects by itself. The minus button deletes the
selected server: a saved server leaves the saved settings at once after a
confirmation, the connected one passes the connection to its list neighbor, and
an unsaved server only leaves the draft. Editing active connection parameters
and saving restarts after the old listener closes. Editing inactive profiles, display-only names or log
level must not interrupt active traffic. Explicit Disconnect cancels pending
automatic restarts. Saving a blank new profile must not unexpectedly select the
first profile or reconnect to it.

Settings use RS's own private JSON file, directory mode 0700 and file mode 0600
with atomic replacement. NF-format TOML imports are explicit; exports can omit
passwords and can select server or application scope. NF's per-server
`probe_target` is validated, stored, exported and used for readiness; RS
provides no field to edit it. Exporting secrets requires
private file permissions. RS must not change NF's saved settings, parent server
files, system proxy settings or another app's process.

## Logs

The level menu runs from most to least detailed: Everything, Detailed, Normal,
Warnings and Errors, Errors Only. It filters TRACE/DEBUG/INFO/WARN/ERROR.
Third-party wire/payload traces remain disabled even at Everything. Changing
level updates diagnostics and the view without reconnecting. Raising verbosity
cannot recover messages that were not generated earlier.

Everything additionally generates reviewed Rust transport metadata: I/O event
kind, resource handle, event byte count, received byte count and EOF marker.
It must differ from Detailed without dumping event contents, packet bodies,
encoded headers or credentials. A resource handle identifies a local backend
resource; it must not be interpreted as a QUIC stream ID. Detailed retains
connection, selected transport, ALPN and destination diagnostics.

Headless mode accepts `--log-level errors|warnings|normal|detailed|everything`.
The override affects that run only and does not rewrite GUI preferences.
Source edits rerun the build metadata generator; the packaged app's build
script explicitly sets UTC build time and source identity.

Presentation preserves monospaced selectable text, severity styling, Follow
latest, Latest, Copy All and Save. The retained in-memory buffer is capped at
5,000 lines, removing verbose records first. Copy All and Save export retained
lines even when the view hides them. Logs are not automatically persisted.
UTC timestamps and a run tag identify connection attempts. Startup/About
metadata identifies version, build time and source, including a dirty suffix.
Passwords, authentication headers, application packet bodies and private keys
must not be logged.

## Release acceptance

Run separate real network-relay and caddy-network-relay matrix rows for all
three forced transports. At minimum verify TCP and UDP target replies, bad
authentication, bad certificate/hostname, denied destinations, remote DNS,
binary bulk data, empty/large UDP, both half-closes, cancellation and reconnect.
Test IPv6 when supported by the host; mark an unavailable fixture as NOT RUN.

Actual Mac acceptance additionally covers successful ARM64 linking and
packaging, launch, NF appearance/interaction comparison, menu bar, file panels,
profile imports, active server/transport changes, server deletion, blank draft selection and log
controls. Run at least ten minutes per real server and transport with separate
idle and active TCP/UDP periods, exceeding the historical ten-second and probe
renewal intervals. Confirm no periodic automatic failure/reconnect cycle.

Record client source/build, Rust toolchain, OS/build, server revision/binary hash,
transport and sanitized results. A passed Linux matrix is evidence of RS's
production transport compatibility, but not a Mac UI execution or a complete
remote-deployment soak. PASS, FAIL and NOT RUN must remain distinct.
