# HTTP/1.1 reset and TLS EOF boundary review

Date: 2026-10-16. Changes for this investigation are limited to Network Relay
NF tests and this evidence document. Neither server nor Network Relay RS was
changed.

## Finding

The earlier NF/Caddy HTTP/1.1 reset observation does not establish an NF
implementation defect. An independent OpenSSL TLS client, with no NF code or
NF transport emulator, reproduced orderly TLS EOF followed by a raw TCP reset
from the same Caddy fixture. Changing NF to turn every TLS EOF into a reset
would break real orderly closes and independent TCP half-closes.

The scope is the retained local Caddy test build below. This is not evidence
that an arbitrary currently deployed or newer Caddy binary has the same path.
Actual Apple Network.framework error delivery remains a separate device test.

## Independent real-server reproduction

- Server: Caddy 2.11.6 with caddy-network-relay commit
  `8a0df410a4734790dd34aa8b95097be2b7994381`.
- Binary SHA-256:
  `b309743bdc76c37330aada6b53f29afbf432ebcb34dbd18192af0fd2ea6a53e7`.
- Disposable local account and trusted loopback certificate; TLS certificate
  checking stayed enabled. The client forced ALPN `http/1.1` and successful
  authenticated CONNECT, then read application bytes.
- The destination attempted an 8 MiB write, then used zero-linger close to
  generate a real TCP reset. A duplicated underlying client TCP descriptor
  allowed inspection after the OpenSSL TLS reader's terminal result.
- Python `SSLSocket` used `suppress_ragged_eofs=False`, so bare unannounced TLS
  EOF was not silently accepted by the Python wrapper.

Results from 30 destination-reset cases:

| TLS reader result | Underlying TCP result | Cases |
| --- | --- | --- |
| Orderly TLS EOF (`recv` returned empty) | `ECONNRESET` on the duplicated descriptor | 26 |
| TLS unexpected-EOF error | EOF after the TLS reader had processed the failure | 4 |

Three clean destination half-close controls delivered all 8 MiB, then orderly
TLS EOF. Their underlying TCP read remained open until the client closed its
other direction. The reset cases could receive fewer than 8 MiB; the
destination intentionally aborted rather than guaranteeing delivery.

This independently reproduces the important boundary: the application can see
TLS EOF before the later raw transport failure. It is not caused exclusively
by the NF SOCKS implementation, its production HTTP parser, or its Rust test
bridge.

## Source explanation

In the inspected Caddy source, `h1Client.abort` sets zero linger on the
underlying TCP connection, then calls `Close` on the wrapped TLS connection.
Go's TLS `Conn.Close` attempts `close_notify` after a completed handshake before
closing its underlying connection, except when a concurrent writer makes the
abort take the direct transport-close path. This explains the observed pair of
terminal outcomes without a client-side exception being lost.

The NF native reader already delivers buffered data before an accompanying
non-security error. The Rust bridge also retains terminal failures separately
from its receive queue, and reports a recorded failure even after queued or
previously observed EOF. There is no evidence here that one of those recorded
errors is being erased. An error never delivered by the TLS transport cannot
be reconstructed from arbitrary tunnel bytes.

## Standards and compatibility

[RFC 8446 section 6.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-6.1)
defines `close_notify` as notification that the sender will send no more
messages. Either side may close its write direction with that alert; doing so
does not close its read direction. A transport close before `close_notify`
does not assure the receiver that all sent data arrived.

Accordingly, the NF-side change is a regression test, not a new protocol rule:

1. An orderly TLS half-close still yields EOF and permits upload afterward.
2. A reset without `close_notify` remains an error and becomes a local SOCKS
   reset.
3. An authenticated `close_notify` observed before a later TCP reset is not
   reclassified as an invented failure.

The controlled test covers direct production-client reads and the production
SOCKS path over the test-only rustls bridge. It does not weaken TLS validation,
change wire messages, affect HTTP/2 or HTTP/3, or modify server behavior.
It must not be used to claim that the original reset-preservation expectation
is now achieved with the retained Caddy build. A server-side abort audit would
be needed for that; server changes are outside this task.

Validation: `h1_tls_close_notify_reset_and_half_close_remain_distinct` passed
all six direct/SOCKS cases. Twenty additional executions, with up to four test
processes in parallel, passed all 120 case executions. This is portable TLS
bridge coverage, not execution of Network.framework on an Apple device.

The local raw reproduction script and results are retained under the uncommitted
`network-relay-nf/.build/h1-reset-review/` directory. No real server or WARP
credentials appear in the committed evidence.

## Native macOS follow-up, 2026-11-21

Against current Caddy on Linux x86-64 and arm64, the native NF SOCKS client
and OpenSSL each received a reset in all 30 trials on the packet-preserving
path. On the TCP port-forwarded path OpenSSL detected 30 unannounced TLS
ends; NF delivered 30 orderly EOFs. All normal half-closes delivered the
full 8 MiB and accepted a reverse write. The receive completion's context
identifier, final flag, connection state and error were indistinguishable
between authenticated and bare EOF on the forwarded path. These observations
apply to macOS 27 and the two tested paths.
[Paired trials](https://github.com/ArcCal/caddy-network-relay/actions/runs/44847396355).
[Native receive metadata](https://github.com/ArcCal/caddy-network-relay/actions/runs/44849940017).

A transparent TCP framer beneath native TLS still delivered ordinary EOF
in all 30 forwarded aborts and was discarded. With the same forwarder,
the first NF H2 and RS H1 series each delivered a reset in all 30 aborts
and passed all ten clean half-close and reverse-write controls. The x86-64
job later reached its 40-second read deadline on an RS packet-path abort.
A repeat also reached that deadline on an RS port-forwarded abort. Use NF H2
when a forwarder obscures NF H1 resets. The two initial RS series alone
cannot establish that RS always signals the abort promptly.
[Framer comparison](https://github.com/ArcCal/caddy-network-relay/actions/runs/44850438063).
[Transport and client alternatives](https://github.com/ArcCal/caddy-network-relay/actions/runs/44850786265).

An instrumented x86-64 repeat observed 30/30 resets on the packet path
and 29/30 on the port-forwarded path. In the remaining case the reader
received 5,665,101 bytes, then reached its 40-second deadline. The origin
had queued its payload and initiated the abort. RS reported a missing TLS
close_notify and successfully set abortive linger for that SOCKS peer.
The loopback capture contained a TCP RST to the reader's port. Why the
read still timed out remains open. All 20 clean controls delivered 8 MiB
and a reverse write. [Matched socket trace](https://github.com/ArcCal/caddy-network-relay/actions/runs/44852285536).

Two separate macOS TCP connections can account for a reader timeout.
A direct Python/OpenSSL client with no relay software timed out in eight
of 16 trials when the peer aborted after writing 8 MiB. Waiting at the
peer for its send queue to drain yielded 16 resets. In RS, a bare FIN
after TLS data triggered the expected truncation error, yet two of 16
SOCKS clients timed out after RS issued its local abort. Waiting for the
local send queue eliminated those two timeouts in the comparison. A local
change cannot recover an upstream reset that the TLS socket never reports.
[Direct TLS control](https://github.com/ArcCal/caddy-network-relay/actions/runs/44853209330).
[Independent controls on both sockets](https://github.com/ArcCal/caddy-network-relay/actions/runs/44853350067).

In two 32-case batches with the production RS local stream, immediate
reset left six readers waiting. A fixed two-millisecond delay and a wait
for the macOS send queue each delivered 64/64 resets. RS checks the queue
so it can close an empty socket immediately. The wait has a 100 ms upper
bound if the reader stalls. [Three local alternatives](https://github.com/ArcCal/caddy-network-relay/actions/runs/44853457999).

With the final RS implementation, both Linux release architectures and
both paths delivered all 120 aborts as SOCKS resets and all 40 clean
8 MiB bodies with a successful reverse write. The same source passed the
client suite on macOS 27, Linux x86-64 and arm64. On macOS the local bulk
regression also passed four additional eight-abort batches, and a stalled
reader released the abort task within the test's one-second deadline.
[Two Linux servers and two paths](https://github.com/ArcCal/caddy-network-relay/actions/runs/44853719803).
[Exact candidate core tests](https://github.com/ArcCal/caddy-network-relay/actions/runs/44853767475).
