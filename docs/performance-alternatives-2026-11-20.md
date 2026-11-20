# Performance alternatives, 20 November 2026

The tested server platforms are Linux x86-64 and arm64. The client runs use
real macOS networking APIs and an iOS simulator. Each comparison below identifies
its workload, a baseline, separate alternatives and the acceptance measure.
A complete file requires the expected byte count and digest. A UDP round trip
requires a matching payload at the intended destination. Separate trials that use
the same implementation are repetitions of one candidate.

## Server results

### VLESS DNS cache at capacity

At 4096 entries the old resolver scanned for expired results on every insertion.
If all entries were valid it cleared the entire cache, even when replacing an
existing name. The experiment populated 4096 valid answers, then accessed a
128-name working set through the resolver. A real local WebSocket/VLESS DNS peer
answered any misses. Four crossover repetitions per architecture compared three
eviction policies at the same capacity, TTLs, timeout and verification settings.

| Policy | Extra upstream queries after refreshing one name | After inserting one new name | Mixed trace, 1024 additions interleaved with 128 active names |
| --- | ---: | ---: | ---: |
| Original clear-on-full | 127 | 128 | 128 |
| Evict earliest expiry | 0 | 2 | 1152 |
| Rotate through occupied slots | 0 | 128 | 128 |
| Give recently accessed entries a second chance | 0 | 0 | 0 |

Counts include the final sweep of the active names. The two architectures agreed
on every count in the table. Earliest-expiry repeatedly removed recently
looked-up records with shorter remaining TTLs and also scanned all 4096 slots on
each new insertion. The simple rotating cursor could displace an active name
and evict its neighbor when the miss was filled. Second chance preserved the
working set. During the mixed portion (before its final sweep), time fell from
146.5 to 0.272 ms on x86-64 and 155.6 to 0.372 ms on arm64. With 16384 all-new
names and no recent references during that churn, every policy later made
128 queries. Eviction without reads cannot preserve an arbitrary older working
set indefinitely.

The selected implementation stores one reference bit per entry and a rotating
index in a bounded table. A full-cache insertion can sweep the table once if
every entry was used. Expired entries are never returned, hits never renew a
TTL, and fresh success still wins a race against failure. IndexMap 2.14.2
was already in the VLESS lock. Local testing covered 52 unit tests, three
additional non-gated integration tests and all seven separately enabled real
Xray 26.10.31 cases. Strict all-target Clippy passed. The four diagnostic
implementations each passed the same 28 DNS tests on both native Linux CPUs.
The final release source passed 55 VLESS tests, 15 server policy tests and
seven real Xray cases on each architecture. [Release validation](https://github.com/ArcCal/network-relay/actions/runs/44790641968).
[Cache experiments and raw counts](https://github.com/ArcCal/network-relay/actions/runs/44789401612).
[RFC 2308](https://www.rfc-editor.org/rfc/rfc2308).
[RFC 9520 section 3.2](https://www.rfc-editor.org/rfc/rfc9520#section-3.2).

### Concurrent VLESS DNS misses

The previous resolver started one DNS-over-TCP WebSocket transaction per
simultaneous cold caller for the same name. The tests used a VLESS peer
with a 20 ms response delay and verified the returned IPv4 address.
Four crossover rounds compared the original behavior, serializing cold
queries globally, serializing across 32 hash buckets, and sharing the
outcome only among callers of the same active transaction.

| Workload | Original upstream queries | Global queue | 32 queues | Same-name transaction | Median wall ms for original and same-name, x86-64 / arm64 |
| --- | ---: | ---: | ---: | ---: | --- |
| 32 callers, one cold name | 32 | 1 | 1 | 1 | 28.5 to 21.5 / 25.9 to 21.5 |
| 32 callers, 32 cold names | 32 | 32 | 32 | 32 | 27.7 to 28.3 / 25.7 to 25.7 |
| 64 callers, eight cold names | 64 | 8 | 8 | 8 | 33.9 to 23.2 / 30.2 to 22.0 |
| 32 overlapping callers, zero TTL | 32 | 32 | 32 | 1 | 27.3 to 21.4 / 25.1 to 21.3 |
| 32 callers, one warm name | 0 | 0 | 0 | 0 | 0.021 to 0.021 / 0.025 to 0.024 |

Global serialization raised the 32-distinct median to 681-683 ms. Bucket
collisions raised it to about 91 ms. Both queues took about 680 ms for the
zero-TTL burst. The same-name version used a fresh transaction for the
next zero-TTL request. A cancelled leader wakes its waiters. A caller that
times out while waiting leaves the resolver preference and failure cache
intact. Coalescing is scoped to one configured resolver instance, whose
address-family preferences, DNS servers and VLESS credentials are fixed.
This first implementation shared the complete failover sequence. A later comparison below found a deadline regression in that choice.
The first comparison completed on both CPUs. Its release-format check found an import-order mismatch. The corrected run passed formatting, strict Clippy, all four comparison policies, 57 VLESS tests, 15 destination-policy tests and seven real Xray tests on each architecture. [Initial comparison](https://github.com/ArcCal/network-relay/actions/runs/44794053304).
[Corrected candidate and release results](https://github.com/ArcCal/network-relay/actions/runs/44794908661).
[RFC 1035 section 3.2.1](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1).
[RFC 9520 sections 2.3 and 3.2](https://www.rfc-editor.org/rfc/rfc9520#section-2.3).

A short-budget caller could also start a full first attempt while having
little time left for a second resolver. The first peer in the regression
test was silent. The second returned a verified answer after 400 ms. The
first caller had 2625 ms in total and the second had 5000 ms. Whole-lookup
sharing incorrectly timed both out after 2627 ms. The alternatives disabled
sharing for multi-server configurations, shared only between callers with
identical absolute deadlines, or shared full attempts to the same upstream
server while allowing each caller to follow its own failover sequence.

| Strategy on a two-resolver configuration | Longer caller reaches the working fallback | Upstream attempts for the two callers | Cold queries for 32 callers / one name | Cold queries for 64 callers / eight names |
| --- | --- | ---: | ---: | ---: |
| Share the entire lookup | No | 2 | 1 | 8 |
| Bypass the shared lookup | Yes | 4 | 32 | 64 |
| Key the lookup by absolute deadline | Yes | 4 | 32 | 64 |
| Share each complete attempt to one resolver | Yes | 3 | 1 | 8 |

Both native CPUs agreed in all four rounds. The last strategy reached the
working fallback after 2904 ms while the short caller still timed out as
requested. With a healthy first server, 32 distinct cold names remained
concurrent (26.71 ms on x86-64 and 25.90 ms on arm64). The warm case made
zero upstream queries. A caller with little time and two address families
can independently use a partial A or AAAA before a full-duration transaction
finishes. The regression includes both families with a real WebSocket peer.
[Deadline strategies, functional cases and real Xray](https://github.com/ArcCal/network-relay/actions/runs/44799349103).

### CF MASQUE DNS cache at capacity

The WARP resolver has its own DNS implementation. Its 4096 slots are keyed
by both name and query type, and concurrent callers already share a pending
family query. Before this change, refreshing a full cache could discard every
other unexpired family answer. The comparison used the real CF resolver,
two local packet stacks and counted queries received at the DNS peer. Four
rounds on each architecture exercised all four eviction policies.

| Policy | Extra upstream queries after refreshing a name | After adding a name | During and after mixed activity | After 16384 all-new names |
| --- | ---: | ---: | ---: | ---: |
| Clear all valid entries when full | 127 | 128 | 128 | 128 |
| Evict the earliest expiry | 0 | 2 | 1024 | 128 |
| Rotate through slots | 0 | 128 | 128 | 128 |
| Give recently read family entries a second chance | 0 | 0 | 0 | 128 |

The active set contained 128 names. For 1024 interleaved insertions and
reads, the median time on x86-64 fell from 1.827 to 0.318 ms. On arm64
it fell from 2.021 to 0.469 ms. The tests also checked a cached A answer,
a short-lived negative AAAA answer for the same name, zero TTL, failure
caching, cancellation, UDP-to-TCP retry and a failed WARP tunnel.
The table size and the configured DNS servers and transports stay the same.
The ordered map dependency was already in both CF lockfiles.
With the original TCP scheduling, the selected cache also passed the
packet-backed frontend and egress suites, the 484-test vendor suite,
strict Clippy and a standalone external build on both architectures.
The two long-lived runs recorded 3918.69 / 3927.77 measured seconds
on x86-64 / arm64, twelve continuously held flows, one outer connection
generation per transport and zero reported packet queue drops.
[CF cache experiments and Linux release validation](https://github.com/ArcCal/network-relay/actions/runs/44796189061).
[RFC 2308 section 5](https://www.rfc-editor.org/rfc/rfc2308#section-5).
[RFC 9520 section 3.2](https://www.rfc-editor.org/rfc/rfc9520#section-3.2).

### Caddy UDP Capsule receive allocation

Four counterbalanced repetitions measured complete streams containing one
1200-byte payload, one maximum-size payload, a mixed-size sequence, an eight-packet
train and an idle control. All strategies used the production parser. Boundary
and race tests checked exact delivery including zero, 63 and maximum-sized
payloads. The table gives medians in ns per stream with the x86-64 value first.

| Strategy | Small | Large | Mixed | Eight small |
| --- | ---: | ---: | ---: | ---: |
| Original dedicated maximum-size storage | 30573 / 31622 | 32137 / 33739 | 26859 / 25704 | 15948 / 12455 |
| Borrow from the existing reader for small payloads | 6512 / 6785 | 32333 / 34332 | 27275 / 23476 | 4606 / 4023 |
| Grow private storage to the payload size | 7093 / 7397 | 32568 / 34536 | 32585 / 32298 | 5436 / 4877 |
| Reuse and wipe a bounded set of large buffers | 7626 / 7716 | 9249 / 8894 | 10006 / 9955 | 8113 / 8418 |

Borrowing saved 65536 B/stream for small packets. Exact growth used 101840 B
and seven allocations for the mixed case, compared with 82064 B and four for
the existing borrowed approach. Using the pool alone increased eight-small-packet
costs. Both CPUs passed the exact package reader tests under the Go race detector.
[Caddy reader and authenticated setup measurements](https://github.com/ArcCal/caddy-network-relay/actions/runs/44788127978).
[RFC 9297 section 3](https://www.rfc-editor.org/rfc/rfc9297#section-3).
[RFC 9298 section 5](https://www.rfc-editor.org/rfc/rfc9298#section-5).

The next two experiments combined the shipping small-payload reader with a
four-buffer cache used only by streams that actually receive a large
Capsule. Buffers were cleared on return. Thirty-two concurrent large
streams passed exact-byte tests under the race detector. With four workers,
the first hybrid reduced large-only cost from 15.6 to 4.8 us on x86-64 and
16.8 to 4.5 us on arm64. Eight 1200-byte datagrams in one stream became
slower on both machines. The second hybrid moved cleanup out of the loop.
Six independent samples per implementation with one pinned worker again
put the eight-small median at 4.15 versus 4.82 us on x86-64, and 3.94 versus
5.36 us on arm64. Both versions saved a large allocation on mixed streams.
The extra cache was discarded. The small-payload borrow remains the selected
change. [Contended large buffers](https://github.com/ArcCal/caddy-network-relay/actions/runs/44789884078).
[Independent processes, native H1/H2 large echoes and race suite](https://github.com/ArcCal/caddy-network-relay/actions/runs/44792644899).

### Authenticated connection setup

A trusted client used the same verified certificate chain and opened 24
authenticated CONNECT tunnels. Each wrote and checked 4096 bytes, including
half-close. Four alternating rounds compared full H1 handshakes with H1
session resumption, shared H2 and shared H3. Fresh H2 and fresh H3 were
additional controls. Session-state callbacks counted actual TLS handshakes
and resumptions.

| Strategy | Handshakes per 24 tunnels | Median wall ms, x86-64 / arm64 |
| --- | ---: | ---: |
| Fresh H1 | 24 | 38.0 / 36.4 |
| H1 session resumption | 24, including 23 resumed | 31.6 / 30.6 |
| Shared H2 | 1 | 15.0 / 15.8 |
| Shared H3 | 1 | 19.9 / 21.0 |
| Fresh H2 | 24 | 42.9 / 42.8 |
| Fresh H3 | 24 | 58.8 / 65.0 |

The project clients already support connection reuse. These results justify
retaining that behavior. Changing authentication or certificate policy would
not address the measured cost. [Native Linux handshake controls](https://github.com/ArcCal/caddy-network-relay/actions/runs/44788127978).

### Rust H2 bidirectional bulk

The three H2 builds used 16 KiB copy
chunks, omitted a redundant capacity reservation when sufficient credit is already
available, or advertised a larger maximum incoming DATA frame of 32 KiB.
Neither the configured peer credit nor the per-connection memory budget was
increased. Each candidate was compiled independently. Four crossover rounds per
architecture checked bytes and FIN, one 32 MiB stream, four shared 8 MiB streams
and four shared streams including a deliberately slow consumer.

| Implementation | Single 32 MiB ms, x86-64 / arm64 | Four shared streams ms | Four with a slow consumer ms |
| --- | ---: | ---: | ---: |
| Stock | 65.4 / 90.6 | 45.9 / 62.0 | 399.3 / 396.6 |
| Smaller copy chunks | 66.5 / 90.6 | 47.2 / 63.3 | 402.4 / 397.1 |
| Conditional credit reservation | 83.6 / 90.5 | 45.1 / 62.3 | 401.6 / 395.3 |
| Larger advertised incoming frame | 84.0 / 90.0 | 43.3 / 60.6 | 400.0 / 398.5 |

The small improvements for the four shared streams came with a single-stream
regression on x86-64. None of the three justified a new default. The bulk tests
used native Linux loopback. Long-distance H2 throughput remains dependent on
path latency and peer windows. [Rust H2 architecture runs and per-flow times](https://github.com/ArcCal/network-relay/actions/runs/44789983008).
[RFC 9113 sections 4.2 and 5.2](https://www.rfc-editor.org/rfc/rfc9113#section-4.2).

### HTTP Date generation

Real wall-clock reads in one and four workers compared uncached formatting,
a cache per thread, an RwLock shared by all workers, and a specialized
uncached IMF-fixdate formatter. Each value is elapsed ns divided by total
calls across the workers. Correctness tests include same-second reuse,
rollover and a backward clock adjustment. All implementations emit the same
header bytes.

| Implementation | x86-64, one / four workers | arm64, one / four workers |
| --- | ---: | ---: |
| Uncached | 369.9 / 123.8 | 458.7 / 116.2 |
| Per thread | 78.5 / 23.1 | 79.1 / 24.2 |
| Shared cache | 77.3 / 154.6 | 82.0 / 132.1 |
| Specialized formatter | 123.6 / 50.3 | 141.6 / 50.2 |

The per-thread cache performed best on the real four-worker workload. An
artificial clock that changes on every call favors the specialized formatter.
[Native time and concurrency controls](https://github.com/ArcCal/network-relay/actions/runs/44789009501).
[RFC 9110 section 6.6.1](https://www.rfc-editor.org/rfc/rfc9110#section-6.6.1).

### Encapsulating UDP datagrams

The Rust client code was compared with a two-buffer implementation, a single
owned buffer, retained per-flow scratch and scatter/gather writes. Four
counterbalanced repetitions checked the wire length, context and payload.
For 1200 bytes, the median pure preparation cost was 83.7, 52.4, 18.8 and
2.1 ns on x86-64, respectively. On arm64 it was 116.7, 67.9, 28.2 and 3.0 ns.
The scatter/gather preparation only builds slices. Complete delivery and
checking over a Unix socket took 990, 924, 871 and 958 ns on x86-64 and
1048, 979, 980 and 985 ns on arm64. Maximum-size vectored writes also
performed worse than a single owned buffer on arm64. The selected code
keeps one owned buffer. Reserving up to 65507 bytes on each participating
flow or assuming that the TLS backend preserves write vectors has no
verified transport-wide benefit. [Preparation and checked socket delivery](https://github.com/ArcCal/network-relay/actions/runs/44789009501).

### CF MASQUE inner TCP over delay

The pinned stack sent 8 MiB in each direction on the CF MASQUE egress
component's inner TCP path. The fixture used two independent IP stacks,
a full-duplex delay line, data hashes, FIN, socket reclamation and queue
counters. The first comparison used the shipping stack, four times its TCP
buffers, Reno instead of CUBIC, or an immediate delayed-ACK timer. All 72
bidirectional trials across the two release architectures passed. Throughput stayed
near 11.1 Mbit/s at 50 ms RTT and 5.7 Mbit/s at 100 ms for all four.
Quadrupling buffers reduced the default 1 GiB admission limit from 682 to
170 sockets. These three alternatives were discarded.
[Stack, congestion control and buffer comparisons](https://github.com/ArcCal/network-relay/actions/runs/44789009501).

The second comparison counted advancing TCP acknowledgments on the wire
and sampled outstanding bytes, sender congestion windows, advertised peer
windows and the queued application data. The original polled up to 256
received packets before socket dispatch. In one 50 ms arm64 trial, 115
of 117 advancing ACKs acknowledged more than twice the 1240-byte MSS. One
advanced 131072 bytes. The median sampled active sender had about 72 KiB
of congestion credit while roughly 200 KiB of peer receive credit remained.
Three separate candidates processed at most two incoming packets per poll,
interleaved socket dispatch with ingestion, or returned a cumulative ACK
from the TCP receive path. Each reached approximately 17.9 Mbit/s at 50 ms
and 9.2 Mbit/s at 100 ms in both directions on both CPUs. The socket change
kept every advancement to at most 2480 bytes. All 72 trials passed the
byte, FIN, reclamation and drop checks. In the instrumented zero-delay
fixture the extra ACK processing reduced throughput. [ACK numbers, windows and CPU measurements](https://github.com/ArcCal/network-relay/actions/runs/44791624077).
[RFC 5681 section 4.2](https://www.rfc-editor.org/rfc/rfc5681#section-4.2).
[RFC 9293 section 3.8.6.3](https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.3).

An independent cost comparison removed the instrumented delay line for the
zero-delay arm. Each direct trial sent 64 MiB per direction, and each delayed
trial sent 8 MiB per direction. Eight crossover rounds at zero delay and three
at each added RTT on each CPU produced 112 verified bidirectional trials.

| Receive strategy | Zero-delay median wall ms, x86-64 / arm64 | 50 ms RTT wall s, x86-64 / arm64 | 100 ms RTT wall s, x86-64 / arm64 |
| --- | ---: | ---: | ---: |
| Original | 123 / 143 | 12.08 / 12.07 | 23.63 / 23.63 |
| Timely ACK per pair | 152 / 159 | 7.49 / 7.49 | 14.65 / 14.64 |
| Batched channel reads and reusable transmit queue | 120 / 136 | 12.07 / 12.07 | 23.63 / 23.62 |
| Timely ACK and batched channel reads | 145 / 154 | 7.50 / 7.49 | 14.66 / 14.65 |

In these fixed-MTU trials the receive path calculated the MSS for the local interface. A regression
test advertises a different peer MSS and requires each pair of full-sized
segments to advance the ACK once. Reads in batches reduced the cost of
delivering ACKs across the in-process channels. At zero added delay a cost
remained on both native CPUs. All 112 trials matched both data hashes,
returned EOF, released both sockets and reported zero stack drops.
[Transfer costs, process CPU and memory](https://github.com/ArcCal/network-relay/actions/runs/44794371888).

The native-kernel comparison connected the production packet stack to a
real TCP socket in a fresh Linux network namespace through a private TUN
device. Linux netem applied the specified delay on one direction of the
link. Four ordered crossover repetitions exercised 64 MiB each way for
one local flow and 8 MiB each way per flow for the other cases. Every
trial verified both peer digests, EOF, application socket reclamation
and the kernel queue counters. The tested kernel versions were 7.0.0 on
x86-64 and 6.8.0 on arm64. Across 160 trials, both endpoints checked a
combined 9 GiB and the qdiscs reported zero drops.

| Native-kernel workload | Original wall s, x86-64 / arm64 | Timely ACK | Batch | Timely ACK and batch |
| --- | ---: | ---: | ---: | ---: |
| One flow, 0 ms | 0.177 / 0.211 | 0.191 / 0.237 | 0.176 / 0.209 | 0.184 / 0.237 |
| Four flows, 0 ms | 0.096 / 0.115 | 0.102 / 0.130 | 0.095 / 0.116 | 0.101 / 0.126 |
| One flow, 50 ms | 5.789 / 5.793 | 5.736 / 5.555 | 5.735 / 5.734 | 5.665 / 5.651 |
| One flow, 100 ms | 11.543 / 11.584 | 11.216 / 10.974 | 11.541 / 11.472 | 11.293 / 11.177 |
| Four flows, 100 ms | 11.744 / 11.628 | 11.446 / 11.358 | 11.549 / 12.576 | 11.528 / 11.186 |

On the arm64 zero-delay single-flow path, receiving from the kernel fell
from 5.02 to 4.03 Gbit/s with timely ACKs. At 100 ms this direction rose
from 15.8 to 18.0 Mbit/s, while transmission to the kernel stayed near
9.3 Mbit/s. The simulated two-stack improvement therefore overstates the
size of the whole-transfer improvement with a Linux peer.
[Linux kernel, TUN, netem and packet accounting](https://github.com/ArcCal/network-relay/actions/runs/44796366644).

Three further implementations tried to recover the zero-delay cost of timely
ACKs and batched reads. They reserved several channel writes at once, used a
wider Internet checksum accumulator, or combined both. The five builds,
including the original and the ACK-plus-batch control, ran six local rounds
and two 50 ms rounds per architecture. All 80 bidirectional transfers passed
their byte, FIN, reclamation and drop checks.

| Zero-delay upload, Mbit/s | Original | Timely ACK and batch | Reserve writes | Wide checksum | Both refinements |
| --- | ---: | ---: | ---: | ---: | ---: |
| x86-64 | 7559 | 6428 | 6567 | 6545 | 6616 |
| arm64 | 7781 | 7597 | 7705 | 7717 | 7704 |

The wider sum improved 1280-byte checksum time on arm64 from 1.12 to
0.76 ms per 26214 calls, but increased it from 0.96 to 1.04 ms on x86-64.
Both architectures took longer for 40-byte headers. In three of the six
x86-64 original trials the reply reader took about a second longer than
its writer. All six original arm64 replies completed without that pause.
No short-path timing was discarded. Neither refinement recovered original
upload throughput on both platforms. The production checksum, ACK scheduling,
channel batching and buffer sizes were retained.
[Packet costs, transfer times and CPU](https://github.com/ArcCal/network-relay/actions/runs/44797939859).
[RFC 1071](https://www.rfc-editor.org/rfc/rfc1071).

Timely ACKs alone and timely ACKs with batching also passed independent
3900-second local WARP soaks on both architectures. Each of the four
traces had 131 samples, six TCP flows, six UDP flows, one outer generation
per transport and zero reported queue drops. The minimum age of every
held flow was 3910 seconds on x86-64 and 3920 seconds on arm64. These
results cover liveness. The low-delay throughput cost remained in the
separate crossover measurements. [Full-duration checks](https://github.com/ArcCal/network-relay/actions/runs/44794371888).

Four further runs paired the selected WARP DNS cache with either ACK
strategy. Their 131-sample traces covered 3916.67-3927.89 measured seconds.
All twelve flows survived on each runner, the independent TCP hash stayed
correct, and both outer transports stayed on generation one with zero reported
packet queue drops. The low-delay cost still excludes the ACK changes from the product.
[Combined cache and ACK soak controls](https://github.com/ArcCal/network-relay/actions/runs/44797267346).

### One-second delay at the end of a WARP TCP response

In the local two-stack tests, a sender sometimes finished queuing its reply
in about 45 ms, but the receiver obtained the last bytes about a second
later. A separate job sampled both sockets' TCP states, send and receive
queues, flight, congestion window, peer window and timers. It ran twelve
64 MiB exchanges per setting on each native CPU. Every reply matched its
digest and ended with EOF.

| Scheduling or lifetime change | Replies taking over 750 ms on x86-64 / arm64 |
| --- | ---: |
| Original | 4/12 / 0/12 |
| Reduce maximum idle poll time from 1 s to 100 ms | 6/12 / 0/12 |
| Poll again after emitting packets | 8/12 / 0/12 |
| Keep the application handle after shutdown until its send queue drains | 6/12 / 0/12 |

All 24 delayed x86-64 samples across the four settings had the same
disagreement. The reader in FIN-WAIT-2 had freed its buffer and advertised
a full window. The sender in LAST-ACK recorded zero peer window, zero bytes
in flight, a running persist timer and 13920-128991 queued bytes. Its probe
eventually resumed transmission. None of these scheduling changes repaired
the missing window update.
[Paired socket and timer traces](https://github.com/ArcCal/network-relay/actions/runs/44801033544).

The socket marks an application close as LAST-ACK even when response bytes
are waiting to be sent ahead of its FIN. A pure ACK at SND.UNA used to be
challenged before its changed window reached normal TCP processing. RFC 9293
section 3.10.4 queues CLOSE in CLOSE-WAIT until earlier sends have been
segmentized. Sections 3.8.6.1 and 3.10.7.4 cover window reopening and
valid incoming ACKs. A deterministic packet test on the old implementation
got a challenge ACK instead of resuming the pending response. Test packets
also cover a smaller window, window scaling, the peer FIN sequence, data
and FIN order, and the final acknowledgment.
[RFC 9293 section 3.10.4](https://www.rfc-editor.org/rfc/rfc9293#section-3.10.4).
[RFC 9293 section 3.8.6.1](https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1).
[RFC 9293 section 3.10.7.4](https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4).

The next comparison used ordinary socket reads and a reader that paused for
80 ms before the last 320 KiB. Three independent alternatives accepted only
a zero-to-open window, accepted a changed window for outstanding unsent data,
or delayed application shutdown until all queued bytes were acknowledged.
Every variant ran twelve times per reader and CPU in rotating order.

| Implementation | Normal replies over 750 ms, x86-64 / arm64 | Paused replies over 750 ms, x86-64 / arm64 | Paused median reply ms, x86-64 / arm64 |
| --- | ---: | ---: | ---: |
| Original | 3/12 / 10/12 | 12/12 / 12/12 | 1060.53 / 1064.78 |
| Accept only reopening from zero | 0/12 / 0/12 | 0/12 / 0/12 | 129.35 / 134.73 |
| Honor changed windows while response data is still unsent | 0/12 / 0/12 | 0/12 / 0/12 | 129.74 / 133.63 |
| Wait before calling shutdown | 0/12 / 0/12 | 0/12 / 0/12 | 134.36 / 140.35 |

The first remedy misses a smaller nonzero window or a retraction to zero.
The application wait adds an acknowledgment dependency to shutdown. The
socket correction applies only to an empty ACK at the current receive
sequence and the current unacknowledged send sequence while previously
unsent data remains. It preserves the existing checks after FIN, peer
credit, congestion control and persist timing. All 192 bidirectional
transfers verified both hashes, EOF and reclamation with zero reported
stack drops. The one-second delay is separate from the two Apple native
Relay observations below.
[Window alternatives and kernel control](https://github.com/ArcCal/network-relay/actions/runs/44804341398).

The first native-kernel control checked 4.5 GiB across 80 bidirectional
transfers. The x86-64 single-flow 50 ms median increased from 5.617 to
5.719 s in four paired rounds. An independent run repeated this workload
twelve times per implementation and also reversed which peer sent FIN first.
The bounded-reader arm set a 64 KiB kernel receive buffer before the handshake
and paused 200 ms before the final 160 KiB. The table shows median wall time
for the complete exchange, including this pause where present.

| Kernel peer and condition | x86-64 original / corrected, s | arm64 original / corrected, s |
| --- | ---: | ---: |
| Userspace sends first at 50 ms RTT, independent repeat | 5.728 / 5.570 | 5.757 / 5.736 |
| Kernel sends first, ordinary reader at 0 ms | 0.197 / 0.196 | 0.205 / 0.206 |
| Kernel sends first, ordinary reader at 50 ms | 5.570 / 5.520 | 5.501 / 5.472 |
| Kernel sends first, paused reader at 0 ms | 1.248 / 0.405 | 1.249 / 0.408 |
| Kernel sends first, paused reader at 50 ms | 9.143 / 8.577 | 9.602 / 8.659 |

With a paused local kernel reader, all 24 original trials spent more than
30 consecutive samples in LAST-ACK persist, and zero corrected trials did.
At 50 ms the corresponding counts were 15/24 and 0/24. Each sample interval
was about 10 ms. All 240 repeated trials checked both payloads, EOF and
socket cleanup across 14.25 GiB, with zero stack or qdisc drops. The initial
50 ms slowdown did not repeat. Revision `d5bd2b7` retains the packet-level
correction. [Independent repeat and reverse half-close](https://github.com/ArcCal/network-relay/actions/runs/44806641227).

Both final native Linux runs also passed the 487-test vendored stack suite,
the complete CF MASQUE test entry point, the standalone example and strict
lint. The final 3900-second soaks matched all 188 frozen source hashes to
the integrated product. The x86-64 / arm64 traces measured 3918.87 / 3928.85
seconds, with minimum held-flow ages of 3910 / 3920 s, at least 393 / 394
pings per flow, a single outer generation per transport and zero reported
queue drops. [Standard egress and relay suites](https://github.com/ArcCal/network-relay/actions/runs/44807767481).
[Verified long-lived flows](https://github.com/ArcCal/network-relay/actions/runs/44804341398).

### Historical WARP connection interruptions

One earlier local-peer soak timed out on H3 after about ten minutes. Another
reset after 3842.91 seconds. Their causes are still open.
[Original timeout](https://github.com/ArcCal/network-relay/pull/31) and
[reset evidence](historical-issue-recheck-2026-11-13.md#h03-cf-soak-reset-after-384291-seconds). Eight real-time runs compared the normal local test peer
with three single-variable changes. Each run kept six TCP flows and six UDP
flows open through H1/H2/H3 frontends and H2/H3 egresses while independent
transfers continued. The baseline outer keepalive was one second and the
application heartbeat was ten seconds.

| Setting | Measured seconds, x86-64 / arm64 | Minimum age of the twelve held flows, s | Fewest successful pings per flow |
| --- | ---: | ---: | ---: |
| Reference | 3916.84 / 3928.31 | 3910 / 3920 | 393 / 394 |
| Deployment outer keepalive of 15 s | 3916.74 / 3928.11 | 3910 / 3920 | 393 / 394 |
| Application heartbeat every 3 s | 3916.93 / 3926.91 | 3915 / 3924 | 1307 / 1310 |
| Reno for inner TCP | 3916.24 / 3927.80 | 3910 / 3920 | 393 / 394 |

Each independently verified trace contained 131 samples, one outer connection
generation per transport, zero reported packet queue drops and the expected
TCP digest at every sample. Each process used at most 43 file descriptors.
The first two 15-second jobs had also changed a separate three-second idle
fixture and failed its finite check before the long test. Scoping that
setting to the long test restored the independent idle control. All four
settings survived beyond the historical interruptions with the local peer.
The failures did not recur in these local runs. The timeouts and congestion
control remain at their production settings. Public Cloudflare service still
requires independent validation.
[All four settings and original failed controls](https://github.com/ArcCal/network-relay/actions/runs/44790798330).
[Correctly scoped 15-second keepalive](https://github.com/ArcCal/network-relay/actions/runs/44791712698).

## Client and interoperability results

### Native NF and TUN UI log retention

At the 5000-line limit, adding a single important record reclassified every
older important line. The code built the full formatted message each time
and immediately discarded it. On macOS 15 and 27, three candidates measured
classification from the level tokens, in-place array removal, and indexed
priority eviction with an ordered snapshot. The indexed structure was fastest
when every record was important. With predominantly verbose records it cost
several times more to materialize the snapshot. In-place removal still
formatted the full messages.

The chosen implementation scans at most the first four words until it finds
a recognized level, checks that a message follows, and uses the same
classification for display. Below capacity the history still appends directly.
Six alternating release-optimized repetitions measured 32 individual updates
to a full important-only history.

| Client and native runner | Before, ms | After, ms | Mixed history, 32 updates of 16 lines, before / after ms |
| --- | ---: | ---: | ---: |
| NF macOS 15 | 518.5 | 134.9 | 17.9 / 7.2 |
| TUN macOS 15 | 504.9 | 131.0 | 17.1 / 6.6 |
| NF macOS 27 | 423.1 | 139.7 | 12.4 / 6.0 |
| TUN macOS 27 | 340.2 | 99.7 | 16.3 / 5.5 |

Under capacity, the single-record updates took 0.005-0.006 ms for both
implementations. Nine thousand generated lines in both native models
matched the previous visibility and retention behavior, including Unicode,
unclassified lines and levels without a message. The macOS 27 job compiled the exact log models and tested them directly. Its TUN package used that checkout and passed 74 Swift tests. The NF packaging entry point fetched main and passed 71 Swift tests there. The exact NF revision then passed 72 Swift tests. Its signed application launched with the expected revision in its bundle and executable SHA-256 starting with `5195f481ed26`.
[Three implementation controls](https://github.com/ArcCal/network-relay/actions/runs/44792234924).
[Exact model comparison and initial package run](https://github.com/ArcCal/network-relay/actions/runs/44792999314).
[Pinned application build and executable checks](https://github.com/ArcCal/network-relay/actions/runs/44798152669).

### Native RS log timer

The AppKit controller polls every 150 ms. Each tick copied up to 5000
retained strings, reapplied the severity filter and rebuilt the display,
including ticks with no log changes. The comparison ran 120 ticks per
history on both Linux and macOS, checked the visible text and counts
at every visible tick, and used four counterbalanced repetitions. Three
alternatives borrowed the entries, delayed rendering until visible, or
remembered the last retained sequence and the selected filter.

| macOS 27 log history | Original ms | Borrow entries ms | Render while visible ms | Check sequence and filter ms |
| --- | ---: | ---: | ---: | ---: |
| Visible, no new records | 42.8 | 26.4 | 43.4 | 0.3 |
| Visible, a new record at every tick | 43.7 | 25.0 | 46.0 | 45.9 |
| Filter changed every eight ticks | 41.1 | 28.9 | 46.5 | 6.3 |
| Hidden until the last tick | 45.8 | 29.7 | 0.4 | 0.3 |
| Erase followed by one new message | 27.8 | 16.0 | 26.3 | 0.6 |

These figures time the Rust projection of the log window, excluding AppKit
painting. A rejected trace record leaves the retained sequence unchanged.
Switching the filter or erasing a populated history must invalidate it.
[Individual alternatives](https://github.com/ArcCal/network-relay/actions/runs/44796905916).

Combining the retained-sequence check with borrowing also reduced the
cost when the history changed at every tick. On macOS the four-round
medians for the original and combined projections, in ms per 120 ticks,
were 39.48 and 0.21 when idle, 42.25 and 29.29 when active, 41.68 and
3.60 while changing filters, 42.01 and 0.22 while hidden, and 21.89
and 0.23 during erase. The visible text and counts matched after every
visible tick, including re-opening the view. The macOS application crate
passed 31 library and 23 integration tests in its normal test entry point.
The Linux control also reduced the original idle / continuously changing
medians from 36.57 / 37.39 ms to 0.14 / 18.90 ms. The signed macOS
package built from the measured RS source and launched with executable
SHA-256 beginning `bc7c4af83e4a`.
[Combined projection and exact package validation](https://github.com/ArcCal/network-relay/actions/runs/44798152669).

### Product connection reuse and application concurrency

The release transport paths of NF, RS and TUN on macOS 27 used each Linux
arm64 relay over H2 and H3. A client on each SOCKS port downloaded four 1 MiB
files in sequence over fresh origin TLS connections, reused one authenticated
inner TLS connection, or scheduled two or four independent TLS connections.
Two rounds used opposite order per path. All 384 bulk responses matched their
SHA-256 and every group reached the Linux origin. All 12 additional short TCP
controls passed. NF, RS and TUN each rejected an unrelated relay root and the
origin counted no traffic during those three checks. The system certificate list
matched before and after. TUN used its transport entry point here. Its separate
packet, route and administrator-helper results are in the main audit.

The following times are seconds for four bodies.

| Linux relay | macOS client | Transport | Four fresh TLS | One reused TLS | Two concurrent | Four concurrent |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Rust | NF | H2 | 1.181 | 0.584 | 0.801 | 0.643 |
| Rust | NF | H3 | 1.994 | 1.732 | 1.996 | 2.182 |
| Rust | RS | H2 | 1.138 | 0.538 | 0.789 | 0.684 |
| Rust | RS | H3 | 2.354 | 1.737 | 1.722 | 1.536 |
| Rust | TUN | H2 | 1.098 | 0.460 | 0.770 | 0.605 |
| Rust | TUN | H3 | 2.777 | 1.986 | 3.159 | 1.853 |
| Caddy | NF | H2 | 1.431 | 0.747 | 0.939 | 0.821 |
| Caddy | NF | H3 | 3.273 | 3.342 | 3.233 | 3.164 |
| Caddy | RS | H2 | 1.323 | 0.579 | 0.949 | 0.798 |
| Caddy | RS | H3 | 3.147 | 2.771 | 2.825 | 2.722 |
| Caddy | TUN | H2 | 1.455 | 0.956 | 0.875 | 0.835 |
| Caddy | TUN | H3 | 3.550 | 2.570 | 2.787 | 2.711 |

Origin connection reuse reduced time on every H2 path. Parallelism had
workload-dependent results on H3. Origin connections belong to the initiating
application and traffic is encrypted end to end. These results do not justify
a proxy-side concurrency cap or terminating origin TLS in the relay.
[All 12 product/back-end/transport combinations](https://github.com/ArcCal/caddy-network-relay/actions/runs/44789550337).

The production client sources at `d5bd2b7` subsequently ran on macOS 27
against both Linux architectures. Each guest reported the SHA-256 of the
actual Rust and Caddy ELFs, independently matched to their native builds.
Across the 24 combinations, all 768 one-MiB bodies matched the expected hash,
all 24 short TLS requests succeeded, and the origins received 96 expected
UDP datagrams. Six wrong-root controls failed before reaching an origin.
Both hosts restored their certificate state. Reusing the origin TLS connection
cut median H2 time on every product/backend path. The ratios of fresh to reused
time were 1.33-1.80 on the translated Linux x86-64 guest and 1.76-2.42 on
the translated arm64 guest. These ratios compare connection strategies
within each guest.
[Final clients, Linux binary identities and transfer records](https://github.com/ArcCal/caddy-network-relay/actions/runs/44805060120).

### Actual Apple conditions and outstanding tests

With per-request path checks, 60/60 proxied 64 MiB requests reached the intended Linux origin across macOS and both iOS simulator orders. H2 returned all 48 hashes. Caddy H3 returned eight of twelve, all after 180 seconds. The other four still advanced to 217.88 MiB combined at the 360-second cutoff. Both iOS orders also had one direct TLS failure before the origin. [Per-body route and hashes](https://github.com/ArcCal/caddy-network-relay/actions/runs/44794629320).

The detailed native audit records exact directional UDP sizes, packet-level QUIC credit and acknowledged
offsets, final binary identities, cold path-MTU behavior and the matched native
Linux versus emulated Linux throughput comparisons. This audit used runners.
Physical iPhone MDM profiles, Wi-Fi to cellular handover and the operator's
actual WAN, NIC and WARP service have no measurement in this environment.
[Apple native matrix and traffic traces](audit-2026-11-20.md#apple-native-per-session-matrix).
