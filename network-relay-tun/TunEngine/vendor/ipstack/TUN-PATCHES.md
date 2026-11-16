# Network Relay Tun stack changes

Upstream: https://github.com/narrowlink/ipstack
Revision: 295a85e96dd9f7c6927b54db3520f8f1a3bc5c7a
License: Apache-2.0, retained in LICENSE.

Local changes add datagram-oriented UDP methods, remove UDP reply truncation,
validate transport checksums, bound packet queues and session admission, discard
unsupported IP protocols, and add bounded overlap-rejecting fragment reassembly.
TCP peer FIN now closes only the upload half: pending data drains before EOF,
upstream replies can continue, and local shutdown controls the final FIN.
Final-ACK validation, FIN retransmission sequence and shutdown wakeups are adjusted
for that lifecycle. Input buffers accommodate complete IP datagrams.

The retained upstream regression tests and independent packet-level tests run
from TunEngine's workspace. Oversized native utun delivery, PMTU behavior and
physical macOS lifecycle tests remain required.
