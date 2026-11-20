# Implementation review

## Source selection and protocol boundary

Reviewed sources:

| Source | Revision | Role |
| --- | --- | --- |
| Network Relay NF | 55ef9aa1a9eb2666be84a24567b81ef7513ea742 | Independent GUI, settings/model tests, native TLS/QUIC bridge and CONNECT/CONNECT-UDP core |
| Masque VPN Mac | eba1198996be0974a0a6d84a555a0522a3b0a827 | Reference route ownership, temporary DNS and durable recovery |
| Leaf | 5e8d94759ce983eb8ac226c315024b55ff2bb7b0 | TUN/stream separation and stack evaluation |
| netstack-smoltcp | 25e6ad4019dc74119f68a106e3eb5625b0a8c8d4 | Evaluated prototype, not a production dependency |
| tun2proxy | a8cb332a2116adf3b962960c19fb0f2d4d7cb770 | Selected TUN-to-SOCKS adapter |
| ipstack | 295a85e96dd9f7c6927b54db3520f8f1a3bc5c7a | Selected TCP/UDP userspace stack |

Masque VPN uses CONNECT-IP, which cannot substitute for CONNECT/CONNECT-UDP on
existing Network Relay servers. Its host configuration approach is reusable;
its transport and IPv6-disable policy are not selected. Leaf's broad routing and
outbound plugin system is unnecessary for this product. A direct smoltcp prototype
was evaluated; the selected standalone adapter instead keeps NF's native relay
implementation intact behind SOCKS. There is no server modification.

## Runtime and privilege separation

The Swift application owns configuration, secrets, native TLS/QUIC, SOCKS and the
connection lifecycle. Core is an independent copy with its own Cargo workspace,
lockfile and library name. The inherited internal `nf_*` ABI is local to the
bundle; it does not load or depend on the NF product.

The GUI launches an unprivileged bundled control bridge. The bridge authenticates
the root daemon with getpeereid. The daemon authenticates the installed user,
validates bounded JSON requests and generates random session leases. Request
fields cannot name commands, files, executables, account IDs or passwords.

The daemon prepares endpoint bypass and utun before starting an installed,
root-owned packet worker. Only descriptor 3, MTU and the local SOCKS port cross
that boundary. The worker clears supplementary groups and runs as the installing
user. It cannot configure routes. Parent-pipe EOF cancels its lifetime.

Before preparation the GUI checks both installed executables and the running
helper's control revision. An IPv6 relay uses the kernel-selected physical
interface for the outer connection. After native admission the GUI activates
capture and transient DNS. During refresh the helper compares both families'
split routes and its own DNS dictionary with the installed state. Stop, failed
activation, failed path refresh, control EOF and
helper restart attempt owned-state cleanup. A failed cleanup preserves its
journal and RecoveryRequired state. Quit awaits restoration. Journal boot UUIDs
prevent a previous boot's ephemeral state from deleting a reused interface's
current routes. Kernel interface indices additionally guard against interface
name reuse within the same boot. The helper never invokes inherited IPv6-disable
operations.

## Reproduced and corrected defects

- 8192-byte UDP uploads were truncated to 4096 bytes in the selected SOCKS
  adapter. Both adapter buffers now accommodate full datagrams and headers.
- Empty UDP datagrams were confused with stream EOF. Datagram-specific receive
  and send methods retain zero-length payloads and preserve entire replies.
- SOCKS replies must claim the expected target and use FRAG=0 before injection.
- Normal DNS forwarding no longer reparses/reserializes responses when IPv6 is
  enabled; the transport preserves opaque DNS wire bytes.
- The userspace TCP stack sent FIN immediately after peer FIN whenever its
  current send queue was empty. This discarded responses produced after upload
  half-close. It now retains the download half until upstream shutdown, drains
  pending upload data before EOF, handles data plus FIN, wakes shutdown after
  final data ACKs, and validates/retransmits the final FIN acknowledgment.
- Packet queues were unbounded. They now cap queued packets; admission limits
  prevent pending accept work from creating unlimited sessions.
- Bounded IPv4/IPv6 fragment reassembly rejects overlaps and expires incomplete
  contexts. Completed identifiers are removed independently.
- TCP/UDP checksums are checked before transport dispatch. IPv4's optional UDP
  checksum is permitted; a zero IPv6 UDP checksum is rejected.
- Unit-variant JSON decoding accepted unknown keys despite a Serde attribute.
  Explicit request-key validation closes that schema gap.
- GUI stop now queries actual helper state and retries recovery, rather than
  declaring success based only on a cached lease that may have disappeared.

Tests cover these changes, but do not establish native macOS packet delivery,
physical network switching, GUI build success or production performance.
