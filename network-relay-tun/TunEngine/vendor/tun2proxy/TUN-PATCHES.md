# Network Relay Tun integration changes

Upstream: https://github.com/tun2proxy/tun2proxy
Revision: a8cb332a2116adf3b962960c19fb0f2d4d7cb770
License: MIT, retained in LICENSE.

The adapter depends on the locally vendored ipstack. Its selected SOCKS UDP
handler uses datagram methods that distinguish empty data from EOF, 65536-byte
buffers, and complete datagram writes. It rejects fragmented SOCKS responses and
responses claiming another target. With IPv6 enabled, DNS wire bytes pass through
without parsing or reserialization. This preserves the existing relay protocol.
System setup and virtual DNS are disabled by the independent wrapper.

Portable packet tests cover IPv4/IPv6, empty and large datagrams, fragmentation,
DNS-port forwarding and TCP half-close. Native macOS acceptance remains separate.
