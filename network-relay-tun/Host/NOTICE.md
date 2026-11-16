# Host network management source

network.rs is adapted from ArcCal/masque-vpn, masque-vpn-mac/src/network.rs,
revision eba1198996be0974a0a6d84a555a0522a3b0a827. This does not grant a new license
for ArcCal code. Product-specific state uses NetworkRelayTun.

Local additions implement request validation, peer-authenticated IPC, leases,
rollback, IPv6 capture routes, boot-aware journals, the concrete macOS backend,
daemon and unprivileged control bridge. Failed restoration remains durable.
Inherited IPv6-disable functions remain reference code and are not invoked by
the selected backend. Actual privileged installation and native networking have
not been executed in the development environment.
