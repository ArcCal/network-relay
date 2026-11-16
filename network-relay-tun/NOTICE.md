# Source notices

The protocol core and Swift application/model/bridge/tests/icon are independent
copies of Network Relay NF at 55ef9aa1a9eb2666be84a24567b81ef7513ea742, renamed for
this product. Existing legal notices and vendored licenses remain applicable.
This document does not grant a new license for ArcCal code.

Host/src/network.rs is adapted from ArcCal/masque-vpn revision
eba1198996be0974a0a6d84a555a0522a3b0a827; see Host/NOTICE.md.

TunEngine/vendor/tun2proxy is copied from revision
a8cb332a2116adf3b962960c19fb0f2d4d7cb770 under its retained MIT LICENSE.
TunEngine/vendor/ipstack is copied from revision
295a85e96dd9f7c6927b54db3520f8f1a3bc5c7a under its retained Apache-2.0 LICENSE.
Local modifications are described in each vendor directory's TUN-PATCHES.md.

Leaf and netstack-smoltcp were evaluated as references; neither is a production
dependency of this implementation. No sibling source checkout is required to
build this product.
