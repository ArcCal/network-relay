# Source and dependency notices

The application behavior and shared icon were adapted from ArcCal's Network
Realy NF at the revision recorded in SOURCE-PROVENANCE.json. Its Rust protocol
core, protocol parsers and vendored hyperium/h3 implementation were independently
copied into this application. UI behavior was reimplemented in Rust; no Swift
or Network.framework adapter is a build dependency.

The copy does not grant a new license for ArcCal-owned application code or icon.
Third-party components retain their original licenses. The vendored h3
implementation retains its upstream license in `Core/vendor/h3/LICENSE`; its
inherited local patches are documented in `Core/vendor/h3/PATCH.md`.

Cargo.lock records external dependency versions. Tokio, rustls, Quinn, hyper,
h2 and the other Rust dependencies retain their applicable licenses. Apple
AppKit and Foundation are system frameworks, used through the Objective-C ABI
from Rust. Native certificate-store access supplies trust roots only; rustls
performs TLS validation and protocol processing.

No parent-server files or sibling-application libraries are required to build
this application. Test harnesses consume explicitly supplied server binaries
and do not patch those servers.
