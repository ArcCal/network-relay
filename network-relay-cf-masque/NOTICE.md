# Source and license provenance

The relay, its configuration and its helper commands are ArcCal/network-relay
itself, the parent directory of this project, used as a Cargo path dependency
(MIT OR Apache-2.0), as is network-relay's vendored hyperium/h3 (MIT, with
its local patch record in `../vendor/h3/PATCH.md`). The WARP transport,
userspace stack and resolver reuse ArcCal/cf-masque at
`a65c600494cd50fed2c621b8538be7abda5e7fa4` under MIT; its original license is
retained in `crates/warp-egress/LICENSE` and `LICENSE-MIT`.

Research reports cite usque, usque-rs, Xray-core, sing-box and mihomo. GPL
reference implementation source is not included in this production project.
Research snapshots, generated artifacts and private runtime registrations are
ignored, are not part of the distributed source, and retain their own licenses.
