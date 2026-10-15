# Source and license provenance

The relay frontend and CLI reuse ArcCal/network-relay at
`cc7ea4df2924d0454ab5075e089cbb53d94b178e`, whose Cargo manifest declares
MIT OR Apache-2.0. The WARP transport, userspace stack and resolver reuse
ArcCal/cf-masque at `a65c600494cd50fed2c621b8538be7abda5e7fa4` under MIT;
its original license is retained in `crates/warp-egress/LICENSE` and
`LICENSE-MIT`. The HTTP/3 components retain their upstream MIT license files
and documented local patch provenance. See `docs/evidence/reuse-baseline.json`
and `docs/H3-PATCH-PROVENANCE.md` for exact input and resulting source identity.

Research reports cite usque, usque-rs, Xray-core, sing-box and mihomo. GPL
reference implementation source is not included in this production project.
Research snapshots, generated artifacts and private runtime registrations are
ignored, are not part of the distributed source, and retain their own licenses.
