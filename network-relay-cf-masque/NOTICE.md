# Source and license provenance

The relay, its configuration and its helper commands are ArcCal/network-relay
itself, the parent directory of this project, used as a Cargo path dependency
(MIT OR Apache-2.0), as is network-relay's vendored hyperium/h3 (MIT, with
its local patch record in `../vendor/h3/PATCH.md`). The WARP transport,
userspace stack and resolver reuse ArcCal/cf-masque at
`a65c600494cd50fed2c621b8538be7abda5e7fa4` under MIT; its original license is
retained in `crates/warp-egress/LICENSE` and `LICENSE-MIT`.

The TCP/IP dependency is vendored from smoltcp revision
`336a1dd1aaf0eeb1afab5e3b4b479e818a23c03e` under 0BSD, with its original
[license](vendor/smoltcp/LICENSE-0BSD.txt) and source retained. Its
[provenance record](vendor/smoltcp/UPSTREAM.json) hashes every upstream file;
[the local TCP patch](vendor/smoltcp/effective-smss.patch) records the
sender-MSS, startup-window and acknowledgement/retransmission corrections.
A separate packaging-only ignore adjustment preserves all ten upstream
parser seeds for normal source export.
`python3 scripts/verify-smoltcp.py --test` verifies that record, reverses and
reapplies the patch in a disposable copy, and runs upstream unit regressions
with the production dependency's exact feature selection. Generated test
locks remain outside the product source.

Research reports cite usque, usque-rs, Xray-core, sing-box and mihomo. GPL
reference implementation source is not included in this production project.
Research snapshots, generated artifacts and private runtime registrations are
ignored, are not part of the distributed source, and retain their own licenses.
