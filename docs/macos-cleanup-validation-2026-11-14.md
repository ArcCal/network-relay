# Mac build completion cleanup

The normal final cleanup step used direct `rm -rf`, although downloaded Go
module-cache directories can be read-only. Earlier failure and exit paths
already made owned temporary directories writable before deletion. As a result,
a run could finish all builds, export artifacts and verify checksums, then
report one failed step solely because normal cleanup could not remove its cache.

The production change is one line: reuse `relay_remove_build_work` for the
validated private workspace. The existing helper checks directory ownership,
does not follow symbolic links and grants owner write permission to directories
before removal. Compiler behavior, server source, artifact checks and failure
reporting are unchanged. This implements the documented design that temporary
sources and caches are removed while artifacts, logs and existing installations
remain intact.

A regression exercises the actual all-target orchestrator with real local Git
repositories and simulated compiler/signing tools. Before the fix, all build,
manifest and checksum steps pass, followed by a permission error in cleanup
and a nonzero final status. After the fix, completion succeeds, nested read-only
cache directories disappear, artifact bytes and checksums remain intact, and
an external read-only directory reached by a symlink retains its data and modes.
The existing Linux-build failure control still fails and preserves completed
Mac products. This is orchestration coverage, not a native macOS compilation
or signature-validation claim.

All 91 build-tool tests pass, including the 10 focused Mac orchestration tests.
All seven standalone
installer packaging tests pass without regenerating or changing the packages.
The original user log does not include the requested artifact listing, so it
cannot alone establish that every artifact in that particular run completed.
The added Rust compiler excerpt ends successfully; its linker deprecation
warning is not a compiler error. Existing `MANIFEST.txt`, `SHA256SUMS` and
`logs/cleanup.log`, together with successful checksum verification, can identify
a completed build whose final cleanup alone failed.

Evidence is retained in the audit workspace under `mac-final-cleanup-20261114`.
Native macOS CI was previously blocked before scheduling by GitHub account
payment/spending limits; no new native execution is claimed here.
