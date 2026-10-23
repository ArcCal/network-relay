# Agent instructions for network-relay

## Project context

- The root application is an Apple Network Relay server: classic CONNECT for
  TCP and CONNECT-UDP for UDP over H1/H2/H3. It is not a CONNECT-IP/TUN VPN.
- Start with `docs/USER_GUIDE.md`, `src/main.rs`, `src/config.rs` and
  `deploy/relay.example.toml`. Preserve authentication, destination protections,
  bounded resource ownership and TCP/UDP payload semantics.
- `network-relay-nf`, `network-relay-rs` and `network-relay-cf-masque` are separate
  applications. NF uses Network.framework; RS uses Rust transports; the
  experimental CF server requires WARP egress without a direct fallback.
- Standalone installer scripts contain generated payloads. Follow
  `deploy/package-installer.py` and associated checksum procedures when changing
  their inputs; do not hand-edit embedded payloads.
- Distinguish local protocol tests, emulated NF bridges, native Apple observations
  and live WARP evidence. Do not turn incomplete acceptance into a readiness claim.

## Repository-wide contribution rules

The following six rules apply to this repository and all its subdirectories.

### 1. Anonymity and English

- Maintain complete anonymity in contributions and change metadata.
- Use exactly `Anonymous <anonymous@example.invalid>` as both the raw Git
  author and committer of every new commit, and as the tagger of annotated tags.
  Keep commits and tags unsigned. Do not add personal attribution, identity
  trailers, agent session identifiers or personal account details. Preserve
  required legal attribution.
- Keep repository text and change metadata in English. Do not introduce Chinese,
  Korean or Russian content, Han, Hangul or Cyrillic characters, or dedicated
  CJK/fullwidth punctuation. Use ASCII punctuation for new prose. Preserve
  protocol data, existing test semantics and required legal notices.

### 2. Read before editing and preserve design objectives

Before making any change, read the project's design objectives, commit history,
change history and entire codebase. No change may violate the design objectives
unless the user explicitly requests changing those objectives.

### 3. Minimal necessary changes

- Every change must be minimal and necessary for the requested task.
- Do not perform large refactors unless the user explicitly requests them.

### 4. Server requirements

All MASQUE-related servers must have no violations of applicable IETF
specifications, no known performance or security issues, and no regressions.

All network-relay-related servers must have no violations of applicable IETF
specifications and Apple's specifications, no known performance or security
issues, and no regressions.

### 5. Client requirements

Clients are not required to strictly follow IETF or Apple specifications, but
must remain fully compatible and interoperable with their corresponding
servers, with no serious performance or security issues and no regressions.

### 6. Test before committing

- No change may introduce new problems or regressions.
- Test changes before committing. Commit only after the tests appropriate to
  the change pass and no new issues are found.
- Failed, skipped, unavailable or interrupted tests do not count as passes.
  Do not commit changes whose required validation is incomplete.
