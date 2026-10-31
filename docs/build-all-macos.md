# Fresh builds of all VPN applications on Apple silicon

Run [tools/build-all-macos.sh](../tools/build-all-macos.sh) on the Mac.
It downloads fresh source and cross-compiles the Linux software; no Linux
VM, Docker, existing checkout, enrollment, server password, or VPN settings
are needed. Mac mini M6 uses the same `arm64` target as other Apple silicon.
Existing source/build directories and installed applications are not replaced.
When the script ends, every folder in the new build directory is mode 777.

## First run

The complete current application set requires **macOS 27 and a macOS 27+
SDK**, plus XCTest for the original app tests. The script checks these tools
and installs/updates **Xcode from the Mac App Store** if they are missing.
NF documents full Xcode as its supported build environment.
The script selects `/Applications/Xcode.app/Contents/Developer` for its own
process when available, without changing the machine's global selection.
The current IETF Masque recipe requires host major version exactly 27; NF
allows 27 or newer. These requirements come from the existing app recipes.

Download the script using a browser signed into GitHub, save it as
`build-all-macos.sh` in Downloads, then run:

```bash
bash "$HOME/Downloads/build-all-macos.sh"
```

These five repositories are private. The script installs Homebrew if absent,
installs missing Go/Zig/GitHub CLI packages, installs/updates Rust stable,
installs `cargo-zigbuild`, and adds the three required Rust targets. It checks
Rust is at least 1.99, as required by the experimental CF servers. Homebrew
may request the Mac administrator password. When necessary, GitHub CLI opens
its normal browser sign-in flow; use an account with access to all five repos.
No GitHub token is embedded in a URL, script or build report.

If SDK 27+ or XCTest is missing, the script bootstraps Homebrew and Apple's
Command Line Tools, installs the `mas` App Store client, and runs
`mas get --force 497799835` to obtain/update Apple's Xcode. It then completes
Xcode first-run components and checks the SDK and XCTest again. Existing
developer tools that already satisfy these checks are reused.

Apple may require an App Store sign-in, license acceptance, or administrator
authentication. If the command cannot finish automatically, the script opens
Xcode's App Store page and asks you to press Return after its installation
and setup finish; compilation then continues in the same Terminal. In a
noninteractive shell it stops with instructions instead of claiming success.
No Apple password is stored by the script. It does not change macOS itself
or download SDK archives from third-party sites.

Apple documents that [Command Line Tools](https://developer.apple.com/documentation/xcode/installing-the-command-line-tools)
include the macOS SDK, but the existing app tests also require the XCTest
runner. Installing the complete Xcode app supplies both. The App Store
installation command follows [mas's documented free-app workflow](https://github.com/mas-cli/mas#commands).

Alternatively, with Homebrew and GitHub CLI already installed:

```bash
gh auth login --hostname github.com --git-protocol https --web
gh api -H 'Accept: application/vnd.github.raw+json' \
  'repos/ArcCal/network-relay/contents/tools/build-all-macos.sh?ref=main' \
  > "$HOME/Downloads/build-all-macos.sh"
bash "$HOME/Downloads/build-all-macos.sh"
```

Use the branch/commit containing this script instead of `main` while its PR
is unmerged. For a completely fresh source build every time, run the same
command again: each invocation creates a new directory. Downloaded compiler
and dependency caches may be reused; existing source folders are never used.
Several Rust workspaces and app tests can consume substantial disk space;
allow approximately 80 GiB free, with actual usage depending on tool versions.

## Products and architectures

All application source comes from each repository's `main` at clone time.
The exact five commit IDs are saved in `SOURCE-REVISIONS.tsv`.

| Software | Linux x64 | Linux arm64 | macOS arm64 |
| --- | --- | --- | --- |
| Caddy Masque server | Yes | Yes | — |
| Caddy Network Relay server | Yes | Yes | — |
| Rust `masque-server` | Yes | Yes | — |
| Rust `network-relay` server | Yes | Yes | — |
| `masque-vpn-cf-masque` server | Yes | Yes | — |
| `network-relay-cf-masque` server | Yes | Yes | — |
| `masque-client` command-line client | Yes | — | Yes |
| `cf-masque` command-line client | Yes | — | Yes |
| `masque-passwd` utility | Yes | Yes | Yes |
| `masque-cf-passwd` utility | Yes | Yes | Yes |
| IETF Masque.app | — | — | Yes |
| Masque NF.app | — | — | Yes |
| Masque VPN Mac.app | — | — | Yes |
| Masque VPN Killswitch.app | — | — | Yes |
| Network Relay NF.app | — | — | Yes |
| Network Relay RS.app | — | — | Yes |
| Cloudflare Masque.app | — | — | Yes |

The two password helpers are additionally built natively so passwords can
be generated on the Mac. App-specific routing/daemon helpers are packaged
by their app's original recipe; they are not portable Linux clients. Libraries,
examples, test fixtures and the retired Masque Swift app are not application
deliverables. `network-relay` has integrated `check/profile/passwd` commands,
and those remain included in its Linux server binaries.

## Outputs

The default build root looks like:

```text
~/Projects/vpn-build-YYYYMMDD-HHMMSS-XXXXXX/
  sources/                         five fresh, complete working trees
  logs/                            one log per job
  SOURCE-REVISIONS.tsv              exact source commits
  TOOL-VERSIONS.txt                 compiler/SDK versions
  BUILD-RESULTS.tsv                 per-job PASS/FAIL and log paths
  out/
    linux-amd64/                   six servers, two clients, two helpers
    linux-arm64/                   six servers, two helpers
    macos-arm64/
      bin/                         two clients, two helpers
      apps/                        seven .app bundles and their .app.zip files
    SOURCE-REVISIONS.tsv
    BUILD-RESULTS.tsv
    SHA256SUMS
```

The two Caddy executables are named `caddy-masque` and `caddy-network-relay`
to prevent collisions. Either can be renamed `caddy` when deploying it to
its intended VPS. The other binaries retain their own program names.
The script prints the exact output location and opens it in Finder after
all jobs pass. App bundles use the original recipes' ad-hoc signing and are
not notarized releases.
When the script ends, successfully or not, every folder in the build
directory, including sources and `out/`, is mode 777 so other users and file
synchronization tools such as Syncthing can use it.
The build directory is printed before compiler-version checks; their output
is displayed in Terminal and saved in `TOOL-VERSIONS.txt`, including errors.

Check the collected files without relying on a shell variable from an old
Terminal tab:

```bash
cd "$HOME/Projects/vpn-build-REPLACE-WITH-THE-PRINTED-DIRECTORY/out"
shasum -a 256 -c SHA256SUMS
```

## Build behavior and failure reporting

- All six servers are cross-compiled for Debian 13's `amd64` and `arm64`.
  Rust Linux targets use static musl and Zig; Go uses `CGO_ENABLED=0`.
  File headers must match the requested architecture and static linking.
- Native Mac executables must be arm64 Mach-O. GUI builds invoke the existing
  project scripts, including their tests, helper packaging and signatures.
  Inherited Cargo target/compiler/SDK/Go flags are cleared to avoid stale
  settings breaking cross-compilation or app packaging. GUI scripts keep
  the target directories they expect.
- Caddy is built from the full respective checkout using `./cmd/caddy`.
  This preserves its vendored HTTP/3 and HTTP/2 patches. Caddy Network Relay
  uses `http2legacy`; Caddy Masque's production build does not need that tag.
  A declared Go `toolchain` is honored; otherwise Go uses automatic toolchain
  selection. The standard Caddy commands do not add an optional Cloudflare
  DNS-provider plugin. Existing Certbot-issued certificates remain usable.
- Git clones use shallow history, complete source trees, HTTP/1.1, and up to
  three attempts. Retry cleanup removes only that job's newly created staging
  directory. HTTPS authentication is configured per command, without editing
  global Git configuration.
- A failed job does not prevent unrelated products from building. The final
  output audit requires the entire requested product set; **any failure
  produces a nonzero exit status and an INCOMPLETE summary**. Successful
  artifacts and logs remain available. There is no fallback to an older
  binary or different architecture.
- Compilation/header/signature checks do not establish VPN interoperability.
  Linux binaries cannot execute on the Mac; deploy and test their behavior
  on the Linux VPS separately. No remote server or WARP credentials are used
  while compiling.

Useful options:

```bash
bash "$HOME/Downloads/build-all-macos.sh" --plan
bash "$HOME/Downloads/build-all-macos.sh" --jobs 4
bash "$HOME/Downloads/build-all-macos.sh" --output-parent "$HOME/Desktop/VPN Builds"
bash "$HOME/Downloads/build-all-macos.sh" --no-bootstrap
```

The default is two concurrent Cargo compilation jobs, with projects built
sequentially. Individual app scripts retain their own Swift job settings.
`--no-bootstrap` requires all tools to be installed already; it still adds
required Rust standard-library targets and authenticates GitHub if needed.
It does not install/update Xcode, its SDK, Homebrew, or compiler packages.

## Maintainer validation

The orchestration tests use mocked build tools and temporary sources on
Linux, including a GNU Bash 3.2 compatibility run. They check architecture
routing, clean environments, clone retries, SDK installation decisions,
failure propagation/aggregation, original app recipes, SDK gates, filenames
with spaces and SHA-256 collection. These tests do **not** claim actual
Apple SDK compilation or running a Mac app:

```bash
bash -n tools/build-all-macos.sh
python3 -m unittest discover -s tools/tests -v
shellcheck --shell=bash --severity=warning tools/build-all-macos.sh
```
