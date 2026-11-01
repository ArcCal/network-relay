#!/usr/bin/env bash
# Interactive repeatable deployment: native Linux build + Certbot Cloudflare DNS-01.
# Requires Debian 12+ or Ubuntu 24.04+, Bash 4+, systemd and amd64/arm64.
# Run from the complete checkout on the server. --plan makes no changes.
# Token permissions: Zone:DNS:Edit and Zone:Zone:Read for the selected zone.
# Direct client access uses TCP/UDP 443; DNS-01 has no A/AAAA target prerequisite.
# DNS validation does not need inbound port 80. No Python helper is used.
#
# Maintainer contract: requirements and deployment lessons
# ========================================================
# Keep these notes when maintaining this installer. They distinguish observed
# failures, required behavior and remaining verification limits.
#
# Required behavior
# -----------------
# - Keep a clearly named executable Bash installer in the repository root.
#   Modify this installer, not application code or shared source templates.
#   Read repository design/deployment documentation before making changes.
# - Support Debian 12+ and Ubuntu 24.04+ without an artificial upper version cap.
#   Detect native amd64/arm64 and build the corresponding pinned server.
# - Accept only the domain and hidden CF_API_TOKEN as terminal input. An inherited
#   token can skip its prompt; on reruns an empty answer reuses this domain's
#   checked root-only renewal token. Do not ask for email, username, build jobs, profile
#   scope, password or confirmation. Keep apt/Git/helper commands noninteractive.
# - Use Cloudflare DNS-01. It validates TXT records and requires appropriate
#   zone-scoped token permissions, not an A/AAAA record pointing at this machine.
#   Do not add a public-IP lookup or DNS-to-host IP equality prerequisite.
# - Support install, upgrade and repair on every run. The current script governs
#   dedicated configuration/unit files; validate and automatically replace them.
#   Reuse a safe dedicated account and create it only when absent. Existing files,
#   directories or accounts are not errors by themselves. Keep genuine conflicts
#   (unsafe shared identities/parents, foreign listeners) distinct from existence.
# - Retain valid managed certificates, matching keys, issuer metadata and ACME
#   accounts. Do not force issuance just because the installer runs again.
#   Missing/invalid certificates need issuance; renewal when due stays enabled.
#   Never delete certificate state merely to make an installation look new.
# - Use a cryptographically random 22-character password with uppercase, lowercase,
#   digits and + or /. Reuse a compatible private client record when possible.
#   Keep server, Apple profile and Rust Network Relay RS TOML credentials aligned.
#   If plaintext credentials are unrecoverable, generate new ones and explain
#   that old clients need the refreshed configuration. Export both files privately.
# - Run the daemon as its dedicated non-root user with restricted groups and only
#   necessary capabilities. Protect DNS tokens, TLS keys, client exports and
#   backups; keep secrets out of argv/logs and outside the public web directory.
#   Preserve certificate renewal/reload and required TCP/UDP traffic.
# - Do not install UFW or another firewall, add firewall rules, or configure VPN
#   tunnel pools/NAT as a side effect of installing this application relay.
# - Persist binaries, configuration, credentials and certificate state. Reserve
#   /run for systemd-recreated transient data. Require active service state,
#   persistent enabled state and successful HTTPS/protocol checks before success.
#   Retain automatic restart and certificate renewal across host reboots.
# - Build and validate the candidate while the prior service remains running.
#   Back up dedicated files privately; stop the old dedicated unit and any
#   positively identified manually started instance of this relay (exact BIN
#   executable and `serve` with this CONFIG), verify 443 is free, and install
#   atomically. On failure restore files and the prior active/enabled state,
#   including runtime-only enablement. Preserve ACME state and unrelated
#   services. Backups cannot recover files deleted before the run. Rollback
#   restarts the old unit, not terminated manually started commands.
#
# Earlier failures and remedies
# -----------------------------
# 1. Fresh-only checks rejected each existing file, directory and account, forcing
#    manual deletion and risking certificate loss. Inspect/reuse safe resources
#    and replace managed files transactionally; support interrupted installs.
#    A same-named file with a bad mode/owner, a symlinked file, or a directory
#    where a file belongs is replaced or set aside rather than stopping the run;
#    the same-named account gets a nologin shell, no supplementary groups and a
#    non-writable home (changed after the old relay stops when it is in use).
#    Unsafe or symlinked dedicated directories (their content may be planted),
#    unit files, wants links and drop-ins, unsafe shared parents, privileged or
#    shared IDs and foreign listeners/aliases still stop the run.
# 2. systemd-run tried to execute /run/<service>-candidate/<binary> before its
#    BindReadOnlyPaths namespace existed. It resolves the first executable in the
#    HOST namespace. Use the host's /usr/bin/env -- entry point to exec the mapped
#    candidate inside the unit, retaining --wait to propagate failures. Never
#    expose the root-only work tree to work around a namespace/permission error.
# 3. The old mock mapped paths before checking the host executable and hid that
#    real ARM deployment failure. Test host lookup, then namespace execution,
#    argument/credential preservation and nonzero exits; reproduce the real CLI
#    behavior where possible. A passing mock alone is not deployment evidence.
# 4. Stopping a missing old unit may return exit 5 during a first/partial install.
#    Continue only if it is inactive and 443 is free. Treat a live listener/failed
#    stop as a genuine problem. Stop with the OLD unit before replacing drop-ins
#    or unit content; never terminate another service to steal its port.
# 5. A long hexadecimal password did not meet the requested length/classes. It
#    was not insecure merely for being hexadecimal. The application fast-hash
#    mode requires 24+ characters, so the requested 22-character password uses the
#    supported Argon2id stdin mode. Never expose plaintext in command arguments.
# 6. Earlier firewall handling and generic paths did not match the deployment
#    requirements. Keep firewall management out, and use dedicated binary/config/
#    account/state names instead of altering a general-purpose installation.
# 7. Hardening must fit the actual process: check filesystem needs, credential
#    copy timing, dynamic libraries and reload helpers. Do not grant broad write
#    access or extra privileges simply to silence a sandbox failure.
#
# Lesson from an external installer's DNS gate
# --------------------------------------------
# An external script refused installation unless the DNS-only A record matched
# one detected public IPv4. That is inappropriate as a Cloudflare DNS-01 issuance
# prerequisite: the CA checks _acme-challenge TXT records, not that IP endpoint.
# A/AAAA may point elsewhere or be absent. IPv6-only DNS, multiple records, NAT,
# multiple NICs and VPN/proxy egress also make one IPv4 comparison unreliable.
# Its log alone does not prove the detected IP was wrong; DNS may truly point
# elsewhere. Do not reproduce that issuance gate. Cloudflare proxy/grey-cloud
# routing choices are also separate from TXT-based domain authorization.
#
# Verification limits and maintenance improvements
# ------------------------------------------------
# - A certificate proves domain authorization, not public routing or client
#   connectivity. Current HTTPS/relay checks connect to 127.0.0.1 with real
#   hostname/SNI and bypass public DNS. Report their local scope accurately;
#   do not turn this observation into a new A/AAAA installation prerequisite.
# - Current built-in test targets are example.com:80 and 1.1.1.1:53. Restricted
#   egress or no IPv4 route may fail them while other destinations work. Diagnose
#   target reachability before blaming DNS/certificates or changing server policy.
# - Distinguish config validation, active/enabled state, offline unit checks,
#   mocks and actual end-to-end/reboot tests. Never claim a real reboot, public
#   ACME flow or a deployment on every OS version without actually testing it.
#   Keep regressions for reruns, partial repair, certificate reuse, canonical
#   replacement, boot paths, secrets and failed-switch restoration.
# - journalctl -f waits for new entries; Ctrl+C exits the viewer. Missing old
#   units, skipped recent storage cleaning and renewal-information messages are
#   not by themselves deployment failures. Several available certificate chains
#   do not mean several separate certificate requests.
#
# Cross-installer audit lessons
# -----------------------------
# - Check lock directories and single-link files before opening; append instead
#   of truncating. Disable allexport and inherited secret export attributes.
# - Distinct masks/wants links can resolve to the same leaf. Deduplicate only
#   parent aliases in backups, and verify canonical unit IDs before stopping.
# - Publish TLS pairs as validated immutable generations with one current-link
#   switch and a publication lock; retain old generations for backup recovery.
#   Recheck the desired source after locking so queued old hooks cannot overwrite
#   a new domain. Installation and rollback share that publication critical section.
#   SIGHUP notification is asynchronous, not proof of certificate consumption.
# - Exclude a work tree nested inside the checkout before copying the source;
#   compiler temporary files belong inside private staging, not inherited TMPDIR.
# - A qualified daemon account still needs a locked password and non-writable
#   NSS home; changing that home never moves or chowns the previous directory.
# - Takeover of a manually started relay needs positive evidence: the actual
#   /proc exe (also when deleted) and complete argv, never a truncated comm.
# - Recheck 443 immediately before the start as well as after the stop.
# - Certificate preparation runs concurrently with the build. errexit does not
#   apply inside if/|| contexts, so the job runs as a plain subshell command.
#   The job ignores Ctrl+C (an interrupted Certbot can lose an issued
#   certificate); cleanup waits for it and ignores further signals until done.
# - apt-get's DPkg::Lock::Timeout does not cover the package-list or archive
#   locks; retry only those lock failures, for a bounded time.
# - Takeover identification also requires this installer's namespaces and root
#   and excludes processes of other systemd service units (containers can show
#   identical paths and argv).
#
# Rust-specific requirements
# --------------------------
# Build the pinned native GNU Rust server. Install apt Certbot and its Cloudflare
# DNS plugin. Keep per-domain renewal tokens root-only and expose only active TLS
# copies to network-relay. Skip certonly for an already valid matching lineage.
# Retain archive/live/account files, compatible DNS renewal parameters, the root
# deploy hook and persistently enabled certbot.timer. Do not force issuance merely
# to migrate renewal settings on older Certbot versions.
# The native GNU binary may need its loader/NSS libraries and /bin/kill for HUP
# reload. Do not blindly copy static Go's binary-only execution restriction.
#
# Repeatable deployment/repair sequence:
#   1. Check the host, dedicated path ownership, account and socket ownership.
#   2. Read only the relay domain and a hidden Cloudflare token.
#   3. Install prerequisites noninteractively; verify and build native Rust
#   4. while concurrently reusing a valid certificate or obtaining one (DNS-01).
#   5. Stage/validate current-script configuration, TLS copies and both exports.
#   6. Back up old dedicated files/state, switch the unit and run real checks.
#   7. Commit on success; otherwise restore prior files and service state.
# The current script is authoritative on every run. Existing websites and the
# Certbot archive/account state are retained. The daemon never receives the API
# token. A failed switch restores the prior dedicated deployment, while valid
# newly issued certificates and their renewal credentials remain available.
#
# Disable tracing before reading any credentials, even under bash -x/-v.
set +x
set +v
set +a
# Remove inherited export attributes before local scopes can shadow these names.
export -n cf_token relay_password account candidate old_password

# Use trusted system tools when executed as root. Sourcing helpers for tests
# leaves PATH unchanged; proxy and CA trust variables are deliberately retained.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    unset CDPATH
fi

# Resolve source paths relative to the script, not the caller's working folder.
SERVICE=network-relay
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ETC=/etc/$SERVICE
TLS=$ETC/tls
BIN=/usr/local/bin/$SERVICE
UNIT=/etc/systemd/system/$SERVICE.service
HOOK=/etc/letsencrypt/renewal-hooks/deploy/$SERVICE-cloudflare-dns
CREDS=/etc/letsencrypt/$SERVICE-cloudflare.ini
CERTBOT=/usr/bin/certbot
CERT_ROOT=/etc/letsencrypt
TOOLS=/opt/$SERVICE-native-build-cloudflare-dns
WWW=/var/www/$SERVICE-cloudflare-dns
CONFIG=$ETC/relay.toml
# Client exports contain the plaintext relay password. The daemon does not
# need these files: place them in a root-only directory hidden by its sandbox.
EXPORTS=$ETC/relay
PROFILE=$EXPORTS/device.mobileconfig
CLIENT_CONFIG=$EXPORTS/network-relay-rs-client.toml
# Only systemd-managed logs, runtime files and private temporary files are
# writable by the running daemon. Certificates/configuration remain read-only.
LOGS=/var/log/$SERVICE
RUNTIME=/run/$SERVICE
SYSCTL=/etc/sysctl.d/90-$SERVICE-cloudflare-dns.conf
work=
transaction_started=0
backup_dir=
was_active=0
was_enabled=disabled
tls_lock=
certificate_job=
account_home_pending=0

nr_die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
nr_usage() {
    cat <<EOF
Usage: sudo bash ${0##*/}
       bash ${0##*/} --plan

Build this checkout for the server's native amd64/arm64 architecture. Prompt
only for the relay domain and hidden CF_API_TOKEN (Enter on a rerun keeps the
domain's saved renewal token; CF_API_TOKEN may be inherited). Install apt
Certbot with its Cloudflare DNS plugin, obtain a DNS-01 certificate, configure
renewal/reload, systemd, a website and a protected Apple device profile, then
stage private client exports, then publish them after HTTPS and TCP/UDP checks.
Debian 12+ or Ubuntu 24.04+, systemd 249+ and 5 GiB free under /opt required.

Defaults: user iphone, a generated 22-character mixed-case/digit/symbol password,
one build job and the bundled selected-domain device profile.
Certbot registers without email. Running this installer accepts the ACME CA
terms. There is no installation confirmation or other interactive prompt.

Repeatable installs/repairs: current-script files replace old dedicated files
after staging and validation. A failed switch restores the prior deployment.
The token stays in a root-only Certbot file for renewal, never in argv or the
relay service environment. The daemon runs under a dedicated non-root account with
read-only host files, private logs/runtime and a separate TLS certificate copy.
DNS-01 needs no A/AAAA records or IP match. Direct domain-based clients need
DNS-only records routing here; permit inbound TCP/UDP 443.
Provider firewall rules and real-device verification remain your responsibility.
EOF
}
# The native GNU target matches this server's architecture. This is a local
# build, not a portable static/musl cross-build; the binary may use system libc.
nr_host() {
    [[ $(uname -s) == Linux ]] || nr_die 'Run this on the Linux server.'
    case $(uname -m) in
        x86_64) arch=amd64; triple=x86_64-unknown-linux-gnu ;;
        aarch64|arm64) arch=arm64; triple=aarch64-unknown-linux-gnu ;;
        *) nr_die 'Only x86_64/amd64 and aarch64/arm64 are supported.' ;;
    esac
    local ID= VERSION_ID= major minor
    # shellcheck source=/dev/null
    . /etc/os-release
    [[ $VERSION_ID =~ ^[0-9]+([.][0-9]+)?$ ]] || nr_die 'A released Debian/Ubuntu version is required.'
    major=${VERSION_ID%%.*}; minor=${VERSION_ID#*.}
    case $ID in
        debian) (( 10#$major >= 12 )) || nr_die 'Debian 12+ is required.' ;;
        ubuntu)
            [[ $VERSION_ID == *.* ]] || nr_die 'Ubuntu 24.04+ is required.'
            (( 10#$major > 24 || (10#$major == 24 && 10#$minor >= 4) )) || nr_die 'Ubuntu 24.04+ is required.' ;;
        *) nr_die 'Only Debian 12+ and Ubuntu 24.04+ are supported.' ;;
    esac
}
# Accept only a bare ASCII DNS hostname. Reject URLs, addresses, wildcards and
# configuration/shell metacharacters before using the value in TOML or hooks.
# The final label may be an IDNA A-label TLD (xn--...); an all-letter-only
# rule wrongly rejected valid punycode TLDs. An all-numeric label stays invalid.
nr_domain() {
    local value=$1
    (( ${#value} <= 253 )) && [[ $value =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+([a-z]{2,63}|xn--[a-z0-9]([a-z0-9-]{0,57}[a-z0-9])?)$ ]]
}
# This helper and the silent token read are the only terminal input points.
# Child commands receive EOF after these prompts unless explicitly piped input.
nr_ask() {
    local prompt=$1 default=${2:-}
    if [[ -n $default ]]; then prompt+=" [$default]"; fi
    read -r -p "$prompt: " REPLY </dev/tty || nr_die 'Interactive terminal input is required.'
    REPLY=${REPLY:-$default}
}
# A root-owned leaf can still be renamed through a writable parent. Refuse
# shared writable/non-root ancestors, including a symlink's resolved ancestry,
# rather than chmod/chown a shared directory such as /var/www behind its owner.
nr_check_parent_dirs() {
    local path=$1 parent resolved metadata owner mode
    [[ $path == /* ]] || nr_die 'Installation paths must be absolute.'
    parent=${path%/*}; [[ -n $parent ]] || parent=/
    resolved=$(readlink -m -- "$parent") || nr_die "Cannot resolve parent of $path."
    for parent in "$parent" "$resolved"; do
        while :; do
            if [[ -e $parent || -L $parent ]]; then
                [[ -d $parent ]] || nr_die "Installation parent is not a directory: $parent."
                metadata=$(stat -Lc '%u %a' -- "$parent") || nr_die "Cannot inspect installation parent: $parent."
                read -r owner mode <<< "$metadata"
                [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0022) == 0 )) \
                    || nr_die "Installation parent must be root-owned and not group/other writable: $parent."
            fi
            [[ $parent != / ]] || break
            parent=${parent%/*}; [[ -n $parent ]] || parent=/
        done
    done
}
nr_check_account() {
    local entry name ignored uid gid gecos home shell members aliases group_entry primary users
    entry=$(getent passwd "$SERVICE" || true)
    group_entry=$(getent group "$SERVICE" || true)
    if [[ -z $entry ]]; then
        if [[ -n $group_entry ]]; then
            IFS=: read -r name ignored gid members <<< "$group_entry"
            [[ $gid =~ ^[0-9]+$ && $gid != 0 && -z $members ]] || nr_die 'Existing dedicated group is not safe to reuse.'
            aliases=$(getent group | awk -F: -v gid="$gid" '$3 == gid {n++} END {print n+0}')
            users=$(getent passwd | awk -F: -v gid="$gid" '$4 == gid {n++} END {print n+0}')
            [[ $aliases == 1 && $users == 0 ]] || nr_die 'Existing dedicated group is shared by another identity.'
        fi
        return
    fi
    IFS=: read -r name ignored uid gid gecos home shell <<< "$entry"
    [[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && $uid != 0 && $gid != 0 ]] || nr_die 'Dedicated account must not be privileged.'
    # A login shell, another home or supplementary groups on this same-named
    # account are repaired by nr_account (usermod; no home move or chown).
    [[ -n $group_entry ]] || nr_die 'Dedicated primary group is missing.'
    IFS=: read -r name ignored primary members <<< "$group_entry"
    [[ $primary == "$gid" && -z $members && $(id -gn "$SERVICE") == "$SERVICE" ]] || nr_die 'Existing service account/group is shared or mismatched.'
    aliases=$(getent passwd | awk -F: -v uid="$uid" '$3 == uid {n++} END {print n+0}')
    users=$(getent passwd | awk -F: -v gid="$gid" '$4 == gid {n++} END {print n+0}')
    [[ $aliases == 1 && $users == 1 ]] || nr_die 'Existing service UID/GID is shared by another account.'
    aliases=$(getent group | awk -F: -v gid="$gid" '$3 == gid {n++} END {print n+0}')
    [[ $aliases == 1 ]] || nr_die 'Existing primary GID has another group alias.'
}
# After repair the identity must be exactly the dedicated non-login account.
nr_verify_account() {
    local entry home shell item
    entry=$(getent passwd "$SERVICE") || nr_die 'The dedicated service account is missing.'
    IFS=: read -r _ _ _ _ _ home shell <<< "$entry"
    (( account_home_pending )) || [[ $home == /nonexistent ]] || nr_die 'Cannot establish a non-writable service home.'
    case $shell in /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false) ;; *) nr_die 'Cannot disable the service account login shell.' ;; esac
    for item in $(id -G "$SERVICE"); do
        [[ $item == "$(id -g "$SERVICE")" ]] || nr_die 'Cannot remove supplementary groups from the service account.'
    done
    [[ $(passwd -S "$SERVICE") == "$SERVICE L "* ]] || nr_die 'Cannot lock the dedicated service login password.'
}
# Kept as an alias for older callers; existing safe accounts are now accepted.
nr_require_new_account() { nr_check_account; }
# A root-owned leaf is insufficient when another service can rename it through
# a writable parent. In particular, file_server follows symlinks: replacing the
# web root could otherwise expose files readable by the relay account. Check
# both lexical and resolved ancestors so a symlink cannot hide an unsafe parent.
# Refuse unsafe shared directories instead of changing their ownership or mode.
nr_check_leaf() {
    local path=$1 kind=$2 owner mode metadata service_uid=0
    nr_check_parent_dirs "$path"
    [[ ! -L $path ]] || nr_die "Refusing an unknown installation symlink: $path."
    [[ -e $path ]] || return 0
    metadata=$(stat -Lc '%u %a' -- "$path") || nr_die "Cannot inspect $path."
    read -r owner mode <<< "$metadata"
    [[ $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0022) == 0 )) || nr_die "Dedicated path is group/other writable: $path."
    case $kind in
        file) [[ -f $path && $owner == 0 ]] || nr_die "Dedicated file is not a root-owned regular file: $path." ;;
        private) [[ -f $path && $owner == 0 ]] && (( (8#$mode & 0077) == 0 )) || nr_die "Private export/token is not root-only: $path." ;;
        rootdir) [[ -d $path && $owner == 0 ]] || nr_die "Dedicated directory is not root-owned: $path." ;;
        statedir)
            service_uid=$(id -u "$SERVICE" 2>/dev/null || printf 0)
            [[ -d $path && ( $owner == 0 || $owner == "$service_uid" ) ]] || nr_die "Dedicated state/runtime directory has an unrelated owner: $path." ;;
    esac
}
# A /dev/null mask is a managed unit state, not an unknown installation link.
# Runtime units and wants links must participate in the same repair transaction.
nr_check_unit() {
    local path=$1
    nr_check_parent_dirs "$path"
    if [[ -L $path ]]; then
        [[ $(readlink -- "$path") == /dev/null && $(stat -c %u -- "$path") == 0 ]] || nr_die "Unsafe dedicated unit link: $path."
    else
        nr_check_leaf "$path" file
    fi
}
nr_unit_paths() {
    printf '%s\n' "$UNIT" "/run/systemd/system/$SERVICE.service" \
        "/etc/systemd/system/multi-user.target.wants/$SERVICE.service" \
        "/run/systemd/system/multi-user.target.wants/$SERVICE.service"
}
# Never follow a planted lock link or truncate its target. /run is trusted;
# the private directory and single-link lock must already have safe ownership.
nr_acquire_lock() {
    local directory=/run/$SERVICE-native-cloudflare-install lock
    nr_check_parent_dirs "$directory/lock"
    [[ ! -L $directory ]] || nr_die 'Installer lock directory must not be a symlink.'
    if [[ -e $directory ]]; then
        [[ -d $directory && $(stat -c '%u:%a' -- "$directory") == 0:700 ]] || nr_die 'Unsafe installer lock directory.'
    else
        install -d -o root -g root -m 700 "$directory"
    fi
    lock=$directory/lock
    [[ ! -L $lock && ( ! -e $lock || ( -f $lock && $(stat -c '%u:%h:%a' -- "$lock") == 0:1:600 ) ) ]] || nr_die 'Unsafe installer lock file.'
    exec {install_lock}>>"$lock"
    flock -n "$install_lock" || nr_die 'Another installer is running.'
}
# The publisher lock stays at a stable inode. Use it for the install/rollback
# critical section as well as renewal, and release it before starting a unit.
nr_lock_tls() {
    local lock=$TLS/.publish.lock
    nr_check_leaf "$TLS" rootdir
    [[ ! -L $lock && ( ! -e $lock || ( -f $lock && $(stat -c '%u:%h:%a' -- "$lock") == 0:1:600 ) ) ]] || nr_die 'Unsafe certificate publication lock.'
    if [[ -n $tls_lock ]]; then
        [[ $(stat -Lc '%d:%i' -- "/proc/self/fd/$tls_lock") == $(stat -c '%d:%i' -- "$lock") ]] || nr_die 'Certificate publication lock changed.'
    else
        exec {tls_lock}>>"$lock"
    fi
    flock -x "$tls_lock"
}
nr_unlock_tls() {
    if [[ -n $tls_lock ]]; then exec {tls_lock}>&-; tls_lock=; fi
}
nr_port_records() {
    local sockets=(/proc/net/tcp /proc/net/udp) file
    for file in /proc/net/tcp6 /proc/net/udp6; do [[ ! -r $file ]] || sockets+=("$file"); done
    for file in "${sockets[@]}"; do [[ -r $file ]] || nr_die "Cannot inspect listening sockets: $file."; done
    awk 'FNR > 1 && $2 ~ /:01BB$/ && (FILENAME ~ /udp/ || $4 == "0A") {
        printf "%s\t%s\t%s\n", (FILENAME ~ /udp/ ? "UDP" : "TCP"), $2, $10
    }' "${sockets[@]}"
}
nr_port_inodes() {
    nr_port_records | awk -F '\t' '{print $3}'
}
# Convert Linux's little-endian socket-table addresses for diagnostics when ss
# is unavailable. Supported amd64/arm64 hosts use this kernel representation.
nr_endpoint_text() {
    local address=${1%:*} reordered='' part index result=''
    if [[ $address =~ ^[a-fA-F0-9]{8}$ ]]; then
        printf '%d.%d.%d.%d:443' "0x${address:6:2}" "0x${address:4:2}" "0x${address:2:2}" "0x${address:0:2}"
    elif [[ $address =~ ^[a-fA-F0-9]{32}$ ]]; then
        for ((index=0; index<32; index+=8)); do
            part=${address:index:8}
            reordered+=${part:6:2}${part:4:2}${part:2:2}${part:0:2}
        done
        for ((index=0; index<32; index+=4)); do
            [[ -z $result ]] || result+=:
            result+=${reordered:index:4}
        done
        printf '[%s]:443' "$result"
    else
        printf '%s' "$1"
    fi
}
# Fallback ownership lookup is read-only. Report executable/PID rather than
# full command lines, which could contain secrets from an old manual launch.
nr_socket_owners() {
    local inode=$1 link pid executable name seen=$'\n' found=0
    [[ $inode =~ ^[0-9]+$ ]] || return 1
    while IFS= read -r link; do
        pid=${link#/proc/}; pid=${pid%%/*}
        [[ $pid =~ ^[0-9]+$ && $seen != *$'\n'"$pid"$'\n'* ]] || continue
        seen+="$pid"$'\n'
        executable=$(readlink -- "/proc/$pid/exe" 2>/dev/null || printf unavailable)
        name=$(cat "/proc/$pid/comm" 2>/dev/null || printf unavailable)
        printf '    PID=%s process=%q executable=%q\n' "$pid" "$name" "$executable" >&2
        found=1
    done < <(find -P /proc/[0-9]*/fd -maxdepth 1 -type l -lname "socket:\[$inode\]" -print 2>/dev/null)
    (( found )) || printf '    Owner unavailable in this PID namespace (socket inode %s).\n' "$inode" >&2
}
# Every conflict prints both protocols, even if only one is occupied. ss gives
# readable listener addresses and PID/process details; /proc remains a fallback
# on a minimal host before iproute2 is installed. Never install/stop anything
# merely to produce these diagnostics.
nr_report_ports() {
    local records protocol item address inode output reported
    records=$(nr_port_records) || return 1
    for protocol in TCP UDP; do
        printf '%s 443:\n' "$protocol" >&2
        reported=0
        if command -v ss >/dev/null 2>&1; then
            if [[ $protocol == TCP ]]; then
                output=$(ss -H -ltnp '( sport = :443 )' 2>/dev/null) || output=
            else
                output=$(ss -H -aunp '( sport = :443 )' 2>/dev/null) || output=
            fi
            # Process names in ss output can contain terminal control bytes.
            if [[ -n $output ]]; then printf '%s\n' "$output" | LC_ALL=C sed -n 'l 0' >&2; fi
        fi
        # ss prints truncated process names only; always add each socket's
        # owning PID and executable path from /proc (never command lines).
        while IFS=$'\t' read -r item address inode; do
            [[ $item == "$protocol" ]] || continue
            printf '  local=%s\n' "$(nr_endpoint_text "$address")" >&2
            nr_socket_owners "$inode"
            reported=1
        done <<< "$records"
        if (( !reported )); then printf '  Not occupied.\n' >&2; fi
    done
}
nr_pid_socket_inodes() {
    local pid=$1 fd target
    [[ -d /proc/$pid/fd && -r /proc/$pid/fd ]] || nr_die 'Cannot inspect the dedicated service socket ownership.'
    for fd in /proc/"$pid"/fd/*; do
        target=$(readlink -- "$fd" 2>/dev/null || true)
        if [[ $target =~ ^socket:\[([0-9]+)\]$ ]]; then printf '%s\n' "${BASH_REMATCH[1]}"; fi
    done
}
# The running dedicated unit may keep 443 during a long rebuild. Every occupied
# inode must belong to its actual MainPID; never stop or kill a different server.
# A unit name may resolve through a vendor alias to an unrelated workload.
# Its MainPID is not ours merely because show was called with our alias.
nr_unit_identity() {
    local identity
    identity=$(systemctl show "$SERVICE" --property=Id --value 2>/dev/null || true)
    if [[ -n $identity && $identity != "$SERVICE.service" ]]; then
        printf 'Error: the relay unit name aliases a different service; that workload was not stopped.\n' >&2
        return 1
    fi
}
# A manually started old relay may hold 443 with no unit MainPID. comm names
# are truncated, so identify it by its actual executable (including an unlinked
# old copy of BIN) and exact clap argv: `serve` plus at most one -c/--config
# naming this deployment's file (clap's default path is that same file). Any
# other option, --check, a relative or different config is not ownership proof.
nr_is_relay_pid() {
    local pid=$1 executable argument index configurations=0 selected=/etc/network-relay/relay.toml
    local -a arguments=()
    [[ $pid =~ ^[1-9][0-9]*$ && $pid != 1 && $pid != "$$" && $pid != "$BASHPID" ]] || return 1
    executable=$(readlink -- "/proc/$pid/exe" 2>/dev/null) || return 1
    executable=${executable% (deleted)}
    [[ $executable == "$BIN" ]] || return 1
    nr_same_host_process "$pid" || return 1
    {
        while IFS= read -r -d '' argument; do arguments+=("$argument"); done < "/proc/$pid/cmdline"
    } 2>/dev/null || return 1
    [[ ${arguments[1]:-} == serve ]] || return 1
    for ((index=2; index<${#arguments[@]}; index++)); do
        case ${arguments[index]} in
            --config=*) selected=${arguments[index]#--config=} ;;
            -c|--config)
                index=$((index + 1))
                (( index < ${#arguments[@]} )) || return 1
                selected=${arguments[index]} ;;
            -c=*) return 1 ;;
            -c?*) selected=${arguments[index]#-c} ;;
            *) return 1 ;;
        esac
        configurations=$((configurations + 1))
    done
    (( configurations <= 1 )) && [[ $selected == "$CONFIG" ]]
}
# /proc/PID/exe shows a path inside the process's own mount namespace, so a
# relay in a container can look identical to this deployment's. Require this
# installer's mount, PID and network namespaces and root directory. A process
# supervised by another systemd service unit belongs to that unit: it is
# reported as a port owner, never signalled.
nr_same_host_process() {
    local pid=$1 namespace line group='' part unit=''
    local -a parts=()
    for namespace in mnt pid net; do
        [[ $(readlink -- "/proc/$pid/ns/$namespace" 2>/dev/null) == "$(readlink -- "/proc/self/ns/$namespace")" ]] || return 1
    done
    [[ $(readlink -- "/proc/$pid/root" 2>/dev/null) == / ]] || return 1
    {
        while IFS= read -r line; do
            case $line in
                0::*) group=${line#0::}; break ;;
                *:name=systemd:*) group=${line#*:name=systemd:} ;;
            esac
        done < "/proc/$pid/cgroup"
    } 2>/dev/null || return 1
    IFS=/ read -r -a parts <<< "$group"
    for part in "${parts[@]}"; do
        if [[ $part == *.service || $part == *.scope ]]; then unit=$part; fi
    done
    [[ $unit != *.service || $unit == "$SERVICE.service" ]]
}
nr_standalone_pids() {
    local directory
    for directory in /proc/[0-9]*; do
        if nr_is_relay_pid "${directory##*/}"; then printf '%s\n' "${directory##*/}"; fi
    done
}
nr_ports() {
    nr_unit_identity || return 1
    local occupied pid pids owned='' sockets inode found item
    occupied=$(nr_port_inodes) || nr_die 'Cannot inspect listening sockets; port availability is unknown.'
    [[ -n $occupied ]] || return 0
    pid=$(systemctl show "$SERVICE" --property=MainPID --value) || nr_die 'Cannot inspect dedicated service MainPID.'
    # The canonical unit's MainPID and positively identified standalone relay
    # instances are takeover targets; every other socket owner is a conflict.
    pids=$(nr_standalone_pids)
    if [[ $pid =~ ^[1-9][0-9]*$ ]]; then pids+=$'\n'$pid; fi
    while IFS= read -r pid; do
        [[ -n $pid ]] || continue
        # A process may exit between the socket snapshot and this read.
        if sockets=$(nr_pid_socket_inodes "$pid" 2>/dev/null); then owned+=$sockets$'\n'; fi
    done <<< "$pids"
    while IFS= read -r inode; do
        [[ $inode =~ ^[0-9]+$ ]] || nr_die 'Invalid kernel socket record.'
        found=0
        while IFS= read -r item; do [[ $inode != "$item" ]] || found=1; done <<< "$owned"
        if (( !found )); then
            nr_report_ports || true
            nr_die 'TCP or UDP 443 belongs to another process; no other service was stopped.'
        fi
    done <<< "$occupied"
}
# Compatibility name retained for existing usage/tests; this is now a safe
# installation preflight, not an existence-based fresh-install gate.
# Permit safe prior deployments and interrupted attempts; never require users to
# delete paths one by one. A same-named dedicated entry with the wrong type,
# owner or mode (including a symlink) is replaced or repaired, never written
# through: files are renamed over after backup, a non-directory at a directory
# path is unlinked without touching its target, and a real directory gets only
# its own owner/mode fixed. Unsafe shared PARENTS, foreign unit aliases, shared
# or privileged accounts and foreign listeners are still genuine conflicts.
nr_note_repair() {
    local reason
    if ! reason=$( (nr_check_leaf "$1" "$2") 2>&1 ); then
        printf 'Will replace or repair same-named dedicated entry: %s\n' "${reason#Error: }"
    fi
}
nr_fresh() {
    nr_unit_identity || return 1
    local path dropin entry link
    nr_check_account
    # Dedicated DIRECTORIES must already be safe. Another account that could
    # write one may have planted content in it; a top-level chmod/chown would
    # adopt that content, so they are refused as before, never "repaired".
    for path in "$ETC" "$TLS" "$EXPORTS" "$TOOLS" "$TOOLS/backups" "$WWW"; do nr_check_leaf "$path" rootdir; done
    for path in "$LOGS" "$RUNTIME"; do nr_check_leaf "$path" statedir; done
    # Same-named dedicated FILES with a bad mode/owner or a symlink are only
    # reported here: they are saved and then replaced by rename.
    for path in "$BIN" "$CONFIG" "$SYSCTL" "$HOOK"; do nr_check_parent_dirs "$path"; nr_note_repair "$path" file; done
    for path in "$CREDS" "$PROFILE" "$CLIENT_CONFIG" "$TLS/.desired-source"; do
        nr_check_parent_dirs "$path"; nr_note_repair "$path" private
    done
    # Stopping the old unit runs its ExecStop= lines, drop-ins included, as
    # root: unit files, masks, wants links and drop-ins keep their strict checks.
    nr_check_unit "$UNIT"
    nr_check_unit "/run/systemd/system/$SERVICE.service"
    while IFS= read -r link; do
        [[ $link == *.wants/* ]] || continue
        nr_check_parent_dirs "$link"
        if [[ -e $link || -L $link ]]; then
            [[ -L $link && $(stat -c %u -- "$link") == 0 ]] || nr_die "Unsafe dedicated enablement entry: $link."
        fi
    done < <(nr_unit_paths)
    for dropin in "$UNIT.d" "/run/systemd/system/$SERVICE.service.d" "/usr/lib/systemd/system/$SERVICE.service.d" "/lib/systemd/system/$SERVICE.service.d"; do
        nr_check_leaf "$dropin" rootdir
        [[ -d $dropin ]] || continue
        while IFS= read -r entry; do nr_check_leaf "$entry" file; done < <(find -P "$dropin" -mindepth 1 -maxdepth 1 -print)
    done
    nr_ports
}
# A directory occupying a dedicated FILE path is kept under another name, never
# deleted or followed; the deployment backup also holds a copy.
nr_set_aside() {
    local aside
    aside=$1.replaced-$(date -u +%Y%m%d%H%M%S)-$$
    mv -T -- "$1" "$aside"
    printf 'Moved the conflicting same-named entry %s to %s.\n' "$1" "$aside"
}
# Ignore per-user curl configuration, retaining HTTPS/TLS verification, proxy
# routing and configured CA trust. Artifact checksums are checked before use.
nr_download() {
    curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --show-error --location \
        --retry 3 --connect-timeout 20 --max-time 900 --output "$2" "$1"
}
# The expected digest comes from the official HTTPS checksum endpoint. A bad
# or malformed digest must stop before the bootstrap executable can run.
nr_verify() {
    local actual
    [[ $2 =~ ^[a-f0-9]{64}$ ]] || nr_die 'Invalid checksum metadata.'
    actual=$(sha256sum -- "$1"); actual=${actual%% *}
    [[ $actual == "$2" ]] || nr_die 'Download checksum mismatch; refusing to use the artifact.'
}
# Create only new files. Private umask plus noclobber protects initial writes;
# then set the explicit installed mode/owner. Never truncate a pre-existing file.
nr_new_file() {
    local path=$1 mode=$2 group=${3:-root}
    [[ ! -e $path && ! -L $path ]] || nr_die "Refusing to replace $path."
    # noclobber also prevents following an existing symlink or truncating a file.
    (set -o noclobber; umask 077; cat > "$path")
    chmod "$mode" "$path"
    chown root:"$group" "$path"
}
# Dedicated files participate in a rollback transaction. Certificates, ACME
# accounts, websites and logs remain in place: remote issuance cannot be undone
# by restoring a configuration file. Backups are root-only and retained.
nr_rollback() {
    nr_lock_tls || return 1
    local failed=0 index=0 path existed type prior
    # A mask removal may expose a foreign vendor alias. Never stop that target,
    # but still restore our recorded pathname entries, including the old mask.
    if nr_unit_identity; then
        if ! systemctl stop "$SERVICE" >/dev/null 2>&1; then
            if systemctl is-active --quiet "$SERVICE"; then failed=1; fi
        fi
    fi
    for prior in /etc/systemd/system/multi-user.target.wants/$SERVICE.service /run/systemd/system/multi-user.target.wants/$SERVICE.service; do
        rm -f -- "$prior" || failed=1
    done
    while IFS=$'\t' read -r index existed type path; do
        if [[ $type == dir ]]; then
            [[ ! -e $path ]] || rm -rf -- "$path" || failed=1
            if [[ $existed == 1 ]]; then cp -a -- "$backup_dir/files/$index" "$path" || failed=1; fi
        elif [[ $existed == 1 && -d $backup_dir/files/$index && ! -L $backup_dir/files/$index ]]; then
            # A directory that had occupied a file path is restored as it was.
            rm -rf -- "$path" && cp -a -- "$backup_dir/files/$index" "$path" || failed=1
        elif [[ $existed == 1 ]]; then
            prior=$(mktemp "${path%/*}/.${path##*/}.restore.XXXXXXXX") || { failed=1; continue; }
            if cp -a -- "$backup_dir/files/$index" "$prior" && mv -fT -- "$prior" "$path"; then :; else
                rm -f -- "$prior"; failed=1
            fi
        else
            rm -f -- "$path" || failed=1
        fi
    done < "$backup_dir/manifest"
    nr_unlock_tls
    systemctl daemon-reload || failed=1
    # Saved persistent/runtime wants entries establish the previous enablement;
    # do not issue enable against a newly exposed foreign alias during recovery.
    if (( was_active )); then
        if [[ -x $BIN && -f $CONFIG ]]; then
            if nr_unit_identity; then
                systemctl start "$SERVICE" || failed=1
                systemctl is-active --quiet "$SERVICE" || failed=1
            else
                failed=1
            fi
        else
            printf 'Warning: the previous deployment was already missing binary/config/unit files; its disk baseline was restored but it cannot be restarted.\n' >&2
            failed=1
        fi
    fi
    if (( !was_active )) && systemctl is-active --quiet "$SERVICE"; then failed=1; fi
    prior=$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)
    [[ $prior == "$was_enabled" || ( $was_enabled == not-found && -z $prior ) ]] || failed=1
    (( failed == 0 ))
}
nr_cleanup() {
    local status=$?
    trap - EXIT
    # A second Ctrl+C or TERM must not abort rollback or leave the scratch
    # token file behind; finish cleanup with these signals ignored.
    trap '' INT TERM HUP
    # Never delete scratch files under a running Certbot request; the job
    # ignores Ctrl+C, so wait for that bounded request to finish.
    if [[ -n $certificate_job ]] && kill -0 "$certificate_job" 2>/dev/null; then
        printf 'Waiting for the running certificate request to finish...\n' >&2
    fi
    if [[ -n $certificate_job ]]; then wait "$certificate_job" 2>/dev/null || true; fi
    if (( transaction_started )); then
        if nr_rollback; then
            printf 'The candidate failed; dedicated files and prior active/enabled state were restored.\n' >&2
        else
            printf 'Rollback was incomplete; inspect private backup %s and journalctl -u %s.\n' "$backup_dir" "$SERVICE" >&2
        fi
        (( status != 0 )) || status=1
    fi
    if [[ -n $work ]] && ! rm -rf -- "$work"; then
        printf 'Warning: could not remove private scratch directory %s.\n' "$work" >&2
        (( status != 0 )) || status=1
    fi
    if (( status )); then printf 'Deployment incomplete (exit %s). Private backup: %s\n' "$status" "${backup_dir:-not needed before file replacement}" >&2; fi
    exit "$status"
}
# Copy into a same-filesystem temporary file, then rename. Replacing the pathname
# never truncates the executable inode still in use by the previous process.
# rename(2) replaces a same-named symlink itself and never writes through it.
# A directory at a file path is set aside (callers have already saved it).
nr_atomic_install() {
    local source=$1 destination=$2 mode=$3 group=${4:-root} temporary
    nr_check_parent_dirs "$destination"
    if [[ -d $destination && ! -L $destination ]]; then nr_set_aside "$destination"; fi
    temporary=$(mktemp "${destination%/*}/.${destination##*/}.install.XXXXXXXX")
    if install -o root -g "$group" -m "$mode" -- "$source" "$temporary" && mv -fT -- "$temporary" "$destination"; then :; else
        rm -f -- "$temporary"
        nr_die "Atomic installation failed: $destination."
    fi
}
nr_backup() {
    local path index=0 existed type canonical seen=$'\n'
    was_active=0
    if systemctl is-active --quiet "$SERVICE"; then was_active=1; fi
    was_enabled=$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)
    was_enabled=${was_enabled:-disabled}
    nr_check_leaf "$TOOLS/backups" rootdir
    install -d -o root -g root -m 700 "$TOOLS/backups"
    backup_dir=$(mktemp -d "$TOOLS/backups/deployment-$(date -u +%Y%m%d-%H%M%S).XXXXXXXX")
    install -d -m 700 "$backup_dir/files"
    : > "$backup_dir/manifest"
    local paths=("$BIN" "$CONFIG" "$UNIT" "/run/systemd/system/$SERVICE.service"
        "/etc/systemd/system/multi-user.target.wants/$SERVICE.service"
        "/run/systemd/system/multi-user.target.wants/$SERVICE.service"
        "$PROFILE" "$CLIENT_CONFIG" "$SYSCTL" "$HOOK" "$TLS/current" "$TLS/.desired-source"
        "$TLS/fullchain.pem" "$TLS/privkey.pem" "$UNIT.d" "/run/systemd/system/$SERVICE.service.d"
        "/usr/lib/systemd/system/$SERVICE.service.d" "/lib/systemd/system/$SERVICE.service.d")
    for path in "${paths[@]}"; do
        canonical=$(readlink -m -- "${path%/*}")/${path##*/}
        [[ $seen != *$'\n'"$canonical"$'\n'* ]] || continue
        seen+="$canonical"$'\n'
        type=file; [[ $path != *.service.d ]] || type=dir
        existed=0
        if [[ -e $path || -L $path ]]; then existed=1; cp -a -- "$path" "$backup_dir/files/$index"; fi
        printf '%s\t%s\t%s\t%s\n' "$index" "$existed" "$type" "$path" >> "$backup_dir/manifest"
        index=$((index + 1))
    done
    printf 'active=%s\nenabled=%s\n' "$was_active" "$was_enabled" > "$backup_dir/service-state"
    printf 'Private deployment backup: %s\n' "$backup_dir"
}
# Inspect adjacent module/replacement records in `go version -m` output. Merely
# finding a module name is insufficient: the binary must use its patched source.
# Compile a private copy of the checkout with its committed Cargo.lock. Build
# output and toolchain/cache files stay outside the source and daemon paths.
# Unset inherited cross-build/compiler hooks; the configured proxy/CA remains.
nr_build() {
    local jobs=$1 expected url
    mkdir "$work/source"
    # Build a snapshot; leave the caller's tracked files and lockfiles untouched.
    local -a snapshot_excludes=(--exclude=.git --exclude=target --exclude=__pycache__ --exclude=.venv --exclude='relay-servers-*')
    # A checkout placed directly under /opt may contain this run's work tree.
    # Exclude it before tar sees its own growing source copy.
    if [[ $work == "${REPO%/}/"* ]]; then snapshot_excludes+=(--exclude="./${work#"${REPO%/}/"}"); fi
    tar -C "$REPO" "${snapshot_excludes[@]}" -cf - . | tar -C "$work/source" -xf -
    mkdir -m 700 "$work/tmp"
    export TMPDIR=$work/tmp
    local env_name
    # Ignore inherited compiler/linker/runner overrides without printing values.
    # Preserve HTTP(S)_PROXY, CA trust and platform Git authentication bindings.
    while IFS= read -r env_name; do
        case $env_name in
            RUSTC|RUSTDOC|RUSTC_*|RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_*|CARGO_TARGET_*|CC|CXX|AR|RANLIB|CC_*|CXX_*|AR_*|RANLIB_*|CFLAGS*|CXXFLAGS*)
                unset "$env_name" ;;
        esac
    done < <(compgen -e)
    url=https://static.rust-lang.org/rustup/dist/$triple/rustup-init
    nr_download "$url" "$work/rustup-init"
    nr_download "$url.sha256" "$work/rustup-init.sha256"
    read -r expected _ < "$work/rustup-init.sha256"
    nr_verify "$work/rustup-init" "$expected"
    chmod 700 "$work/rustup-init"
    # rustup's independently downloaded manifests retain their own verification.
    # Pin its distribution/update origins and keep Cargo's HTTPS verification on.
    export RUSTUP_DIST_SERVER=https://static.rust-lang.org
    export RUSTUP_UPDATE_ROOT=https://static.rust-lang.org/rustup
    export CARGO_HTTP_SSL_VERIFY=true
    export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
    export CARGO_REGISTRIES_CRATES_IO_INDEX=sparse+https://index.crates.io/
    export CARGO_HOME=$work/cargo RUSTUP_HOME=$work/rustup RUSTUP_TOOLCHAIN=1.99.1
    export CARGO_TARGET_DIR=$work/target
    export PATH="$CARGO_HOME/bin:$PATH"
    "$work/rustup-init" -y --no-modify-path --profile minimal --default-toolchain "$RUSTUP_TOOLCHAIN"
    (cd "$work/source"; "$CARGO_HOME/bin/cargo" build --locked --release --bin network-relay --target "$triple" --jobs "$jobs")
    install -m 755 "$CARGO_TARGET_DIR/$triple/release/network-relay" "$work/$SERVICE"
    "$work/$SERVICE" --version
}
# Certbot runs this hook as root after successful renewal. The daemon cannot
# enter Certbot's directory or read its Cloudflare token; it reads only copies
# of its active certificate/key, owned by root and readable by its own group.
# Validate and publish an immutable generation under a serialized current link.
# Reload through systemd/SIGHUP; a failed notification restores the old link.
# SIGHUP is asynchronous: local final health checks remain necessary.
nr_hook_text() {
    printf '#!/usr/bin/env bash\nset -Eeuo pipefail\nset +x\nset +v\nset +a\n'
    printf 'lineage=%q\ndomain=%q\ndir=%q\nservice=%q\narchive=%q\n' "$CERT_ROOT/live/$domain" "$domain" "$TLS" "$SERVICE" "$CERT_ROOT/archive"
    cat <<'HOOK'
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
[[ ${RENEWED_LINEAGE:-$lineage} == "$lineage" ]] || exit 0
[[ $# == 0 || ( $# == 1 && $1 == --no-reload ) ]] || { printf 'Unknown certificate hook argument.\n' >&2; exit 1; }
fail() { printf 'Certificate publication failed: %s\n' "$*" >&2; exit 1; }
# Recheck at the signal boundary as well as before staging: another root
# operation may have changed a unit alias while this hook waited or validated.
reload_service() {
    local identity
    identity=$(systemctl show "$service" --property=Id --value 2>/dev/null || true)
    if [[ $identity != "$service.service" ]]; then
        printf 'Refusing certificate reload through a foreign or unidentified unit alias.\n' >&2
        return 1
    fi
    systemctl reload "$service"
}
root_chain() {
    local path=$1
    while :; do
        [[ ! -L $path && -d $path && $(stat -c %u -- "$path") == 0 ]] || fail 'Unsafe certificate directory.'
        (( (8#$(stat -c %a -- "$path") & 0022) == 0 )) || fail 'Writable certificate directory.'
        [[ $path != / ]] || break
        path=${path%/*}; [[ -n $path ]] || path=/
    done
}
root_chain "$lineage"
root_chain "$dir"
identity=$(systemctl show "$service" --property=Id --value 2>/dev/null || true)
[[ -z $identity || $identity == "$service.service" ]] || fail 'The relay unit aliases another service.'
lock=$dir/.publish.lock
[[ ! -L $lock && ( ! -e $lock || ( -f $lock && $(stat -c '%u:%h:%a' -- "$lock") == 0:1:600 ) ) ]] || fail 'Unsafe certificate publication lock.'
if [[ -n ${NR_TLS_LOCK_FD:-} ]]; then
    [[ ${1:-} == --no-reload && $NR_TLS_LOCK_FD =~ ^[0-9]+$ ]] || fail 'Invalid inherited publication lock.'
    [[ $(stat -Lc '%d:%i' -- "/proc/self/fd/$NR_TLS_LOCK_FD") == $(stat -c '%d:%i' -- "$lock") ]] || fail 'Inherited publication lock does not match.'
    publication_lock=$NR_TLS_LOCK_FD
else
    exec {publication_lock}>>"$lock"
fi
# flock on an inherited duplicate uses the same open-file description and
# cannot deadlock the installer that already owns this lock.
flock -x "$publication_lock"
unset NR_TLS_LOCK_FD
marker=$dir/.desired-source
[[ ! -L $marker && -f $marker && $(stat -c '%u:%h:%a' -- "$marker") == 0:1:600 ]] || fail 'Unsafe or missing desired certificate source.'
expected=$(printf '%s\n%s' "$lineage" "$domain")
# A hook queued before a domain/source replacement must not publish afterwards.
[[ $(cat -- "$marker") == "$expected" ]] || exit 0
previous=
if [[ -e $dir/current || -L $dir/current ]]; then
    [[ -L $dir/current && $(stat -c %u -- "$dir/current") == 0 ]] || fail 'Unsafe current certificate entry.'
    previous=$(readlink -- "$dir/current")
    [[ $previous =~ ^generation[.][A-Za-z0-9]+$ ]] || fail 'Current certificate points outside managed generations.'
    if [[ -e $dir/$previous || -L $dir/$previous ]]; then
        root_chain "$dir/$previous"
    else
        # A deleted managed mirror is a repair case; Certbot originals below
        # still determine whether a new complete generation may be published.
        previous=
    fi
fi
generation=$(mktemp -d "$dir/generation.XXXXXXXX")
link=$dir/.current-${generation##*/}
published=0
cleanup() {
    local result=$? recovery=0
    trap - EXIT
    if (( result != 0 && published )); then
        if [[ -n $previous ]]; then
            ln -s -- "$previous" "$link" && mv -fT -- "$link" "$dir/current" || recovery=1
        else
            rm -f -- "$dir/current" || recovery=1
        fi
        # A failed SIGHUP notification does not prove that the process loaded
        # the candidate. Restore the old disk generation and notify again.
        if [[ -n $previous ]] && systemctl is-active --quiet "$service"; then
            reload_service || recovery=1
        fi
        (( recovery == 0 )) || printf 'Certificate recovery incomplete; retained generation: %s\n' "$generation" >&2
    fi
    rm -f -- "$link"
    if (( !published )); then rm -rf -- "$generation"; fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for file in fullchain.pem privkey.pem; do
    source=$lineage/$file
    [[ $(stat -c %u -- "$source") == 0 ]] || fail 'Certificate source is not root-owned.'
    resolved=$(readlink -e -- "$source") || fail 'Missing certificate source.'
    [[ $resolved == "$archive/"* || $resolved == "$source" ]] || fail 'Certificate source leaves the managed archive.'
    root_chain "${resolved%/*}"
    [[ ! -L $resolved && -f $resolved && $(stat -c '%u:%h' -- "$resolved") == 0:1 ]] || fail 'Unsafe certificate source file.'
    (( (8#$(stat -c %a -- "$resolved") & 0022) == 0 )) || fail 'Certificate source has extra writers.'
    install -o root -g "$service" -m 640 -- "$resolved" "$generation/$file"
done
cert=$generation/fullchain.pem
key=$generation/privkey.pem
openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 || fail 'Certificate is expired or malformed.'
openssl verify -purpose sslserver -verify_hostname "$domain" -untrusted "$cert" "$cert" >/dev/null 2>&1 || fail 'Certificate hostname, validity or trust check failed.'
certificate_key=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum) || fail 'Cannot read certificate key.'
private_key=$(openssl pkey -in "$key" -passin pass: -pubout -outform DER | sha256sum) || fail 'Cannot read private key.'
[[ $certificate_key == "$private_key" ]] || fail 'Certificate and private key do not match.'
chown root:"$service" "$generation"
chmod 750 "$generation"
ln -s -- "${generation##*/}" "$link"
mv -fT -- "$link" "$dir/current"
published=1
if [[ ${1:-} != --no-reload ]] && systemctl is-active --quiet "$service"; then
    reload_service || fail 'Service reload failed; restoring the preceding generation.'
    systemctl is-active --quiet "$service" || fail 'Service stopped after reload.'
fi
# Keep immutable generations for transaction backups, including a generation
# referenced by a previous installer's saved current link. Root may retire old
# backups/generations together; never prune keys behind a recoverable backup.
HOOK
}
# Keep server configuration/TLS outside home directories because ProtectHome
# hides them. Unspecified relay policies retain the server's reviewed defaults.
# File logs are the only persistent data written by this relay implementation.
nr_config_text() {
    cat <<EOF
listen = "[::]:443"
log_dir = "$LOGS"
[tls]
cert = "$TLS/current/fullchain.pem"
key = "$TLS/current/privkey.pem"
[web]
root = "$WWW"
[relay]
udp_template = "/.well-known/masque/udp/{target_host}/{target_port}/"
$account
EOF
}
# Adapt the repository service template without changing that tracked file.
# systemd 249+ is the supported manager baseline for this installer.
#
# - Keep the non-root identity and only CAP_NET_BIND_SERVICE for TCP/UDP 443.
# - Make the host filesystem read-only. LogsDirectory/RuntimeDirectory and
#   PrivateTmp provide the writable paths the daemon actually needs.
# - Hide the root Certbot tree (including API token and original private keys),
#   client exports and compiler/tool caches. TLS copies remain readable, and
#   root's renewal hook can replace them outside the daemon's mount namespace.
# - Protect kernel/host control paths, devices, IPC and other users' processes.
# - Keep Internet, Unix and Netlink sockets and /proc/meminfo available for relay
#   traffic, DNS, own-address filtering and the application's memory budgets.
# - Deny dangerous syscall classes but avoid a fragile broad syscall allowlist.
# - The native GNU Rust binary may use a dynamic loader and NSS shared libraries.
#   Do NOT use NoExecPaths=/ plus a single ExecPaths exception as for static Go:
#   /lib, /usr/lib and the /bin/kill reload helper must remain executable.
#   Mark only writable temporary/log/runtime directories noexec instead.
# These controls limit access after a compromise; they do not eliminate all risk
# or isolate the service from the Internet it must use for relayed traffic.
nr_unit_text() {
    awk -v service="$SERVICE" -v binary="$BIN" -v config="$CONFIG" \
        -v certroot="$CERT_ROOT" -v exports="$EXPORTS" -v tools="$TOOLS" \
        -v logs="$LOGS" -v runtime="$RUNTIME" '
        /^(LogsDirectory|RuntimeDirectory|LogsDirectoryMode|RuntimeDirectoryMode)=/ { next }
        /^ExecStart=/ { print "ExecStart=" binary " serve --config " config; next }
        { print }
        /^\[Service\]$/ {
            print "RuntimeDirectory=" service
            print "RuntimeDirectoryMode=0700"
            print "LogsDirectory=" service
            print "LogsDirectoryMode=0700"
            print "UMask=0077"
            print "LimitCORE=0"
            print "UnsetEnvironment=CF_API_TOKEN"
            print "PrivateIPC=yes"
            print "ProtectProc=invisible"
            print "SystemCallFilter=~@mount @reboot @swap @raw-io @debug @cpu-emulation @obsolete memfd_create"
            print "InaccessiblePaths=-" certroot " -" exports " -" tools " -/dev/shm"
            print "NoExecPaths=/tmp /var/tmp " logs " " runtime
        }
    ' "$REPO/deploy/network-relay.service"
}
# Build an argv array rather than command text. The Apple profile uses bundled
# selected-domain rules and excludes the relay itself to avoid routing loops.
nr_profile_args() {
    profile_args=(profile --host "$domain" --user "$device_user" --exclude-domain "$domain"
        --ui-toggle-enabled true --out "$PROFILE")
    if [[ $scope == selected ]]; then
        local value file count=0
        for file in google-ai-social.txt global-services.txt; do
            while IFS= read -r value || [[ -n $value ]]; do
                value=${value%%#*}
                value=${value//[$' \t\r']/}
                [[ -n $value ]] || continue
                nr_domain "$value" || nr_die "Invalid bundled domain in $file."
                profile_args+=(--match-domain "$value")
                count=$((count + 1))
            done < "$REPO/deploy/domains/$file"
        done
        (( count > 0 )) || nr_die 'Refusing an empty selected-domain profile.'
    fi
}
# Reuse only the independently checked non-login, unshared identity. Account
# creation happens before staging but does not stop the currently running unit.
nr_account() {
    nr_check_account
    if ! id -u "$SERVICE" >/dev/null 2>&1; then
        if getent group "$SERVICE" >/dev/null; then
            useradd --system --gid "$SERVICE" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE"
        else
            useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE"
        fi
    fi
    nr_check_account
    nr_check_leaf /nonexistent rootdir
    # Narrow repair of this same-named identity only: no -m/-u, so the old home
    # is neither moved nor chowned, and other accounts/groups are unchanged.
    # Shell, supplementary groups and password lock have no in-use check.
    usermod --shell /usr/sbin/nologin --groups '' --lock "$SERVICE"
    nr_account_home
    nr_verify_account
}
# usermod refuses a home change while any process runs as the account, e.g.
# the old relay during an upgrade. The change then waits until the previous
# instances are stopped inside the transaction (it is not rolled back).
nr_account_home() {
    local home
    home=$(getent passwd "$SERVICE" | cut -d: -f6)
    account_home_pending=0
    [[ $home != /nonexistent ]] || return 0
    if ! usermod --home /nonexistent "$SERVICE" 2>/dev/null; then
        account_home_pending=1
        printf 'The service account is in use; its home changes after the previous relay stops.\n'
    fi
}
# Export the same account used by both server and Apple profile. This format is
# accepted by the Rust GUI importer and headless client. Loopback-only SOCKS does
# not expose an unauthenticated LAN proxy. Apple selected-domain routing rules
# are not part of SOCKS configuration; applications choose traffic for the proxy.
nr_client_config_text() {
    # Validated domain/user and the base64 password alphabet are TOML-safe.
    cat <<EOF
# Network Relay RS client configuration. Contains a password: keep private.
# Import into Network Relay RS, or run network-relay-rs --config FILE.
uri_template = "https://$domain/.well-known/masque/udp/{target_host}/{target_port}/"
username = "$device_user"
password = "$relay_password"
transport = "auto"
mode = "socks"

[socks]
listen = ["127.0.0.1:1080"]
EOF
}
# Generate exactly 22 base64 characters from OpenSSL's cryptographic
# RNG, requiring uppercase, lowercase, digits and + or /. Resample the whole
# candidate instead of inserting a predictable character-class prefix/suffix.
# The alphabet needs no TOML/XML/Basic-auth escaping and contains no colon.
nr_generate_password() {
    local candidate
    export -n candidate
    while :; do
        candidate=$(openssl rand -base64 18) || return
        [[ $candidate =~ ^[A-Za-z0-9+/]{24}$ ]] || nr_die 'OpenSSL returned invalid password material.'
        candidate=${candidate:0:22}
        if [[ $candidate =~ [A-Z] && $candidate =~ [a-z] && $candidate =~ [0-9] && $candidate =~ [+/] ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
}
# Read only the installer's root-private TOML, never source/eval it. Reusing a
# trusted same-domain 22-character password avoids breaking existing clients;
# all configuration and the Argon2id server hash are still regenerated.
nr_recover_credentials() {
    local old_domain old_user old_password
    # A password from a linked, foreign-owned or group/other-readable export may
    # be exposed or planted: generate a new one rather than reuse it.
    [[ -f $CLIENT_CONFIG && ! -L $CLIENT_CONFIG && $(stat -c '%u' -- "$CLIENT_CONFIG") == 0 ]] || return 1
    (( (8#$(stat -c %a -- "$CLIENT_CONFIG") & 0077) == 0 )) || return 1
    old_domain=$(sed -n 's|^uri_template = "https://\([^/]*\)/.well-known/masque/udp/{target_host}/{target_port}/"$|\1|p' "$CLIENT_CONFIG")
    old_user=$(sed -n 's/^username = "\([A-Za-z0-9_-][A-Za-z0-9_.-]*\)"$/\1/p' "$CLIENT_CONFIG")
    old_password=$(sed -n 's/^password = "\([A-Za-z0-9+/]*\)"$/\1/p' "$CLIENT_CONFIG")
    [[ $old_domain == "$domain" && $old_user == "$device_user" && ${#old_password} == 22 ]] || return 1
    [[ $old_password =~ [A-Z] && $old_password =~ [a-z] && $old_password =~ [0-9] && $old_password =~ [+/] ]] || return 1
    relay_password=$old_password
    credentials_reused=1
}
# Normal Certbot live/ files are symlinks into archive/. They are read, not
# replaced here. Validate the leaf's dates, hostname, trusted chain and key pair
# before declaring a certificate reusable. Offline validation cannot prove that
# Cloudflare permissions or future ACME requests will succeed.
nr_certificate_valid() {
    local certificate=$1 key=$2 certificate_key private_key
    [[ -f $certificate && -f $key ]] || return 1
    openssl x509 -in "$certificate" -noout -checkend 0 >/dev/null 2>&1 || return 1
    openssl x509 -in "$certificate" -noout -checkhost "$domain" >/dev/null 2>&1 || return 1
    openssl verify -purpose sslserver -verify_hostname "$domain" -untrusted "$certificate" "$certificate" >/dev/null 2>&1 || return 1
    certificate_key=$(openssl x509 -in "$certificate" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum) || return 1
    private_key=$(openssl pkey -in "$key" -passin pass: -pubout -outform DER 2>/dev/null | sha256sum) || return 1
    [[ $certificate_key == "$private_key" ]]
}
# Certbot 2.1 (Debian 12) does not provide reconfigure. Preserve existing
# account/server/archive/file metadata and change only this lineage's renewal
# parameters, with a private backup. Inserting at the section start keeps these
# scalars out of any old [[webroot_map]] child section. None disables an old
# installer or per-lineage shell hook without modifying global hooks/lineages.
# This follows Certbot's advanced renewal-file editing mechanism; `certificates`
# checks storage/INI readability, not actual DNS authorization. A later optional
# `certbot renew --dry-run --cert-name DOMAIN` can exercise staging renewal.
nr_renewal_text() {
    awk -v credentials="$CREDS" '
        function parameters() {
            print "authenticator = dns-cloudflare"
            print "installer = None"
            print "dns_cloudflare_credentials = " credentials
            print "dns_cloudflare_propagation_seconds = 60"
            print "pref_challs = dns-01,"
            print "autorenew = True"
            print "pre_hook = None"
            print "post_hook = None"
            print "renew_hook = None"
            print "deploy_hook = None"
        }
        /^[[:space:]]*\[renewalparams\][[:space:]]*([#;].*)?$/ {
            if (seen++) exit 43
            print; parameters(); in_renewal=1; next
        }
        /^[[:space:]]*\[/ { in_renewal=0 }
        in_renewal && /^[[:space:]]*(authenticator|installer|dns_cloudflare_credentials|dns_cloudflare_propagation_seconds|pref_challs|autorenew|pre_hook|post_hook|renew_hook|deploy_hook)[[:space:]]*=/ {next}
        {print}
        END {if (!seen) {print ""; print "[renewalparams]"; parameters()}}
    ' "$1"
}
# A missing renewal file can be reconstructed only for a complete managed
# Certbot layout and one unambiguous existing Let's Encrypt account. Arbitrary
# external PEM files or lost/multiple accounts need their original metadata;
# never reissue an otherwise valid certificate merely to hide that loss.
nr_reconstruct_renewal() {
    local lineage=$CERT_ROOT/live/$domain archive=$CERT_ROOT/archive/$domain name target resolved account count=0 version
    resolved=$(readlink -f -- "$archive") || nr_die 'Valid certificate exists but its Certbot archive is missing; restore its renewal metadata.'
    for name in cert privkey chain fullchain; do
        [[ -L $lineage/$name.pem && -f $lineage/$name.pem ]] || nr_die 'Valid certificate exists but a complete managed Certbot lineage is missing; restore its renewal metadata.'
        target=$(readlink -f -- "$lineage/$name.pem") || nr_die 'Cannot resolve existing Certbot certificate files.'
        [[ $target == "$resolved/"* ]] || nr_die 'Existing certificate files do not belong to this Certbot archive.'
    done
    local accounts=$CERT_ROOT/accounts/acme-v02.api.letsencrypt.org/directory
    if [[ -d $accounts ]]; then
        while IFS= read -r target; do
            name=${target##*/}
            [[ $name =~ ^[a-f0-9]{32,64}$ && -f $target/regr.json && -f $target/private_key.json && -f $target/meta.json ]] || continue
            account=$name; count=$((count + 1))
        done < <(find -P "$accounts" -mindepth 1 -maxdepth 1 -type d -print)
    fi
    (( count == 1 )) || nr_die 'Valid certificate was not reissued, but its missing renewal file needs an unambiguous existing ACME account; restore the original renewal metadata.'
    version=$("$CERTBOT" --version); version=${version#certbot }
    [[ $version =~ ^[0-9]+([.][0-9]+)+$ ]] || nr_die 'Cannot determine Certbot version for renewal-file recovery.'
    cat <<EOF
version = $version
archive_dir = $archive
cert = $lineage/cert.pem
privkey = $lineage/privkey.pem
chain = $lineage/chain.pem
fullchain = $lineage/fullchain.pem

[renewalparams]
account = $account
server = https://acme-v02.api.letsencrypt.org/directory
EOF
}
# The API source is domain-specific so a new hostname cannot overwrite another
# lineage's old credential binding. Preserve Certbot accounts/archive/live state.
# Back up this domain's renewal configuration and credential before updating it;
# successful issuance is persistent ACME state, outside the service transaction.
nr_prepare_certificate() {
    local lineage=$CERT_ROOT/live/$domain renewal=$CERT_ROOT/renewal/$domain.conf cert_backup previous=0
    local reused=0 parser_output
    # The token file is replaced by rename below; a bad mode or link is repaired.
    nr_check_parent_dirs "$CREDS"
    nr_check_leaf "$renewal" file
    install -d -o root -g root -m 700 "$TOOLS/backups"
    cert_backup=$(mktemp -d "$TOOLS/backups/certificate-$(date -u +%Y%m%d-%H%M%S).XXXXXXXX")
    if [[ -e $CREDS ]]; then cp -a -- "$CREDS" "$cert_backup/credentials.ini"; fi
    if [[ -e $renewal ]]; then cp -a -- "$renewal" "$cert_backup/renewal.conf"; previous=1; fi
    printf 'Private certificate-state backup: %s\n' "$cert_backup"
    printf 'dns_cloudflare_api_token = %s\n' "$cf_token" > "$work/credentials.ini"
    chmod 600 "$work/credentials.ini"
    unset cf_token
    [[ -d $CERT_ROOT ]] || install -d -m 700 "$CERT_ROOT"
    nr_atomic_install "$work/credentials.ini" "$CREDS" 600
    if nr_certificate_valid "$lineage/fullchain.pem" "$lineage/privkey.pem"; then
        reused=1
        printf 'Existing valid certificate for %s is reused; no certonly/renewal request is made.\n' "$domain"
        if (( previous )); then cp -a -- "$renewal" "$work/renewal-base.conf"; else nr_reconstruct_renewal > "$work/renewal-base.conf"; fi
    else
        printf 'No valid matching certificate/key pair for %s; requesting DNS-01 issuance.\n' "$domain"
        # force-renewal is confined to this invalid/missing-certificate branch;
        # it is never used to migrate an already valid lineage's authenticator.
        "$CERTBOT" certonly --config-dir "$CERT_ROOT" --non-interactive --agree-tos --register-unsafely-without-email \
            --dns-cloudflare --dns-cloudflare-credentials "$CREDS" --dns-cloudflare-propagation-seconds 60 \
            --preferred-challenges dns-01 --cert-name "$domain" -d "$domain" --force-renewal
        nr_certificate_valid "$lineage/fullchain.pem" "$lineage/privkey.pem" || nr_die 'Certbot returned without a valid matching certificate/key pair.'
        [[ -f $renewal && ! -L $renewal ]] || nr_die 'Certbot did not create a renewal configuration.'
        cp -a -- "$renewal" "$work/renewal-base.conf"
    fi
    nr_renewal_text "$work/renewal-base.conf" > "$work/renewal.conf"
    install -d -m 755 "$CERT_ROOT/renewal"
    nr_atomic_install "$work/renewal.conf" "$renewal" 600
    # `certificates` never requests a certificate. Verify it can read the updated
    # managed layout and selects this exact lineage before touching the server.
    if "$CERTBOT" certificates --config-dir "$CERT_ROOT" --cert-name "$domain" --non-interactive > "$work/certificate-check.log" 2>&1; then
        parser_output=$(sed -n 's/^[[:space:]]*Certificate Name: //p' "$work/certificate-check.log")
        if [[ $parser_output == "$domain" ]]; then return 0; fi
    fi
    # A valid pre-existing renewal configuration remains recoverable on parser
    # failure. Do not pretend that a readable certificate alone proves renewal.
    if (( previous )); then nr_atomic_install "$cert_backup/renewal.conf" "$renewal" 600; fi
    nr_die "Certbot cannot read the updated renewal metadata; inspect private backup $cert_backup."
}
# Background wrapper. errexit is ignored inside `if`/`||` contexts, so run the
# subshell as a plain command after set +e, then report its status. A failure
# is shown at once; the installer stops after the concurrent build returns.
nr_certificate_job() {
    local status=0
    set +e
    # Ctrl+C must not stop Certbot between issuance and saving the lineage,
    # which would lose an issued certificate; the ignored disposition is
    # inherited by Certbot. Cleanup waits for this bounded request instead.
    ( set -e; trap '' INT; nr_prepare_certificate ) > "$work/certificate.log" 2>&1
    status=$?
    if (( status )); then
        printf 'Certificate preparation failed; the installer stops after the running build:\n' >&2
        cat -- "$work/certificate.log" >&2
    fi
    return "$status"
}
nr_wait_certificate() {
    local status=0
    wait "$certificate_job" || status=$?
    certificate_job=
    (( status == 0 )) || nr_die 'Certificate preparation failed; see the messages above. No deployed file was changed.'
    cat -- "$work/certificate.log"
}
# Stage both certificate copies, configuration and exports before stopping the
# old unit. The candidate is exposed read-only at a stable runtime mount so the
# actual service UID can validate it without traversing root-only build caches.
nr_prepare() {
    local candidate=$work/candidate validation_root=/run/$SERVICE-candidate
    install -d -o root -g "$SERVICE" -m 750 "$candidate"
    install -d -o root -g root -m 700 "$work/exports"
    install -o root -g root -m 755 "$work/$SERVICE" "$candidate/$SERVICE"
    install -d -o root -g "$SERVICE" -m 750 "$candidate/current"
    install -o root -g "$SERVICE" -m 640 "$CERT_ROOT/live/$domain/fullchain.pem" "$candidate/current/fullchain.pem"
    install -o root -g "$SERVICE" -m 640 "$CERT_ROOT/live/$domain/privkey.pem" "$candidate/current/privkey.pem"
    credentials_reused=0
    if nr_recover_credentials; then
        printf 'Reusing the existing private client password; configuration follows the current script.\n'
    else
        relay_password=$(nr_generate_password)
        printf 'A new 22-character relay password was generated; refresh old clients from the new exports.\n'
    fi
    account=$(printf '%s\n' "$relay_password" | "$work/$SERVICE" passwd --name "$device_user" --stdin)
    [[ $account == *'[[user]]'* && $account == *'password_hash = "$argon2id$'* ]] || nr_die 'Unexpected Argon2id password hash output.'
    nr_config_text > "$work/config"
    (
        local TLS=$validation_root
        nr_config_text > "$candidate/relay.toml"
    )
    chmod 640 "$candidate/relay.toml"
    chown root:"$SERVICE" "$candidate/relay.toml"
    nr_unit_text > "$work/unit"
    nr_hook_text > "$work/hook"
    chmod 644 "$work/unit"; chmod 700 "$work/hook"
    (
        local PROFILE=$work/exports/device.mobileconfig
        nr_profile_args
        printf '%s\n' "$relay_password" | "$work/$SERVICE" "${profile_args[@]}"
    )
    nr_client_config_text > "$work/exports/network-relay-rs-client.toml"
    chmod 600 "$work/exports/"*
    # systemd-run resolves its first executable in the host namespace, before
    # BindReadOnlyPaths exists. Start the host's env, which execs the candidate
    # inside the unit namespace; --wait still propagates validation failures.
    systemd-run --no-ask-password --unit="$SERVICE-validate" --collect --wait --pipe --service-type=exec \
        --property="User=$SERVICE" --property="Group=$SERVICE" --property=UMask=0077 \
        --property="RuntimeDirectory=$SERVICE-validate" --property=RuntimeDirectoryMode=0700 \
        --property="BindReadOnlyPaths=$candidate:$validation_root" \
        /usr/bin/env -- "$validation_root/$SERVICE" serve --config "$validation_root/relay.toml" --check
}
# A first install may have no unit yet: systemctl stop then returns "not loaded".
# That is harmless only when the dedicated service is inactive and every 443
# socket is free. Never hide a real stop failure or kill an unrelated listener.
nr_stop_service() {
    nr_unit_identity || return 1
    if ! systemctl stop "$SERVICE" >/dev/null 2>&1; then
        if systemctl is-active --quiet "$SERVICE"; then nr_die 'Cannot stop the existing relay service.'; fi
    fi
    if systemctl is-active --quiet "$SERVICE"; then nr_die 'The existing relay service did not stop.'; fi
    nr_stop_standalone
    nr_ports_free
}
# Recheck identity immediately before each signal; this narrows, but cannot
# close, the window in which an exited relay's PID is reused (Bash has no
# pidfd). TERM first, KILL only after a bounded grace.
nr_signal_standalone() {
    local signal=$1 pid
    while IFS= read -r pid; do
        [[ -n $pid ]] || continue
        if nr_is_relay_pid "$pid" && kill -s "$signal" -- "$pid" 2>/dev/null; then
            printf 'Sent %s to manually started previous %s process %s.\n' "$signal" "$SERVICE" "$pid"
        fi
    done < <(nr_standalone_pids)
}
nr_stop_standalone() {
    local attempt
    [[ -n $(nr_standalone_pids) ]] || return 0
    nr_signal_standalone TERM
    for ((attempt=0; attempt<15; attempt++)); do
        [[ -n $(nr_standalone_pids) ]] || return 0
        (( attempt != 10 )) || nr_signal_standalone KILL
        sleep 1
    done
    nr_die 'A manually started previous relay process did not exit.'
}
# Used after the stop and again immediately before the start: another program
# may bind the released port while files are replaced. Report it; never stop it.
nr_ports_free() {
    local occupied
    occupied=$(nr_port_inodes) || nr_die 'Cannot verify that 443 was released.'
    if [[ -n $occupied ]]; then
        nr_report_ports || true
        nr_die 'TCP/UDP 443 is still occupied; no unrelated process was stopped.'
    fi
}
# The current script replaces dedicated files after a validated build/stage.
# Retain old websites/logs/ACME state; preserve complete file and unit-state
# backups. On failure after the switch, restore old files and active/enabled
# state. A missing old binary/config from manual deletion is honestly reported.
nr_deploy() {
    local relay_password account key current response ready=0 attempt path index existed type
    # Clear an inherited export attribute as well as disabling bash -a above.
    export -n relay_password account
    nr_fresh
    nr_account
    # Shared parents are never chmodded. Only create absent standard directories
    # after their existing ancestors have passed the root-ownership checks.
    for path in "$BIN" "$UNIT" "$SYSCTL" "$HOOK"; do
        if [[ ! -d ${path%/*} ]]; then install -d -o root -g root -m 755 "${path%/*}"; fi
    done
    install -d -o root -g "$SERVICE" -m 750 "$ETC" "$TLS"
    install -d -o root -g root -m 700 "$EXPORTS"
    [[ -d ${WWW%/*} ]] || install -d -m 755 "${WWW%/*}"
    if [[ ! -e $WWW ]]; then install -d -m 755 "$WWW"; fi
    if [[ -z $(find -P "$WWW" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
        printf '<!doctype html>\n<title>Welcome</title>\n<h1>Welcome</h1>\n' | nr_new_file "$WWW/index.html" 644
    fi
    nr_prepare
    nr_ports
    {
        printf '# UDP buffer limits for Network Relay.\n'
        for key in net.core.rmem_max net.core.wmem_max; do
            current=$(sysctl -n "$key")
            [[ $current =~ ^[0-9]+$ ]] || nr_die 'Cannot read socket-buffer ceilings.'
            (( current >= 8388608 )) || current=8388608
            printf '%s = %s\n' "$key" "$current"
        done
    } > "$work/sysctl"
    nr_lock_tls
    nr_backup
    # Lock waits and private backup copies can take time. Prove ownership again
    # before the first deployed mutation, without stopping anything on conflict.
    nr_ports
    transaction_started=1
    printf '%s\n%s\n' "$CERT_ROOT/live/$domain" "$domain" > "$work/desired-source"
    nr_atomic_install "$work/desired-source" "$TLS/.desired-source" 600
    # PID 1 cannot stop a locally masked unit until its managed mask is replaced.
    # Retain the loaded old unit for ordinary upgrades; repair only actual masks.
    local unit_path
    for unit_path in "$UNIT" "/run/systemd/system/$SERVICE.service"; do
        if [[ -L $unit_path && $(readlink -- "$unit_path") == /dev/null ]]; then rm -- "$unit_path"; fi
    done
    systemctl daemon-reload
    nr_stop_service
    if (( account_home_pending )); then
        usermod --home /nonexistent "$SERVICE" || nr_die 'Cannot change the service account home after stopping the previous relay.'
        account_home_pending=0
        nr_verify_account
    fi
    rm -f -- "/run/systemd/system/$SERVICE.service"
    while IFS=$'\t' read -r index existed type path; do
        if [[ $type == dir && -d $path ]]; then rm -rf -- "$path"; fi
    done < "$backup_dir/manifest"
    nr_atomic_install "$work/$SERVICE" "$BIN" 755
    nr_atomic_install "$work/config" "$CONFIG" 640 "$SERVICE"
    nr_atomic_install "$work/unit" "$UNIT" 644
    nr_atomic_install "$work/hook" "$HOOK" 700
    NR_TLS_LOCK_FD=$tls_lock "$HOOK" --no-reload
    nr_atomic_install "$work/sysctl" "$SYSCTL" 644
    nr_unlock_tls
    systemctl daemon-reload
    # Replace only this unit's stale enablement entries after recording them.
    rm -f -- "/etc/systemd/system/multi-user.target.wants/$SERVICE.service" "/run/systemd/system/multi-user.target.wants/$SERVICE.service"
    systemctl enable "$SERVICE"
    nr_ports_free
    systemctl start "$SERVICE"
    for ((attempt=0; attempt<30; attempt++)); do
        systemctl is-active --quiet "$SERVICE" || nr_die 'Candidate stopped during HTTPS readiness; restoring the previous deployment.'
        if curl --disable --noproxy '*' --silent --show-error --output /dev/null --max-time 3 \
            --resolve "$domain:443:127.0.0.1" "https://$domain/" 2>/dev/null; then ready=1; break; fi
        sleep 1
    done
    (( ready )) || nr_die 'Trusted HTTPS readiness failed; restoring the previous deployment.'
    if ! printf '%s\n' "$relay_password" | "$BIN" check --server "$domain" --address 127.0.0.1 --user "$device_user"; then
        nr_die 'Protocol checks failed; restoring the previous deployment.'
    fi
    nr_atomic_install "$work/exports/device.mobileconfig" "$PROFILE" 600
    nr_atomic_install "$work/exports/network-relay-rs-client.toml" "$CLIENT_CONFIG" 600
    systemctl enable --now certbot.timer
    [[ $(systemctl is-enabled certbot.timer) == enabled ]] || nr_die 'Certbot renewal timer is not enabled at boot.'
    systemctl is-active --quiet certbot.timer || nr_die 'Certbot renewal timer is not active.'
    [[ $(systemctl is-enabled "$SERVICE") == enabled ]] || nr_die 'Relay is not enabled at boot.'
    systemctl is-active --quiet "$SERVICE" || nr_die 'Relay is not active after protocol checks.'
    unset relay_password
    transaction_started=0
    sysctl -p "$SYSCTL" || printf 'Warning: socket-buffer tuning was denied; existing runtime settings remain.\n'
    printf 'All TCP/UDP checks passed; %s and certbot.timer are active and enabled at boot.\n' "$SERVICE"
    printf 'Apple profile: %s; Rust client TOML: %s (root-only, mode 600).\n' "$PROFILE" "$CLIENT_CONFIG"
    printf 'Keep %s and Certbot archive/account state for automatic DNS renewal.\n' "$CREDS"
    printf 'Private deployment backup: %s. Optional staging renewal test: certbot renew --dry-run --cert-name %s\n' "$backup_dir" "$domain"
}
# Only these two values are interactive. An inherited CF_API_TOKEN can supply
# the token directly; otherwise read it silently. Existing Certbot state is
# inspected separately, with valid certificates reused and DNS renewal updated.
# Accept the legacy token alphabet and newer cfut_/cfat_ prefixes, including
# their documented maximum body length. This is only syntax validation, not a
# remote permission check. Diagnostics must not echo a rejected secret value.
nr_token_valid() {
    [[ $1 =~ ^[A-Za-z0-9_-]{35,50}$ || $1 =~ ^cf(ut|at)_[A-Za-z0-9_-]{32,256}$ ]]
}
# A rerun may press Enter to keep this domain's saved root-only renewal token.
# Read it only from the dedicated file and by a strict line pattern, never by
# sourcing; it is then rewritten root-only (0600). Return 1 without a usable
# token, so the caller reports it instead of a misleading syntax error.
nr_saved_token_usable() {
    # Never read a secret through a link or from a file another account owns.
    [[ -f $CREDS && ! -L $CREDS && $(stat -c %u -- "$CREDS") == 0 ]]
}
nr_saved_token() {
    local token
    export -n token
    nr_check_parent_dirs "$CREDS"
    nr_saved_token_usable || return 1
    token=$(sed -n 's/^dns_cloudflare_api_token = \([A-Za-z0-9_-]*\)$/\1/p' "$CREDS")
    [[ -n $token ]] || return 1
    if (( (8#$(stat -c %a -- "$CREDS") & 0077) != 0 )); then
        printf 'The saved renewal token was accessible to other accounts; it is rewritten root-only. Consider rotating it at Cloudflare.\n' >&2
    fi
    printf '%s\n' "$token"
}
nr_inputs() {
    nr_ask 'Relay domain'; domain=${REPLY,,}; domain=${domain%.}
    nr_domain "$domain" || nr_die 'Invalid DNS hostname; omit scheme, port and wildcard.'
    CREDS=$CERT_ROOT/$SERVICE-cloudflare-$domain.ini
    printf 'Use a zone-scoped token with Zone:DNS:Edit and Zone:Zone:Read.\n'
    if [[ -z $cf_token ]]; then
        if nr_saved_token_usable; then
            read -r -s -p 'CF_API_TOKEN (hidden; Enter keeps the saved renewal token): ' cf_token </dev/tty || nr_die 'Could not read token.'
        else
            read -r -s -p 'CF_API_TOKEN (hidden): ' cf_token </dev/tty || nr_die 'Could not read token.'
        fi
        printf '\n'
        if [[ -z $cf_token ]]; then
            cf_token=$(nr_saved_token) || nr_die 'No safe saved renewal token exists for this domain; enter a Cloudflare API Token.'
        fi
    fi
    nr_token_valid "$cf_token" || nr_die 'Expected a Cloudflare API Token.'
}
# Suppress package-manager and Git credential prompts. Commands cannot consume
# extra terminal answers because stdin is EOF; explicit secret pipes still work.
nr_noninteractive() {
    # Explicit password pipes and domain-list files still supply their own input.
    exec </dev/null
    export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
}
# DPkg::Lock::Timeout makes apt-get wait only for the dpkg locks. The package
# list and archive locks (held by apt-daily's own update at boot) still fail at
# once, so retry exactly that failure for up to 30 minutes. Other errors are
# returned immediately; apt's output is shown after each attempt.
nr_apt() {
    local attempt status errors
    errors=$(mktemp) || return
    for ((attempt=1; ; attempt++)); do
        status=0
        apt-get "$@" 2> "$errors" || status=$?
        cat -- "$errors" >&2
        if (( status == 0 )) || (( attempt >= 180 )) || ! grep -Eq '^E: (Could not get lock|Unable to lock)' "$errors"; then
            rm -f -- "$errors"
            return "$status"
        fi
        printf 'Another package manager holds an apt lock; retrying in 10 seconds...\n' >&2
        sleep 10
    done
}
# Check the manager version before credentials or installation: do not silently
# rely on a sandbox directive that an older manager would ignore as unknown.
nr_require_systemd() {
    local version
    version=$(systemd --version) || nr_die 'Cannot determine the systemd version.'
    version=${version%%$'\n'*}
    [[ $version =~ ^systemd[[:space:]]([0-9]+) ]] || nr_die 'Cannot determine the systemd version.'
    (( 10#${BASH_REMATCH[1]} >= 249 )) || nr_die 'systemd 249+ is required for the service sandbox.'
}
# Sequence preflight before input/packages, compile before service installation,
# and keep every optional deployment choice fixed to the documented defaults.
nr_main() {
    case ${1:-} in
        -h|--help) nr_usage; return ;;
        --plan) [[ $# == 1 ]] || nr_die 'Unexpected extra arguments.'; nr_host
            printf '%s: native Linux/%s build, Certbot Cloudflare DNS-01, systemd, device profile and checks.\n' "$SERVICE" "$arch"; return ;;
        '') ;;
        *) nr_die 'Unknown option; use --help or --plan.' ;;
    esac
    nr_host
    [[ $EUID == 0 && -d /run/systemd/system ]] || nr_die 'Run as root on a server booted with systemd.'
    # Keep the token shell-local rather than exposing it to builds/packages.
    local cf_token=${CF_API_TOKEN:-} jobs path plugins free_kib
    unset CF_API_TOKEN
    export -n cf_token
    nr_require_systemd
    umask 077
    command -v flock >/dev/null || nr_die 'flock from util-linux is required.'
    # A persistent root-owned lock directory serializes competing installers.
    nr_acquire_lock
    nr_fresh
    nr_inputs
    nr_noninteractive
    device_user=iphone
    scope=selected
    jobs=1
    printf 'Defaults: user iphone, one build job, bundled selected-domain profile.\n'
    printf 'DNS-01 needs no A/AAAA records. For direct clients, route DNS-only records here and allow TCP/UDP 443.\n'
    printf 'This installs packages, builds this checkout, stores the token root-only,\naccepts Let\047s Encrypt terms, and enables the service and certbot.timer.\n'
    # This script requires the complete checkout, including local transport
    # patches and the repository unit template; it is not a standalone bundle.
    local required=(deploy/domains/google-ai-social.txt deploy/domains/global-services.txt)
    required+=(Cargo.toml Cargo.lock src/main.rs deploy/network-relay.service)
    for path in "${required[@]}"; do [[ -f $REPO/$path ]] || nr_die "Complete checkout required; missing $path."; done
    free_kib=$(df -Pk /opt | awk 'NR==2 {print $4}')
    [[ $free_kib =~ ^[0-9]+$ ]] && (( free_kib >= 5*1024*1024 )) || nr_die 'At least 5 GiB free under /opt is required.'
    # Bound dpkg-lock waits, retry downloads and preserve existing conffiles.
    # The installation list deliberately contains no firewall package.
    local apt=(nr_apt -o DPkg::Lock::Timeout=1800 -o Acquire::Retries=3
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
    "${apt[@]}" update
    "${apt[@]}" install -y --no-install-recommends \
        ca-certificates curl certbot python3-certbot-dns-cloudflare build-essential pkg-config iproute2 openssl
    plugins=$("$CERTBOT" plugins)
    [[ $plugins == *dns-cloudflare* ]] || nr_die 'The apt Certbot cannot load dns-cloudflare.'
    if nr_certificate_valid "$CERT_ROOT/live/$domain/fullchain.pem" "$CERT_ROOT/live/$domain/privkey.pem"; then
        printf 'Certificate check: a currently valid matching certificate exists; it will be retained.\n'
    else
        printf 'Certificate check: DNS-01 issuance is needed; it runs concurrently with the build.\n'
    fi
    nr_check_leaf "$TOOLS" rootdir
    install -d -m 700 "$TOOLS"
    nr_check_leaf "$TOOLS/backups" rootdir
    install -d -o root -g root -m 700 "$TOOLS/backups"
    work=$(mktemp -d "$TOOLS/build.XXXXXXXX")
    # Install traps only after this run owns a unique scratch directory.
    trap nr_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # DNS-01 issuance (or reuse/renewal-metadata repair) needs no compiled
    # binary: run it while Rust builds. The shell keeps no token copy afterwards.
    nr_certificate_job &
    certificate_job=$!
    unset cf_token
    nr_build "$jobs"
    nr_wait_certificate
    nr_deploy
}

# Sourcing exposes helpers for isolated tests without inspecting/installing a
# real host. Executing directly turns on strict pipeline/error/variable checks.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -Eeuo pipefail
    unset CDPATH
    export LC_ALL=C
    nr_main "$@"
fi
