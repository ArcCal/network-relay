#!/usr/bin/env bash
# Interactive repeatable deployment: native Linux build + Certbot Cloudflare DNS-01.
# Requires Debian 12+ or Ubuntu 24.04+, Bash 4+, systemd and amd64/arm64.
# Run from the complete checkout on the server. --plan makes no changes.
# Token permissions: Zone:DNS:Edit and Zone:Zone:Read for the selected zone.
# Keep DNS-only A/AAAA records pointing here; allow inbound TCP/UDP 443.
# DNS validation does not need inbound port 80. No Python helper is used.
#
# Repeatable deployment/repair sequence:
#   1. Check the host, dedicated path ownership, account and socket ownership.
#   2. Read only the relay domain and a hidden Cloudflare token.
#   3. Install prerequisites noninteractively; verify and build native Rust.
#   4. Reuse a valid domain certificate, or obtain one with DNS-01 when needed.
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

nr_die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
nr_usage() {
    cat <<EOF
Usage: sudo bash ${0##*/}
       bash ${0##*/} --plan

Build this checkout for the server's native amd64/arm64 architecture. Prompt
only for the relay domain and hidden CF_API_TOKEN. Install apt
Certbot with its Cloudflare DNS plugin, obtain a DNS-01 certificate, configure
renewal/reload, systemd, a website and a protected Apple device profile, then
run HTTPS and TCP/UDP protocol checks, then generate a private Rust client TOML.
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
Set Cloudflare A/AAAA records to DNS only and permit inbound TCP/UDP 443.
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
nr_domain() {
    local value=$1
    (( ${#value} <= 253 )) && [[ $value =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]{2,63}$ ]]
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
    local entry name ignored uid gid gecos home shell members aliases group_entry primary users groups item
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
    [[ $home == /nonexistent || $home == /var/lib/$SERVICE ]] || nr_die 'Existing service account has an unrelated home directory.'
    case $shell in /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false) ;; *) nr_die 'Existing service account has a login shell.' ;; esac
    [[ -n $group_entry ]] || nr_die 'Dedicated primary group is missing.'
    IFS=: read -r name ignored primary members <<< "$group_entry"
    [[ $primary == "$gid" && -z $members && $(id -gn "$SERVICE") == "$SERVICE" ]] || nr_die 'Existing service account/group is shared or mismatched.'
    aliases=$(getent passwd | awk -F: -v uid="$uid" '$3 == uid {n++} END {print n+0}')
    users=$(getent passwd | awk -F: -v gid="$gid" '$4 == gid {n++} END {print n+0}')
    [[ $aliases == 1 && $users == 1 ]] || nr_die 'Existing service UID/GID is shared by another account.'
    aliases=$(getent group | awk -F: -v gid="$gid" '$3 == gid {n++} END {print n+0}')
    [[ $aliases == 1 ]] || nr_die 'Existing primary GID has another group alias.'
    groups=$(id -G "$SERVICE")
    for item in $groups; do [[ $item == "$gid" ]] || nr_die 'Dedicated account has supplementary groups.'; done
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
nr_port_inodes() {
    local sockets=(/proc/net/tcp /proc/net/udp) file
    for file in /proc/net/tcp6 /proc/net/udp6; do [[ ! -r $file ]] || sockets+=("$file"); done
    for file in "${sockets[@]}"; do [[ -r $file ]] || nr_die "Cannot inspect listening sockets: $file."; done
    awk 'FNR > 1 && $2 ~ /:01BB$/ && (FILENAME ~ /udp/ || $4 == "0A") {print $10}' "${sockets[@]}"
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
nr_ports() {
    local occupied pid owned inode found item
    occupied=$(nr_port_inodes) || nr_die 'Cannot inspect listening sockets; port availability is unknown.'
    [[ -n $occupied ]] || return 0
    pid=$(systemctl show "$SERVICE" --property=MainPID --value) || nr_die 'Cannot inspect dedicated service MainPID.'
    [[ $pid =~ ^[0-9]+$ && $pid != 0 ]] || nr_die 'TCP or UDP 443 belongs to another process; no other service was stopped.'
    owned=$(nr_pid_socket_inodes "$pid") || nr_die 'Cannot establish service socket ownership.'
    while IFS= read -r inode; do
        [[ $inode =~ ^[0-9]+$ ]] || nr_die 'Invalid kernel socket record.'
        found=0
        while IFS= read -r item; do [[ $inode != "$item" ]] || found=1; done <<< "$owned"
        (( found )) || nr_die 'TCP or UDP 443 belongs to another process; no other service was stopped.'
    done <<< "$occupied"
}
# Compatibility name retained for existing usage/tests; this is now a safe
# installation preflight, not an existence-based fresh-install gate.
# Permit safe prior deployments and interrupted attempts; never require users to
# delete paths one by one. Unknown symlinks, writable roots and shared accounts
# are still rejected, because replacement must not affect another workload.
nr_fresh() {
    local path dropin entry
    nr_check_account
    for path in "$ETC" "$TLS" "$EXPORTS" "$TOOLS" "$TOOLS/backups" "$WWW"; do nr_check_leaf "$path" rootdir; done
    for path in "$LOGS" "$RUNTIME"; do nr_check_leaf "$path" statedir; done
    for path in "$BIN" "$UNIT" "$CONFIG" "$SYSCTL" "$HOOK"; do nr_check_leaf "$path" file; done
    for path in "$CREDS" "$PROFILE" "$CLIENT_CONFIG"; do nr_check_leaf "$path" private; done
    for dropin in "$UNIT.d" "/run/systemd/system/$SERVICE.service.d" "/usr/lib/systemd/system/$SERVICE.service.d" "/lib/systemd/system/$SERVICE.service.d"; do
        nr_check_leaf "$dropin" rootdir
        [[ -d $dropin ]] || continue
        while IFS= read -r entry; do nr_check_leaf "$entry" file; done < <(find -P "$dropin" -mindepth 1 -maxdepth 1 -print)
    done
    nr_ports
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
    local failed=0 index=0 path existed type prior
    if ! systemctl stop "$SERVICE" >/dev/null 2>&1; then
        # A missing/previously incomplete unit may legitimately have nothing to
        # stop. A still-active process is an actual rollback failure.
        if systemctl is-active --quiet "$SERVICE"; then failed=1; fi
    fi
    while IFS=$'\t' read -r index existed type path; do
        if [[ $type == dir ]]; then
            [[ ! -e $path ]] || rm -rf -- "$path" || failed=1
            if [[ $existed == 1 ]]; then cp -a -- "$backup_dir/files/$index" "$path" || failed=1; fi
        elif [[ $existed == 1 ]]; then
            prior=$(mktemp "${path%/*}/.${path##*/}.restore.XXXXXXXX") || { failed=1; continue; }
            if cp -a -- "$backup_dir/files/$index" "$prior" && mv -fT -- "$prior" "$path"; then :; else
                rm -f -- "$prior"; failed=1
            fi
        else
            rm -f -- "$path" || failed=1
        fi
    done < "$backup_dir/manifest"
    systemctl daemon-reload || failed=1
    # Remove candidate enablement first. In particular, restoring an originally
    # runtime-only enable must not leave the candidate's persistent wants link.
    if ! systemctl disable "$SERVICE" >/dev/null 2>&1; then
        if systemctl is-enabled --quiet "$SERVICE"; then failed=1; fi
    fi
    case $was_enabled in
        enabled) systemctl enable "$SERVICE" >/dev/null 2>&1 || failed=1 ;;
        enabled-runtime) systemctl enable --runtime "$SERVICE" >/dev/null 2>&1 || failed=1 ;;
    esac
    if (( was_active )); then
        if [[ -x $BIN && -f $CONFIG ]]; then
            systemctl start "$SERVICE" || failed=1
        else
            printf 'Warning: the previous deployment was already missing binary/config/unit files; its disk baseline was restored but it cannot be restarted.\n' >&2
            failed=1
        fi
    fi
    (( failed == 0 ))
}
nr_cleanup() {
    local status=$?
    trap - EXIT
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
nr_atomic_install() {
    local source=$1 destination=$2 mode=$3 group=${4:-root} temporary
    nr_check_parent_dirs "$destination"
    [[ ! -L $destination ]] || nr_die "Refusing installation symlink: $destination."
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
    local paths=("$BIN" "$CONFIG" "$UNIT" "$PROFILE" "$CLIENT_CONFIG" "$SYSCTL" "$HOOK"
        "$TLS/fullchain.pem" "$TLS/privkey.pem" "$UNIT.d" "/run/systemd/system/$SERVICE.service.d"
        "/usr/lib/systemd/system/$SERVICE.service.d" "/lib/systemd/system/$SERVICE.service.d")
    for path in "${paths[@]}"; do
        canonical=$(readlink -m -- "$path")
        [[ $seen != *$'\n'"$canonical"$'\n'* ]] || continue
        seen+="$canonical"$'\n'
        type=file; [[ $path != *.service.d ]] || type=dir
        existed=0
        if [[ -e $path ]]; then existed=1; cp -a -- "$path" "$backup_dir/files/$index"; fi
        printf '%s\t%s\t%s\t%s\n' "$index" "$existed" "$type" "$path" >> "$backup_dir/manifest"
        index=$((index + 1))
    done
    printf 'active=%s\nenabled=%s\n' "$was_active" "$was_enabled" > "$backup_dir/service-state"
    printf 'Private deployment backup: %s\n' "$backup_dir"
    transaction_started=1
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
    tar -C "$REPO" --exclude=.git --exclude=target --exclude=__pycache__ --exclude=.venv \
        --exclude='relay-servers-*' -cf - . | tar -C "$work/source" -xf -
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
# Stage both first so a missing new key cannot replace only the old certificate.
# Reload through systemd/SIGHUP after replacement; other lineages do nothing.
nr_hook_text() {
    cat <<EOF
#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
lineage=$CERT_ROOT/live/$domain
[ "\${RENEWED_LINEAGE:-\$lineage}" = "\$lineage" ] || exit 0
dir=$TLS
trap 'rm -f "\$dir/.fullchain.pem.new" "\$dir/.privkey.pem.new"' EXIT HUP INT TERM
for file in fullchain.pem privkey.pem; do
    install -o root -g $SERVICE -m 640 "\$lineage/\$file" "\$dir/.\$file.new"
done
for file in fullchain.pem privkey.pem; do
    mv -f "\$dir/.\$file.new" "\$dir/\$file"
done
if systemctl is-active --quiet $SERVICE; then
    systemctl reload $SERVICE
fi
EOF
}
# Keep server configuration/TLS outside home directories because ProtectHome
# hides them. Unspecified relay policies retain the server's reviewed defaults.
# File logs are the only persistent data written by this relay implementation.
nr_config_text() {
    cat <<EOF
listen = "[::]:443"
log_dir = "$LOGS"
[tls]
cert = "$TLS/fullchain.pem"
key = "$TLS/privkey.pem"
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
    [[ -f $CLIENT_CONFIG ]] || return 1
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
    nr_check_leaf "$CREDS" private
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
# Stage both certificate copies, configuration and exports before stopping the
# old unit. The candidate is exposed read-only at a stable runtime mount so the
# actual service UID can validate it without traversing root-only build caches.
nr_prepare() {
    local candidate=$work/candidate validation_root=/run/$SERVICE-candidate
    install -d -o root -g "$SERVICE" -m 750 "$candidate"
    install -d -o root -g root -m 700 "$work/exports"
    install -o root -g root -m 755 "$work/$SERVICE" "$candidate/$SERVICE"
    install -o root -g "$SERVICE" -m 640 "$CERT_ROOT/live/$domain/fullchain.pem" "$candidate/fullchain.pem"
    install -o root -g "$SERVICE" -m 640 "$CERT_ROOT/live/$domain/privkey.pem" "$candidate/privkey.pem"
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
    if ! systemctl stop "$SERVICE" >/dev/null 2>&1; then
        if systemctl is-active --quiet "$SERVICE"; then nr_die 'Cannot stop the existing relay service.'; fi
    fi
    if systemctl is-active --quiet "$SERVICE"; then nr_die 'The existing relay service did not stop.'; fi
    local occupied
    occupied=$(nr_port_inodes) || nr_die 'Cannot verify that 443 was released.'
    [[ -z $occupied ]] || nr_die 'TCP/UDP 443 is still occupied; no unrelated process was stopped.'
}
# The current script replaces dedicated files after a validated build/stage.
# Retain old websites/logs/ACME state; preserve complete file and unit-state
# backups. On failure after the switch, restore old files and active/enabled
# state. A missing old binary/config from manual deletion is honestly reported.
nr_deploy() {
    local relay_password account key current response ready=0 attempt path index existed type
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
    nr_prepare_certificate
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
    nr_backup
    # Stop using the old unit/drop-ins before removing their dedicated overrides.
    # Missing units from first or partially deleted installs are handled safely.
    nr_stop_service
    while IFS=$'\t' read -r index existed type path; do
        if [[ $type == dir && -d $path ]]; then rm -rf -- "$path"; fi
    done < "$backup_dir/manifest"
    nr_atomic_install "$work/$SERVICE" "$BIN" 755
    nr_atomic_install "$work/config" "$CONFIG" 640 "$SERVICE"
    nr_atomic_install "$work/candidate/fullchain.pem" "$TLS/fullchain.pem" 640 "$SERVICE"
    nr_atomic_install "$work/candidate/privkey.pem" "$TLS/privkey.pem" 640 "$SERVICE"
    nr_atomic_install "$work/unit" "$UNIT" 644
    nr_atomic_install "$work/hook" "$HOOK" 700
    nr_atomic_install "$work/sysctl" "$SYSCTL" 644
    systemctl daemon-reload
    systemctl enable "$SERVICE"
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
nr_inputs() {
    nr_ask 'Relay domain'; domain=${REPLY,,}; domain=${domain%.}
    nr_domain "$domain" || nr_die 'Invalid DNS hostname; omit scheme, port and wildcard.'
    CREDS=$CERT_ROOT/$SERVICE-cloudflare-$domain.ini
    printf 'Use a zone-scoped token with Zone:DNS:Edit and Zone:Zone:Read.\n'
    if [[ -z $cf_token ]]; then
        read -r -s -p 'CF_API_TOKEN (hidden): ' cf_token </dev/tty || nr_die 'Could not read token.'
        printf '\n'
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
    install -d -m 700 "/run/$SERVICE-native-cloudflare-install"
    exec {install_lock}>"/run/$SERVICE-native-cloudflare-install/lock"
    flock -n "$install_lock" || nr_die 'Another installer is running.'
    nr_fresh
    nr_inputs
    nr_noninteractive
    device_user=iphone
    scope=selected
    jobs=1
    printf 'Defaults: user iphone, one build job, bundled selected-domain profile.\n'
    printf 'Set DNS-only A/AAAA records to this server; open TCP/UDP 443 in the provider firewall.\n'
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
    local apt=(apt-get -o DPkg::Lock::Timeout=1800 -o Acquire::Retries=3
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
    "${apt[@]}" update
    "${apt[@]}" install -y --no-install-recommends \
        ca-certificates curl certbot python3-certbot-dns-cloudflare build-essential pkg-config iproute2 openssl
    plugins=$("$CERTBOT" plugins)
    [[ $plugins == *dns-cloudflare* ]] || nr_die 'The apt Certbot cannot load dns-cloudflare.'
    if nr_certificate_valid "$CERT_ROOT/live/$domain/fullchain.pem" "$CERT_ROOT/live/$domain/privkey.pem"; then
        printf 'Certificate check: a currently valid matching certificate exists; it will be retained.\n'
    else
        printf 'Certificate check: DNS-01 issuance is needed after the candidate build.\n'
    fi
    nr_check_leaf "$TOOLS" rootdir
    install -d -m 700 "$TOOLS"
    work=$(mktemp -d "$TOOLS/build.XXXXXXXX")
    # Install traps only after this run owns a unique scratch directory.
    trap nr_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    nr_build "$jobs"
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
