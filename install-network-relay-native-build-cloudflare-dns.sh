#!/usr/bin/env bash
# Interactive fresh deployment: native Linux build + Certbot Cloudflare DNS-01.
# Requires Debian 12+ or Ubuntu 22.04+, Bash 4+, systemd and amd64/arm64.
# Run from the complete checkout on the server. --plan makes no changes.
# Token permissions: Zone:DNS:Edit and Zone:Zone:Read for the selected zone.
# Keep DNS-only A/AAAA records pointing here; allow inbound TCP/UDP 443.
# DNS validation does not need inbound port 80. No Python helper is used.
#
# Deployment sequence (this is a fresh installer, not an upgrade/repair tool):
#   1. Check the host, dedicated paths/account and service/port conflicts.
#   2. Read only the relay domain and a hidden Cloudflare token.
#   3. Install prerequisites noninteractively; verify and build native Rust.
#   4. Create a dedicated account, private directories and root token source.
#   5. Obtain a certificate as root, copy its pair and configure the sandbox.
#   6. Validate/start the server and run trusted HTTPS and relay protocol checks.
#   7. Export a Rust client TOML using the same generated account credentials.
# The Apple profile is written before startup so it retains the password if a
# later check fails. The runtime never receives the Cloudflare API token.
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
startup_pending=0

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
Debian 12+ or Ubuntu 22.04+, systemd 249+ and 5 GiB free under /opt required.

Defaults: user iphone, a generated 22-character mixed-case/digit/symbol password,
one build job and the bundled selected-domain device profile.
Certbot registers without email. Running this installer accepts the ACME CA
terms. There is no installation confirmation or other interactive prompt.

Fresh installations only: existing service/configuration files are refused.
The token stays in a root-only Certbot file for renewal, never in argv or the
relay service environment. The daemon runs under a fresh non-root account with
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
            [[ $VERSION_ID == *.* ]] || nr_die 'Ubuntu 22.04+ is required.'
            (( 10#$major > 22 || (10#$major == 22 && 10#$minor >= 4) )) || nr_die 'Ubuntu 22.04+ is required.' ;;
        *) nr_die 'Only Debian 12+ and Ubuntu 22.04+ are supported.' ;;
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
# Do not adopt a previous account, cache, log tree or unit override. An existing
# UID may have live processes/access, and a drop-in could cancel unit sandboxing.
# This also refuses dangling symlinks. Partial failed installations need manual
# inspection; silently deleting/reusing their state would hide a prior problem.
nr_fresh() {
    local path loaded certbot_path
    local paths=("$ETC" "$BIN" "$UNIT" "$HOOK" "$CREDS" "$WWW" "$SYSCTL" "$TOOLS" "$LOGS" "$RUNTIME" "$UNIT.d"
        "/lib/systemd/system/$SERVICE.service" "/usr/lib/systemd/system/$SERVICE.service"
        "/run/systemd/system/$SERVICE.service"
        "/etc/systemd/system/$SERVICE.service.d" "/run/systemd/system/$SERVICE.service.d"
        "/lib/systemd/system/$SERVICE.service.d" "/usr/lib/systemd/system/$SERVICE.service.d")
    for path in "${paths[@]}"; do
        [[ ! -e $path && ! -L $path ]] || nr_die "Existing installation/file: $path. Fresh installs only."
        nr_check_parent_dirs "$path"
    done
    if id -u "$SERVICE" >/dev/null 2>&1 || getent group "$SERVICE" >/dev/null; then
        nr_die 'Fresh installation requires an unused service user and group name.'
    fi
    loaded=$(systemctl show "$SERVICE" --property=LoadState --value) || nr_die 'Cannot inspect systemd.'
    [[ -z $loaded || $loaded == not-found ]] || nr_die "An existing $SERVICE unit is loaded."
    certbot_path=$(type -P certbot || true)
    [[ -z $certbot_path || $certbot_path == /usr/bin/certbot ]] || nr_die 'Do not mix snap/pip Certbot with apt Certbot; resolve the existing installation first.'
    # /proc is available before iproute2 is installed. TCP state 0A is LISTEN;
    # UDP sockets of any state bound to 443 also conflict with QUIC.
    local sockets=(/proc/net/tcp /proc/net/udp) file
    for file in /proc/net/tcp6 /proc/net/udp6; do [[ ! -r $file ]] || sockets+=("$file"); done
    for file in "${sockets[@]}"; do
        [[ -r $file ]] || nr_die "Cannot inspect listening sockets: $file is unreadable."
    done
    local port_state
    port_state=$(awk 'FNR > 1 && $2 ~ /:01BB$/ && (FILENAME ~ /udp/ || $4 == "0A") {busy=1} END {print busy+0}' "${sockets[@]}") \
        || nr_die 'Cannot inspect listening sockets; port availability is unknown.'
    if [[ $port_state != 0 ]]; then
        nr_die 'TCP or UDP port 443 is busy. Stop the conflicting service yourself.'
    fi
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
# Stop only this fresh candidate if its startup/readiness interval failed.
# Preserve the first command's failure even if cleanup also fails, and remove
# only this run's scratch directory. Persistent credentials/partial files remain
# for diagnosis: deleting a Certbot renewal source could break future renewal.
nr_cleanup() {
    local status=$? cleanup_status=0
    trap - EXIT
    if (( startup_pending )); then
        if ! systemctl disable --now "$SERVICE" >/dev/null 2>&1; then
            printf 'Warning: failed to stop/disable candidate %s; inspect it manually.\n' "$SERVICE" >&2
            cleanup_status=1
        fi
    fi
    if [[ -n $work ]] && ! rm -rf -- "$work"; then
        printf 'Warning: could not remove scratch directory %s.\n' "$work" >&2
        cleanup_status=1
    fi
    if (( status == 0 && cleanup_status != 0 )); then status=1; fi
    if (( status )); then
        printf 'Deployment incomplete (exit %s). No existing installation was replaced.\n' "$status" >&2
        printf 'Packages, certificates and partial files may remain. Inspect the last completed step before retrying.\n' >&2
        printf 'If already generated, the credential-bearing device profile is %s.\n' "$PROFILE" >&2
    fi
    exit "$status"
}
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
    export CARGO_HOME=$TOOLS/cargo RUSTUP_HOME=$TOOLS/rustup RUSTUP_TOOLCHAIN=1.99.1
    export CARGO_TARGET_DIR=$TOOLS/target
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
# Fresh installs must own a new, independent identity. Re-check immediately
# before useradd as well as during preflight to avoid adopting a racing account.
# Do not try to sanitize someone else's groups, shell, home or live processes.
nr_account() {
    if id -u "$SERVICE" >/dev/null 2>&1 || getent group "$SERVICE" >/dev/null; then
        nr_die 'Fresh installation requires an unused service user and group name.'
    fi
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE"
    [[ $(id -u "$SERVICE") != 0 && $(id -g "$SERVICE") != 0 && $(id -gn "$SERVICE") == "$SERVICE" ]] || nr_die 'Refusing a privileged or mismatched service account.'
    local primary_group group_id groups
    primary_group=$(id -g "$SERVICE")
    groups=$(id -G "$SERVICE")
    for group_id in $groups; do
        [[ $group_id == "$primary_group" ]] || nr_die 'The service account must not have supplementary groups.'
    done
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
# Obtain certificates as root, prepare a service-readable pair and an Argon2id
# user, then validate/start a fresh sandboxed deployment. Root-only credentials
# and client exports are kept separate from the public website and TLS copies.
nr_deploy() {
    local relay_password account key current response ready=0
    local cli=("$work/$SERVICE") path
    # Re-check ancestors after compilation, which may take a long time. Never
    # adopt an untrusted web/config/state parent even if preflight was earlier.
    for path in "$ETC" "$BIN" "$UNIT" "$EXPORTS" "$WWW" "$SYSCTL" "$TOOLS" "$LOGS" "$RUNTIME" "$CREDS" "$HOOK"; do
        nr_check_parent_dirs "$path"
    done
    nr_account
    install -d -o root -g "$SERVICE" -m 750 "$ETC" "$TLS"
    install -d -o root -g root -m 700 "$EXPORTS"
    [[ -d ${WWW%/*} ]] || install -d -m 755 "${WWW%/*}"
    install -d -m 755 "$WWW"
    printf '<!doctype html>\n<title>Welcome</title>\n<h1>Welcome</h1>\n' | nr_new_file "$WWW/index.html" 644
    [[ -d $CERT_ROOT ]] || install -d -m 700 "$CERT_ROOT"
    printf 'dns_cloudflare_api_token = %s\n' "$cf_token" | nr_new_file "$CREDS" 600
    unset cf_token
    "$CERTBOT" certonly --non-interactive --agree-tos --register-unsafely-without-email \
        --dns-cloudflare --dns-cloudflare-credentials "$CREDS" --dns-cloudflare-propagation-seconds 60 \
        --preferred-challenges dns-01 --cert-name "$domain" -d "$domain" --keep-until-expiring
    install -d -m 755 "${HOOK%/*}"
    nr_hook_text | nr_new_file "$HOOK" 700
    "$HOOK"
    relay_password=$(nr_generate_password)
    # A 22-character password cannot use the server's 24+ character fast-hash
    # path. Existing --stdin mode uses Argon2id and prints only the account hash.
    # Feed plaintext through stdin; it is never an external command argument.
    account=$(printf '%s\n' "$relay_password" | "${cli[@]}" passwd --name "$device_user" --stdin)
    [[ $account == *'[[user]]'* && $account == *'password_hash = "$argon2id$'* ]] || nr_die 'Unexpected Rust password hash output.'
    nr_config_text | nr_new_file "$CONFIG" 640 "$SERVICE"
    nr_profile_args
    printf '%s\n' "$relay_password" | "${cli[@]}" "${profile_args[@]}"
    chmod 600 "$PROFILE"
    install -m 755 "$work/$SERVICE" "$BIN"
    nr_unit_text | nr_new_file "$UNIT" 644
    # This validates config/TLS/website as the real UID, before touching service
    # state. It does not reproduce every mount/syscall restriction of the unit.
    runuser -u "$SERVICE" -- "$BIN" serve --config "$CONFIG" --check
    # Only raise existing socket-buffer ceilings used by QUIC/UDP, never lower
    # them. Containers may reject sysctl; report that rather than claim tuning
    # worked. The persistent file may still take effect after a later reboot.
    # This is socket-buffer tuning, not a firewall package or firewall rule.
    {
        printf '# UDP buffer limits for the Cloudflare DNS relay deployment.\n'
        for key in net.core.rmem_max net.core.wmem_max; do
            current=$(sysctl -n "$key")
            [[ $current =~ ^[0-9]+$ ]] || nr_die 'Cannot read UDP buffer limits.'
            (( current >= 8388608 )) || current=8388608
            printf '%s = %s\n' "$key" "$current"
        done
    } | nr_new_file "$SYSCTL" 644
    sysctl -p "$SYSCTL" || printf 'Warning: UDP buffer tuning was denied; using system defaults.\n'
    # Retain the root-only token/Certbot renewal configuration for future runs.
    # The long-running relay unit has no API token and cannot read those sources.
    systemctl enable --now certbot.timer
    systemctl daemon-reload
    # Until trusted local HTTPS is ready, failures stop/disable this candidate.
    # Existing installations have already been rejected; none is stopped here.
    startup_pending=1
    systemctl enable --now "$SERVICE"
    # Preserve the real hostname/SNI while connecting to loopback. TLS chain
    # and hostname verification remain enabled; this does not test public access.
    for ((attempt=0; attempt<30; attempt++)); do
        if response=$(curl --disable --noproxy '*' --fail --silent --show-error --max-time 3 \
            --resolve "$domain:443:127.0.0.1" "https://$domain/" 2>/dev/null); then
            if [[ $response == *'<h1>Welcome</h1>'* ]]; then ready=1; break; fi
        fi
        sleep 1
    done
    (( ready )) || nr_die "Local TLS/website check failed; inspect journalctl -u $SERVICE."
    # A later protocol error may be an outbound-network restriction. Keep the
    # HTTPS-ready service for diagnosis and retain the pre-created Apple profile.
    startup_pending=0
    printf 'Local HTTPS works. Protected device profile: %s\n' "$PROFILE"
    cli=("$BIN")
    if ! printf '%s\n' "$relay_password" | "${cli[@]}" check --server "$domain" --address 127.0.0.1 --user "$device_user"; then
        nr_die "Server remains running, but protocol checks failed. Check outbound TCP 80/UDP 53 and journalctl -u $SERVICE. Do not rerun this fresh installer."
    fi
    # Publish this credential-bearing TOML only after all protocol checks pass.
    nr_client_config_text | nr_new_file "$CLIENT_CONFIG" 600
    unset relay_password
    printf 'All built-in TCP/UDP checks passed. Verify external access on a real device.\n'
    printf 'Download %s over SSH, install it, then delete the profile copies.\n' "$PROFILE"
    printf 'Rust client configuration: %s (same credentials; mode 600).\n' "$CLIENT_CONFIG"
    printf 'Download it over SSH; import into Network Relay RS or use network-relay-rs --config FILE.\n'
    printf 'Keep %s for automatic renewal.\n' "$CREDS"
    printf 'Test renewal: sudo certbot renew --dry-run --cert-name %s\n' "$domain"
}
# Only these two values are interactive. An inherited CF_API_TOKEN can supply
# the token directly; otherwise read it silently. Reject an existing Certbot
# lineage rather than inherit an unknown challenge/renewal configuration.
# Accept the legacy token alphabet and newer cfut_/cfat_ prefixes, including
# their documented maximum body length. This is only syntax validation, not a
# remote permission check. Diagnostics must not echo a rejected secret value.
nr_token_valid() {
    [[ $1 =~ ^[A-Za-z0-9_-]{35,50}$ || $1 =~ ^cf(ut|at)_[A-Za-z0-9_-]{32,256}$ ]]
}
nr_inputs() {
    nr_ask 'Relay domain'; domain=${REPLY,,}; domain=${domain%.}
    nr_domain "$domain" || nr_die 'Invalid DNS hostname; omit scheme, port and wildcard.'
    local path
    for path in "$CERT_ROOT/live/$domain" "$CERT_ROOT/archive/$domain" "$CERT_ROOT/renewal/$domain.conf"; do
        [[ ! -e $path && ! -L $path ]] || nr_die "Existing certificate lineage: $path. Review renewal settings manually."
    done
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
