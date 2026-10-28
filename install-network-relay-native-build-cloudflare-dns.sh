#!/usr/bin/env bash
# Interactive fresh deployment: native Linux build + Certbot Cloudflare DNS-01.
# Requires Debian 12+ or Ubuntu 22.04+, Bash 4+, systemd and amd64/arm64.
# Run from the complete checkout on the server. --plan makes no changes.
# Token permissions: Zone:DNS:Edit and Zone:Zone:Read for the selected zone.
# Keep DNS-only A/AAAA records pointing here; allow inbound TCP/UDP 443.
# DNS validation does not need inbound port 80. No Python helper is used.
# Disable tracing before reading any credentials, even under bash -x/-v.
set +x
set +v

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
PROFILE=$ETC/device.mobileconfig
CLIENT_CONFIG=$ETC/network-relay-rs-client.toml
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
Debian 12+ or Ubuntu 22.04+ required.

Defaults: user iphone, one build job, bundled selected-domain device profile.
Certbot registers without email. Running this installer accepts the ACME CA
terms. There is no installation confirmation or other interactive prompt.

Fresh installations only: existing service/configuration files are refused.
The token stays in a root-only file for automatic renewal, never in argv.
Set Cloudflare A/AAAA records to DNS only and permit inbound TCP/UDP 443.
Provider firewall rules and real-device verification remain your responsibility.
EOF
}
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
nr_domain() {
    local value=$1
    (( ${#value} <= 253 )) && [[ $value =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]{2,63}$ ]]
}
nr_ask() {
    local prompt=$1 default=${2:-}
    if [[ -n $default ]]; then prompt+=" [$default]"; fi
    read -r -p "$prompt: " REPLY </dev/tty || nr_die 'Interactive terminal input is required.'
    REPLY=${REPLY:-$default}
}
nr_fresh() {
    local path loaded certbot_path
    local paths=("$ETC" "$BIN" "$UNIT" "$HOOK" "$CREDS" "$WWW" "$SYSCTL"
        "/lib/systemd/system/$SERVICE.service" "/usr/lib/systemd/system/$SERVICE.service"
        "/run/systemd/system/$SERVICE.service")
    for path in "${paths[@]}"; do
        [[ ! -e $path && ! -L $path ]] || nr_die "Existing installation/file: $path. Fresh installs only."
    done
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
nr_download() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --show-error --location \
        --retry 3 --connect-timeout 20 --max-time 900 --output "$2" "$1"
}
nr_verify() {
    local actual
    [[ $2 =~ ^[a-f0-9]{64}$ ]] || nr_die 'Invalid checksum metadata.'
    actual=$(sha256sum -- "$1"); actual=${actual%% *}
    [[ $actual == "$2" ]] || nr_die 'Download checksum mismatch; refusing to use the artifact.'
}
nr_new_file() {
    local path=$1 mode=$2 group=${3:-root}
    [[ ! -e $path && ! -L $path ]] || nr_die "Refusing to replace $path."
    # noclobber also prevents following an existing symlink or truncating a file.
    (set -o noclobber; umask 077; cat > "$path")
    chmod "$mode" "$path"
    chown root:"$group" "$path"
}
nr_cleanup() {
    local status=$?
    trap - EXIT
    if (( startup_pending )); then systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true; fi
    [[ -z $work ]] || rm -rf -- "$work"
    if (( status )); then
        printf 'Deployment incomplete (exit %s). No existing installation was replaced.\n' "$status" >&2
        printf 'Packages, certificates and partial files may remain. Inspect the last completed step before retrying.\n' >&2
        printf 'If already generated, the credential-bearing device profile is %s.\n' "$PROFILE" >&2
    fi
    exit "$status"
}
nr_build() {
    local jobs=$1 expected url
    mkdir "$work/source"
    # Build a snapshot; leave the caller's tracked files and lockfiles untouched.
    tar -C "$REPO" --exclude=.git --exclude=target --exclude=__pycache__ --exclude=.venv \
        --exclude='relay-servers-*' -cf - . | tar -C "$work/source" -xf -
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
    url=https://static.rust-lang.org/rustup/dist/$triple/rustup-init
    nr_download "$url" "$work/rustup-init"
    nr_download "$url.sha256" "$work/rustup-init.sha256"
    read -r expected _ < "$work/rustup-init.sha256"
    nr_verify "$work/rustup-init" "$expected"
    chmod 700 "$work/rustup-init"
    export CARGO_HOME=$TOOLS/cargo RUSTUP_HOME=$TOOLS/rustup RUSTUP_TOOLCHAIN=1.99.1
    export CARGO_TARGET_DIR=$TOOLS/target
    export PATH="$CARGO_HOME/bin:$PATH"
    "$work/rustup-init" -y --no-modify-path --profile minimal --default-toolchain "$RUSTUP_TOOLCHAIN"
    (cd "$work/source"; "$CARGO_HOME/bin/cargo" build --locked --release --bin network-relay --target "$triple" --jobs "$jobs")
    install -m 755 "$CARGO_TARGET_DIR/$triple/release/network-relay" "$work/$SERVICE"
    "$work/$SERVICE" --version
}
nr_hook_text() {
    cat <<EOF
#!/bin/sh
set -eu
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
nr_config_text() {
    cat <<EOF
listen = "[::]:443"
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
nr_account() {
    if id -u "$SERVICE" >/dev/null 2>&1; then
        [[ $(id -u "$SERVICE") != 0 && $(id -g "$SERVICE") != 0 && $(id -gn "$SERVICE") == "$SERVICE" ]] || nr_die 'Refusing a privileged or mismatched service account.'
    else
        local home=/nonexistent
        useradd --system --user-group --no-create-home --home-dir "$home" --shell /usr/sbin/nologin "$SERVICE"
    fi
}
nr_client_config_text() {
    # The validated domain/user and generated hexadecimal password are TOML-safe.
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
nr_deploy() {
    local relay_password account key current response ready=0
    local cli=("$work/$SERVICE")
    nr_account
    install -d -o root -g "$SERVICE" -m 750 "$ETC" "$TLS"
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
    relay_password=$(openssl rand -hex 24)
    # Bash builtins feed stdin; secrets are never external command arguments.
    account=$(printf '%s\n' "$relay_password" | "${cli[@]}" passwd --name "$device_user" --stdin --fast-hash)
    [[ $account == *'[[user]]'* && $account == *'password_hash = '* ]] || nr_die 'Unexpected Rust password hash output.'
    nr_config_text | nr_new_file "$CONFIG" 640 "$SERVICE"
    nr_profile_args
    printf '%s\n' "$relay_password" | "${cli[@]}" "${profile_args[@]}"
    chmod 600 "$PROFILE"
    install -m 755 "$work/$SERVICE" "$BIN"
    nr_new_file "$UNIT" 644 < "$REPO/deploy/network-relay.service"
    runuser -u "$SERVICE" -- "$BIN" serve --config "$CONFIG" --check
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
    systemctl enable --now certbot.timer
    systemctl daemon-reload
    startup_pending=1
    systemctl enable --now "$SERVICE"
    for ((attempt=0; attempt<30; attempt++)); do
        if response=$(curl --noproxy '*' --fail --silent --show-error --max-time 3 \
            --resolve "$domain:443:127.0.0.1" "https://$domain/" 2>/dev/null); then
            if [[ $response == *'<h1>Welcome</h1>'* ]]; then ready=1; break; fi
        fi
        sleep 1
    done
    (( ready )) || nr_die "Local TLS/website check failed; inspect journalctl -u $SERVICE."
    startup_pending=0
    printf 'Local HTTPS works. Protected device profile: %s\n' "$PROFILE"
    cli=("$BIN")
    if ! printf '%s\n' "$relay_password" | "${cli[@]}" check --server "$domain" --address 127.0.0.1 --user "$device_user"; then
        nr_die "Server remains running, but protocol checks failed. Check outbound TCP 80/UDP 53 and journalctl -u $SERVICE. Do not rerun this fresh installer."
    fi
    nr_client_config_text | nr_new_file "$CLIENT_CONFIG" 600
    unset relay_password
    printf 'All built-in TCP/UDP checks passed. Verify external access on a real device.\n'
    printf 'Download %s over SSH, install it, then delete the profile copies.\n' "$PROFILE"
    printf 'Rust client configuration: %s (same credentials; mode 600).\n' "$CLIENT_CONFIG"
    printf 'Download it over SSH; import into Network Relay RS or use network-relay-rs --config FILE.\n'
    printf 'Keep %s for automatic renewal.\n' "$CREDS"
    printf 'Test renewal: sudo certbot renew --dry-run --cert-name %s\n' "$domain"
}
nr_inputs() {
    nr_ask 'Relay domain'; domain=${REPLY,,}; domain=${domain%.}
    nr_domain "$domain" || nr_die 'Invalid DNS hostname; omit scheme, port and wildcard.'
    local path
    for path in "$CERT_ROOT/live/$domain" "$CERT_ROOT/renewal/$domain.conf"; do
        [[ ! -e $path && ! -L $path ]] || nr_die "Existing certificate lineage: $path. Review renewal settings manually."
    done
    printf 'Use a zone-scoped token with Zone:DNS:Edit and Zone:Zone:Read.\n'
    if [[ -z $cf_token ]]; then
        read -r -s -p 'CF_API_TOKEN (hidden): ' cf_token </dev/tty || nr_die 'Could not read token.'
        printf '\n'
    fi
    [[ $cf_token =~ ^[A-Za-z0-9_-]{20,256}$ ]] || nr_die 'Expected a Cloudflare API Token.'
}
nr_noninteractive() {
    # Explicit password pipes and domain-list files still supply their own input.
    exec </dev/null
    export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
}
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
    local cf_token=${CF_API_TOKEN:-} jobs path plugins free_kib
    unset CF_API_TOKEN
    export -n cf_token
    umask 077
    command -v flock >/dev/null || nr_die 'flock from util-linux is required.'
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
    local required=(deploy/domains/google-ai-social.txt deploy/domains/global-services.txt)
    required+=(Cargo.toml Cargo.lock src/main.rs deploy/network-relay.service)
    for path in "${required[@]}"; do [[ -f $REPO/$path ]] || nr_die "Complete checkout required; missing $path."; done
    free_kib=$(df -Pk /opt | awk 'NR==2 {print $4}')
    [[ $free_kib =~ ^[0-9]+$ ]] && (( free_kib >= 5*1024*1024 )) || nr_die 'At least 5 GiB free under /opt is required.'
    local apt=(apt-get -o DPkg::Lock::Timeout=1800 -o Acquire::Retries=3
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
    "${apt[@]}" update
    "${apt[@]}" install -y --no-install-recommends \
        ca-certificates curl certbot python3-certbot-dns-cloudflare build-essential pkg-config iproute2 openssl
    plugins=$("$CERTBOT" plugins)
    [[ $plugins == *dns-cloudflare* ]] || nr_die 'The apt Certbot cannot load dns-cloudflare.'
    install -d -m 700 "$TOOLS"
    work=$(mktemp -d "$TOOLS/build.XXXXXXXX")
    trap nr_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    nr_build "$jobs"
    nr_deploy
}

# Sourcing exposes helpers for isolated tests without installing anything.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -Eeuo pipefail
    unset CDPATH
    export LC_ALL=C
    nr_main "$@"
fi
