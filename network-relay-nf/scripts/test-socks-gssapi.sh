#!/usr/bin/env bash
# SOCKS5 GSS-API authentication (RFC 1961) with real Kerberos: a throwaway
# MIT KDC realm on loopback, a keytab for the proxy and tickets for its
# clients, then scripts/test-interop.py, which starts both real relay
# servers, with the ignored Kerberos test of Core/tests/socks_gssapi.rs: the
# production SOCKS code over the transport emulator, not Network.framework.
#
# Needs MIT Kerberos (krb5-kdc, krb5-admin-server, krb5-user), openssl and
# python3. No root.
#
# Usage: scripts/test-socks-gssapi.sh --rust-server /path/to/network-relay \
#            --caddy /path/to/caddy-with-network-relay
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d /tmp/relay-nf-gssapi.XXXXXX)
REALM=RELAY.TEST
KDC_PID=""
cleanup() {
    [ -n "$KDC_PID" ] && kill "$KDC_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

for tool in krb5kdc kdb5_util kadmin.local kinit python3; do
    command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
cat >"$WORK/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    dns_canonicalize_hostname = false
    rdns = false
    udp_preference_limit = 1
[realms]
    $REALM = {
        kdc = 127.0.0.1:$PORT
    }
[domain_realm]
    localhost = $REALM
EOF
cat >"$WORK/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = $PORT
    kdc_tcp_ports = $PORT
[realms]
    $REALM = {
        database_name = $WORK/principal
        key_stash_file = $WORK/stash
        acl_file = $WORK/kadm5.acl
        max_life = 1h
    }
[logging]
    kdc = FILE:$WORK/kdc.log
EOF
: >"$WORK/kadm5.acl"
export KRB5_CONFIG="$WORK/krb5.conf" KRB5_KDC_PROFILE="$WORK/kdc.conf"

kdb5_util create -s -r "$REALM" -P masterpassword >/dev/null
for principal in alice bob; do
    kadmin.local -q "addprinc -pw $principal-password $principal" >/dev/null
done
# Clients name the proxy's service rcmd (Dante's default) or socks; the
# keytab holds both, for the proxy at "localhost".
kadmin.local -q "addprinc -randkey rcmd/localhost" >/dev/null
kadmin.local -q "addprinc -randkey socks/localhost" >/dev/null
kadmin.local -q "ktadd -k $WORK/proxy.keytab rcmd/localhost socks/localhost" >/dev/null
krb5kdc -n -P "$WORK/kdc.pid" &
KDC_PID=$!
for _ in $(seq 50); do
    python3 -c "import socket; socket.create_connection(('127.0.0.1', $PORT), timeout=1).close()" 2>/dev/null && break
    sleep 0.1
done
for principal in alice bob; do
    echo "$principal-password" | KRB5CCNAME="FILE:$WORK/$principal.ccache" kinit "$principal@$REALM" >/dev/null
done

export RELAY_NF_GSSAPI_KEYTAB="$WORK/proxy.keytab" RELAY_NF_GSSAPI_CCACHE_DIR="$WORK" RELAY_NF_GSSAPI_REALM="$REALM"
python3 "$ROOT/scripts/test-interop.py" --test socks_gssapi --results "$WORK/results.json" "$@"
