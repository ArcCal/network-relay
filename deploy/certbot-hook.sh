#!/bin/sh
# Certbot deploy hook for network-relay. The relay runs as user
# network-relay and cannot read certbot's files, which only root may read,
# so this copies the renewed certificate and key into /etc/network-relay/tls
# (readable by group network-relay) and reloads the relay.
#
# Install it as /etc/letsencrypt/renewal-hooks/deploy/network-relay, and
# write the certificate's directory, for example
# /etc/letsencrypt/live/relay.example.com, to /etc/network-relay/tls/source.
# Run it once by hand for the first copy.
set -eu
dir=${NETWORK_RELAY_TLS:-/etc/network-relay/tls}
group=${NETWORK_RELAY_GROUP:-network-relay}
source=$(cat "$dir/source")
# Certbot names the renewed certificate; other certificates are not ours.
if [ -n "${RENEWED_LINEAGE:-}" ] && [ "$RENEWED_LINEAGE" != "$source" ]; then
    exit 0
fi
trap 'rm -f "$dir/.fullchain.pem.new" "$dir/.privkey.pem.new"' EXIT HUP INT TERM
# Stage both first. A missing/unreadable new key must not replace the old
# certificate and leave the on-disk pair unusable on the next restart.
for file in fullchain.pem privkey.pem; do
    install -m 640 -g "$group" "$source/$file" "$dir/.$file.new"
done
for file in fullchain.pem privkey.pem; do
    mv -f "$dir/.$file.new" "$dir/$file"
done
if systemctl is-active --quiet network-relay; then
    systemctl reload network-relay
fi
