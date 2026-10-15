# One-file configuration and migration

The application reads one TOML document. Standard relay settings, `[[user]]`
entries, `[warp]` and inline `[warp.registration]` all live in that document.
Certificate/key files and the website directory are ordinary runtime assets;
no additional WARP configuration document is required.

## New installation

Copy `examples/relay.toml`, keep the file private, set the relay's listen
address/TLS/website paths/users, and replace the WARP placeholders with the
values from your existing MASQUE enrollment:

```bash
mkdir -p config
chmod 700 config
cp examples/relay.toml config/relay.toml
chmod 600 config/relay.toml
```

The minimum WARP section for IPv4-only H2 egress is:

```toml
[warp]
transport = "h2"

[warp.registration]
private_key = "REPLACE_WITH_ENROLLED_BASE64_P256_PKCS8_PRIVATE_KEY"
endpoint_public_key = """-----BEGIN PUBLIC KEY-----
REPLACE_WITH_ENROLLED_PUBLIC_KEY_BASE64
-----END PUBLIC KEY-----
"""
tunnel_ipv4 = "172.16.0.2"
```

These are placeholders, not usable credentials. `tunnel_ipv4` must match the
enrollment too. `device_id`, `access_token` and `license` are optional metadata,
not required tunnel inputs. This application does not register or refresh an
account.

H2 uses the existing default IPv4 endpoint `162.159.198.2:443`. For H3, select
`transport = "h3"` and add the enrollment's `endpoint_v4` inside
`[warp.registration]`, or use an explicit numeric `endpoint` under `[warp]`.
Enrollment endpoint port `0` selects port 443. Modes are independent of the
client-facing transport and are never silently changed after a failure.

Defaults also supply tunneled DNS `1.1.1.1:53`, a 15-second keepalive and a
30-second idle limit. Optional settings retain the validation documented by
the examples and source.

Validate without making a WARP connection, then start:

```bash
./target/release/network-relay-cf-masque serve --config config/relay.toml --check
./target/release/network-relay-cf-masque serve --config config/relay.toml
```

Relative TLS/key/website paths retain standard relay behavior: they resolve
from the service working directory. Absolute deployment paths avoid ambiguity.

## IPv4-only operation

Omit `tunnel_ipv6`, `endpoint_v6` and `endpoint_h2_v6`. Leave
`ipv6_endpoint` absent/false and use an IPv4 address for any explicit
`warp.endpoint`. Neither an IPv6 VPS connection nor an inner IPv6 address is
then required. DNS uses the tunnel and skips AAAA queries when no inner IPv6
source is configured. A literal IPv6 destination fails because the tunnel has
no IPv6 address; it never goes out through the VPS directly.

Configured DNS servers must have a matching assigned tunnel address family.
For IPv4-only operation, retain the default IPv4 DNS server or supply other
numeric IPv4 DNS servers; an IPv6 DNS override is rejected during validation.

An assigned inner IPv6 address and an IPv6 outer transport are independent
options. To use inner IPv6, add the enrollment's `tunnel_ipv6`; the tunnel must
also meet the minimum IPv6 MTU. To reach WARP over IPv6, explicitly select an
IPv6 endpoint. Adding an inner IPv6 address alone does not change the default
IPv4 outer transport.

## Existing three-file installation

Keep the existing settings until the new file validates. The migration helper
reads the old relay TOML, WARP TOML and its referenced enrollment JSON, combines
them, validates the result locally and writes a new private file. It does not
print credentials, overwrite an existing output or delete the originals.
Run it with the new binary from the same working directory used by the old
service so that relative relay asset paths keep their meaning:

```bash
umask 077
/usr/local/bin/network-relay-cf-masque migrate-config \
  --config /etc/network-relay/relay.toml \
  --warp-config /etc/network-relay/warp.toml \
  --ipv4-only \
  --out /etc/network-relay/relay-single.toml

/usr/local/bin/network-relay-cf-masque serve \
  --config /etc/network-relay/relay-single.toml --check
```

Use the actual new executable path if it differs. The output retains relay
settings/users and WARP enrollment fields; changing the file layout does not
rotate passwords, replace TLS keys or change the destination policy. The
`--ipv4-only` flag removes the three IPv6 enrollment fields and disables
IPv6 outer-endpoint selection. It rejects an explicit IPv6 endpoint or DNS
override; select an IPv4 value in the old WARP settings before migrating in
that case. Leave out the flag to preserve an existing dual-stack enrollment.
The flag also converts a missing or wildcard IPv6 listener to `0.0.0.0` at
the same port. A specific IPv6 listen address is rejected; choose an IPv4
listen address in the relay input first.

Keep a mode-0600 backup of the original files outside any public website or
source tree. If the service runs as an unprivileged user, give that user read
access to the new mode-0600 file using appropriate ownership. Do not print its
contents to troubleshoot a path or permission error.

Edit only the existing unit's `ExecStart` arguments to retain its current
binary path and working directory, select the new combined file and remove
`--warp-config`:

```text
ExecStart=/usr/local/bin/network-relay-cf-masque serve --config /etc/network-relay/relay-single.toml
```

If your existing binary is named `/usr/local/bin/network-relay`, keep that
path after replacing it with the new experimental binary. Likewise, an
existing `network-relay.service` does not need to be renamed. After editing
the actual unit, run `systemctl daemon-reload`, restart that unit and inspect
its journal. The supplied independent deployment template instead uses
`network-relay-cf-masque.service` and `/opt/network-relay-cf-masque` paths.

WARP settings are fixed for a process generation and need a restart to take
effect. SIGHUP retains the standard relay users/policy/TLS/website reload;
it cannot switch the active WARP tunnel. Explicit `--warp-config` and
`registration = "path.json"` remain supported for installations that have
not yet migrated, but are optional compatibility forms rather than the
recommended deployment layout.
