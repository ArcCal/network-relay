# One-file configuration

The application reads one standalone TOML file. network-relay's settings and
`[[user]]` entries, `[warp]` and the inline `[warp.registration]` all live in
that file; there is no other configuration file. Everything outside `[warp]`
is read exactly as network-relay reads its own configuration file, with the
same fields, defaults and checks. Certificate/key files and the website
directory are ordinary runtime assets.

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

## IPv4-only operation and the IPv6 warning

If `[warp.registration]` lacks `tunnel_ipv6` or `endpoint_v6`, the server
prints a warning when it starts (and `serve --check` prints it too), logs it,
and keeps running:

```text
network-relay-cf-masque: warning: [warp.registration] has no tunnel_ipv6 or endpoint_v6; copy it from the WARP enrollment for IPv6 (for example tunnel_ipv6 = "2606:4700:110:88ca:7332:13e4:5a18:e3d9" and endpoint_v6 = "[2606:4700:103::2]:0"); until then IPv6 destinations cannot be reached through WARP, only IPv4 ones; until then the HTTP/3 tunnel cannot use an IPv6 WARP endpoint
```

Copy the two values from the enrollment to enable IPv6:

```toml
[warp.registration]
tunnel_ipv6 = "2606:4700:110:88ca:7332:13e4:5a18:e3d9"
endpoint_v6 = "[2606:4700:103::2]:0"
```

Without `tunnel_ipv6`, DNS uses the tunnel and skips AAAA queries, and a
literal IPv6 destination fails because the tunnel has no IPv6 address; it
never goes out through the VPS directly. Without `endpoint_v6`, the H3 tunnel
can only use an IPv4 WARP endpoint (`ipv6_endpoint = true` is then refused).
Leave `ipv6_endpoint` absent or false and use an IPv4 address for any
explicit `warp.endpoint` to reach WARP over IPv4.

Configured DNS servers must have a matching assigned tunnel address family.
For IPv4-only operation, retain the default IPv4 DNS server or supply other
numeric IPv4 DNS servers; an IPv6 DNS override is rejected during validation.

An assigned inner IPv6 address and an IPv6 outer transport are independent
options. To use inner IPv6, add the enrollment's `tunnel_ipv6`; the tunnel must
also meet the minimum IPv6 MTU. To reach WARP over IPv6, set
`ipv6_endpoint = true` (with `endpoint_v6`, or `endpoint_h2_v6` for H2) or an
explicit IPv6 endpoint. Adding an inner IPv6 address alone does not change the
default IPv4 outer transport.

## Moving from separate files

Earlier versions also accepted a separate WARP settings file
(`--warp-config`), an enrollment JSON file (`registration = "path.json"`) and
a `migrate-config` command. These are gone: the server reads only the one
file. To move, append the old WARP settings as a `[warp]` table to the relay
configuration file and copy the enrollment's values into `[warp.registration]`
(field names as above; the JSON's keys are the same). Keep the file mode 0600,
run `serve --config FILE --check`, then remove `--warp-config` from the unit's
`ExecStart` and restart it. Do not print the file's contents to troubleshoot a
path or permission error.

WARP settings are fixed for a process generation and need a restart to take
effect. SIGHUP keeps network-relay's users/policy/TLS/website reload; it
cannot switch the active WARP tunnel.
