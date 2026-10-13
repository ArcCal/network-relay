# User-reported Mac build and SOCKS forwarding

Date: 2026-10-11. Source: application logs and terminal output pasted by the
user in this conversation. These operations ran on the user's Mac, not in the
Linux test environment. The excerpts below omit credentials, password hashes,
HTTP cookies and unrelated headers. They are selected excerpts, not a byte-for-byte
archive of the original messages.
The quoted launch record retains the historical application spelling; the
current name is Network Relay NF.

## Application identity and earlier authentication failure

The most recently supplied application identity was:

```text
2026-10-11T09:37:35Z INFO app: Network Realy NF launched; Network.framework transport; app 0.1.0; core 0.1.0 (Rust HTTP CONNECT / CONNECT-UDP); built 2026-10-11T09:37:18Z; source 666b795c881b44eeaade9891edfae04ffcbd34a6
```

This is evidence that the user built and launched the earlier application with
its Rust core and native bridge. A complete build transcript, Swift test results,
native smoke results, signature verification and binary checksum were not supplied.
The user previously reported macOS 27.0.1, build 26A434, on this Mac mini; the
forwarding excerpt does not contain a fresh environment inventory.

Two earlier forced HTTP/2 attempts received HTTP 404. Corresponding Rust
network-relay logs explicitly recorded authentication failure; the server masks
unauthenticated proxy requests with its website response. One attempt used a
different account name. The uploaded client password matched the newly generated
password hash, but not the old hash shown before editing. No secret values are
retained here. Subsequent configuration checks passed and systemd reported reload.
Those older failures do not establish a Network.framework defect or a failure
with the new credentials.

## Successful external observations

The user then ran these commands from the application directory, now named
`network-relay-nf`:

```bash
curl -I --noproxy '' --proxy socks5h://127.0.0.1:1080 \
  --connect-timeout 10 --max-time 30 https://www.google.com/ \
  2>&1 | tee nf-http2-curl.log

python3 scripts/probe-socks-udp.py --proxy-port 1080 \
  --dns-server 1.1.1.1 --name www.google.com \
  2>&1 | tee nf-http2-udp.log
```

Relevant supplied output:

```text
HTTP/2 200
date: Sun, 11 Oct 2026 09:56:09 GMT
PASS SOCKS UDP: DNS www.google.com via 1.1.1.1:53; reply=1.1.1.1:53; answers=8; bytes=160
```

- **PASS, user reported:** SOCKS5 CONNECT with a domain destination obtained an
  HTTPS response from Google. `socks5h` delegates destination-name resolution to
  the proxy; `--noproxy ''` prevents curl's no-proxy list from bypassing it.
- **PASS, user reported:** SOCKS5 UDP ASSOCIATE carried a DNS query and its response.
  The observation helper sends the query only to the SOCKS UDP relay and checks
  the response ID, question, DNS response structure and answer presence. Its
  sockets belong to the external observer, not the application's production I/O.
- The later cumulative application log supplies run `810BA952`: forced HTTP/2
  at 09:55:42 UTC, authenticated HTTP/2 readiness at 09:55:43.635736, and a SOCKS
  UDP relay opened at 09:56:09. The terminal response has the same 09:56:09 UTC
  timestamp. This now attributes the positive probes to the forced HTTP/2 run.
  Rust network-relay is identified by the user's server deployment context.

## Coverage boundary and remaining evidence

The terminal status alone identifies Google's response protocol. The subsequently
supplied application trace provides the missing outer HTTP/2 attribution; this
supersedes the earlier unconfirmed designation. The trace is cumulative and
includes the launch identity above; no new launch/build identity was supplied.
The endpoint logged for this deployment is `relay.kitendesecschool.com`, with IP
override `35.212.234.101:443`. Certificate-name validation remains enabled.

This establishes a user-reported native application forwarding success for one
Rust server deployment. It does not establish native caddy-network-relay
compatibility, sustained HTTP/3 forwarding, Automatic fallback, every UI interaction, negative
trust cases, large transfers, IPv6, concurrency or long-session behavior. The
complete native acceptance matrix remains incomplete. Later forced HTTP/3 runs
reach admission but repeatedly fail with native EINVAL about ten seconds later.
An HTTP/2 readiness probe also ends cleanly after 300.001568 seconds. These are
different incidents; see the [QUIC report](../QUIC-RESEARCH.md), [selected log](native-quic-20261011.log)
and [original-upload hashes](native-quic-20261011.json). No Mac retest of the new
stream-error propagation and readiness-probe renewal fixes has run yet.
