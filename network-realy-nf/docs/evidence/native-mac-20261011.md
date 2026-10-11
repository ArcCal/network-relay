# User-reported Mac build and SOCKS forwarding

Date: 2026-10-11. Source: application logs and terminal output pasted by the
user in this conversation. These operations ran on the user's Mac, not in the
Linux test environment. The excerpts below omit credentials, password hashes,
HTTP cookies and unrelated headers. They are selected excerpts, not a byte-for-byte
archive of the original messages.

## Application identity and earlier authentication failure

The most recently supplied application identity was:

```text
2026-10-11T09:37:35Z INFO app: Network Realy NF launched; Network.framework transport; app 0.1.0; core 0.1.0 (Rust HTTP CONNECT / CONNECT-UDP); built 2026-10-11T09:37:18Z; source 666b795c881b44eeaade9891edfae04ffcbd34a6
```

This is evidence that the user built and launched the renamed application with
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

The user then ran these commands from the `network-realy-nf` directory:

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
- These results follow the Rust network-relay server troubleshooting above.
  The server type is identified by that user-supplied context, not by a server
  identity or a correlated application run embedded in the terminal output.

## Coverage boundary and remaining evidence

The commands were supplied for a forced HTTP/2 test, but neither a file name nor
curl's `HTTP/2 200` proves the outer relay transport. That status line describes
the HTTPS response from Google through the relayed TCP connection. The earlier
exported settings selected HTTP/1.1; no current application `Relay ready` line
or run ID accompanied these successful probes. Record their outer transport as
**unconfirmed**, rather than declaring a forced native HTTP/2 row complete.
Likewise, the latest known source identity above is not a fresh identity captured
alongside these probes.

This establishes a user-reported native application forwarding success for one
Rust server deployment. It does not establish native caddy-network-relay
compatibility, HTTP/3 success, Automatic fallback, every UI interaction, negative
trust cases, large transfers, IPv6, concurrency or long-session behavior. The
complete native acceptance matrix remains incomplete. Preserve HTTP/2 as the
requested baseline and the single-attempt QUIC stopping rule.
