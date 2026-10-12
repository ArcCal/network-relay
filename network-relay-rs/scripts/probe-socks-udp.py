#!/usr/bin/env python3
"""Send one DNS query through the running app's SOCKS5 UDP association.

This external observation tool uses Python sockets. The app's production I/O
uses Rust sockets, rustls and Quinn. No DNS query is sent directly to the DNS server.
"""
import argparse
import ipaddress
import secrets
import socket
import struct
import sys


def read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise RuntimeError("SOCKS control connection closed before its reply")
        data.extend(chunk)
    return bytes(data)


def address_bytes(host, port):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if not 0 < len(encoded) <= 255:
            raise ValueError("SOCKS destination name must contain 1 to 255 bytes")
        return b"\x03" + bytes([len(encoded)]) + encoded + struct.pack("!H", port)
    return bytes([1 if address.version == 4 else 4]) + address.packed + struct.pack("!H", port)


def read_address(read, kind):
    if kind == 1:
        host = str(ipaddress.IPv4Address(read(4)))
    elif kind == 4:
        host = str(ipaddress.IPv6Address(read(16)))
    elif kind == 3:
        host = read(read(1)[0]).decode("ascii")
    else:
        raise RuntimeError(f"Invalid SOCKS address type {kind}")
    return host, struct.unpack("!H", read(2))[0]


def dns_query(name):
    labels = name.rstrip(".").split(".")
    encoded = [label.encode("idna") for label in labels]
    if not encoded or any(not 0 < len(label) <= 63 for label in encoded):
        raise ValueError("Invalid DNS name")
    question = b"".join(bytes([len(label)]) + label for label in encoded) + b"\x00"
    if len(question) > 255:
        raise ValueError("DNS name is too long")
    identifier = secrets.randbelow(65536)
    return identifier, struct.pack("!6H", identifier, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)


def observe(args):
    # Proxy address is literal; the DNS destination name is encoded for the relay.
    ipaddress.ip_address(args.proxy_host)
    identifier, query = dns_query(args.name)
    with socket.create_connection((args.proxy_host, args.proxy_port), args.timeout) as control:
        control.settimeout(args.timeout)
        control.sendall(b"\x05\x01\x00")
        if read_exact(control, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS proxy did not accept unauthenticated local access")
        with socket.socket(control.family, socket.SOCK_DGRAM) as datagrams:
            datagrams.bind((control.getsockname()[0], 0))
            datagrams.settimeout(args.timeout)
            local_host, local_port = datagrams.getsockname()[:2]
            control.sendall(b"\x05\x03\x00" + address_bytes(local_host, local_port))
            reply = read_exact(control, 4)
            if reply[0] != 5 or reply[2] != 0 or reply[1] != 0:
                raise RuntimeError(f"SOCKS UDP ASSOCIATE rejected; reply={reply.hex()}")
            relay_host, relay_port = read_address(lambda n: read_exact(control, n), reply[3])
            relay_ip = ipaddress.ip_address(relay_host)
            if relay_ip.is_unspecified:
                relay_host = control.getpeername()[0]
            if relay_port == 0:
                raise RuntimeError("SOCKS proxy returned no UDP relay port")
            datagrams.connect((relay_host, relay_port))
            datagrams.send(b"\x00\x00\x00" + address_bytes(args.dns_server, 53) + query)
            packet = datagrams.recv(65535)
            if len(packet) < 4 or packet[:3] != b"\x00\x00\x00":
                raise RuntimeError("Invalid or fragmented SOCKS UDP response")
            offset = 4

            def take(length):
                nonlocal offset
                end = offset + length
                if end > len(packet):
                    raise RuntimeError("Truncated SOCKS UDP response")
                part = packet[offset:end]
                offset = end
                return part

            source, port = read_address(take, packet[3])
            payload = packet[offset:]
            if port != 53 or len(payload) < 12:
                raise RuntimeError("Reply is not a complete DNS header from port 53")
            response_id, flags, questions, answers, authority, additional = struct.unpack("!6H", payload[:12])
            if response_id != identifier or not flags & 0x8000 or questions != 1:
                raise RuntimeError("DNS reply did not match this query")
            rcode = flags & 15
            if rcode != 0 or flags & 0x0200 or answers == 0:
                raise RuntimeError(f"DNS response is unsuccessful or truncated: rcode={rcode}, answers={answers}")
            question_end = len(query)
            if payload[12:question_end] != query[12:]:
                raise RuntimeError("DNS response question differs from this query")
            cursor = question_end
            for _ in range(answers + authority + additional):
                while True:
                    if cursor >= len(payload):
                        raise RuntimeError("Truncated DNS record name")
                    size = payload[cursor]
                    cursor += 1
                    if size == 0:
                        break
                    if size & 0xC0 == 0xC0:
                        if cursor >= len(payload) or ((size & 63) << 8 | payload[cursor]) >= len(payload):
                            raise RuntimeError("Invalid DNS compression pointer")
                        cursor += 1
                        break
                    if size > 63 or cursor + size > len(payload):
                        raise RuntimeError("Invalid DNS record name")
                    cursor += size
                if cursor + 10 > len(payload):
                    raise RuntimeError("Truncated DNS record header")
                length = struct.unpack("!H", payload[cursor + 8:cursor + 10])[0]
                cursor += 10 + length
                if cursor > len(payload):
                    raise RuntimeError("Truncated DNS record data")
            print(f"PASS SOCKS UDP: DNS {args.name} via {args.dns_server}:53; reply={source}:{port}; answers={answers}; bytes={len(payload)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-host", default="127.0.0.1", help="Literal local SOCKS address")
    parser.add_argument("--proxy-port", type=int, default=1080)
    parser.add_argument("--dns-server", default="1.1.1.1", help="IP or domain, resolved by the relay")
    parser.add_argument("--name", default="example.com")
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()
    if not 0 < args.proxy_port <= 65535 or not 0 < args.timeout <= 120:
        parser.error("proxy port must be 1..65535; timeout must be greater than 0 and at most 120 seconds")
    try:
        observe(args)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"FAIL SOCKS UDP: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
