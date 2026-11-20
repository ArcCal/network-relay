"""Exercise a short global capture on a disposable Mac using a loopback SOCKS peer."""

import contextlib
import json
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time


TARGETS = {"198.51.100.42", "2001:db8::42"}
DNS = "192.0.2.53"
ENDPOINT = "198.51.100.254"


def exact(stream, count):
    value = stream.read(count)
    if len(value) != count:
        raise EOFError("short test stream")
    return value


def numeric_address(stream, kind):
    family, length = {1: (socket.AF_INET, 4), 4: (socket.AF_INET6, 16)}[kind]
    return socket.inet_ntop(family, exact(stream, length)), struct.unpack("!H", exact(stream, 2))[0]


class Socks(socketserver.StreamRequestHandler):
    def handle(self):
        import io

        self.connection.settimeout(12)
        try:
            version, count = exact(self.rfile, 2)
            if version != 5 or 0 not in exact(self.rfile, count):
                return
            self.wfile.write(b"\x05\x00")
            version, command, reserved, kind = exact(self.rfile, 4)
            if version != 5 or reserved:
                return
            target, port = numeric_address(self.rfile, kind)
            if command == 1 and target in TARGETS and port == 443:
                self.wfile.write(b"\x05\x00\x00\x01" + bytes(6))
                while chunk := self.rfile.read1(16384):
                    self.wfile.write(chunk)
            elif command == 3:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.bind(("127.0.0.1", 0))
                    udp.settimeout(8)
                    self.wfile.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.getsockname()[1]))
                    while True:
                        packet, source = udp.recvfrom(65535)
                        if packet[:3] != bytes(3):
                            continue
                        data = io.BytesIO(packet)
                        data.seek(3)
                        host, port = numeric_address(data, exact(data, 1)[0])
                        if host in TARGETS and port == 443:
                            udp.sendto(packet, source)
                        elif (host, port) == (DNS, 53):
                            # Return the question with QR set and no answers.
                            offset = data.tell()
                            query = data.read()
                            if len(query) >= 12:
                                udp.sendto(packet[:offset] + query[:2] + bytes([query[2] | 0x80]) + query[3:], source)
            else:
                self.wfile.write(b"\x05\x02\x00\x01" + bytes(6))
        except (EOFError, KeyError, OSError):
            return


def output(*args, stdin=None):
    return subprocess.run(args, input=stdin, capture_output=True, text=True, check=True, timeout=8).stdout


def dns_state():
    return output("/usr/sbin/scutil", stdin=f"show State:/Network/Service/NetworkRelayTun-{os.getuid()}/DNS\nquit\n")


def route_interface(address):
    family = "-inet6" if ":" in address else "-inet"
    fields = (row.strip().partition(":") for row in output("/sbin/route", "-n", "get", family, address).splitlines())
    return next(value.strip() for key, _, value in fields if key == "interface")


def check_packets():
    payload = bytes(range(251)) * 47
    for host in sorted(TARGETS):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as tcp:
            tcp.settimeout(5)
            tcp.connect((host, 443))
            tcp.sendall(payload)
            with tcp.makefile("rb") as response:
                assert exact(response, len(payload)) == payload, host
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            udp.connect((host, 443))
            for size in (63, 1200, 8192):
                udp.send(payload[:size])
                assert udp.recv(65535) == payload[:size], (host, size)
    query = bytes.fromhex("123401000001000000000000") + b"\x05relay\x04test\x00\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(5)
        udp.connect((DNS, 53))
        udp.send(query)
        assert udp.recv(512) == query[:2] + b"\x81" + query[3:]


def main():
    initial_dns = dns_state()
    initial_route = route_interface(ENDPOINT)
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Socks) as socks:
        socks.daemon_threads = True
        threading.Thread(target=socks.serve_forever, daemon=True).start()
        with subprocess.Popen([sys.argv[1], "control"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as bridge:
            # Losing this control connection releases its lease even if a test stalls.
            watchdog = threading.Timer(90, bridge.kill)
            watchdog.start()

            def request(op, **fields):
                bridge.stdin.write(json.dumps({"operation": op, **fields}) + "\n")
                bridge.stdin.flush()
                reply = json.loads(bridge.stdout.readline())
                if not reply["ok"]:
                    raise RuntimeError(f"{op}: {reply['error']}")
                return reply["status"]

            try:
                assert request("recover")["state"] == "idle"
                prepared = request("prepare", plan={"endpoints": [ENDPOINT], "resolvers": [DNS],
                                                    "mtu": 1500, "socks_port": socks.server_address[1]})
                lease, interface = prepared["lease"], prepared["interface"]
                assert request("activate", lease=lease)["state"] == "active"
                assert request("refresh", lease=lease)["state"] == "active"
                assert route_interface(ENDPOINT) == initial_route
                assert all(route_interface(host) == interface for host in TARGETS)
                assert DNS in dns_state()
                check_packets()
                # Leave capture active across a controller heartbeat.
                time.sleep(2)
                assert request("refresh", lease=lease)["state"] == "active"
                check_packets()
                assert request("stop", lease=lease)["state"] == "idle"
                assert dns_state() == initial_dns
                assert route_interface(ENDPOINT) == initial_route
                print("PASS native dual-stack TCP, UDP, DNS, relay bypass and resolver restoration")
            finally:
                try:
                    if bridge.poll() is None:
                        with contextlib.suppress(BrokenPipeError):
                            request("recover")
                        bridge.stdin.close()
                        bridge.wait(timeout=10)
                finally:
                    watchdog.cancel()
                    socks.shutdown()


if __name__ == "__main__":
    main()
