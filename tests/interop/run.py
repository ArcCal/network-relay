#!/usr/bin/env python3
"""Local, trusted-TLS fixture for the existing Go and curl clients.

Run after cargo build: python3 tests/interop/run.py
Only this temporary configuration permits loopback destinations.
"""
import base64
import contextlib
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]


@contextlib.contextmanager
def relay(binary, host='127.0.0.1'):
    with tempfile.TemporaryDirectory(prefix='relay-interop-') as directory:
        d = Path(directory)
        def openssl(*args):
            subprocess.run(['openssl', *args], cwd=d, check=True, capture_output=True, timeout=15)
        openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=Interop CA',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                '-addext', 'subjectKeyIdentifier=hash')
        openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', 'key.pem', '-out', 'cert.csr', '-subj', '/CN=relay.test')
        (d / 'extensions').write_text('subjectAltName=DNS:relay.test,IP:127.0.0.1,IP:::1\n'
                                     'extendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n'
                                     'keyUsage=critical,digitalSignature\n'
                                     'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        openssl('x509', '-req', '-in', 'cert.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                '-CAcreateserial', '-out', 'cert.pem', '-days', '1', '-extfile', 'extensions')
        password = secrets.token_urlsafe(24)
        account = subprocess.run([str(binary), 'passwd', '--name', 'alice', '--stdin', '--fast-hash'],
                                 input=password + '\n', text=True, capture_output=True, check=True, timeout=15).stdout
        # Reserve the chosen TCP and UDP port while preparing the fixture.
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        with socket.socket(family) as tcp, socket.socket(family, socket.SOCK_DGRAM) as udp:
            tcp.bind((host, 0))
            port = tcp.getsockname()[1]
            udp.bind((host, port))
            config = d / 'relay.toml'
            address = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
            config.write_text(f'listen = "{address}"\n[tls]\n'
                              f'cert = {json.dumps(str(d / "cert.pem"))}\n'
                              f'key = {json.dumps(str(d / "key.pem"))}\n'
                              '[relay]\nblocked_destinations = []\nblock_own_addresses = false\n'
                              'max_tunnels = 64\nmax_connections = 64\n'
                              '[debug]\nlog_requests = true\n' + account)
        subprocess.run([str(binary), 'serve', '--config', str(config), '--check'], check=True, timeout=15)
        with (d / 'server.log').open('w+') as log:
            proc = subprocess.Popen([str(binary), 'serve', '--config', str(config)], stdout=log, stderr=log)
            try:
                trust = ssl.create_default_context(cafile=str(d / 'ca.pem'))
                trust.verify_flags |= ssl.VERIFY_X509_STRICT
                deadline = time.monotonic() + 10
                while True:
                    if proc.poll() is not None:
                        raise RuntimeError('relay exited during startup')
                    try:
                        with socket.create_connection((host, port), timeout=.5) as tcp:
                            with trust.wrap_socket(tcp, server_hostname='relay.test') as tls:
                                tls.sendall(b'GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n')
                                assert tls.recv(1024).startswith(b'HTTP/1.1 404'), 'unexpected readiness response'
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.05)
                yield d, port, password, proc
            except BaseException:
                log.seek(0)
                print(log.read())  # server masks authentication headers
                raise
            finally:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    code = proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    raise RuntimeError('relay did not shut down in time')
                if code != 0:
                    raise RuntimeError(f'relay exited with {code}')


def curl_checks(d, port, password):
    capabilities = subprocess.run(['curl', '--version'], capture_output=True, text=True, check=True, timeout=5).stdout
    help_text = subprocess.run(['curl', '--help', 'all'], capture_output=True, text=True, check=True, timeout=5).stdout
    has_h2_proxy = 'HTTP2' in capabilities and '--proxy-http2' in help_text
    print(capabilities.splitlines()[0])
    if not has_h2_proxy:
        print('NOT APPLICABLE curl H2 CONNECT: this build lacks HTTP2 / --proxy-http2')
    payload = bytes(range(256)) * 4096
    class Echo(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            data = self.rfile.read(int(self.headers['Content-Length']))
            if data != payload or self.headers.get('Proxy-Authorization') or self.headers.get('Authorization'):
                self.send_error(400)
                return
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass
    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Echo) as target:
        thread = threading.Thread(target=target.serve_forever)
        thread.start()
        try:
            for h2 in (False, True):
                if h2 and not has_h2_proxy:
                    continue
                for header in ('Authorization', 'Proxy-Authorization'):
                    auth = base64.b64encode(f'alice:{password}'.encode()).decode()
                    command = ['curl', '--silent', '--show-error', '--fail', '--noproxy', '',
                               '--proxy', f'https://127.0.0.1:{port}', '--proxytunnel',
                               '--proxy-cacert', str(d / 'ca.pem'), '--max-time', '15',
                               '--verbose', '--proxy-header', f'{header}: Basic {auth}', '--data-binary', '@-']
                    if h2:
                        command += ['--proxy-http2']
                    command += [f'http://127.0.0.1:{target.server_port}/']
                    result = subprocess.run(command, input=payload, capture_output=True, timeout=20)
                    trace = result.stderr.decode().replace(auth, '<redacted>')
                    assert result.returncode == 0, trace
                    assert result.stdout == payload, 'curl payload corrupted'
                    evidence = ('CONNECT tunnel: HTTP/2', 'ALPN: server accepted h2') if h2 else (
                        'CONNECT tunnel: HTTP/1.1', f'> CONNECT 127.0.0.1:{target.server_port} HTTP/1.1')
                    assert any(line in trace for line in evidence), 'wrong proxy transport'
                    print(f'PASS curl {"H2" if h2 else "H1"} CONNECT, {header}, 1 MiB each way')
                # Reuse the same proxy transport and target for negative checks.
                wrong = base64.b64encode(b'alice:wrong-password').decode()
                # curl's H2 proxy does not expose %{http_connect} or proxy
                # response headers via --dump-header; its proxy trace does.
                trace_args = ['--trace-config', 'h2-proxy'] if h2 else []
                bad_auth = [arg.replace(auth, wrong) for arg in command] + ['--write-out', '%{http_connect}', *trace_args]
                result = subprocess.run(bad_auth, input=payload, capture_output=True, timeout=20)
                trace = result.stderr.decode().replace(wrong, '<redacted>')
                status_ok = 'HTTP/2 404' in trace if h2 else result.stdout == b'404'
                assert result.returncode != 0 and status_ok, trace
                blocked = command[:-1] + ['http://127.0.0.1:25/', '--write-out', '%{http_connect}', '--dump-header', '-', *trace_args]
                result = subprocess.run(blocked, input=payload, capture_output=True, timeout=20)
                trace = result.stderr.decode().replace(auth, '<redacted>')
                status_ok = 'HTTP/2 403' in trace if h2 else result.stdout.endswith(b'403')
                assert result.returncode != 0 and status_ok, trace
                status_headers = trace.encode() if h2 else result.stdout
                assert b'error=http_request_denied' in status_headers, 'missing Proxy-Status'
                untrusted = command.copy()
                at = untrusted.index('--proxy-cacert')
                del untrusted[at:at + 2]
                result = subprocess.run(untrusted, input=payload, capture_output=True, timeout=20)
                trace = result.stderr.decode().replace(auth, '<redacted>')
                assert result.returncode == 60, trace
                print(f'PASS curl {"H2" if h2 else "H1"} wrong credentials / denied target / untrusted TLS')
        finally:
            target.shutdown()
            thread.join(timeout=5)


def main():
    binary = Path(os.environ.get('RELAY_BINARY', ROOT / 'target/debug/network-relay')).resolve()
    with tempfile.TemporaryDirectory(prefix='relay-go-') as directory:
        client = Path(directory) / 'masque-client'
        subprocess.run(['go', 'build', '-mod=readonly', '-o', str(client), '.'],
                       cwd=ROOT / 'tests/interop/masque-go', check=True, timeout=180)
        with relay(binary) as (d, port, password, _):
            subprocess.run([str(client), '-relay', f'127.0.0.1:{port}', '-ca', str(d / 'ca.pem')],
                           env={**os.environ, 'RELAY_TEST_PASSWORD': password}, check=True, timeout=75)
            curl_checks(d, port, password)


if __name__ == '__main__':
    main()
