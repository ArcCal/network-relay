#!/usr/bin/env python3
"""Run the production Rust client against both real relay server binaries.
HTTP/1.1, HTTP/2 and HTTP/3 use the app's actual Rust transport implementation.
The fixture uses disposable local certificates and accounts, never live credentials.
"""
import argparse, base64, datetime, hashlib, json, os, pathlib, platform, re, secrets, socket, struct, subprocess, tempfile, threading, time


def run(*command, **kw):
    return subprocess.run(command, check=True, capture_output=True, text=True, **kw)


def read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise RuntimeError('SOCKS connection closed before its reply')
        data.extend(chunk)
    return bytes(data)


def socks_address(stream):
    reply = read_exact(stream, 4)
    if reply[:3] != b'\x05\x00\x00':
        raise RuntimeError('SOCKS request failed: ' + reply.hex())
    if reply[3] == 1:
        address = socket.inet_ntop(socket.AF_INET, read_exact(stream, 4))
    elif reply[3] == 4:
        address = socket.inet_ntop(socket.AF_INET6, read_exact(stream, 16))
    elif reply[3] == 3:
        address = read_exact(stream, read_exact(stream, 1)[0]).decode('ascii')
    else:
        raise RuntimeError('Unknown SOCKS reply address type')
    return address, struct.unpack('!H', read_exact(stream, 2))[0]


def cli_smoke(binary, directory, fixture, environment, transports=('http/1.1', 'h2', 'h3', 'auto')):
    """Exercise the app controller and configuration importer, not just the core."""
    outcomes = []
    for transport in transports:
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            proxy_port = reserve.getsockname()[1]
        settings = directory / 'client.toml'
        settings.write_text(
            f'uri_template = "https://{fixture["server"]}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"\n'
            f'username = "alice"\npassword = "{fixture["password"]}"\n'
            f'server_name = "relay.test"\ntransport = "{transport}"\nmode = "socks"\n'
            f'probe_target = "{fixture["udp"]}"\n[socks]\nlisten = ["127.0.0.1:{proxy_port}"]\n'
        )
        settings.chmod(0o600)
        log_path = directory / 'client.log'
        with log_path.open('w+') as log:
            client = subprocess.Popen(
                [str(binary), '--config', str(settings), '--ca-file', fixture['ca'],
                 '--transport', transport, '--log-level', 'everything', '--duration', '25'],
                stdout=log, stderr=log, env=environment,
            )
            try:
                deadline = time.monotonic() + 15
                while True:
                    if client.poll() is not None:
                        log.seek(0)
                        raise RuntimeError('Headless app exited: ' + log.read().replace(fixture['password'], '[redacted]'))
                    try:
                        connection = socket.create_connection(('127.0.0.1', proxy_port), timeout=.2)
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise RuntimeError('Headless SOCKS listener did not start')
                        time.sleep(.05)
                target_port = int(fixture['tcp'].rsplit(':', 1)[1])
                with connection:
                    connection.settimeout(15)
                    connection.sendall(b'\x05\x01\x00')
                    if read_exact(connection, 2) != b'\x05\x00':
                        raise RuntimeError('Headless SOCKS greeting failed')
                    connection.sendall(b'\x05\x01\x00\x03\x09localhost' + struct.pack('!H', target_port))
                    socks_address(connection)
                    payload = (bytes(range(251)) * ((1024 * 1024 + 250) // 251))[:1024 * 1024]
                    connection.sendall(payload)
                    connection.shutdown(socket.SHUT_WR)
                    if read_exact(connection, len(payload)) != payload:
                        raise RuntimeError('Headless SOCKS TCP payload corruption')
                with socket.create_connection(('127.0.0.1', proxy_port), timeout=15) as control:
                    control.settimeout(15)
                    control.sendall(b'\x05\x01\x00')
                    if read_exact(control, 2) != b'\x05\x00':
                        raise RuntimeError('Headless SOCKS UDP greeting failed')
                    control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
                    association = socks_address(control)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagrams:
                        datagrams.bind(('127.0.0.1', 0)); datagrams.settimeout(15)
                        packet = b'\x00\x00\x00\x03\x09localhost' + struct.pack('!H', int(fixture['udp'].rsplit(':', 1)[1])) + b'RS app SOCKS UDP'
                        datagrams.sendto(packet, association)
                        reply, peer = datagrams.recvfrom(65535)
                        if peer != association or reply != packet:
                            raise RuntimeError('Headless SOCKS UDP payload corruption')
                client.send_signal(__import__('signal').SIGINT)
                client.wait(timeout=10)
                if client.returncode != 0:
                    raise RuntimeError('Headless app did not shut down cleanly')
                log.seek(0)
                output = log.read()
                encoded = base64.b64encode(('alice:' + fixture['password']).encode()).decode('ascii')
                if fixture['password'] in output or encoded in output:
                    raise RuntimeError('Fixture credentials appeared in the Everything log')
                if 'TRACE' not in output or 'Rust I/O request' not in output or 'Rust stream received' not in output:
                    raise RuntimeError('Everything logging did not include Rust I/O metadata diagnostics')
                outcomes.append({'transport': transport, 'outcome': 'PASS',
                                 'checks': 'app configuration import, listener, 1 MiB SOCKS TCP half-close, remote DNS SOCKS UDP, Control-C shutdown, Everything metadata logs without plaintext/Basic credentials',
                                 'logging_checks': {'level': 'everything', 'trace_io_requests': output.count('Rust I/O request'),
                                                    'trace_stream_reads': output.count('Rust stream received'),
                                                    'plaintext_password_present': False, 'basic_token_present': False},
                                 'output': output})
            finally:
                if client.poll() is None:
                    client.terminate()
                    try: client.wait(timeout=8)
                    except subprocess.TimeoutExpired: client.kill(); client.wait()
    return outcomes


def cli_error_logging(binary, directory, fixture, environment):
    outcomes = []
    for wrong in (False, True):
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0)); proxy_port = reserve.getsockname()[1]
        password = 'incorrect-rs-fixture-password' if wrong else fixture['password']
        path = directory / 'client-errors.toml'
        path.write_text(
            f'uri_template = "https://{fixture["server"]}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"\n'
            f'username = "alice"\npassword = "{password}"\n'
            f'server_name = "relay.test"\ntransport = "h2"\nmode = "socks"\n'
            f'[socks]\nlisten = ["127.0.0.1:{proxy_port}"]\n'
        ); path.chmod(0o600)
        child = subprocess.run([str(binary), '--config', str(path), '--ca-file', fixture['ca'],
                                '--log-level', 'errors', '--duration', '2'], env=environment,
                               capture_output=True, text=True, timeout=15)
        output = child.stdout + child.stderr
        if re.search(r' (INFO|WARN|DEBUG|TRACE) ', output):
            raise RuntimeError('Errors-only CLI printed a hidden log level')
        if wrong:
            if child.returncode == 0 or ' ERROR ' not in output:
                raise RuntimeError('Errors-only CLI did not display a rejected-credential error')
        elif child.returncode != 0 or ' ERROR ' in output:
            raise RuntimeError('Healthy errors-only CLI failed')
        for secret in (fixture['password'], password):
            token = base64.b64encode(('alice:' + secret).encode()).decode('ascii')
            if secret in output or token in output:
                raise RuntimeError('Fixture credentials appeared in errors-only logs')
        outcomes.append({'case': 'wrong-credentials' if wrong else 'healthy', 'level': 'errors',
                         'outcome': 'PASS', 'hidden_levels_present': False,
                         'returncode': child.returncode, 'output': output})
    return outcomes


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust-server',required=True,type=pathlib.Path)
    parser.add_argument('--caddy',required=True,type=pathlib.Path)
    parser.add_argument('--results',type=pathlib.Path,help='Evidence destination; defaults to this app\'s docs/evidence/interop-results.json')
    parser.add_argument('--client',type=pathlib.Path,help='Built Network Relay RS app binary for headless SOCKS smoke tests')
    parser.add_argument('--rust-source',help='Exact source revision of the Rust server binary')
    parser.add_argument('--caddy-source',help='Exact source revision of the Caddy server binary')
    parser.add_argument('--skip-soak',action='store_true',help='Run the protocol/security matrix without the 125-second HTTP/3 soak')
    args=parser.parse_args()
    root=pathlib.Path(__file__).resolve().parents[1]
    if args.results is None: args.results = root/'docs/evidence/interop-results.json'
    def tree_digest(directory):
        digest=hashlib.sha256()
        files=sorted(directory.rglob('*.rs'))
        for path in files:
            digest.update(path.relative_to(directory).as_posix().encode()+b'\0')
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        return {'sha256':digest.hexdigest(),'rust_files':len(files),'method':'sorted relative path + NUL + file SHA-256 bytes'}
    result={'scope':'production Rust protocol core and production Rust TCP/TLS/QUIC/SOCKS transport against both real local server binaries',
            'executed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'client_core_source':tree_digest(root/'Core/src'),
            'client_app_source':tree_digest(root/'src'),
            'client_h3_source':tree_digest(root/'Core/vendor/h3/src'),
            'client_tests_source':tree_digest(root/'Core/tests'),
            'client_manifest_sha256':hashlib.sha256((root/'Core/Cargo.toml').read_bytes()).hexdigest(),
            'client_app_manifest_sha256':hashlib.sha256((root/'Cargo.toml').read_bytes()).hexdigest(),
            'client_lockfile_sha256':hashlib.sha256((root/'Cargo.lock').read_bytes()).hexdigest(),
            'network_framework':'NOT USED', 'platform':platform.platform(), 'architecture':platform.machine(),
            'macos_gui':'NOT RUN by this headless suite', 'http3_soak_seconds':0 if args.skip_soak else 125, 'servers':[]}
    if args.client:
        app_binary = args.client.resolve()
        result['client_app'] = {'binary_sha256': hashlib.sha256(app_binary.read_bytes()).hexdigest(),
                                'version': run(str(app_binary), '--version', timeout=15).stdout.strip()}
    def ensure_same_inputs():
        for field, directory in [('client_core_source', root/'Core/src'),
                                 ('client_app_source', root/'src'),
                                 ('client_h3_source', root/'Core/vendor/h3/src'),
                                 ('client_tests_source', root/'Core/tests')]:
            if tree_digest(directory) != result[field]:
                raise RuntimeError('Client/test source changed during the run; rerun against stable inputs')
        if hashlib.sha256((root/'Cargo.lock').read_bytes()).hexdigest() != result['client_lockfile_sha256']:
            raise RuntimeError('Cargo.lock changed during the run; rerun against stable inputs')
        if hashlib.sha256((root/'Core/Cargo.toml').read_bytes()).hexdigest() != result['client_manifest_sha256'] or hashlib.sha256((root/'Cargo.toml').read_bytes()).hexdigest() != result['client_app_manifest_sha256']:
            raise RuntimeError('Cargo manifest changed during the run; rerun against stable inputs')
        if args.client and hashlib.sha256(args.client.resolve().read_bytes()).hexdigest() != result['client_app']['binary_sha256']:
            raise RuntimeError('App binary changed during the run; rerun against a stable binary')
    with tempfile.TemporaryDirectory(prefix='relay-rs-interop-') as tmp:
        directory=pathlib.Path(tmp)
        def openssl(*arguments): run('openssl',*arguments,cwd=directory,timeout=15)
        openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Relay RS fixture CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
        openssl('req','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=relay.test')
        (directory/'server.ext').write_text('subjectAltName=DNS:relay.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n')
        openssl('x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','1','-extfile','server.ext')
        stop=threading.Event()
        tcp=socket.socket();tcp.bind(('127.0.0.1',0));tcp.listen();tcp.settimeout(.1)
        udp=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);udp.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0);udp.bind(('::',0));udp.settimeout(.1)
        def echo(connection):
            with connection:
                while True:
                    try:
                        data=connection.recv(65536)
                        if not data: break
                        connection.sendall(data)
                    except ConnectionResetError: break
        def tcp_echo():
            while not stop.is_set():
                try: connection,_=tcp.accept()
                except socket.timeout: continue
                except OSError: return
                threading.Thread(target=echo,args=(connection,),daemon=True).start()
        def udp_echo():
            while not stop.is_set():
                try: data,peer=udp.recvfrom(65535)
                except socket.timeout: continue
                except OSError: return
                udp.sendto(data,peer)
        for target in (tcp_echo,udp_echo):threading.Thread(target=target,daemon=True).start()
        try:
            for kind,binary in (('network-relay',args.rust_server.resolve()),('caddy-network-relay',args.caddy.resolve()),('caddy-network-relay-tcp-only',args.caddy.resolve())):
                tcp_only = kind.endswith('-tcp-only')
                password=secrets.token_urlsafe(24)
                passwd_command=[str(binary)]+(['network-relay'] if kind.startswith('caddy') else [])+['passwd','--name','alice','--stdin','--fast-hash']
                account=run(*passwd_command,input=password+'\n',timeout=15).stdout
                if kind.startswith('caddy'): password_hash=account.strip().split()[2]
                else:
                    import re
                    password_hash=re.search(r'password_hash\s*=\s*"([^"\n]+)"',account).group(1)
                with socket.socket() as reserve: reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
                if kind.startswith('caddy'):
                    config={'admin':{'disabled':True},'storage':{'module':'file_system','root':str(directory/'storage')},'logging':{'logs':{'default':{'level':'ERROR'}}},'apps':{'http':{'servers':{'relay':{'listen':[f'127.0.0.1:{port}'],'automatic_https':{'disable':True},'tls_connection_policies':[{}],'routes':[{'handle':[{'handler':'network_relay','relay_id':'rs-test','users':[{'name':'alice','password_hash':password_hash}],'blocked_destinations':[],'blocked_ports':[1]},{'handler':'static_response','status_code':404}]}]}}},'tls':{'certificates':{'load_files':[{'certificate':str(directory/'server.pem'),'key':str(directory/'server.key')}]}}}}
                    if tcp_only: config['apps']['http']['servers']['relay']['protocols'] = ['h1','h2']
                    path=directory/'caddy.json';path.write_text(json.dumps(config));command=[str(binary),'run','--config',str(path)]
                else:
                    path=directory/'relay.toml'
                    path.write_text(f'listen = "127.0.0.1:{port}"\n[tls]\ncert = "{directory}/server.pem"\nkey = "{directory}/server.key"\n[relay]\nblocked_destinations = []\nblocked_ports = [1]\nblock_own_addresses = false\nudp_idle_timeout_secs = 120\n[[user]]\nname = "alice"\npassword_hash = "{password_hash}"\n')
                    command=[str(binary),'serve','--config',str(path)]
                environment=os.environ.copy();environment['XDG_CONFIG_HOME']=str(directory/'config');environment['XDG_DATA_HOME']=str(directory/'data')
                with (directory/'server.log').open('w+') as server_log:
                    server=subprocess.Popen(command,stdout=server_log,stderr=server_log,env=environment)
                    try:
                        deadline=time.monotonic()+12
                        while True:
                            if server.poll() is not None:
                                server_log.seek(0);raise RuntimeError('Server startup failed: '+server_log.read())
                            try:
                                with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                            except OSError:
                                if time.monotonic()>deadline: raise RuntimeError('Server not ready')
                                time.sleep(.05)
                        fixture_data={'kind':kind,'server':f'127.0.0.1:{port}','ca':str(directory/'ca.pem'),'password':password,'tcp':'%s:%s'%tcp.getsockname(),'udp':f'127.0.0.1:{udp.getsockname()[1]}'}
                        fixture=directory/'fixture.json';fixture.write_text(json.dumps(fixture_data));fixture.chmod(0o600)
                        environment['RELAY_RS_FIXTURE']=str(fixture)
                        selected_test='auto_falls_back_when_quic_is_unavailable' if tcp_only else 'real_server_matrix'
                        test_command=['cargo','test','--locked','--manifest-path',str(root/'Cargo.toml'),'-p','network-relay-rs-core','--test','server_interop','--','--ignored','--nocapture','--test-threads=1','--exact',selected_test]
                        ensure_same_inputs()
                        print(f"Running {kind}: " + ("real QUIC failure and automatic HTTP/2 fallback" if tcp_only else "HTTP/1.1, HTTP/2, HTTP/3, auto, security and " + ("protocol matrix" if args.skip_soak else "125-second HTTP/3 stability soak")), flush=True)
                        started=time.monotonic()
                        tested=subprocess.run(test_command,cwd=root,env=environment,capture_output=True,text=True,timeout=480)
                        completed_tests = [selected_test]
                        if tested.returncode == 0 and not tcp_only:
                            ensure_same_inputs()
                            print(f'{kind}: checking 80 concurrent HTTP/3 streams and cancellation', flush=True)
                            reuse_command = test_command[:-1] + ['http3_concurrent_streams_share_one_connection']
                            reused = subprocess.run(reuse_command, cwd=root, env=environment, capture_output=True, text=True, timeout=90)
                            tested = subprocess.CompletedProcess(test_command, reused.returncode, tested.stdout + reused.stdout, tested.stderr + reused.stderr)
                            completed_tests.append('http3_concurrent_streams_share_one_connection')
                        if tested.returncode == 0 and not args.skip_soak and not tcp_only:
                            ensure_same_inputs()
                            print(f'{kind}: fast matrix passed; starting the 125-second HTTP/3 soak', flush=True)
                            soak_command=test_command[:-1]+['http3_stability_soak']
                            soak=subprocess.run(soak_command,cwd=root,env=environment,capture_output=True,text=True,timeout=220)
                            completed_tests.append('http3_stability_soak')
                            tested=subprocess.CompletedProcess(test_command,soak.returncode,tested.stdout+soak.stdout,tested.stderr+soak.stderr)
                        print(tested.stdout);print(tested.stderr)
                        result['servers'].append({'kind':kind,'source_revision':args.caddy_source if kind.startswith('caddy') else args.rust_source,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'version':run(str(binary),*(['version'] if kind.startswith('caddy') else ['--version']),timeout=15).stdout.strip(),'duration_seconds':round(time.monotonic()-started,3),'outcome':'PASS' if tested.returncode==0 else 'FAIL','tests':completed_tests,'output':tested.stdout,'stderr':tested.stderr})
                        if args.client and tested.returncode == 0:
                            ensure_same_inputs()
                            result['servers'][-1]['app_smoke'] = cli_smoke(args.client.resolve(), directory, fixture_data, environment, ('auto',) if tcp_only else ('http/1.1','h2','h3','auto'))
                            result['servers'][-1]['error_logging_cases'] = cli_error_logging(args.client.resolve(), directory, fixture_data, environment)
                        args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+'\n')
                        if tested.returncode: raise RuntimeError(kind+' interoperability failed')
                    finally:
                        server.terminate()
                        try: server.wait(timeout=8)
                        except subprocess.TimeoutExpired: server.kill();server.wait()
        finally: stop.set();tcp.close();udp.close()
    print('Both production Rust transport server matrices passed. GUI/macOS runtime validation is separate.')


if __name__=='__main__':main()
