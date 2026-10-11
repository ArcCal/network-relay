#!/usr/bin/env python3
"""Run the production relay protocol core against both real server binaries.
Transport is emulated with test-only rustls/Quinn; this is not a macOS result.
"""
import argparse, datetime, hashlib, json, os, pathlib, secrets, socket, subprocess, tempfile, threading, time


def run(*command, **kw):
    return subprocess.run(command, check=True, capture_output=True, text=True, **kw)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust-server',required=True,type=pathlib.Path)
    parser.add_argument('--caddy',required=True,type=pathlib.Path)
    parser.add_argument('--results',type=pathlib.Path,default=pathlib.Path('docs/evidence/interop-results.json'))
    args=parser.parse_args()
    root=pathlib.Path(__file__).resolve().parents[1]
    def tree_digest(directory):
        digest=hashlib.sha256()
        files=sorted(directory.rglob('*.rs'))
        for path in files:
            digest.update(path.relative_to(directory).as_posix().encode()+b'\0')
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        return {'sha256':digest.hexdigest(),'rust_files':len(files),'method':'sorted relative path + NUL + file SHA-256 bytes'}
    result={'scope':'production protocol core over test-only rustls/Quinn native bridge emulator',
            'executed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'client_core_source':tree_digest(root/'Core/src'),
            'client_h3_source':tree_digest(root/'Core/vendor/h3/src'),
            'client_manifest_sha256':hashlib.sha256((root/'Core/Cargo.toml').read_bytes()).hexdigest(),
            'client_lockfile_sha256':hashlib.sha256((root/'Core/Cargo.lock').read_bytes()).hexdigest(),
            'native_network_framework':'NOT RUN','servers':[]}
    with tempfile.TemporaryDirectory(prefix='realy-nf-interop-') as tmp:
        directory=pathlib.Path(tmp)
        def openssl(*arguments): run('openssl',*arguments,cwd=directory,timeout=15)
        openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Relay NF fixture CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
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
            for kind,binary in (('network-relay',args.rust_server.resolve()),('caddy-network-relay',args.caddy.resolve())):
                password=secrets.token_urlsafe(24)
                passwd_command=[str(binary)]+(['network-relay'] if kind.startswith('caddy') else [])+['passwd','--name','alice','--stdin','--fast-hash']
                account=run(*passwd_command,input=password+'\n',timeout=15).stdout
                if kind.startswith('caddy'): password_hash=account.strip().split()[2]
                else:
                    import re
                    password_hash=re.search(r'password_hash\s*=\s*"([^"\n]+)"',account).group(1)
                with socket.socket() as reserve: reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
                if kind.startswith('caddy'):
                    config={'admin':{'disabled':True},'storage':{'module':'file_system','root':str(directory/'storage')},'logging':{'logs':{'default':{'level':'ERROR'}}},'apps':{'http':{'servers':{'relay':{'listen':[f'127.0.0.1:{port}'],'automatic_https':{'disable':True},'tls_connection_policies':[{}],'routes':[{'handle':[{'handler':'network_relay','relay_id':'nf-test','users':[{'name':'alice','password_hash':password_hash}],'blocked_destinations':[]},{'handler':'static_response','status_code':404}]}]}}},'tls':{'certificates':{'load_files':[{'certificate':str(directory/'server.pem'),'key':str(directory/'server.key')}]}}}}
                    path=directory/'caddy.json';path.write_text(json.dumps(config));command=[str(binary),'run','--config',str(path)]
                else:
                    path=directory/'relay.toml'
                    path.write_text(f'listen = "127.0.0.1:{port}"\n[tls]\ncert = "{directory}/server.pem"\nkey = "{directory}/server.key"\n[relay]\nblocked_destinations = []\nblocked_ports = []\nblock_own_addresses = false\nudp_idle_timeout_secs = 120\n[[user]]\nname = "alice"\npassword_hash = "{password_hash}"\n')
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
                        fixture=directory/'fixture.json';fixture.write_text(json.dumps({'kind':kind,'server':f'127.0.0.1:{port}','ca':str(directory/'ca.pem'),'password':password,'tcp':'%s:%s'%tcp.getsockname(),'udp':f'127.0.0.1:{udp.getsockname()[1]}'}));fixture.chmod(0o600)
                        environment['RELAY_NF_FIXTURE']=str(fixture)
                        tested=subprocess.run(['cargo','test','--locked','--manifest-path',str(root/'Core/Cargo.toml'),'--test','server_interop','--','--ignored','--nocapture'],cwd=root,env=environment,capture_output=True,text=True,timeout=240)
                        print(tested.stdout);print(tested.stderr)
                        result['servers'].append({'kind':kind,'binary_sha256':__import__('hashlib').sha256(binary.read_bytes()).hexdigest(),'outcome':'PASS' if tested.returncode==0 else 'FAIL','test':'real_server_matrix','output':tested.stdout})
                        args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+'\n')
                        if tested.returncode: raise RuntimeError(kind+' interoperability failed')
                    finally:
                        server.terminate()
                        try: server.wait(timeout=8)
                        except subprocess.TimeoutExpired: server.kill();server.wait()
        finally: stop.set();tcp.close();udp.close()
    print('Both real server matrices passed. Network.framework remains untested.')


if __name__=='__main__':main()
