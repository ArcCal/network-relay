#!/usr/bin/env bash
# Disposable CI host only. Exercise privileged preparation and recovery without
# activating split-default routes or changing system DNS.
set -euo pipefail
[[ $(uname -s) == Darwin && ${CI:-} == true ]] || { echo 'Requires a disposable macOS CI runner.' >&2; exit 77; }
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
app="$root/dist/Network Relay Tun.app"
installed='/Library/Application Support/NetworkRelayTun'
[[ ! -e $installed ]] || { echo 'Refusing to reuse an existing helper installation.' >&2; exit 1; }
owner=$(id -u)
[[ $owner != 0 ]] || { echo 'Run the test as the runner user, not root.' >&2; exit 1; }
cleanup() {
    sudo /bin/bash "$app/Contents/Resources/uninstall-helper.sh"
}
trap cleanup EXIT
sudo /bin/bash "$app/Contents/Resources/install-helper.sh" "$owner"
python3 - "$app/Contents/Helpers/network-relay-tun-host" "$installed/control.sock" <<'PY'
import json, pathlib, subprocess, sys, time
socket=pathlib.Path(sys.argv[2])
for _ in range(100):
 if socket.exists(): break
 time.sleep(0.1)
else: raise SystemExit('Installed helper did not create its control socket')
child=subprocess.Popen([sys.argv[1],'control'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
def request(value):
 child.stdin.write(json.dumps(value)+'\n');child.stdin.flush()
 line=child.stdout.readline()
 if not line: raise RuntimeError('Control bridge exited without a reply')
 result=json.loads(line)
 print(json.dumps(result),flush=True)
 if not result['ok']: raise RuntimeError(result['error'])
 return result['status']
try:
 assert request({'operation':'recover'})['state']=='idle'
 state=request({'operation':'prepare','plan':{'endpoints':['198.51.100.254'],'resolvers':['1.1.1.1'],'mtu':1500,'socks_port':1080}})
 assert state['state']=='prepared' and state['interface'].startswith('utun')
 assert request({'operation':'stop','lease':state['lease']})['state']=='idle'
 print('PASS: installed daemon, authenticated IPC, utun worker startup and owned-state recovery')
finally:
 try: request({'operation':'recover'})
 finally:
  child.stdin.close()
  child.wait(timeout=15)
PY
