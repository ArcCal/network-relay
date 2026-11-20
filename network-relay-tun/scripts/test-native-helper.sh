#!/usr/bin/env bash
# Disposable CI host only. With --capture also activate and restore real
# split-default routes and DNS while exercising the local packet worker.
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
 assert result['control_revision']==2
 if not result['ok']: raise RuntimeError(result['error'])
 return result['status']
try:
 assert request({'operation':'recover'})['state']=='idle'
 state=request({'operation':'prepare','plan':{'endpoints':['198.51.100.254'],'resolvers':['1.1.1.1'],'mtu':1500,'socks_port':1080}})
 assert state['state']=='prepared' and state['interface'].startswith('utun')
 assert request({'operation':'refresh','lease':state['lease']})['state']=='prepared'
 assert request({'operation':'stop','lease':state['lease']})['state']=='idle'
 print('PASS: installed daemon, authenticated IPC, utun worker startup and owned-state recovery')
finally:
 try: request({'operation':'recover'})
 finally:
  child.stdin.close()
  child.wait(timeout=15)
PY
if [[ ${1:-} == --capture ]]; then
    uplink=$(/sbin/route -n get -inet 198.51.100.254 | awk '$1 == "interface:" { print $2 }')
    [[ -n "$uplink" ]]
    monitor="$root/.build/physical-path-capture"
    mkdir -p "$root/.build"
    xcrun swiftc -swift-version 5 -parse-as-library -o "$monitor" \
        "$root/App/Sources/NetworkRelayTun/NetworkChanges.swift" "$root/tests/PhysicalPathCapture.swift"
    "$monitor" "$uplink" python3 "$root/tests/native_capture.py" "$app/Contents/Helpers/network-relay-tun-host"
    # Exercise an update of a running service and wait for its new listener.
    sudo /bin/bash "$app/Contents/Resources/install-helper.sh" "$owner"
    for ((attempt = 0; attempt < 100; attempt++)); do
        [[ -S "$installed/control.sock" ]] && break
        /bin/sleep 0.1
    done
    "$monitor" "$uplink" python3 "$root/tests/native_capture.py" "$app/Contents/Helpers/network-relay-tun-host"
fi
trap - EXIT
cleanup
[[ ! -e $installed && ! -e /Library/LaunchDaemons/com.arccal.network-relay-tun.helper.plist ]]
