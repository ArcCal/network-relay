#!/bin/bash
# Invoked only after explicit local administrator authorization.
set -euo pipefail
umask 077
[[ $(uname -s) == Darwin && $EUID == 0 ]] || { echo 'macOS administrator privileges required' >&2; exit 1; }
[[ $# == 1 && $1 =~ ^[0-9]+$ && $1 != 0 ]] || { echo 'Expected installing user UID' >&2; exit 1; }
owner=$1
/usr/bin/id -nu "$owner" >/dev/null
source_dir=$(cd -- "$(dirname -- "$0")/../Helpers" && pwd)
root='/Library/Application Support/NetworkRelayTun'
label='com.arccal.network-relay-tun.helper'
plist="/Library/LaunchDaemons/$label.plist"
# Never follow or reuse a user-writable state directory.
if [[ -e $root || -L $root ]]; then
    [[ ! -L $root && -d $root && $(/usr/bin/stat -f %u "$root") == 0 ]] || exit 1
    mode=$(/usr/bin/stat -f %Lp "$root")
    (( (8#$mode & 0022) == 0 )) || exit 1
else
    /usr/bin/install -d -o root -g wheel -m 755 "$root"
fi
[[ ! -e "$root/network.json" ]] || { echo 'Disconnect and recover the network before updating the helper.' >&2; exit 1; }
[[ -f "$source_dir/network-relay-tun-host" && -f "$source_dir/packet-worker" ]] || exit 1
if /bin/launchctl print "system/$label" >/dev/null 2>&1; then
    /bin/launchctl bootout "system/$label"
fi
if /bin/launchctl print "system/$label" >/dev/null 2>&1; then
    echo 'Helper is still running; installation files preserved.' >&2; exit 1
fi
if [[ -e "$root/network.json" ]]; then
    # Resume the existing helper so its recovery command remains available.
    [[ ! -f "/Library/LaunchDaemons/$label.plist" ]] || /bin/launchctl bootstrap system "/Library/LaunchDaemons/$label.plist"
    echo 'Recovery journal remains; recover with the existing helper first.' >&2; exit 1
fi
/usr/bin/install -o root -g wheel -m 755 "$source_dir/network-relay-tun-host" "$root/network-relay-tun-host.new"
/usr/bin/install -o root -g wheel -m 755 "$source_dir/packet-worker" "$root/packet-worker.new"
/bin/mv -f "$root/network-relay-tun-host.new" "$root/network-relay-tun-host"
/bin/mv -f "$root/packet-worker.new" "$root/packet-worker"
# Numeric UID and fixed paths are the only substituted values.
/bin/cat > "$root/launchd.new" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$label</string>
<key>ProgramArguments</key><array><string>$root/network-relay-tun-host</string><string>serve</string><string>$owner</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>StandardOutPath</key><string>/dev/null</string>
<key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
PLIST
/usr/bin/plutil -lint "$root/launchd.new"
/usr/bin/install -o root -g wheel -m 644 "$root/launchd.new" "$plist"
/bin/rm "$root/launchd.new"
/bin/launchctl bootstrap system "$plist"
