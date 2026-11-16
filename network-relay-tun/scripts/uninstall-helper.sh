#!/bin/bash
# Disconnect and quit the GUI before invoking this explicitly as administrator.
set -euo pipefail
[[ $(uname -s) == Darwin && $EUID == 0 ]] || { echo 'macOS administrator privileges required' >&2; exit 1; }
root='/Library/Application Support/NetworkRelayTun'
label='com.arccal.network-relay-tun.helper'
[[ ! -L $root && -d $root && $(/usr/bin/stat -f %u "$root") == 0 ]] || exit 1
mode=$(/usr/bin/stat -f %Lp "$root")
(( (8#$mode & 0022) == 0 )) || exit 1
[[ ! -e "$root/network.json" ]] || { echo 'Disconnect and use Recover Network before uninstalling.' >&2; exit 1; }
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
# A session may have raced the first check. Preserve all recovery resources.
[[ ! -e "$root/network.json" ]] || { echo 'Recovery journal remains; helper files preserved.' >&2; exit 1; }
/bin/rm -f "/Library/LaunchDaemons/$label.plist" "$root/network-relay-tun-host" "$root/packet-worker" "$root/control.sock" "$root/helper.lock"
/bin/rmdir "$root"
echo 'Network Relay Tun helper removed. Application settings were preserved.'
