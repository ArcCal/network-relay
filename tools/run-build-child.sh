#!/usr/bin/env bash
# Keep an owned build process group inside its staging owner's lifetime.

relay_build_group_active() {
    ps -A -o pgid= -o stat= | awk -v group="$1" '
        $1 == group && $2 !~ /^Z/ { active = 1 }
        END { exit !active }'
}

relay_build_terminal_group() {
    PYTHONDONTWRITEBYTECODE=1 python3 - "$1" <<'PY'
import os
import signal
import sys

signal.signal(signal.SIGTTOU, signal.SIG_IGN)
try:
    fd = os.open('/dev/tty', os.O_RDWR)
    try:
        if sys.argv[1] == 'get':
            print(os.tcgetpgrp(fd))
        else:
            os.tcsetpgrp(fd, int(sys.argv[1]))
    finally:
        os.close(fd)
except OSError:
    sys.exit(1)
PY
}

relay_stop_build_child() {
    local child=${1:-} group=${2:-} wait_cleanup=${3:-0} child_signal=${4-TERM} attempt
    [[ $child =~ ^[1-9][0-9]*$ ]] || return 0
    if [[ $group == "$child" ]]; then
        if [[ -n $child_signal ]]; then kill -"$child_signal" -- "-$group" 2>/dev/null || true; fi
        # A terminal reader can have stopped before foreground ownership moved.
        # Let it handle the pending signal and finish any installer rollback.
        kill -CONT -- "-$group" 2>/dev/null || true
        if (( wait_cleanup )); then
            # Installers may be restoring a live deployment. Do not kill their
            # rollback or delete their source while that cleanup is running.
            while relay_build_group_active "$group"; do sleep 0.1; done
            return 0
        fi
        for ((attempt = 0; attempt < 10; attempt++)); do
            relay_build_group_active "$group" || return 0
            sleep 0.1
        done
        kill -KILL -- "-$group" 2>/dev/null || true
    else
        if [[ -n $child_signal ]]; then kill -"$child_signal" "$child" 2>/dev/null || true; fi
        kill -CONT "$child" 2>/dev/null || true
    fi
}

relay_run_build_child() {
    local relay_child_pid='' relay_child_group='' relay_child_status=0 relay_child_interrupted=0
    local relay_child_monitor=0 relay_child_actual relay_child_int relay_child_term relay_child_hup relay_child_wait=0
    local relay_child_tty='' relay_child_parent_group relay_child_final_signal=TERM
    if [[ ${1:-} == --wait-for-cleanup ]]; then relay_child_wait=1; shift; fi
    [[ $# -gt 0 ]] || return 2
    if ! command -v ps >/dev/null || ! ps -A -o pgid= -o stat= >/dev/null 2>&1; then
        printf 'Build process cleanup requires ps (procps on Linux).\n' >&2
        return 125
    fi
    if { : </dev/tty; } 2>/dev/null; then
        if ! command -v python3 >/dev/null; then
            printf 'Interactive build process cleanup requires Python 3.\n' >&2
            return 125
        fi
        relay_child_tty=$(relay_build_terminal_group get) || return 125
        relay_child_parent_group=$(ps -o pgid= -p "$$") || return 125
        relay_child_parent_group=${relay_child_parent_group//[[:space:]]/}
        # A deliberately backgrounded build must not take the user's terminal.
        [[ $relay_child_tty == "$relay_child_parent_group" ]] || relay_child_tty=''
    fi
    relay_child_int=$(trap -p INT)
    relay_child_term=$(trap -p TERM)
    relay_child_hup=$(trap -p HUP)
    case $- in *m*) relay_child_monitor=1 ;; esac
    trap 'relay_child_interrupted=130; trap "" INT TERM HUP; relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"' INT
    trap 'relay_child_interrupted=143; trap "" INT TERM HUP; relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"' TERM
    trap 'relay_child_interrupted=129; trap "" INT TERM HUP; relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"' HUP
    # Job control creates a group distinct from the caller. Disable it inside
    # the runner so cargo, rustc and their children stay in that owned group.
    set -m
    (
        set +m
        trap - EXIT INT TERM HUP
        "$@"
    ) &
    relay_child_pid=$! relay_child_group=$!
    (( relay_child_monitor )) || set +m
    relay_child_actual=$(ps -o pgid= -p "$relay_child_pid" 2>/dev/null) || relay_child_actual=''
    relay_child_actual=${relay_child_actual//[[:space:]]/}
    if [[ -n $relay_child_actual && $relay_child_actual != "$relay_child_pid" ]]; then
        # Never send a group signal unless this is the group we just created.
        relay_child_group=''
        relay_child_interrupted=125
        relay_stop_build_child "$relay_child_pid" ''
    fi
    if (( relay_child_interrupted )); then
        relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"
    fi
    if [[ -n $relay_child_tty && -n $relay_child_group && $relay_child_interrupted == 0 ]]; then
        if ! relay_build_terminal_group "$relay_child_group" && relay_build_group_active "$relay_child_group"; then
            relay_child_interrupted=125
            relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait"
        fi
        kill -CONT -- "-$relay_child_group" 2>/dev/null || true
    fi
    if wait "$relay_child_pid"; then relay_child_status=0; else relay_child_status=$?; fi
    # A command can exit before a helper it spawned. Stop those helpers before
    # its caller removes sources/caches, and reap our direct child after signals.
    if (( relay_child_wait && !relay_child_interrupted )) &&
       [[ $relay_child_status == 129 || $relay_child_status == 130 || $relay_child_status == 143 ]]; then
        # A terminal signal already reached the foreground group. Do not send
        # a second signal while a surviving installer is restoring deployment.
        relay_child_final_signal=''
    fi
    relay_stop_build_child "$relay_child_pid" "$relay_child_group" "$relay_child_wait" "$relay_child_final_signal"
    wait "$relay_child_pid" 2>/dev/null || true
    [[ -z $relay_child_tty ]] || relay_build_terminal_group "$relay_child_tty" || true
    trap - INT TERM HUP
    [[ -z $relay_child_int ]] || eval "$relay_child_int"
    [[ -z $relay_child_term ]] || eval "$relay_child_term"
    [[ -z $relay_child_hup ]] || eval "$relay_child_hup"
    if (( relay_child_interrupted )); then return "$relay_child_interrupted"; fi
    return "$relay_child_status"
}
