#!/usr/bin/env bash
# Read-only Linux build preflight. Sourcing this file changes no host state.

relay_build_memory_error() { printf 'build-memory: %s\n' "$*" >&2; return 1; }

# Match the native installer's memory accounting, including reclaimable inactive
# file cache and every visible ancestor limit. Host swap is not usable when a
# cgroup forbids it, even if that cgroup has no RAM limit.
relay_build_cgroup_headroom() {
    local cgroups=$1 mountinfo=$2 host_ram=$3 host_swap=$4
    local hierarchy controllers relative type root mount dir limit usage inactive ram swap used level smallest=''
    [[ -r $cgroups && -r $mountinfo ]] || return 1
    while IFS=: read -r hierarchy controllers relative; do
        if [[ $hierarchy == 0 && -z $controllers ]]; then type=cgroup2
        elif [[ ,$controllers, == *,memory,* ]]; then type=cgroup
        else continue
        fi
        while read -r root mount; do
            root=$(printf '%b' "$root"); mount=$(printf '%b' "$mount")
            if [[ $root == / || $relative == "$root" || $relative == "$root"/* ]]; then
                dir=$mount${relative#"${root%/}"}
            else
                # A cgroup namespace can report a relative process path while
                # mountinfo still exposes its host-side root (including /..).
                dir=$mount$relative
            fi
            dir=${dir%/}
            [[ -d $dir ]] || dir=${mount%/}
            while [[ -d $dir ]]; do
                ram=$host_ram; swap=$host_swap; inactive=0
                if [[ $type == cgroup2 && -r $dir/memory.max ]]; then
                    limit=$(< "$dir/memory.max")
                    if [[ $limit =~ ^[0-9]+$ ]] && (( ${#limit} < 19 )); then
                        usage=$(cat -- "$dir/memory.current") || return 1
                        [[ $usage =~ ^[0-9]+$ ]] || return 1
                        inactive=$(awk '$1 == "inactive_file" {print $2}' "$dir/memory.stat" 2>/dev/null)
                        ram=$(( (limit - usage + ${inactive:-0}) / 1024 ))
                    fi
                    limit=$(cat -- "$dir/memory.swap.max" 2>/dev/null || printf max)
                    if [[ $limit =~ ^[0-9]+$ ]] && (( ${#limit} < 19 )); then
                        used=$(cat -- "$dir/memory.swap.current") || return 1
                        [[ $used =~ ^[0-9]+$ ]] || return 1
                        swap=$(( (limit - used) / 1024 ))
                    fi
                elif [[ $type == cgroup && -r $dir/memory.limit_in_bytes ]]; then
                    limit=$(< "$dir/memory.limit_in_bytes")
                    inactive=$(awk '$1 == "total_inactive_file" {print $2}' "$dir/memory.stat" 2>/dev/null)
                    if [[ $limit =~ ^[0-9]+$ ]] && (( ${#limit} < 19 )); then
                        usage=$(cat -- "$dir/memory.usage_in_bytes") || return 1
                        [[ $usage =~ ^[0-9]+$ ]] || return 1
                        ram=$(( (limit - usage + ${inactive:-0}) / 1024 ))
                    fi
                fi
                (( ram >= 0 )) || ram=0
                (( swap >= 0 )) || swap=0
                (( ram <= host_ram )) || ram=$host_ram
                (( swap <= host_swap )) || swap=$host_swap
                level=$((ram + swap))
                if [[ $type == cgroup ]]; then
                    limit=$(cat -- "$dir/memory.memsw.limit_in_bytes" 2>/dev/null || true)
                    if [[ $limit =~ ^[0-9]+$ ]] && (( ${#limit} < 19 )); then
                        used=$(cat -- "$dir/memory.memsw.usage_in_bytes") || return 1
                        [[ $used =~ ^[0-9]+$ ]] || return 1
                        used=$(( (limit - used + ${inactive:-0}) / 1024 ))
                        (( used >= 0 )) || used=0
                        (( level <= used )) || level=$used
                    fi
                fi
                if [[ -z $smallest ]] || (( level < smallest )); then smallest=$level; fi
                [[ $dir != "${mount%/}" ]] || break
                dir=${dir%/*}
            done
        done < <(awk -v type="$type" '{
            for (i = 7; i <= NF; i++) if ($i == "-") {
                if ($(i + 1) == type && (type == "cgroup2" || $(i + 3) ~ /(^|,)memory(,|$)/)) print $4, $5
                break
            }
        }' "$mountinfo")
    done < "$cgroups"
    [[ -z $smallest ]] || printf '%s\n' "$smallest"
    return 0
}

relay_build_memory_kib() {
    local ram swap headroom
    ram=$(awk '/^MemAvailable:/ {print $2}' "${1:-/proc/meminfo}") || return 1
    swap=$(awk '/^SwapFree:/ {print $2}' "${1:-/proc/meminfo}") || return 1
    [[ $ram =~ ^[0-9]+$ && $swap =~ ^[0-9]+$ ]] || return 1
    headroom=$(relay_build_cgroup_headroom "${2:-/proc/self/cgroup}" "${3:-/proc/self/mountinfo}" "$ram" "$swap") || return 1
    ram=$((ram + swap))
    if [[ -n $headroom ]] && (( headroom < ram )); then ram=$headroom; fi
    printf '%s\n' "$ram"
}

relay_build_memory_jobs() {
    local requested=$1 available jobs
    shift
    [[ $requested =~ ^[1-9][0-9]*$ && ${#requested} -le 18 ]] || { relay_build_memory_error 'Build jobs must be a positive integer of at most 18 digits.'; return 1; }
    available=$(relay_build_memory_kib "$@") || { relay_build_memory_error 'Cannot inspect available RAM, swap and cgroup limits.'; return 1; }
    if (( available < 1048576 )); then
        relay_build_memory_error 'The build needs about 1 GiB of available RAM plus free swap within all container/service limits; add swap on a disk filesystem (not /tmp tmpfs), raise the cgroup memory/swap limit, or use a larger host.'
        return 1
    fi
    jobs=$((available / 1048576))
    (( jobs <= requested )) || jobs=$requested
    if (( jobs < requested )); then
        printf 'Build memory budget: %s KiB; limiting compilation to %s job(s).\n' "$available" "$jobs" >&2
    fi
    printf '%s\n' "$jobs"
}
