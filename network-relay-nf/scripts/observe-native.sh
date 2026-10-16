#!/usr/bin/env bash
# Opt-in observations of an already running GUI; never starts an emulator/server.
set -euo pipefail
if [[ $(uname -s) != Darwin ]]; then
  printf 'NOT RUN: this observation requires the real macOS application.\n' >&2
  exit 2
fi
if [[ $# != 3 || ! $1 =~ ^(rust|caddy)$ || ! $2 =~ ^(http1|h2|h3)$ ]]; then
  printf 'Usage: bash scripts/observe-native.sh rust|caddy http1|h2|h3 NEW_OUTPUT_DIRECTORY\n' >&2
  exit 2
fi
NF_ROOT=$(cd "$(dirname "$0")/.." && pwd)
NF_SERVER=$1
NF_TRANSPORT=$2
NF_OUT=$3
NF_SECONDS=${NF_OBSERVE_SECONDS:-600}
NF_PORT=${NF_PROXY_PORT:-1080}
NF_URL=${NF_TCP_URL:-https://example.com/}
NF_APP=${NF_APP_EXECUTABLE:-"$NF_ROOT/dist/Network Relay NF.app/Contents/MacOS/NetworkRelayNF"}
if [[ ! $NF_SECONDS =~ ^[1-9][0-9]{1,3}$ ]] || (( NF_SECONDS < 60 || NF_SECONDS > 3600 )); then
  printf 'NF_OBSERVE_SECONDS must be between 60 and 3600.\n' >&2
  exit 2
fi
if [[ ! $NF_PORT =~ ^[1-9][0-9]{0,4}$ ]] || (( NF_PORT > 65535 )); then
  printf 'NF_PROXY_PORT must be between 1 and 65535.\n' >&2
  exit 2
fi
if [[ ! -f $NF_APP ]]; then
  printf 'Build the app first or set NF_APP_EXECUTABLE to its executable.\n' >&2
  exit 2
fi
if [[ ! $NF_URL =~ ^https:// ]]; then
  printf 'NF_TCP_URL must use HTTPS.\n' >&2
  exit 2
fi
if [[ -n ${NF_DOWNLOAD_URL:-} || -n ${NF_DOWNLOAD_SHA256:-} ]]; then
  if [[ ! ${NF_DOWNLOAD_URL:-} =~ ^https:// || ! ${NF_DOWNLOAD_SHA256:-} =~ ^[[:xdigit:]]{64}$ ]]; then
    printf 'Bulk observation requires both an HTTPS NF_DOWNLOAD_URL and its NF_DOWNLOAD_SHA256.\n' >&2
    exit 2
  fi
fi
umask 077
mkdir "$NF_OUT" # Refuse to mix evidence with an earlier run.
NF_OUT=$(cd "$NF_OUT" && pwd)
trap 'printf "INCOMPLETE: failed; inspect individual logs.\n" >> "$NF_OUT/result.txt"' ERR
trap 'printf "INCOMPLETE: interrupted.\n" >> "$NF_OUT/result.txt"; exit 130' INT
trap 'printf "INCOMPLETE: terminated.\n" >> "$NF_OUT/result.txt"; exit 143' TERM
{
  date -u '+started=%Y-%m-%dT%H:%M:%SZ'
  printf 'operator_server_kind=%s\noperator_forced_transport=%s\n' "$NF_SERVER" "$NF_TRANSPORT"
  printf 'These labels require matching application and server logs; they are not inferred by curl.\n'
  printf 'server_revision=%s\nserver_running_executable_sha256=%s\n' \
    "${NF_SERVER_REVISION:-NOT_RECORDED}" "${NF_SERVER_SHA256:-NOT_RECORDED}"
  git -C "$NF_ROOT" rev-parse HEAD
  git -C "$NF_ROOT" status --short -- .
  sw_vers
  uname -m
  xcodebuild -version
  xcrun --sdk macosx --show-sdk-version
  shasum -a 256 "$NF_APP"
} > "$NF_OUT/environment.txt" 2>&1
printf 'IN PROGRESS: native TCP/UDP observations only.\n' > "$NF_OUT/result.txt"
NF_PROXY="socks5h://127.0.0.1:$NF_PORT"
if [[ -n ${NF_DOWNLOAD_URL:-} ]]; then
  curl --fail --show-error --silent --noproxy '' --proxy "$NF_PROXY" \
    --connect-timeout 30 --max-time 600 \
    --output "$NF_OUT/download.bin" "$NF_DOWNLOAD_URL" 2> "$NF_OUT/download.log"
  NF_ACTUAL_SHA=$(shasum -a 256 "$NF_OUT/download.bin")
  NF_ACTUAL_SHA=${NF_ACTUAL_SHA%% *}
  [[ $NF_ACTUAL_SHA == "$(printf '%s' "$NF_DOWNLOAD_SHA256" | tr '[:upper:]' '[:lower:]')" ]]
  printf 'Bulk file SHA-256 matched: %s\n' "$NF_ACTUAL_SHA" >> "$NF_OUT/result.txt"
  wc -c < "$NF_OUT/download.bin" > "$NF_OUT/download-bytes.txt"
  rm "$NF_OUT/download.bin"
else
  printf 'NOT RUN: bulk download (set NF_DOWNLOAD_URL and NF_DOWNLOAD_SHA256).\n' >> "$NF_OUT/result.txt"
fi
NF_START=$SECONDS
NF_COUNT=0
while (( SECONDS - NF_START < NF_SECONDS )); do
  NF_COUNT=$((NF_COUNT + 1))
  date -u '+%Y-%m-%dT%H:%M:%SZ' >> "$NF_OUT/tcp.log"
  curl --fail --show-error --silent --noproxy '' --proxy "$NF_PROXY" \
    --connect-timeout 30 --max-time 45 --output /dev/null \
    --write-out 'HTTP=%{http_code} bytes=%{size_download}\n' \
    "$NF_URL" >> "$NF_OUT/tcp.log" 2>&1
  date -u '+%Y-%m-%dT%H:%M:%SZ' >> "$NF_OUT/udp.log"
  python3 "$NF_ROOT/scripts/probe-socks-udp.py" --proxy-port "$NF_PORT" \
    --dns-server "${NF_DNS_SERVER:-1.1.1.1}" --name "${NF_DNS_NAME:-example.com}" \
    >> "$NF_OUT/udp.log" 2>&1
  if (( SECONDS - NF_START < NF_SECONDS )); then sleep 10; fi
done
printf 'Completed %s TCP requests and matching UDP probes over %s seconds.\n' \
  "$NF_COUNT" "$((SECONDS - NF_START))" >> "$NF_OUT/result.txt"
printf 'NOT RUN: held long connection, idle, sleep/wake, network change and negative security cases.\n' >> "$NF_OUT/result.txt"
printf 'Native matrix NOT COMPLETE: save matching app run and deployed server revision/hash; follow docs/NATIVE-ACCEPTANCE.md.\n' >> "$NF_OUT/result.txt"
cat "$NF_OUT/result.txt"
