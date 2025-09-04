#!/bin/sh
set -eu

ScriptName="Detect-Unsigned-Processes"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart=$(date +%s)

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$Level] $Message"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

iso_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

BeginNDJSON() { TMP_AR="$(mktemp)"; }
AddRecord() {
  ts="$(iso_now)"
  pid_num="$1"; cmd="$2"; exe="$3"; reason="$4"; user="$5"
  case "$pid_num" in ''|*[!0-9]*) pid_num=0 ;; esac
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"pid":%s,"user":"%s","cmd":"%s","exe":"%s","reason":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" \
    "$pid_num" \
    "$(escape_json "$user")" "$(escape_json "$cmd")" "$(escape_json "$exe")" "$(escape_json "$reason")" \
    >> "$TMP_AR"
}
AddStatus() {
  ts="$(iso_now)"; st="${1:-info}"; msg="$(escape_json "${2:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"%s","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$st" "$msg" >> "$TMP_AR"
}

CommitNDJSON() {
  [ -s "$TMP_AR" ] || AddStatus "no_results" "no suspicious/unsigned processes found"
  AR_DIR="$(dirname "$ARLog")"
  [ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog"; then
    WriteLog "Wrote NDJSON to $ARLog" INFO
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new"; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed to write both $ARLog and $ARLog.new; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="
BeginNDJSON
WriteLog "Scanning /proc for suspicious/unsigned processes..." INFO

# Rules:
# 1) Executable missing (no /proc/PID/exe or not a file)
# 2) Executable path under temp dirs: /tmp, /var/tmp, /dev/shm
emitted=0

for pid_dir in /proc/[0-9]*; do
  [ -d "$pid_dir" ] || continue
  pid="${pid_dir#/proc/}"

  cmdline_raw="$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)"
  [ -n "$cmdline_raw" ] || continue
  cmd="${cmdline_raw% }"

  exe_path=""
  if [ -L "$pid_dir/exe" ]; then
    resolved="$(readlink -f "$pid_dir/exe" 2>/dev/null || true)"
    [ -n "$resolved" ] && exe_path="$resolved"
  fi

  suspicious=0
  reason=""
  if [ -z "$exe_path" ] || [ ! -f "$exe_path" ]; then
    suspicious=1
    reason="Executable missing"
  elif printf '%s' "$exe_path" | grep -Eq '^(/tmp|/var/tmp|/dev/shm)(/|$)'; then
    suspicious=1
    reason="Executable in temp directory"
  fi

  if [ "$suspicious" -eq 1 ]; then
    owner="$(stat -c '%U' "$pid_dir" 2>/dev/null || echo "unknown")"
    AddRecord "$pid" "$cmd" "${exe_path:-}" "$reason" "$owner"
    emitted=$((emitted+1))
  fi
done

[ "$emitted" -gt 0 ] || AddStatus "no_results" "no suspicious/unsigned processes found"

CommitNDJSON

dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="
