#!/bin/sh
# Sandbox runner. Executes the skill under strace and ships events as JSONL.
#
# Contract with the host orchestrator:
#   /var/log/cleanskill/audit.jsonl    one JSON event per line
#   exit code                          0 on clean exit, non-zero on skill error
#
# We deliberately use POSIX sh so the sandbox image stays minimal.

set -eu

SKILL_DIR="${1:-/skill}"
AUDIT="/var/log/cleanskill/audit.jsonl"
: > "$AUDIT"

log_event() {
  printf '%s\n' "$1" >> "$AUDIT"
}

# 1) Start the mock LLM in the background.
python /opt/clean-skill/mock_llm.py &
MOCK_PID=$!

# 2) Pick entrypoint. Platform-specific hints come from env; fall back to common names.
ENTRY="${CLEAN_SKILL_ENTRYPOINT:-}"
if [ -z "$ENTRY" ]; then
  for candidate in "$SKILL_DIR/main.py" "$SKILL_DIR/plugin.py" "$SKILL_DIR/server.py" "$SKILL_DIR/run.sh"; do
    if [ -f "$candidate" ]; then
      ENTRY="$candidate"
      break
    fi
  done
fi

if [ -z "$ENTRY" ] || [ ! -e "$SKILL_DIR/$ENTRY" ] && [ ! -e "$ENTRY" ]; then
  log_event '{"kind":"runner","msg":"no entrypoint found"}'
  kill "$MOCK_PID" 2>/dev/null || true
  exit 2
fi

# Resolve to absolute path inside the bundle.
case "$ENTRY" in
  /*) ABS="$ENTRY" ;;
  *)  ABS="$SKILL_DIR/$ENTRY" ;;
esac

log_event "$(printf '{"kind":"runner","msg":"exec","entry":"%s"}' "$ABS")"

# 3) strace filters: file writes + process spawns. Output is parsed into JSONL
#    by a tiny awk filter so we keep everything in one append-only log.
STRACE_LOG=$(mktemp)
strace -f -qq -e trace=openat,connect,execve -o "$STRACE_LOG" \
  sh -c 'exec "$0" "$@"' "$ABS" </dev/null >/tmp/skill.stdout 2>/tmp/skill.stderr
RC=$?

awk '
  /execve\(/ {
    match($0, /"([^"]+)"/, arr);
    printf("{\"kind\":\"process\",\"detail\":{\"op\":\"execve\",\"argv\":[\"%s\"]}}\n", arr[1]);
    next
  }
  /openat\(.*O_(WRONLY|RDWR|CREAT)/ {
    match($0, /"([^"]+)"/, arr);
    printf("{\"kind\":\"filesystem\",\"detail\":{\"op\":\"write\",\"path\":\"%s\"}}\n", arr[1]);
    next
  }
  /connect\(/ {
    match($0, /sin_addr\("([^"]+)"\)/, a);
    match($0, /sin_port=htons\(([0-9]+)\)/, p);
    if (a[1] != "") printf("{\"kind\":\"network\",\"detail\":{\"host\":\"%s\",\"port\":%s}}\n", a[1], p[1]);
    next
  }
' "$STRACE_LOG" >> "$AUDIT" || true

kill "$MOCK_PID" 2>/dev/null || true
wait "$MOCK_PID" 2>/dev/null || true

exit "$RC"
