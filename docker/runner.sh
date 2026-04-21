#!/bin/sh
# Sandbox runner. Executes the skill under strace and ships events as JSONL.
#
# Contract with the host orchestrator:
#   /var/log/cleanskill/audit.jsonl    one JSON event per line
#   exit code                          0 on clean exit, non-zero on skill error
#
# Runs under POSIX sh; awk parsing uses gawk (installed in the image).

set -u

SKILL_DIR="${1:-/skill}"
AUDIT="/var/log/cleanskill/audit.jsonl"
: > "$AUDIT"

log_event() {
  printf '%s\n' "$1" >> "$AUDIT"
}

# 1) Start the mock LLM in the background.
python /opt/clean-skill/mock_llm.py &
MOCK_PID=$!

cleanup() {
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
  [ -n "${MOCK_PID:-}" ] && wait "$MOCK_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# 2) Pick entrypoint. Platform-specific hints come from env; fall back to
#    common names. Store the ABSOLUTE path in $ABS.
ABS=""
if [ -n "${CLEAN_SKILL_ENTRYPOINT:-}" ]; then
  case "$CLEAN_SKILL_ENTRYPOINT" in
    /*) [ -f "$CLEAN_SKILL_ENTRYPOINT" ] && ABS="$CLEAN_SKILL_ENTRYPOINT" ;;
    *)  [ -f "$SKILL_DIR/$CLEAN_SKILL_ENTRYPOINT" ] && ABS="$SKILL_DIR/$CLEAN_SKILL_ENTRYPOINT" ;;
  esac
  # Skip instructional/documentation files — the runner needs something
  # the shell can actually exec. Claude's SKILL.md and similar fall in
  # this bucket; auto-discovery below will find the real code file.
  case "$ABS" in
    *.md|*.txt|*.rst|*.json) ABS="" ;;
  esac
fi

if [ -z "$ABS" ]; then
  for candidate in \
    "$SKILL_DIR/main.py" \
    "$SKILL_DIR/plugin.py" \
    "$SKILL_DIR/server.py" \
    "$SKILL_DIR/run.sh" \
    "$SKILL_DIR/skill.py"; do
    if [ -f "$candidate" ]; then
      ABS="$candidate"
      break
    fi
  done
fi

if [ -z "$ABS" ]; then
  log_event '{"kind":"runner","detail":{"msg":"no entrypoint found"}}'
  exit 2
fi

log_event "$(printf '{"kind":"runner","detail":{"msg":"exec","entry":"%s"}}' "$ABS")"

# Choose interpreter based on extension; fall back to direct exec for shebanged scripts.
case "$ABS" in
  *.py) CMD='python "$ABS"' ;;
  *.sh) CMD='sh "$ABS"' ;;
  *)    CMD='"$ABS"' ;;
esac

# 3) strace filters: file writes + process spawns + outbound connects.
#    We append a single JSON line per interesting syscall to the audit log.
STRACE_LOG=$(mktemp)

# shellcheck disable=SC2086
strace -f -qq -e trace=openat,connect,execve -o "$STRACE_LOG" \
  sh -c "$CMD" </dev/null >/tmp/skill.stdout 2>/tmp/skill.stderr
RC=$?

gawk '
  /execve\(/ {
    if (match($0, /"([^"]+)"/, arr))
      printf("{\"kind\":\"process\",\"detail\":{\"op\":\"execve\",\"argv\":[\"%s\"]}}\n", arr[1]);
    next
  }
  /openat\(.*O_(WRONLY|RDWR|CREAT)/ {
    if (match($0, /"([^"]+)"/, arr))
      printf("{\"kind\":\"filesystem\",\"detail\":{\"op\":\"write\",\"path\":\"%s\"}}\n", arr[1]);
    next
  }
  /connect\(/ {
    host = ""; port = "";
    if (match($0, /inet_addr\("([^"]+)"\)/, a)) host = a[1];
    if (host == "" && match($0, /sin_addr\("([^"]+)"\)/, a)) host = a[1];
    if (match($0, /sin_port=htons\(([0-9]+)\)/, p))           port = p[1];
    if (host != "")
      printf("{\"kind\":\"network\",\"detail\":{\"host\":\"%s\",\"port\":%s}}\n", host, port);
    next
  }
' "$STRACE_LOG" >> "$AUDIT" || true

# Always emit a terminal runner event with the exit code. This guarantees the
# audit log contains at least one structured event even when strace cannot
# attach (e.g. sandboxes that disallow ptrace). Also capture the first
# kilobyte of skill stdout/stderr for post-mortem debugging.
STDOUT_PREVIEW=$(head -c 1024 /tmp/skill.stdout 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g' || true)
STDERR_PREVIEW=$(head -c 1024 /tmp/skill.stderr 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g' || true)
STRACE_LINES=$(wc -l < "$STRACE_LOG" 2>/dev/null || echo 0)
log_event "$(printf '{"kind":"runner","detail":{"op":"exit","exit_code":%s,"strace_lines":%s,"stdout_head":"%s","stderr_head":"%s"}}' \
  "$RC" "$STRACE_LINES" "$STDOUT_PREVIEW" "$STDERR_PREVIEW")"

exit "$RC"
