#!/usr/bin/env bash
set -uo pipefail

# Read-only, non-root runtime snapshot. It deliberately omits command arguments,
# environment variables, profiles, URLs, and database row contents.

DATA_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}"
STATE_HOME="${XDG_STATE_HOME:-${HOME}/.local/state}"
DATA_DIR="${DATA_HOME}/v2link-client"
LOG_DIR="${STATE_HOME}/v2link-client/logs"
DB_PATH="${DATA_DIR}/traffic.sqlite3"
WAL_PATH="${DB_PATH}-wal"
findings=0

heading() {
  printf '\n%s\n' "$1"
}

file_size() {
  local path="$1"
  if [[ -e "${path}" ]]; then
    if command -v stat >/dev/null 2>&1; then
      stat -c '%s' -- "${path}" 2>/dev/null || printf 'unavailable'
    else
      printf 'unavailable'
    fi
  else
    printf 'missing'
  fi
}

collect_pids() {
  local pattern="$1"
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -f -- "${pattern}" 2>/dev/null || true
  fi
}

printf '%s\n' 'v2link-client runtime performance diagnostics'
printf '%s\n' 'Privacy: process arguments, environment, profiles, URLs, and traffic rows are omitted.'
printf 'User: uid=%s (root not required)\n' "$(id -u)"

heading 'Paths and bounded files'
printf 'Data directory: %s (%s)\n' "${DATA_DIR}" "$([[ -d "${DATA_DIR}" ]] && printf present || printf missing)"
printf 'Log directory: %s (%s)\n' "${LOG_DIR}" "$([[ -d "${LOG_DIR}" ]] && printf present || printf missing)"
printf 'Traffic DB bytes: %s\n' "$(file_size "${DB_PATH}")"
printf 'Traffic WAL bytes: %s\n' "$(file_size "${WAL_PATH}")"
for name in app.log xray_stdout.log xray_access.log xray_error.log; do
  printf '%s bytes: %s\n' "${name}" "$(file_size "${LOG_DIR}/${name}")"
done

heading 'GUI and Xray processes'
gui_pids="$(collect_pids '(^|/)(v2link-client|python3?)( |$).*v2link_client|(^|/)v2link-client( |$)')"
xray_pids="$(collect_pids '(^|/)xray( |$)')"
stats_pids=""
for pid in ${xray_pids}; do
  if [[ -r "/proc/${pid}/cmdline" ]] && tr '\0' ' ' < "/proc/${pid}/cmdline" | grep -q 'api statsquery'; then
    stats_pids+="${pid} "
  fi
done
printf 'GUI process count: %s\n' "$(wc -w <<< "${gui_pids}")"
printf 'Xray process count (all users visible to this user): %s\n' "$(wc -w <<< "${xray_pids}")"
printf 'Xray stats-query count: %s\n' "$(wc -w <<< "${stats_pids}")"

all_pids="${gui_pids} ${xray_pids}"
if [[ -n "${all_pids// /}" ]] && command -v ps >/dev/null 2>&1; then
  printf '%s\n' 'PID/PPID/PGID/elapsed/CPU%/MEM%/RSS-KiB/name (arguments omitted):'
  # shellcheck disable=SC2086 # ps requires a comma-separated PID list built below.
  pid_csv="$(tr ' ' ',' <<< "${all_pids}" | sed 's/,,*/,/g; s/^,//; s/,$//')"
  ps -o pid=,ppid=,pgid=,etime=,%cpu=,%mem=,rss=,comm= -p "${pid_csv}" 2>/dev/null || true
else
  printf '%s\n' 'No matching GUI/Xray processes found, or ps is unavailable.'
fi

if [[ -z "${gui_pids// /}" && -n "${xray_pids// /}" ]]; then
  printf '%s\n' 'WARNING: Xray exists while no V2Link GUI was detected; inspect ownership before taking action.'
  findings=1
fi
if [[ -z "${gui_pids// /}" && -n "${stats_pids// /}" ]]; then
  printf '%s\n' 'WARNING: an Xray stats-query exists after GUI exit.'
  findings=1
fi

heading 'Traffic database counts (optional)'
if [[ ! -f "${DB_PATH}" ]]; then
  printf '%s\n' 'Database is missing; no counts available.'
elif ! command -v sqlite3 >/dev/null 2>&1; then
  printf '%s\n' 'sqlite3 is unavailable; skipped aggregate counts.'
else
  counts="$(sqlite3 -readonly -batch "${DB_PATH}" \
    "SELECT (SELECT count(*) FROM proxy_sessions), (SELECT count(*) FROM proxy_samples);" \
    2>/dev/null || true)"
  if [[ -n "${counts}" ]]; then
    printf 'Sessions|samples: %s\n' "${counts}"
  else
    printf '%s\n' 'Aggregate count query failed (missing/incompatible/busy database).'
    findings=1
  fi
fi

heading 'Independent v2link-netmon service'
if ! command -v systemctl >/dev/null 2>&1; then
  printf '%s\n' 'systemctl is unavailable; service state not checked.'
else
  active_state="$(systemctl is-active v2link-netmon.service 2>/dev/null || true)"
  enabled_state="$(systemctl is-enabled v2link-netmon.service 2>/dev/null || true)"
  printf 'Service active: %s\n' "${active_state:-unknown}"
  printf 'Service enabled: %s\n' "${enabled_state:-unknown}"
  printf '%s\n' 'The GUI does not stop this system service during shutdown.'
fi

heading 'Result'
if (( findings > 0 )); then
  printf '%s\n' 'Completed with findings. Review warnings; this script never kills processes or changes settings.'
  exit 1
fi
printf '%s\n' 'Completed without stale-process findings.'
exit 0
