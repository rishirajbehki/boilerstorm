#!/bin/sh
set -eu

: "${EXPECTED_HOST:?Set EXPECTED_HOST to cai-fw01, cai-db01, or cai-mail01}"
case "$EXPECTED_HOST" in cai-fw01|cai-db01|cai-mail01) ;; *) echo 'Unsupported host.' >&2; exit 2 ;; esac
[ "$(id -u)" -eq 0 ] || { echo 'Run as root.' >&2; exit 1; }
actual=$(hostname -s | tr '[:upper:]' '[:lower:]')
[ "$actual" = "$EXPECTED_HOST" ] || { echo "Expected $EXPECTED_HOST; this is $actual." >&2; exit 1; }
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
keyfile=/root/.boilerstorm-dashboard-key

if [ "${1:-}" = --init ]; then
  [ ! -e "$keyfile" ] || { echo "Key already exists: $keyfile" >&2; exit 1; }
  printf 'Enter the %s dashboard key printed by cai-db01: ' "$EXPECTED_HOST" > /dev/tty
  trap 'stty echo < /dev/tty' 0 1 2 3 15
  stty -echo < /dev/tty
  IFS= read -r key < /dev/tty
  stty echo < /dev/tty
  trap - 0 1 2 3 15
  printf '\n' > /dev/tty
  [ "${#key}" -eq 22 ] || { echo 'Expected a 22-character dashboard key.' >&2; exit 1; }
  case "$key" in *[!A-Za-z0-9_-]*) echo 'Invalid key characters.' >&2; exit 1 ;; esac
  umask 077
  printf '%s' "$key" > "$keyfile"
  chmod 600 "$keyfile"
  echo "Dashboard key saved: $keyfile"
  exit 0
fi
[ "${1:-}" = --watch ] || [ "$#" -eq 0 ] || { echo 'Usage: send-unix.sh [--init|--watch]' >&2; exit 2; }
: "${DASHBOARD_URL:?Set DASHBOARD_URL to the cai-db01 LAN ingest URL}"
case "$DASHBOARD_URL" in http://10.*/ingest) ;; *) echo 'Use the team-LAN HTTP ingest URL.' >&2; exit 2 ;; esac
authority=${DASHBOARD_URL#http://}
authority=${authority%/ingest}
case "$authority" in *[!0-9.:]*) echo 'Use a numeric team-LAN address.' >&2; exit 2 ;; esac
[ -f "$keyfile" ] && [ ! -L "$keyfile" ] || { echo 'Run --init first.' >&2; exit 1; }
command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 1; }
if [ "$EXPECTED_HOST" = cai-fw01 ]; then
  command -v php >/dev/null || { echo 'PHP CLI is required on OPNsense.' >&2; exit 1; }
else
  command -v python3 >/dev/null || { echo 'Python 3 is required on Linux.' >&2; exit 1; }
fi

pass() {
  monitor_failed=0
  if [ "$EXPECTED_HOST" = cai-fw01 ]; then
    sh "$repo/opnsense/monitor.sh" >/dev/null || monitor_failed=1
    alerts=/root/boilerstorm-monitor/alerts.tsv
  else
    EXPECTED_HOST="$EXPECTED_HOST" bash "$repo/linux/monitor.sh" >/dev/null || monitor_failed=1
    alerts="/var/lib/boilerstorm-monitor-$EXPECTED_HOST/alerts.tsv"
  fi
  payload=$(mktemp)
  signed=$(mktemp)
  if [ "$EXPECTED_HOST" = cai-fw01 ]; then
    if pfctl -s info 2>/dev/null | grep -q '^Status: Enabled'; then state=active; else state=inactive; fi
    printf 'service\tpf\t%s\n' "$state" > "$payload"
  else
    units="/var/lib/boilerstorm-monitor-$EXPECTED_HOST/critical-units.txt"
    if [ -f "$units" ]; then
      while IFS= read -r unit; do
        case "$unit" in ''|*[!A-Za-z0-9_.@-]*) continue ;; esac
        state=$(systemctl is-active "$unit" 2>/dev/null || true)
        case "$state" in active|inactive|failed) ;; *) state=unknown ;; esac
        printf 'service\t%s\t%s\n' "$unit" "$state" >> "$payload"
      done < "$units"
    fi
    [ -s "$payload" ] || printf 'service\tcritical-units\tunknown\n' > "$payload"
  fi
  if [ -f "$alerts" ]; then
    tail -n 19 "$alerts" | awk -F '\t' 'NF >= 3 {print "alert\t" substr($1,1,60) "\t" substr($2,1,80) "\tReview locally on host"}' >> "$payload"
  fi
  if [ "$monitor_failed" -eq 1 ]; then
    printf 'alert\t%s\tmonitor_failed\tReview locally on host\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$payload"
  fi
  stamp=$(date +%s)
  { printf '%s\n' "$stamp"; cat "$payload"; } > "$signed"
  if [ "$EXPECTED_HOST" = cai-fw01 ]; then
    signature=$(php -r 'echo hash_hmac("sha256", file_get_contents($argv[2]), file_get_contents($argv[1]));' "$keyfile" "$signed")
  else
    signature=$(python3 -c 'import hashlib,hmac,sys; print(hmac.new(open(sys.argv[1],"rb").read(),open(sys.argv[2],"rb").read(),hashlib.sha256).hexdigest())' "$keyfile" "$signed")
  fi
  if curl --fail --silent --show-error --noproxy '*' --max-time 5 -X POST \
      -H "X-Host: $EXPECTED_HOST" -H "X-Time: $stamp" -H "X-Signature: $signature" \
      -H 'Content-Type: text/plain; charset=utf-8' --data-binary "@$payload" "$DASHBOARD_URL"; then
    echo "Dashboard report sent: $EXPECTED_HOST"
  else
    echo 'Dashboard send failed; local monitor output remains on this host.' >&2
  fi
  rm -f "$payload" "$signed"
}

while :; do
  pass
  [ "${1:-}" = --watch ] || break
  sleep 300
done
