#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then echo 'Run as root on the firewall console.' >&2; exit 1; fi
if [ "$(uname -s)" != FreeBSD ]; then echo 'Expected OPNsense/FreeBSD.' >&2; exit 1; fi
actual=$(hostname -s | tr '[:upper:]' '[:lower:]')
if [ "$actual" != cai-fw01 ]; then echo "Expected cai-fw01; this is $actual." >&2; exit 1; fi
if [ ! -r /conf/config.xml ]; then echo 'OPNsense configuration missing.' >&2; exit 1; fi

watch=0
interval=300
while [ "$#" -gt 0 ]; do
  case "$1" in
    --watch) watch=1 ;;
    --interval) shift; interval=${1:?Missing interval} ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
case "$interval" in ''|*[!0-9]*) echo 'Interval must be 60 to 3600 seconds.' >&2; exit 2 ;; esac
if [ "$interval" -lt 60 ] || [ "$interval" -gt 3600 ]; then echo 'Interval must be 60 to 3600 seconds.' >&2; exit 2; fi

umask 077
root=/root/boilerstorm-monitor
[ ! -L "$root" ] || { echo 'Refusing a symlinked monitor directory.' >&2; exit 1; }
mkdir -p "$root"
chmod 700 "$root"
alerts="$root/alerts.tsv"

alert() {
  printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" | tee -a "$alerts"
}

compare_state() {
  name=$1
  next="$root/$name.next"
  current="$root/$name.current"
  if [ -e "$current" ] && ! cmp -s "$current" "$next"; then
    diff -u "$current" "$next" > "$root/$name-$(date -u +%Y%m%dT%H%M%SZ).diff" || true
    alert changed "$name changed; inspect the newest $name diff in $root"
  fi
  mv -f "$next" "$current"
}

pass() {
  sha256 -q /conf/config.xml > "$root/config.next"
  compare_state config
  if pfctl -sr > "$root/filter.next" 2> "$root/filter-error.txt"; then compare_state filter;
  else alert query_failed 'pfctl filter rules'; fi
  if pfctl -sn > "$root/nat.next" 2> "$root/nat-error.txt"; then compare_state nat;
  else alert query_failed 'pfctl NAT rules'; fi
  if service -e > "$root/services.next" 2> "$root/services-error.txt"; then compare_state services;
  else alert query_failed 'enabled service list'; fi
  ifconfig -a > "$root/interfaces.txt" 2>&1 || alert query_failed 'interface inventory'
  netstat -rn > "$root/routes.txt" 2>&1 || alert query_failed 'route inventory'
  sockstat -4 -l > "$root/listeners.txt" 2>&1 || alert query_failed 'listener inventory'
  df -k / | awk 'NR==2 {gsub(/%/,"",$5); if ($4 < 2097152 || $5 >= 90) exit 1}' || alert disk_low 'Firewall root filesystem has less than 2 GiB free or is at least 90% used'
  printf 'Firewall monitor pass complete: %s\n' "$root"
}

while :; do
  pass
  [ "$watch" -eq 1 ] || break
  sleep "$interval"
done
