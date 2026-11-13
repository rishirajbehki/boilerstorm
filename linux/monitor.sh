#!/usr/bin/env bash
set -euo pipefail

: "${EXPECTED_HOST:?Set EXPECTED_HOST to cai-db01 or cai-mail01}"
if [[ "$EXPECTED_HOST" != cai-db01 && "$EXPECTED_HOST" != cai-mail01 ]]; then echo 'Unsupported host.' >&2; exit 2; fi
if [ "$EUID" -ne 0 ]; then echo 'Run as root.' >&2; exit 1; fi
actual=$(hostname -s | tr '[:upper:]' '[:lower:]')
if [ "$actual" != "$EXPECTED_HOST" ]; then echo "Expected $EXPECTED_HOST; this is $actual." >&2; exit 1; fi

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
if ! [[ "$interval" =~ ^[0-9]+$ ]] || [ "$interval" -lt 60 ] || [ "$interval" -gt 3600 ]; then
  echo 'Interval must be 60 to 3600 seconds.' >&2; exit 2
fi

umask 077
root="/var/lib/boilerstorm-monitor-$EXPECTED_HOST"
[ ! -L "$root" ] || { echo 'Refusing a symlinked monitor directory.' >&2; exit 1; }
mkdir -p "$root"
chmod 700 "$root"
alerts="$root/alerts.tsv"
units="$root/critical-units.txt"
manifest="$root/config-sha256.txt"
last_run="$root/last-run.txt"

alert() {
  local kind=$1 detail=$2
  printf '%s\t%s\t%s\n' "$(date -Is)" "$kind" "$detail" | tee -a "$alerts"
}

if [ ! -e "$units" ]; then
  if [ "$EXPECTED_HOST" = cai-db01 ]; then pattern='^(postgresql|mysql|mariadb|redis|nginx|apache2|httpd)';
  else pattern='^(postfix|dovecot|httpd|nginx|roundcube)'; fi
  systemctl list-units --type=service --state=active --no-legend --plain --no-pager |
    awk '{if ($1 ~ /\.service$/) print $1; else if ($2 ~ /\.service$/) print $2}' |
    grep -E "$pattern" > "$units" || true
  printf 'Review and add the actual scored application units to %s\n' "$units"
fi

snapshot_config() {
  local target=$1 path
  local paths=()
  shopt -s nullglob
  for path in /etc/systemd/system /etc/cron.d /etc/cron.daily /etc/cron.hourly \
      /var/spool/cron /etc/sudoers /etc/sudoers.d /etc/ssh /root/.ssh \
      /home/*/.ssh /etc/ld.so.preload /etc/passwd /etc/group /etc/shadow \
      /etc/gshadow /etc/pam.d /etc/security /etc/profile.d /etc/rc.local; do
    [ -e "$path" ] && paths+=("$path")
  done
  shopt -u nullglob
  : > "$target"
  if [ "${#paths[@]}" -gt 0 ]; then
    while IFS= read -r -d '' file; do sha256sum "$file" >> "$target" || true; done \
      < <(find "${paths[@]}" -type f -print0 2>/dev/null | sort -z)
  fi
}

pass() {
  local stamp since temp status free total used_percent
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  since=$(cat "$last_run" 2>/dev/null || date -d '5 minutes ago' '+%Y-%m-%d %H:%M:%S')
  if [ ! -s "$units" ]; then alert 'no_critical_units' 'Add the scored service unit names to critical-units.txt'; fi
  while IFS= read -r unit; do
    [ -n "$unit" ] || continue
    if ! systemctl is-active --quiet "$unit"; then
      status=$(systemctl is-active "$unit" 2>/dev/null || true)
      alert 'service_down' "$unit: $status"
    fi
  done < "$units"
  systemctl --failed --type=service --no-legend --plain --no-pager |
    awk '{if ($1 ~ /\.service$/) print $1; else if ($2 ~ /\.service$/) print $2}' |
    while IFS= read -r unit; do [ -n "$unit" ] && alert 'failed_unit' "$unit"; done

  temp="$root/config-sha256.next"
  snapshot_config "$temp"
  if [ -e "$manifest" ] && ! cmp -s "$manifest" "$temp"; then
    diff -u "$manifest" "$temp" > "$root/config-change-$stamp.diff" || true
    alert 'config_changed' "Review $root/config-change-$stamp.diff"
  fi
  mv -f "$temp" "$manifest"

  if [ ! -d /var/log/journal ]; then
    alert 'journal_storage' 'Persistent journal directory missing; check journalctl --disk-usage and journald configuration'
  fi
  journalctl --since "$since" -u ssh -u sshd -t sudo --no-pager -o short-iso 2>/dev/null |
    grep -Ei 'failed|invalid user|authentication failure|sudo:|accepted' | tail -n 100 \
    > "$root/auth-$stamp.txt" || true
  if [ -s "$root/auth-$stamp.txt" ]; then alert 'auth_events' "Review $root/auth-$stamp.txt";
  else rm -f "$root/auth-$stamp.txt"; fi
  journalctl --since "$since" -p err..alert --no-pager -o short-iso 2>/dev/null |
    tail -n 100 > "$root/errors-$stamp.txt" || true
  if [ -s "$root/errors-$stamp.txt" ]; then alert 'journal_errors' "Review $root/errors-$stamp.txt";
  else rm -f "$root/errors-$stamp.txt"; fi
  while read -r total free used_percent; do
    if [ "$total" -gt 0 ] && { [ "$free" -lt 2097152 ] || [ "$used_percent" -ge 90 ]; }; then
      alert 'disk_low' "$free KiB free; $used_percent% used on a monitored filesystem"
    fi
  done < <(df -Pk / /var /var/tmp | awk 'NR>1 {gsub(/%/,"",$5); print $2,$4,$5}')
  date '+%Y-%m-%d %H:%M:%S' > "$last_run"
  printf 'Monitor pass complete: %s\n' "$root"
}

while :; do
  pass
  [ "$watch" -eq 1 ] || break
  sleep "$interval"
done
