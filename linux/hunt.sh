#!/usr/bin/env bash
set -euo pipefail

: "${EXPECTED_HOST:?}"
: "${HUNT_OUT:?}"
if [ "$EUID" -ne 0 ]; then echo 'Run as root.' >&2; exit 1; fi
actual=$(hostname -s | tr '[:upper:]' '[:lower:]')
if [ "$actual" != "$EXPECTED_HOST" ]; then echo "Wrong host: $actual" >&2; exit 1; fi
umask 077
mkdir -p "$HUNT_OUT"
chmod 700 "$HUNT_OUT"

{ date -Is; ss -antup; } > "$HUNT_OUT/connections.txt" 2>&1 || true
{ ps -eo pid,ppid,user,lstart,comm,args --sort=user; } > "$HUNT_OUT/processes.txt" 2>&1 || true
{ getent passwd | awk -F: '$3 == 0 || $3 >= 1000 {print $1 ":" $3 ":" $6 ":" $7}'; getent group sudo wheel || true; } > "$HUNT_OUT/accounts.txt"
{ systemctl list-units --all --type=service --no-pager; systemctl --failed --no-pager; } > "$HUNT_OUT/services.txt" 2>&1 || true
{ find /etc/systemd/system /usr/local/lib/systemd/system -type f -print 2>/dev/null; } > "$HUNT_OUT/local-units.txt" || true
{ grep -RInE 'ExecStart=.*(/tmp/|/var/tmp/|/dev/shm/|/home/)' /etc/systemd/system /usr/local/lib/systemd/system 2>/dev/null || true; } > "$HUNT_OUT/unusual-unit-paths.txt"
{ find /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron -type f -print -exec sed -n '1,120p' {} \; 2>/dev/null || true; } > "$HUNT_OUT/cron.txt"
{ find /root /home -type f -name authorized_keys -print -exec sha256sum {} \; 2>/dev/null || true; } > "$HUNT_OUT/authorized-keys.txt"
{ if [ -e /etc/ld.so.preload ]; then ls -l /etc/ld.so.preload; cat /etc/ld.so.preload; fi; } > "$HUNT_OUT/ld-preload.txt" 2>&1
{ find /tmp /var/tmp /dev/shm -xdev -type f \( -perm /111 -o -perm -4000 \) -printf '%m %u %s %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null || true; } > "$HUNT_OUT/temp-executables.txt"
{ for exe in /proc/[0-9]*/exe; do readlink "$exe" 2>/dev/null || true; done | grep ' (deleted)$' || true; } > "$HUNT_OUT/deleted-executables.txt"
{ find /etc/sudoers.d /etc/pam.d /etc/ssh -type f -printf '%m %u %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null || true; } > "$HUNT_OUT/security-configs.txt"

printf 'Read-only implant triage: %s\n' "$HUNT_OUT"
echo 'Review findings against the expected image; pre-existing does not mean benign.'
