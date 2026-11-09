#!/bin/sh
set -eu

# OPNsense has a single authoritative configuration file. This script makes a
# local backup and inventories the active rule/NAT state. Rule changes need a
# reviewed port and NAT map.
if [ "$(id -u)" -ne 0 ]; then echo 'Run as root on the firewall console.' >&2; exit 1; fi
if [ "$(uname -s)" != FreeBSD ]; then echo 'Expected OPNsense/FreeBSD.' >&2; exit 1; fi
actual=$(hostname -s | tr '[:upper:]' '[:lower:]')
if [ "$actual" != cai-fw01 ]; then
  printf 'Expected cai-fw01; this is %s. No changes made.\n' "$actual" >&2
  exit 1
fi
if [ ! -r /conf/config.xml ]; then echo 'OPNsense config not found.' >&2; exit 1; fi
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="/root/boilerstorm-${stamp}"
umask 077
mkdir -m 700 "$out"
cp -p /conf/config.xml "$out/config.xml"
sha256 "$out/config.xml" > "$out/config.sha256"
uname -a > "$out/system.txt"
if command -v opnsense-version >/dev/null 2>&1; then opnsense-version >> "$out/system.txt" 2>&1 || true; fi
ifconfig -a > "$out/interfaces.txt" 2>&1
netstat -rn > "$out/routes.txt" 2>&1
pfctl -sr > "$out/filter-rules.txt" 2>&1 || true
pfctl -sn > "$out/nat-rules.txt" 2>&1 || true
sockstat -4 -l > "$out/listeners.txt" 2>&1 || true
ps -axo pid,user,command > "$out/processes.txt" 2>&1 || true
service -e > "$out/enabled-services.txt" 2>&1 || true
pkg info > "$out/packages.txt" 2>&1 || true
crontab -l > "$out/root-cron.txt" 2>&1 || true
ls -la /usr/local/etc/rc.d /etc/rc.d > "$out/startup-scripts.txt" 2>&1 || true
printf 'Local firewall backup and inventory: %s\n' "$out"
echo 'No rules, NAT, users, firmware, or interfaces changed.'
