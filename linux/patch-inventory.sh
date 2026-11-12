#!/usr/bin/env bash
set -euo pipefail

: "${EXPECTED_HOST:?Set EXPECTED_HOST to cai-db01 or cai-mail01}"
if [ "$EUID" -ne 0 ]; then echo 'Run as root.' >&2; exit 1; fi
actual=$(hostname -s | tr '[:upper:]' '[:lower:]')
if [ "$actual" != "$EXPECTED_HOST" ]; then echo "Expected $EXPECTED_HOST; this is $actual." >&2; exit 1; fi
if [ "$EXPECTED_HOST" != cai-db01 ] && [ "$EXPECTED_HOST" != cai-mail01 ]; then echo 'Unsupported host.' >&2; exit 2; fi
. /etc/os-release
case "$EXPECTED_HOST:$ID:$VERSION_ID" in
  cai-db01:ubuntu:26.04|cai-mail01:rocky:10|cai-mail01:rocky:10.*) ;;
  *) echo 'Unexpected OS. No inventory taken.' >&2; exit 1 ;;
esac

refresh=0
for arg in "$@"; do
  case "$arg" in --refresh) refresh=1 ;; *) echo "Unknown option: $arg" >&2; exit 2 ;; esac
done
umask 077
out="/var/tmp/boilerstorm-patches-$EXPECTED_HOST-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 700 "$out"
{ date -Is; cat /etc/os-release; uname -a; } > "$out/system.txt"
if [ "$ID" = ubuntu ]; then
  if [ "$refresh" -eq 1 ]; then apt-get update > "$out/refresh.txt" 2>&1; fi
  apt list --upgradable > "$out/pending-packages.txt" 2>&1 || true
  dpkg-query -W -f='${Package}\t${Version}\n' > "$out/installed-packages.tsv"
  if [ -f /var/run/reboot-required ]; then cp /var/run/reboot-required "$out/reboot-required.txt"; fi
  systemctl list-timers --all --no-pager 'apt-daily*' > "$out/update-timers.txt" 2>&1 || true
else
  if [ "$refresh" -eq 1 ]; then dnf makecache --refresh > "$out/refresh.txt" 2>&1; fi
  dnf --cacheonly updateinfo list updates security > "$out/security-advisories.txt" 2>&1 || true
  dnf --cacheonly check-update > "$out/pending-packages.txt" 2>&1 || true
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' > "$out/installed-packages.tsv"
  command -v needs-restarting >/dev/null 2>&1 && needs-restarting -r > "$out/reboot-check.txt" 2>&1 || true
fi
printf 'Patch inventory: %s\n' "$out"
if [ "$refresh" -ne 1 ]; then echo 'Pending results use the existing package cache; use --refresh for current repository data.'; fi
