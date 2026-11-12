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
  *) echo 'Unexpected OS. No changes made.' >&2; exit 1 ;;
esac

umask 077
dir=/etc/systemd/journald.conf.d
target="$dir/90-boilerstorm-persistent.conf"
backup="/var/tmp/boilerstorm-journal-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 700 "$backup"
if [ -L "$dir" ] || [ -L "$target" ] || [ -L /var/log/journal ]; then echo 'Refusing a symlinked journal path.' >&2; exit 1; fi
mkdir -p "$dir" /var/log/journal
if [ -e "$target" ]; then cp -p "$target" "$backup/previous.conf"; fi
cat > "$target" <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=200M
RuntimeMaxUse=50M
EOF
chmod 644 "$target"
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald
journalctl --flush
printf 'Persistent journal enabled; previous config, if any: %s\n' "$backup"
journalctl --disk-usage
