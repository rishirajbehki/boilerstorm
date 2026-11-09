#!/usr/bin/env bash
set -euo pipefail

: "${EXPECTED_HOST:?}"
if [ "$EUID" -ne 0 ]; then echo 'Run as root.' >&2; exit 1; fi
actual=$(hostname -s | tr '[:upper:]' '[:lower:]')
if [ "$actual" != "$EXPECTED_HOST" ]; then echo "Wrong host: $actual" >&2; exit 1; fi
if [ "$#" -ne 2 ]; then echo 'Usage: restore-service.sh BACKUP_DIR UNIT.service' >&2; exit 2; fi
backup_dir=$1
unit=$2
case "$unit" in
  *[!a-zA-Z0-9_.@-]*|'') echo 'Invalid unit name.' >&2; exit 2 ;;
esac
if [ ! -f "$backup_dir/running-units.txt" ] || [ ! -f "$backup_dir/unit-${unit}.config" ]; then
  echo 'Baseline service record missing.' >&2; exit 1
fi
if ! grep -Fxq -- "$unit" "$backup_dir/running-units.txt"; then
  echo 'This unit was not running in the saved snapshot.' >&2; exit 1
fi
if ! diff -q "$backup_dir/unit-${unit}.config" <(systemctl cat "$unit") >/dev/null; then
  echo 'Unit definition changed since backup. Investigate before starting it.' >&2; exit 1
fi
if [ -f "$backup_dir/unit-${unit}.binary-sha256" ]; then
  sha256sum -c "$backup_dir/unit-${unit}.binary-sha256" >/dev/null || {
    echo 'Service executable changed or is missing. Investigate before starting it.' >&2; exit 1;
  }
fi
echo "Starting reviewed service: $unit"
systemctl start "$unit"
systemctl --no-pager --full status "$unit"
echo 'Check the real user workflow and Quotient result now.'
