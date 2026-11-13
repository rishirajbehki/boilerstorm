#!/usr/bin/env bash
set -euo pipefail

# Host-specific wrappers set these three values.
: "${EXPECTED_HOST:?}"
: "${EXPECTED_ID:?}"
: "${EXPECTED_VERSION:?}"

apply=0
upgrade=0
rotate_admin=0
backup_services=0
backup_data=0
hunt=0
verify_packages=0
for arg in "$@"; do
  case "$arg" in
    --apply) apply=1 ;;
    --upgrade-packages) upgrade=1 ;;
    --rotate-admin) rotate_admin=1 ;;
    --backup-services) backup_services=1 ;;
    --backup-data) backup_data=1 ;;
    --hunt) hunt=1 ;;
    --verify-packages) verify_packages=1; hunt=1 ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done
if [ "$EUID" -ne 0 ]; then echo 'Run as root on the host console.' >&2; exit 1; fi
if [ "$upgrade" -eq 1 ] && [ "$apply" -ne 1 ]; then
  echo '--upgrade-packages requires --apply.' >&2; exit 2
fi
if [ "$backup_data" -eq 1 ] && [ "$backup_services" -ne 1 ]; then
  echo '--backup-data requires --backup-services.' >&2; exit 2
fi
actual_host=$(hostname -s | tr '[:upper:]' '[:lower:]')
if [ "$actual_host" != "$EXPECTED_HOST" ]; then
  printf 'Expected %s; this is %s. No changes made.\n' "$EXPECTED_HOST" "$actual_host" >&2
  exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
version_ok=0
if [ "$EXPECTED_ID" = rocky ] && [ "$EXPECTED_VERSION" = 10 ]; then
  case "${VERSION_ID:-}" in 10|10.*) version_ok=1 ;; esac
elif [ "${VERSION_ID:-}" = "$EXPECTED_VERSION" ]; then
  version_ok=1
fi
if [ "${ID:-}" != "$EXPECTED_ID" ] || [ "$version_ok" -ne 1 ]; then
  printf 'Expected %s %s; found %s %s. No changes made.\n' \
    "$EXPECTED_ID" "$EXPECTED_VERSION" "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
  exit 1
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="/var/tmp/boilerstorm-${actual_host}-${stamp}"
umask 077
mkdir -m 700 "$out"

snapshot() {
  local label=$1
  {
    printf 'host=%s os=%s version=%s time=%s\n' "$actual_host" "$ID" "$VERSION_ID" "$(date -Is)"
    printf '\n== listeners ==\n'; ss -lntup || true
    printf '\n== processes ==\n'; ps -eo pid,ppid,user,comm --sort=user || true
    printf '\n== enabled units ==\n'; systemctl list-unit-files --state=enabled --no-pager || true
    printf '\n== failed units ==\n'; systemctl --failed --no-pager || true
    printf '\n== privileged accounts ==\n'; getent passwd | awk -F: '$3 == 0 {print $1 ":" $3 ":" $6 ":" $7}'
    printf '\n== admin groups ==\n'; getent group sudo wheel || true
    printf '\n== scheduled jobs ==\n'; find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/systemd/system -maxdepth 1 -type f -printf '%p\n' 2>/dev/null | sort || true
    printf '\n== ssh effective config ==\n'; sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|denyusers) ' || true
    printf '\n== host key modes ==\n'; find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key' -printf '%m %p\n' 2>/dev/null || true
    printf '\n== key hardening values ==\n'; sysctl fs.protected_hardlinks fs.protected_symlinks 2>/dev/null || true
    printf '\n== role services ==\n'
    if [ "$EXPECTED_HOST" = 'cai-db01' ]; then
      systemctl list-units --all --no-pager 'postgresql*' 'mysql*' 'mariadb*' 'redis*' 'nginx*' 'apache2*' || true
    else
      systemctl list-units --all --no-pager 'postfix*' 'dovecot*' 'httpd*' 'nginx*' 'roundcube*' || true
      getenforce 2>/dev/null || true
      firewall-cmd --state 2>/dev/null || true
    fi
  } > "$out/$label.txt" 2>&1
}

backup_service_state() {
  local config_paths=()
  local path
  local unit
  local exec_line
  local exec_path
  mkdir -m 700 "$out/service-backup"
  systemctl list-units --type=service --state=running --no-legend --plain --no-pager |
    awk '{print $1}' > "$out/service-backup/running-units.txt"
  systemctl list-unit-files --type=service --no-legend --plain --no-pager > "$out/service-backup/unit-files.txt"
  while IFS= read -r unit; do
    [ -n "$unit" ] || continue
    systemctl show "$unit" -p Id -p ActiveState -p SubState -p UnitFileState -p FragmentPath -p DropInPaths -p ExecStart -p User \
      > "$out/service-backup/unit-${unit}.txt" 2>&1 || true
    systemctl cat "$unit" > "$out/service-backup/unit-${unit}.config" 2>&1 || true
    exec_line=$(systemctl show "$unit" -p ExecStart --value 2>/dev/null || true)
    if [[ "$exec_line" == *'path='* ]]; then
      exec_path=${exec_line#*path=}
      exec_path=${exec_path%% *}
      if [ -f "$exec_path" ]; then
        sha256sum "$exec_path" > "$out/service-backup/unit-${unit}.binary-sha256"
      fi
    fi
  done < "$out/service-backup/running-units.txt"
  if [ "$ID" = ubuntu ]; then
    dpkg-query -W -f='${Package}\t${Version}\n' > "$out/service-backup/packages.tsv"
  else
    rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' > "$out/service-backup/packages.tsv"
  fi
  for path in /etc/systemd/system /etc/ssh /etc/cron.d /etc/cron.daily /etc/cron.hourly \
      /etc/sudoers /etc/sudoers.d /etc/pam.d /etc/security /etc/fstab \
      /etc/ufw /etc/firewalld /etc/nftables.conf \
      /etc/postgresql /etc/mysql /etc/mariadb /etc/redis /etc/nginx /etc/apache2 \
      /etc/postfix /etc/dovecot /etc/httpd /etc/roundcubemail /etc/aliases /etc/mail; do
    [ -e "$path" ] && config_paths+=("$path")
  done
  if [ "${#config_paths[@]}" -gt 0 ]; then
    tar -czpf "$out/service-backup/configs.tar.gz" "${config_paths[@]}" 2> "$out/service-backup/tar-stderr.txt"
  fi
  if [ "$backup_data" -eq 1 ]; then
    if [ "$EXPECTED_HOST" = cai-db01 ]; then
      local data_paths=()
      local bytes=0
      local available=0
      for path in /var/lib/postgresql /var/lib/mysql /var/lib/mariadb; do
        [ -d "$path" ] && data_paths+=("$path")
      done
      if [ "${#data_paths[@]}" -eq 0 ]; then
        echo 'No recognized database data directory. No database dump made.' >&2; exit 1
      fi
      bytes=$(du -sb "${data_paths[@]}" | awk '{s+=$1} END {print s+0}')
      available=$(df -B1 --output=avail "$out" | tail -n 1 | tr -d ' ')
      if [ "$available" -lt "$((bytes * 2))" ]; then
        echo 'Not enough free space for a safe local database dump.' >&2; exit 1
      fi
      local dumped=0
      if command -v pg_isready >/dev/null 2>&1 && pg_isready -q; then
        command -v runuser >/dev/null 2>&1 || { echo 'runuser missing; PostgreSQL backup failed.' >&2; exit 1; }
        runuser -u postgres -- pg_dumpall > "$out/service-backup/postgres-all.sql"
        dumped=1
      fi
      if command -v mariadb-dump >/dev/null 2>&1 && command -v mariadb-admin >/dev/null 2>&1 && mariadb-admin ping --silent >/dev/null 2>&1; then
        mariadb-dump --all-databases --single-transaction --routines --events > "$out/service-backup/mariadb-all.sql"
        dumped=1
      elif command -v mysqldump >/dev/null 2>&1 && command -v mysqladmin >/dev/null 2>&1 && mysqladmin ping --silent >/dev/null 2>&1; then
        mysqldump --all-databases --single-transaction --routines --events > "$out/service-backup/mysql-all.sql"
        dumped=1
      fi
      if [ "$dumped" -ne 1 ]; then echo 'No supported running database was dumped.' >&2; exit 1; fi
    else
      local mail_paths=()
      local bytes=0
      local available=0
      shopt -s nullglob
      for path in /var/mail /var/spool/mail /var/vmail /home/*/Maildir; do
        [ -d "$path" ] && mail_paths+=("$path")
      done
      shopt -u nullglob
      if [ "${#mail_paths[@]}" -gt 0 ]; then
        bytes=$(du -sb "${mail_paths[@]}" | awk '{s+=$1} END {print s+0}')
        available=$(df -B1 --output=avail "$out" | tail -n 1 | tr -d ' ')
        if [ "$available" -lt "$((bytes * 2))" ]; then
          echo 'Not enough free space for a safe local mailbox copy.' >&2; exit 1
        fi
        tar -czpf "$out/service-backup/mail-data.tar.gz" "${mail_paths[@]}" 2> "$out/service-backup/mail-tar-stderr.txt"
      else
        echo 'No recognized local mailbox directory. No mailbox copy made.' >&2; exit 1
      fi
    fi
  fi
  printf 'Service backup complete: %s/service-backup\n' "$out"
}

if [ "$rotate_admin" -eq 1 ]; then
  if ! getent passwd admin >/dev/null; then
    echo 'admin account not found; password unchanged.' >&2
    exit 1
  fi
  if [ ! -t 0 ]; then
    echo 'Password rotation requires an interactive console.' >&2
    exit 1
  fi
  printf 'New password for local admin: ' >&2
  IFS= read -r -s new_password
  printf '\n' >&2
  [ -n "$new_password" ] || { echo 'Empty password refused.' >&2; exit 1; }
  printf 'Repeat new password: ' >&2
  IFS= read -r -s confirm_password
  printf '\n' >&2
  [ "$new_password" = "$confirm_password" ] || { unset new_password confirm_password; echo 'Passwords did not match; unchanged.' >&2; exit 1; }
  printf 'admin:%s\n' "$new_password" | chpasswd
  unset new_password confirm_password
  echo 'Local admin password changed. Verify a fresh login before leaving the console.'
fi
snapshot before
if [ "$hunt" -eq 1 ]; then
  EXPECTED_HOST="$EXPECTED_HOST" HUNT_OUT="$out/hunt" bash ./hunt.sh
fi
if [ "$verify_packages" -eq 1 ]; then
  if [ "$ID" = ubuntu ]; then
    dpkg -V > "$out/hunt/package-verify.txt" 2>&1 || echo "dpkg exit $?: inspect package-verify.txt" > "$out/hunt/package-verify-status.txt"
  else
    rpm -Va > "$out/hunt/package-verify.txt" 2>&1 || echo "rpm exit $?: inspect package-verify.txt" > "$out/hunt/package-verify-status.txt"
  fi
fi
if [ "$backup_services" -eq 1 ]; then backup_service_state; fi
if [ "$apply" -ne 1 ]; then
  printf 'Audit complete: %s\n' "$out"
  if [ "$rotate_admin" -eq 1 ]; then echo 'Admin password changed; baseline settings unchanged.'; else echo 'No baseline settings changed.'; fi
  exit 0
fi

# These kernel settings are local filesystem protections and do not change
# network paths, authentication methods, or business application config.
target=/etc/sysctl.d/90-boilerstorm-baseline.conf
if [ -L "$target" ]; then echo 'Refusing a symlinked baseline config.' >&2; exit 1; fi
if [ -e "$target" ]; then cp -p "$target" "$out/sysctl-before.conf"; fi
printf 'fs.protected_hardlinks = 1\nfs.protected_symlinks = 1\n' > "$target"
chmod 644 "$target"
sysctl -p "$target"

# Private host keys must not be readable by non-root users. Public host keys
# and sshd_config are not modified.
find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key' -exec chmod 600 {} +

if [ "$upgrade" -eq 1 ]; then
  echo 'Package upgrade requested: service restarts and network downloads may occur.'
  if [ "$ID" = ubuntu ]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
  else
    dnf -y upgrade --security
  fi
fi

snapshot after
printf 'Completed. Before/after evidence: %s\n' "$out"
echo 'Test the actual scored service and next Quotient result before another change.'
