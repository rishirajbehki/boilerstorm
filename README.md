# BoilerStorm host operations

Host scripts for `cai-fw01` (OPNsense), `CAI-DC01` (Windows Server 2025), `CAI-WEB01` (Windows Server 2022), `cai-db01` (Ubuntu 26.04), and `cai-mail01` (Rocky Linux 10).

## What changes

| Host | No-argument first run | Separate options |
| --- | --- | --- |
| DC | Prompt for domain `admin` password; snapshot; enable security auditing, 4688 command lines and Defender monitoring; increase Security log capacity; disable SMBv1 server and Print Spooler; then hunt and back up service definitions, GPOs and DNS records | Defender signature update; optional System State backup |
| Windows web | Prompt for local `admin` password; snapshot; apply the same logging and Defender baseline; disable SMBv1 server; then hunt and back up services and IIS configuration | Defender signature update; optional web content copy |
| Ubuntu database/app | Prompt for local `admin` password; snapshot; enable protected hardlink/symlink settings and restrict private SSH host keys; then hunt and back up running units and common service configuration | Optional PostgreSQL/MariaDB dump and package upgrade |
| Rocky mail | Prompt for local `admin` password; apply the same Linux baseline; then hunt and back up running units and common service configuration | Optional mailbox copy and security package upgrade |
| OPNsense firewall | Back up local config and record version, interfaces, routes, active rules/NAT, listeners, processes and services | Change `admin` in the UI after backup and fresh-login verification |

The scripts leave the **Splunk Universal Forwarder and competition CA** alone. They do not change hostnames, internal IPs, service content, scored accounts, firewall rules, NAT, SSH login methods, LDAP signing, SMB signing, mail authentication, or database authentication. Those changes require service-specific knowledge and a real user test. The Windows first run disables the SMBv1 server (and DC Spooler); confirm no scored workflow depends on them. OS package upgrades remain separate because they can restart scored services.

See [HUNT-AND-RECOVERY.md](HUNT-AND-RECOVERY.md) for Zerologon, password prompts, implant triage, backups, recovery and the limits of each.
See [MONITORING.md](MONITORING.md) for repeated local checks, patch inventory, journal retention, and service tests.
See [dashboard/README.md](dashboard/README.md) for the five-host, read-only monitor view.

## Run order

1. On the machine's own console, identify it and read its actual Quotient checks. Verify a route back in, and confirm `admin` is not a scored account before rotation. Do not run two operators on the same shared Guacamole session.
2. Download the repository through the competition proxy. Run the matching host wrapper with no arguments. It prompts for a new `admin` password, applies the fast baseline, then hunts and backs up services. OPNsense has a backup/inventory command and a manual UI password change.
3. Keep the current console open and test a fresh login and the real scored service. Check the next Quotient result. Review the hunt and backup files **on that host**; the starting image may already contain implants. Do not copy the output off-network except permitted screenshots for submissions.
4. Start the host monitor or dashboard sender. Use `-AuditOnly` or `--audit-only` for a no-change snapshot; explicit options run only the selected actions.
5. Check free space before a web content, database, mailbox or System State backup. Do package and firmware upgrades only after a service test and recovery route; package scripts may restart services.

### Windows (Administrator PowerShell on the matching host)

```powershell
# First run on the matching host: password prompt, baseline, hunt, service backup
.\windows\CAI-DC01.ps1
.\windows\CAI-WEB01.ps1

# No-change snapshot or separate action
.\windows\CAI-DC01.ps1 -AuditOnly
.\windows\CAI-DC01.ps1 -Apply -UpdateSignatures
.\windows\CAI-WEB01.ps1 -BackupServices -BackupWebContent
```

PowerShell's execution policy may prevent local scripts from running. Use the operating system's supported per-process policy if approved by the team; do not permanently weaken policy. Windows outputs are under `C:\ProgramData\Boilerstorm\<host>-<timestamp>-<random>`. The firewall export is `firewall-before.wfw` in that directory. The script does **not** import it automatically; restoring firewall policy is a deliberate console action.

### Linux (root shell on the matching host)

```sh
# First run on the matching host: password prompt, baseline, hunt, service backup
bash linux/cai-db01.sh
bash linux/cai-mail01.sh

# No-change snapshot or separate action
bash linux/cai-db01.sh --audit-only
bash linux/cai-db01.sh --apply --upgrade-packages
bash linux/cai-mail01.sh --apply --upgrade-packages
bash linux/cai-db01.sh --backup-services --backup-data
```

Linux outputs and any previous baseline sysctl file stay in `/var/tmp/boilerstorm-<host>-<timestamp>` with root-only directory access. Package upgrades do not reboot automatically, but package scripts may restart services. The operator must check the actual app, mail, and database workflows immediately afterward.

### OPNsense (root shell on firewall console)

```sh
sh opnsense/cai-fw01.sh
```

The backup and state dump stay under `/root/boilerstorm-<timestamp>`. OPNsense keeps its configuration in `/conf/config.xml`; the script does not edit that file or reload `pf`. Review the actual NAT/rules in the UI, save a config backup, change the default `admin` password, verify a new login, then adjust one rule at a time and check public-path scoring. Map the public ports and management path before changing firewall policy.

## Primary references

- [Microsoft Defender PowerShell](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2025-ps)
- [Microsoft Process Creation audit subcategory](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d)
- [Microsoft command-line audit policy](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-auditsettings)
- [Microsoft advanced audit subcategory GUIDs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d)
- [Microsoft SMB protocol controls](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [Ubuntu security updates](https://documentation.ubuntu.com/security/security-updates/)
- [Rocky DNF](https://docs.rockylinux.org/guides/package_management/dnf_package_manager/)
- [OPNsense configuration backup](https://docs.opnsense.org/manual/backups.html)
- [OPNsense firewall rules](https://docs.opnsense.org/manual/firewall.html)
