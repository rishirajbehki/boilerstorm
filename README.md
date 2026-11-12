# BoilerStorm host operations

Host scripts for `cai-fw01` (OPNsense), `CAI-DC01` (Windows Server 2025), `CAI-WEB01` (Windows Server 2022), `cai-db01` (Ubuntu 26.04), and `cai-mail01` (Rocky Linux 10).

## What changes

| Host | Default audit | `-Apply` / `--apply` changes | Extra explicit options |
| --- | --- | --- | --- |
| DC | Host/OS, services, listeners, firewall, tasks, Defender, process audit, DNS SOA, Domain Admins, Netlogon events | Security log capacity to 256 MiB; process creation, failed logon, account/group change and audit-policy change auditing; command line in 4688; Defender monitoring | GPO/service backup; optional System State backup; implant hunt; signature update; SMBv1 or Spooler disable; interactive `admin` rotation |
| Windows web | Same Windows baseline plus IIS sites/bindings and W3SVC/WAS | Same logging and Defender settings | IIS/service backup; optional web content copy; implant hunt; signature update; SMBv1 disable; interactive `admin` rotation |
| Ubuntu database/app | OS, listeners, processes, units, root-equivalent accounts, admin groups, cron, SSH policy/key modes, app units | Protected hardlink/symlink settings; private SSH host-key permissions | Service/config backup; optional PostgreSQL/MariaDB dump; implant hunt; package upgrade; interactive `admin` rotation |
| Rocky mail | Same Linux baseline plus mail units, SELinux mode, firewalld status | Same kernel/key settings | Service/config backup; optional local mailbox copy; implant hunt; security package upgrade; interactive `admin` rotation |
| OPNsense firewall | Local config backup; version, interfaces, routes, active rules/NAT, listeners, processes, services | **No automatic rule change** until scored ports, NAT and management path are known | Change `admin` in the UI after backup and fresh-login verification |

The scripts leave the **Splunk Universal Forwarder and competition CA** alone. They do not change hostnames, internal IPs, service content, scored accounts, firewall rules, NAT, SSH login methods, LDAP signing, SMB signing, mail authentication, or database authentication. Those changes require service-specific knowledge and a real user test. SMBv1 disable and package upgrades are separate options because they can affect service compatibility or restart services.

See [HUNT-AND-RECOVERY.md](HUNT-AND-RECOVERY.md) for Zerologon, password prompts, implant triage, backups, recovery and the limits of each.
See [MONITORING.md](MONITORING.md) for repeated local checks, patch inventory, journal retention, and service tests.

## Run order

1. On the machine's own console, identify it and read its actual Quotient checks. Verify a route back in, and confirm `admin` is not a scored account before rotation. Do not run two operators on the same shared Guacamole session.
2. Download the repository through the competition proxy. Run the host wrapper with no arguments first to capture a local before-state.
3. Review the audit files **on that host**. Then use `-Apply` or `--apply`. It creates a backup/snapshot before changes. Do not copy the output off-network except permitted screenshots for submissions.
4. Test the real service from the relevant path and wait for its next Quotient result before using an extra option or starting the next host.
5. Optional package upgrades, SMBv1, Spooler, and password rotation are separate decisions. Package upgrades can take several minutes and restart services. A fresh login must be tested immediately after password rotation.

### Windows (Administrator PowerShell on the matching host)

```powershell
# Read-only audit
.\windows\CAI-DC01.ps1
.\windows\CAI-WEB01.ps1

# Conservative baseline on the corresponding machine
.\windows\CAI-DC01.ps1 -Apply
.\windows\CAI-WEB01.ps1 -Apply

# Examples of separate changes, after service/account checks
.\windows\CAI-DC01.ps1 -Apply -UpdateSignatures
.\windows\CAI-WEB01.ps1 -Apply -DisableSmb1
.\windows\CAI-DC01.ps1 -RotateAdmin
```

PowerShell's execution policy may prevent local scripts from running. Use the operating system's supported per-process policy if approved by the team; do not permanently weaken policy. Windows outputs are under `C:\ProgramData\Boilerstorm\<host>-<timestamp>-<random>`. The firewall export is `firewall-before.wfw` in that directory. The script does **not** import it automatically; restoring firewall policy is a deliberate console action.

### Linux (root shell on the matching host)

```sh
# Read-only audit
bash linux/cai-db01.sh
bash linux/cai-mail01.sh

# Conservative baseline
bash linux/cai-db01.sh --apply
bash linux/cai-mail01.sh --apply

# Separate, potentially disruptive steps
bash linux/cai-db01.sh --apply --upgrade-packages
bash linux/cai-mail01.sh --apply --upgrade-packages
bash linux/cai-mail01.sh --rotate-admin
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
