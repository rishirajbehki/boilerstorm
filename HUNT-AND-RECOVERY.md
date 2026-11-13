# Hunt and recovery procedures

These commands run **on the matching competition host**, from the repo directory, using an elevated PowerShell or root shell. The no-argument wrapper rotates `admin` and applies the fast baseline first, then runs the hunt and service backup in the same invocation. All output stays on that host. The first snapshot follows password rotation and may already contain Red Team persistence; it is not a known-good image.

## Zerologon on the Windows Server 2025 DC

The DC script checks for vulnerable Netlogon secure-channel exceptions. [Microsoft's CVE-2020-1472 guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2020/10/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472) says modern DC updates enforce secure RPC and no longer need the old `FullSecureChannelProtection` registry switch. The audit records System events 5827/5828 (denied) and 5830/5831 (allowed by exception); the hunt saves GPO settings for review. Review an exception's client dependency before removing it.

## Password rotations

The no-argument first run pauses for the new password at the host console. Windows prompts twice with masked input; Linux prompts twice without echo. Mismatched or empty input leaves the password unchanged and stops the first run. The password is not saved to a file or printed. Rotation changes the named `admin` account on that host: domain `CLOSEDAI\admin` on the DC, local `admin` on the web, database and mail servers. Test a new login while the current console remains open. Change the firewall's web `admin` and the team mailbox separately in their UIs. Check Quotient before rotating a scored account; it needs a PCR first. Use the explicit commands below only to retry rotation separately.

Windows examples:

    .\windows\CAI-DC01.ps1 -RotateAdmin
    .\windows\CAI-WEB01.ps1 -RotateAdmin

Linux examples:

    bash linux/cai-db01.sh --rotate-admin
    bash linux/cai-mail01.sh --rotate-admin

## Pre-baked implant hunt

The first run includes this read-only hunt after the fast baseline. To rerun the hunt separately:

    .\windows\CAI-DC01.ps1 -Hunt
    .\windows\CAI-WEB01.ps1 -Hunt
    bash linux/cai-db01.sh --hunt
    bash linux/cai-mail01.sh --hunt
    sh opnsense/cai-fw01.sh

Windows findings: service executable paths, scheduled-task actions, permanent WMI subscriptions, Run keys, startup folders, Defender exclusions and detections, recent security/service events and network connections. The DC hunt adds privileged groups, `adminCount=1` accounts and an XML report of every GPO. The web hunt lists executable and script-like files under IIS site roots. Linux findings: root/admin accounts, units, cron, SSH authorized-key hashes, preload hooks, executables in temporary directories, deleted running executables, security configuration and connections. The firewall script records config, NAT, filter rules, processes, packages, cron and enabled services.

Windows also hashes and checks signatures on the executable paths of running services. For a slower Linux package-integrity pass, use `--verify-packages` on either Linux wrapper. It runs `dpkg -V` or `rpm -Va` and writes the findings locally; modified configuration files can create benign differences.

The output is a **triage list**. A suspicious location or recently changed file is not proof, and a pre-baked implant may be in an ordinary location. Compare services with the actual business role, investigate unfamiliar admin accounts and persistence, preserve timestamped evidence, then remove only a confirmed malicious item and verify scoring.

## Backups

The first run backs up service configuration after the fast baseline. Check free space before larger data backups. The Windows output is a restricted directory under `C:\ProgramData\Boilerstorm`; Linux uses a root-only directory under `/var/tmp`; OPNsense uses `/root`. These are local backups. Do not put them in the public repo. To repeat the hunt and backup:

    .\windows\CAI-DC01.ps1 -BackupServices -Hunt
    .\windows\CAI-WEB01.ps1 -BackupServices -BackupWebContent -Hunt
    bash linux/cai-db01.sh --backup-services --hunt
    bash linux/cai-mail01.sh --backup-services --hunt
    sh opnsense/cai-fw01.sh

The Windows backup exports **all service definitions and their running state**. On the DC it also runs `Backup-GPO -All` and exports AD-integrated DNS zone records. GPO and zone exports are not the AD database. If a separate volume exists, an optional full System State backup uses [wbadmin](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-start-systemstatebackup):

    .\windows\CAI-DC01.ps1 -BackupServices -SystemStateTarget E:

On the web server, `-BackupServices` creates an [IIS AppCmd configuration backup](https://learn.microsoft.com/en-us/iis/get-started/getting-started-with-iis/getting-started-with-appcmdexe); `-BackupWebContent` copies local IIS site roots. Check available disk space first. Any database behind the site is separate.

On Linux, `--backup-services` saves every running unit's definition, package inventory and common service configuration. `--backup-data` additionally attempts an application data copy, and fails if it cannot recognize a supported store:

    bash linux/cai-db01.sh --backup-services --backup-data
    bash linux/cai-mail01.sh --backup-services --backup-data

The database script uses [PostgreSQL pg_dumpall](https://www.postgresql.org/docs/17/app-pg-dumpall.html), [MariaDB mariadb-dump](https://mariadb.com/docs/server/mariadb-quickstart-guides/mariadb-backup-guide) or MySQL mysqldump when a recognized engine is running and local authentication works. It does not cover an unknown application store, Redis or SQLite. The mail script archives recognized local mailbox directories after a space check. A live mailbox archive can race with incoming mail; rehearse its restore before relying on it.

The OPNsense script backs up `/conf/config.xml` and inventories active state. It does not save a disk image or rewrite firewall rules.

## Restoring a stopped service

Backups of service definitions help if Red Team disables or changes a service. They do **not** replace a deleted binary, repair a damaged database or prove the starting configuration was clean. The recovery helpers require you to name one service. They refuse if that service was not running in the snapshot or its launch definition changed. The Windows helper also requires a valid executable signature; the Linux helper compares the current executable with its saved hash when one was captured. Investigate a changed definition or binary before starting it.

Windows accepts `DNS`, `NTDS`, `Netlogon`, `LanmanServer`, `WinRM` and `TermService` on the DC, and `WAS`, `W3SVC`, `LanmanServer`, `WinRM` and `TermService` on the web server. It still requires the service to have been running in the saved snapshot:

    .\windows\Restore-CriticalService.ps1 -ExpectedHost CAI-DC01 -BackupDir 'C:\ProgramData\Boilerstorm\CAI-DC01-...\service-backup' -ServiceName DNS

Linux uses the saved unit directory and an explicit unit name. Replace the example backup path with the real one printed by your backup run:

    EXPECTED_HOST=cai-mail01 bash linux/restore-service.sh /var/tmp/boilerstorm-cai-mail01-.../service-backup postfix.service

After any restart, test the full user workflow and the next Quotient result. If the binary is missing, restore the matching package or clean application release after checking the evidence; repeatedly starting a broken service will not fix it.

## Service discovery

At first access, record the scored accounts, service endpoints, web roots, database engine, mail store and restore locations. Add functional checks for the actual DNS records, IIS pages, database query, mail login and firewall NAT before automating further service changes. Rehearse backup restoration on matching systems.
