# Monitoring and patch checks

Run the monitor on each matching host after the initial audit and implant hunt. The first pass saves a local comparison point. Treat that point as an observed state, not a clean image. Later passes report changes; they never remove an account, restart a service, change a firewall rule, or install a package. Alerts stay on the host in a root or Administrator-only directory. Keep an operator watching Quotient's external checks and testing actual user workflows.

## Windows servers

Run elevated PowerShell on the matching machine:

```powershell
.\windows\CAI-DC01.ps1 -Apply
.\windows\Monitor-Boilerstorm.ps1 -ExpectedHost CAI-DC01 -Watch

.\windows\CAI-WEB01.ps1 -Apply
.\windows\Monitor-Boilerstorm.ps1 -ExpectedHost CAI-WEB01 -Watch
```

The baseline enables process creation success auditing, failed logon auditing, user-account and security-group change auditing, and audit-policy change auditing. It saves the previous effective audit policy. Group Policy can later overwrite local audit settings; check `auditpol /get /category:*` after policy refresh. The watcher checks critical services, IIS site state or the DC's local DNS SOA, Defender and firewall state, disk space, and these events:

| Log | Events |
| --- | --- |
| Security | 4625 failed logon; 4697 new service; 4702 task change; 4719 audit policy change; 4720/4722/4726 user changes; 4728/4732/4756 privileged group additions; 1102 log cleared |
| System | 7045 service install; 7031/7034 unexpected service termination |
| Defender Operational | 1116/1117 malware detection/action; 5007 configuration change; 5009 tamper protection block |

The watcher also compares privileged-group membership with the previous pass. The first five minutes of matching events are captured on startup. Each pass saves event record IDs to avoid repeating them. A busy log can exceed the 500-event query cap; the monitor then emits an `event_query_limit` alert and the operator should inspect that log directly. `alerts.jsonl`, service snapshots, membership changes and cursors are under `C:\ProgramData\Boilerstorm\monitor`. Ctrl+C stops the watch; the console process must remain running for continuous checks. To run one pass, omit `-Watch`; `-IntervalSeconds` changes the watch period (default 60 seconds).

Patch inventory:

```powershell
.\windows\Get-PatchInventory.ps1 -ExpectedHost CAI-DC01
.\windows\Get-PatchInventory.ps1 -ExpectedHost CAI-WEB01 -ScanPendingUpdates
```

The default command records the OS build, installed hotfixes, Defender signatures and reboot indicators. `-ScanPendingUpdates` asks Windows Update Agent for pending software updates; it can take longer and may need the competition proxy or configured update source. The inventory does not install updates. Compare the build with [Microsoft's Windows Server release information](https://learn.microsoft.com/en-us/windows-server/get-started/windows-server-release-info), then schedule a host-by-host update and restart only after preserving a service recovery path.

## Linux servers

Run as root on the matching host:

```sh
EXPECTED_HOST=cai-db01 bash linux/monitor.sh --watch
EXPECTED_HOST=cai-mail01 bash linux/monitor.sh --watch
```

The default watch interval is five minutes; `--interval 60` uses one minute. Omit `--watch` for one pass; the shell process must remain running for continuous checks. The first run creates `/var/lib/boilerstorm-monitor-<host>/critical-units.txt` from installed role units. **Add the actual application, database, mail, webmail and chat unit names** after inspecting the host. The monitor reports failed or stopped units, changes to systemd units, cron, accounts, PAM, sudoers, SSH settings and authorized keys, authentication events, journal errors, and low disk space. It stores diffs and alerts locally. The initial file hash list can already include a pre-baked implant; compare it with the hunt output before trusting it.

If the journal is not persistent, enable bounded disk retention after checking available space:

```sh
EXPECTED_HOST=cai-db01 bash linux/enable-journal-persistence.sh
EXPECTED_HOST=cai-mail01 bash linux/enable-journal-persistence.sh
```

This writes a journald drop-in with `Storage=persistent` and a 200 MiB disk cap, restarts journald, and flushes buffered entries. The previous drop-in, if any, is saved locally. [systemd documents persistent storage and its limits](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html).

Patch inventory uses the existing package cache unless `--refresh` is supplied:

```sh
EXPECTED_HOST=cai-db01 bash linux/patch-inventory.sh --refresh
EXPECTED_HOST=cai-mail01 bash linux/patch-inventory.sh --refresh
```

Results stay in `/var/tmp/boilerstorm-patches-<host>-<timestamp>`. The script lists pending packages, security advisories where available, installed package versions, and reboot indicators. It does not install updates. The existing host wrapper's `--apply --upgrade-packages` performs upgrades after the backup and service checks.

## Firewall and external checks

Run at the firewall console:

```sh
sh opnsense/cai-fw01.sh
sh opnsense/monitor.sh --watch
```

The monitor compares `/conf/config.xml`, loaded filter/NAT rules and enabled services with its previous pass. It records interface, route and listener state and reports low disk space. Alerts and diffs stay under `/root/boilerstorm-monitor`. It does not change policy or restart the firewall. In the OPNsense UI, review **Services → Monit** for alert-only checks of known critical services; configure recipients that remain reachable when the mail server is down. [OPNsense Monit documentation](https://docs.opnsense.org/manual/monit.html). Check **System → Firmware → Updates** for available firmware only after saving the firewall configuration and arranging a recovery window.

Quotient checks the public path. Keep a team-owned check sheet for each scored service: public address, DNS name, protocol, test account, a real transaction, owner and last good result. A process or open port is insufficient. Test a DNS answer and domain login on the DC; the real IIS page and backend on the web host; a database query and application action on `cai-db01`; SMTP delivery, IMAP login and webmail on `cai-mail01`; and public NAT through `cai-fw01`. Fill in the exact endpoints and credentials from the live environment. Do not put them in this public repo.

After any update, account change, service recovery or firewall edit, run the applicable user transaction and check the next Quotient result. Keep the Splunk Universal Forwarder and competition CA untouched.
