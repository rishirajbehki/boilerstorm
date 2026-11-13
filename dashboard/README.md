# Five-host dashboard

This is a read-only browser view of the existing host monitors. It shows each host's last report, critical service state and recent alert **types**. The full alert details remain on the host. It does not change services, accept commands, query Quotient or replace its scored-service checks.

Run the hub on `cai-db01` inside the competition LAN. It uses Python 3's standard library and keeps its state in a private directory under the current user's home. The host senders use the existing monitors; no data is sent outside the competition network. Reports are HMAC-signed with a different key per host. The LAN traffic is not encrypted, so send only the included status and alert-type summaries.

## Start the hub on `cai-db01`

From the repo root, in a shell belonging to the operator who will keep the hub running:

```sh
python3 dashboard/server.py init
python3 dashboard/server.py serve --bind <cai-db01-LAN-IP>
```

`init` asks for the five host LAN addresses, prints five 22-character host keys **once**, and saves both under `~/.boilerstorm-dashboard/`. Keep these files on `cai-db01`. Manually enter each host's own key at its console; do not put keys or addresses in Git or tickets. `init` refuses to replace existing keys. Replace angle-bracketed examples with the real LAN address before running them. Open `http://<cai-db01-LAN-IP>:8765/` **in a browser on either Windows host**, or another configured team host with a browser. The hub denies page requests from other addresses. If port 8765 is already occupied, stop and review the conflict instead of changing a scored service.

If the page does not load, check `ss -lntp` on `cai-db01` and `Test-NetConnection <cai-db01-LAN-IP> -Port 8765` on the Windows host. Review the local firewall and LAN route before changing any rule; port 8765 must stay off the WAN.

## Start senders

On each Windows host, elevated PowerShell from the repo root:

```powershell
.\dashboard\send-windows.ps1 -ExpectedHost CAI-DC01 -Init
.\dashboard\send-windows.ps1 -ExpectedHost CAI-DC01 -HubUrl http://<cai-db01-LAN-IP>:8765/ingest -Watch
```

Use `CAI-WEB01` instead on the web host. `-Init` stores its key in `C:\ProgramData\Boilerstorm\dashboard\key` with Administrator/System access. Without `-Watch`, one pass runs and exits. The sender runs the existing Windows monitor once per pass, then reports every 60 seconds while the console process stays open.

On each Linux host, as root from the repo root:

```sh
EXPECTED_HOST=cai-db01 sh dashboard/send-unix.sh --init
DASHBOARD_URL=http://<cai-db01-LAN-IP>:8765/ingest EXPECTED_HOST=cai-db01 sh dashboard/send-unix.sh --watch
```

Use `cai-mail01` on Rocky. On OPNsense, use `EXPECTED_HOST=cai-fw01 sh dashboard/send-unix.sh --init` and then run it with `DASHBOARD_URL` and `--watch` as above. The Unix sender uses `curl` plus Python 3 on Linux or PHP CLI on OPNsense. It saves its key in `/root/.boilerstorm-dashboard-key` with mode 0600 and reports every five minutes. Check `command -v curl php` on OPNsense before relying on its sender. A one-pass command omits `--watch`.

The sender continues writing local monitor output when the hub cannot be reached; a failed dashboard send prints an error. Keep the hub and sender processes running during scoring. The page marks a host stale after three minutes for Windows or eleven minutes for Linux/OPNsense. Verify an alert on the host and a scored result in Quotient before acting.

## Rehearsal and limits

On a disposable LAN, run the hub and each sender once. Confirm the expected host appears, simulate a stopped non-scored test service, check the red state, then restore it. Check that a wrong host key is rejected and that closing the sender makes its card stale. The hub accepts reports only from the host's expected LAN IP, with a five-minute clock-skew window; keep competition host clocks synchronized. Do not expose port 8765 to WAN or forward it through OPNsense. The dashboard is advisory if a sender, its host, or the hub is compromised.
