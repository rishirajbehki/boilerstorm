#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('CAI-DC01', 'CAI-WEB01')]
    [string]$ExpectedHost,
    [switch]$Apply,
    [switch]$UpdateSignatures,
    [switch]$DisableSmb1,
    [switch]$DisableDcSpooler,
    [switch]$RotateAdmin,
    [switch]$BackupServices,
    [string]$SystemStateTarget,
    [switch]$BackupWebContent,
    [switch]$Hunt
)

$ErrorActionPreference = 'Stop'
$actualHost = $env:COMPUTERNAME
if ($actualHost -ine $ExpectedHost) {
    throw "Expected $ExpectedHost; this is $actualHost. No changes made."
}
$os = Get-CimInstance Win32_OperatingSystem
$expectedYear = if ($ExpectedHost -eq 'CAI-DC01') { '2025' } else { '2022' }
if ($os.Caption -notmatch "Windows Server $expectedYear") {
    throw "Expected Windows Server $expectedYear; found $($os.Caption). No changes made."
}
if (($UpdateSignatures -or $DisableSmb1 -or $DisableDcSpooler) -and -not $Apply) {
    throw 'Optional changes require -Apply.'
}
if ($DisableDcSpooler -and $ExpectedHost -ne 'CAI-DC01') {
    throw '-DisableDcSpooler is only valid on CAI-DC01.'
}
if ($SystemStateTarget -and $ExpectedHost -ne 'CAI-DC01') {
    throw '-SystemStateTarget is only valid on CAI-DC01.'
}
if ($BackupWebContent -and $ExpectedHost -ne 'CAI-WEB01') {
    throw '-BackupWebContent is only valid on CAI-WEB01.'
}
if (($SystemStateTarget -or $BackupWebContent) -and -not $BackupServices) {
    throw '-SystemStateTarget and -BackupWebContent require -BackupServices.'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$baseDir = Join-Path $env:ProgramData 'Boilerstorm'
New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
if ((Get-Item -LiteralPath $baseDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing a reparse-point output directory.' }
$outDir = Join-Path $baseDir "$actualHost-$stamp-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $outDir -ErrorAction Stop | Out-Null
& icacls.exe $outDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict evidence directory permissions.' }
$processCreationGuid = '{0CCE922B-69AE-11D9-BED3-505054503030}'
$auditSubcategories = @(
    @{ Name='Logon'; Guid='{0CCE9215-69AE-11D9-BED3-505054503030}'; Success=$null; Failure=$true },
    @{ Name='User Account Management'; Guid='{0CCE9235-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true },
    @{ Name='Security Group Management'; Guid='{0CCE9237-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true },
    @{ Name='Audit Policy Change'; Guid='{0CCE922F-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true }
)

function Save-Text {
    param([string]$Name, [scriptblock]$Command)
    try {
        (& $Command 2>&1 | Out-String -Width 240) | Set-Content -LiteralPath (Join-Path $outDir "$Name.txt") -Encoding UTF8
    } catch {
        "ERROR: $($_.Exception.Message)" | Set-Content -LiteralPath (Join-Path $outDir "$Name.txt") -Encoding UTF8
    }
}

function Snapshot {
    param([string]$Prefix)
    Save-Text "$Prefix-host" { hostname; Get-Date -Format o; $os | Select-Object Caption, Version, BuildNumber, LastBootUpTime }
    Save-Text "$Prefix-services" { Get-Service | Sort-Object Name | Select-Object Name, Status, StartType }
    Save-Text "$Prefix-listeners" { Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalAddress, LocalPort, OwningProcess }
    Save-Text "$Prefix-firewall" { Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction }
    Save-Text "$Prefix-local-admins" { Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass, PrincipalSource }
    Save-Text "$Prefix-tasks" { Get-ScheduledTask | Select-Object TaskPath, TaskName, State }
    Save-Text "$Prefix-defender" { Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, AntivirusSignatureVersion, AntivirusSignatureLastUpdated }
    Save-Text "$Prefix-audit" { & auditpol.exe /get "/subcategory:$processCreationGuid" }
    Save-Text "$Prefix-monitor-audit" {
        foreach ($item in $auditSubcategories) { & auditpol.exe /get "/subcategory:$($item.Guid)" }
    }
    if ($ExpectedHost -eq 'CAI-DC01') {
        Save-Text "$Prefix-dc-services" { Get-Service DNS, NTDS, Netlogon | Select-Object Name, Status, StartType }
        Save-Text "$Prefix-dns" { Resolve-DnsName -Server 127.0.0.1 -Name closedai.com -Type SOA }
        Save-Text "$Prefix-domain-admins" { Import-Module ActiveDirectory; Get-ADGroupMember 'Domain Admins' -Recursive | Select-Object Name, SamAccountName, ObjectClass }
        Save-Text "$Prefix-zerologon" {
            'Netlogon vulnerable-connection events (5827/5828 denied, 5830/5831 allowed by exception):'
            Get-WinEvent -FilterHashtable @{LogName='System'; Id=5827,5828,5830,5831} -MaxEvents 50 -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Id, ProviderName, Message
            'Netlogon enforcement registry value (historical; modern updates enforce secure RPC by default):'
            Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name FullSecureChannelProtection -ErrorAction SilentlyContinue |
                Select-Object FullSecureChannelProtection
            'Recent installed Windows updates:'
            Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, InstalledOn, Description
            'Applied computer GPO summary:'
            & gpresult.exe /scope computer /r
        }
    } else {
        Save-Text "$Prefix-iis" { Import-Module WebAdministration; Get-WebSite | Select-Object Name, State, PhysicalPath, Bindings }
        Save-Text "$Prefix-web-service" { Get-Service W3SVC, WAS | Select-Object Name, Status, StartType }
    }
}

function Backup-ServiceState {
    $serviceDir = Join-Path $outDir 'service-backup'
    New-Item -ItemType Directory -Path $serviceDir -Force | Out-Null
    Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
        Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $serviceDir 'services.csv')
    & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services' (Join-Path $serviceDir 'services.reg') /y | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service registry export failed.' }
    if ($ExpectedHost -eq 'CAI-DC01') {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpoDir = Join-Path $serviceDir 'gpo'
        New-Item -ItemType Directory -Path $gpoDir -Force | Out-Null
        Backup-GPO -All -Path $gpoDir -ErrorAction Stop | Out-Null
        Save-Text 'dns-zones' { Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope }
        $dnsDir = Join-Path $serviceDir 'dns-exports'
        New-Item -ItemType Directory -Path $dnsDir -Force | Out-Null
        foreach ($zone in @(Get-DnsServerZone | Where-Object IsDsIntegrated)) {
            $safeName = $zone.ZoneName -replace '[^A-Za-z0-9.-]', '_'
            $exportName = "boilerstorm-$stamp-$safeName.dns"
            Export-DnsServerZone -Name $zone.ZoneName -FileName $exportName -ErrorAction Stop | Out-Null
            $created = Join-Path $env:SystemRoot "System32\dns\$exportName"
            try {
                Copy-Item -LiteralPath $created -Destination (Join-Path $dnsDir $exportName) -ErrorAction Stop
            } finally {
                if (Test-Path -LiteralPath $created) { Remove-Item -LiteralPath $created -Force }
            }
        }
        if ($SystemStateTarget) {
            if ($SystemStateTarget -notmatch '^[A-Za-z]:$') { throw 'System State target must be a separate drive letter such as E:.' }
            if ($SystemStateTarget -ieq $env:SystemDrive) { throw 'System State target must differ from the system drive.' }
            & wbadmin.exe start systemstatebackup "-backuptarget:$SystemStateTarget" -quiet
            if ($LASTEXITCODE -ne 0) { throw 'System State backup failed.' }
        }
    } else {
        $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
        if (-not (Test-Path -LiteralPath $appcmd)) { throw 'IIS AppCmd not found.' }
        $name = "Boilerstorm-$stamp"
        & $appcmd add backup $name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'IIS configuration backup failed.' }
        $iisBackup = Join-Path $env:SystemRoot "System32\inetsrv\backup\$name"
        Copy-Item -LiteralPath $iisBackup -Destination (Join-Path $serviceDir 'iis-config') -Recurse -Force -ErrorAction Stop
        if ($BackupWebContent) {
            Import-Module WebAdministration -ErrorAction Stop
            $sites = @(Get-WebSite)
            for ($i = 0; $i -lt $sites.Count; $i++) {
                $root = [Environment]::ExpandEnvironmentVariables($sites[$i].PhysicalPath)
                if ($root -notmatch '^[A-Za-z]:\\' -or -not (Test-Path -LiteralPath $root -PathType Container)) {
                    throw "Site $($sites[$i].Name) has a missing or nonlocal root: $root"
                }
                $dest = Join-Path $serviceDir "site-$i"
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                $logArg = '/LOG:' + (Join-Path $serviceDir "site-$i-robocopy.log")
                & robocopy.exe $root $dest /E /COPY:DAT /DCOPY:DAT /XJ /R:1 /W:1 /NP $logArg | Out-Null
                if ($LASTEXITCODE -ge 8) { throw "Web content backup failed for $($sites[$i].Name): robocopy $LASTEXITCODE" }
            }
        }
    }
    Write-Host "Service backup complete: $serviceDir"
}

function Run-Required {
    param([string]$Label, [scriptblock]$Action)
    Write-Host "Applying: $Label"
    & $Action
}

function Rotate-AdminPassword {
    $first = Read-Host 'New password for admin' -AsSecureString
    $second = Read-Host 'Repeat new password' -AsSecureString
    $firstText = [System.Net.NetworkCredential]::new('', $first).Password
    $secondText = [System.Net.NetworkCredential]::new('', $second).Password
    if (-not $firstText -or $firstText -cne $secondText) {
        throw 'Passwords were empty or did not match; admin password unchanged.'
    }
    $firstText = $null
    $secondText = $null
    if ($ExpectedHost -eq 'CAI-DC01') {
        Import-Module ActiveDirectory -ErrorAction Stop
        Set-ADAccountPassword -Identity 'admin' -Reset -NewPassword $first -ErrorAction Stop
    } else {
        Set-LocalUser -Name 'admin' -Password $first -ErrorAction Stop
    }
    Write-Host 'Admin password changed. Verify a fresh login before leaving this console.'
}

if ($RotateAdmin) { Rotate-AdminPassword }
Snapshot 'before'
if ($Hunt) {
    & (Join-Path $PSScriptRoot 'Find-Implants.ps1') -ExpectedHost $ExpectedHost -OutputDir (Join-Path $outDir 'hunt')
}
if ($BackupServices) { Backup-ServiceState }
if (-not $Apply) {
    Write-Host "Audit complete: $outDir"
    if ($RotateAdmin) { Write-Host 'Admin password changed; baseline settings unchanged.' }
    else { Write-Host 'No baseline settings changed. Use -Apply only after reviewing the scored checks and console access.' }
    return
}

# Keep a rollback copy before touching audit or Defender settings. Firewall rules
# are exported for incident recovery, but this script does not alter firewall policy.
& netsh.exe advfirewall export (Join-Path $outDir 'firewall-before.wfw') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Firewall backup failed; no baseline settings changed.' }
Save-Text 'before-defender-preferences' { Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, ExclusionPath, ExclusionProcess, ExclusionExtension }
Save-Text 'before-smb' { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature }
Save-Text 'before-commandline-policy' {
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue |
        Select-Object ProcessCreationIncludeCmdLine_Enabled
}
Save-Text 'before-full-audit-policy' { & auditpol.exe /get /category:* }

Run-Required 'Security event log capacity 256 MiB' {
    & wevtutil.exe sl Security /ms:268435456
    if ($LASTEXITCODE -ne 0) { throw 'wevtutil failed' }
}
Run-Required 'process creation success auditing' {
    & auditpol.exe /set "/subcategory:$processCreationGuid" /success:enable
    if ($LASTEXITCODE -ne 0) { throw 'auditpol failed' }
}
Run-Required 'logon and account-change auditing' {
    foreach ($item in $auditSubcategories) {
        $arguments = @('/set', "/subcategory:$($item.Guid)")
        if ($null -ne $item.Success) { $arguments += "/success:$(if ($item.Success) { 'enable' } else { 'disable' })" }
        if ($null -ne $item.Failure) { $arguments += "/failure:$(if ($item.Failure) { 'enable' } else { 'disable' })" }
        & auditpol.exe @arguments
        if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $($item.Name)" }
    }
}
Run-Required 'process command line in 4688 events' {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    New-Item -Path $path -Force | Out-Null
    New-ItemProperty -Path $path -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null
}
Run-Required 'Defender real-time and behavior monitoring' {
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -ErrorAction Stop
}
if ($UpdateSignatures) {
    Run-Required 'Defender signature update' { Update-MpSignature -ErrorAction Stop }
}
if ($DisableSmb1) {
    Run-Required 'SMBv1 server disable' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop }
}
if ($DisableDcSpooler) {
    Run-Required 'DC Print Spooler disable' {
        Stop-Service Spooler -Force -ErrorAction Stop
        Set-Service Spooler -StartupType Disabled -ErrorAction Stop
    }
}
Snapshot 'after'
Write-Host "Completed. Before/after evidence and rollback inputs: $outDir"
Write-Host 'Verify the actual Quotient checks and real user workflow before another change.'
