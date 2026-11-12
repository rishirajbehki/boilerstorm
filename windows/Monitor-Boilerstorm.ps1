#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('CAI-DC01','CAI-WEB01')]
    [string]$ExpectedHost,
    [switch]$Watch,
    [ValidateRange(30,3600)]
    [int]$IntervalSeconds = 60
)

$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ine $ExpectedHost) { throw "Expected $ExpectedHost; this is $env:COMPUTERNAME." }
$expectedYear = if ($ExpectedHost -eq 'CAI-DC01') { '2025' } else { '2022' }
if ((Get-CimInstance Win32_OperatingSystem).Caption -notmatch "Windows Server $expectedYear") { throw "Expected Windows Server $expectedYear." }
$root = Join-Path $env:ProgramData 'Boilerstorm\monitor'
New-Item -ItemType Directory -Path $root -Force | Out-Null
if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing a reparse-point monitor directory.' }
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict monitor directory permissions.' }
$alertsPath = Join-Path $root 'alerts.jsonl'
$baselinePath = Join-Path $root 'critical-services.csv'
$membersPath = Join-Path $root 'privileged-members.txt'
$cursorPath = Join-Path $root 'cursors.json'
$critical = if ($ExpectedHost -eq 'CAI-DC01') { @('DNS','NTDS','Netlogon') } else { @('WAS','W3SVC') }
$eventSets = @(
    @{ Key='Security'; Log='Security'; Ids=@(4625,4697,4702,4719,4720,4722,4726,4728,4732,4756,1102) },
    @{ Key='System'; Log='System'; Ids=@(7045,7031,7034) },
    @{ Key='Defender'; Log='Microsoft-Windows-Windows Defender/Operational'; Ids=@(1116,1117,5007,5009) }
)

function Alert {
    param([string]$Kind, [string]$Detail)
    $row = [ordered]@{ Time=(Get-Date).ToUniversalTime().ToString('o'); Host=$ExpectedHost; Kind=$Kind; Detail=$Detail }
    ($row | ConvertTo-Json -Compress -Depth 4) | Add-Content -LiteralPath $alertsPath -Encoding UTF8
    Write-Host "ALERT ${Kind}: $Detail"
}

function Get-CriticalState {
    foreach ($name in $critical) {
        $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
        if ($service) {
            [pscustomobject]@{ Name=$name; State=$service.State; StartMode=$service.StartMode; PathName=$service.PathName }
        } else {
            [pscustomobject]@{ Name=$name; State='Missing'; StartMode=''; PathName='' }
        }
    }
}

function Get-PrivilegeMembers {
    if ($ExpectedHost -eq 'CAI-DC01') {
        Import-Module ActiveDirectory -ErrorAction Stop
        foreach ($group in @('Domain Admins','Enterprise Admins','Administrators','DnsAdmins')) {
            Get-ADGroupMember -Identity $group -ErrorAction Stop |
                ForEach-Object { "$group`t$($_.SID.Value)`t$($_.SamAccountName)" }
        }
    } else {
        Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
            ForEach-Object { "Administrators`t$($_.SID.Value)`t$($_.Name)" }
    }
}

function Run-Pass {
    $now = Get-Date
    $cursor = if (Test-Path -LiteralPath $cursorPath) {
        Get-Content -LiteralPath $cursorPath -Raw | ConvertFrom-Json
    } else {
        [pscustomobject]@{ LastTime=$now.AddMinutes(-5).ToUniversalTime().ToString('o'); Security=0; System=0; Defender=0 }
    }
    $since = [datetime]::Parse($cursor.LastTime).ToLocalTime().AddSeconds(-10)
    $current = @(Get-CriticalState)
    if (-not (Test-Path -LiteralPath $baselinePath)) {
        $current | Export-Csv -LiteralPath $baselinePath -NoTypeInformation -Encoding UTF8
        Write-Host "Initial service snapshot saved: $baselinePath"
    }
    $baseline = @(Import-Csv -LiteralPath $baselinePath)
    foreach ($service in $current) {
        $previous = $baseline | Where-Object Name -eq $service.Name | Select-Object -First 1
        if ($service.State -ne 'Running') { Alert 'service_down' "$($service.Name): $($service.State)" }
        if ($previous -and ($previous.PathName -ne $service.PathName -or $previous.StartMode -ne $service.StartMode)) {
            Alert 'service_definition_changed' "$($service.Name): startup or executable differs from initial snapshot"
        }
    }
    try {
        $members = @(Get-PrivilegeMembers | Sort-Object -Unique)
        if (Test-Path -LiteralPath $membersPath) {
            $previousMembers = @(Get-Content -LiteralPath $membersPath)
            $difference = @(Compare-Object -ReferenceObject $previousMembers -DifferenceObject $members)
            if ($difference.Count -gt 0) {
                $changePath = Join-Path $root "privileged-members-$($now.ToString('yyyyMMdd-HHmmss')).txt"
                $difference | Out-String -Width 240 | Set-Content -LiteralPath $changePath -Encoding UTF8
                Alert 'privileged_members_changed' "Review $changePath"
            }
        }
        $members | Set-Content -LiteralPath $membersPath -Encoding UTF8
    } catch { Alert 'privileged_members_query_failed' $_.Exception.Message }
    if ($ExpectedHost -eq 'CAI-WEB01') {
        try {
            Import-Module WebAdministration -ErrorAction Stop
            foreach ($site in @(Get-WebSite)) {
                if ($site.State -ne 'Started') { Alert 'iis_site_down' "$($site.Name): $($site.State)" }
            }
        } catch { Alert 'iis_query_failed' $_.Exception.Message }
    } else {
        try {
            Resolve-DnsName -Server 127.0.0.1 -Name closedai.com -Type SOA -ErrorAction Stop | Out-Null
        } catch { Alert 'dns_soa_failed' $_.Exception.Message }
    }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.RealTimeProtectionEnabled -or -not $mp.BehaviorMonitorEnabled) {
            Alert 'defender_disabled' 'Real-time or behavior monitoring is off'
        }
    } catch { Alert 'defender_query_failed' $_.Exception.Message }
    try {
        foreach ($profile in @(Get-NetFirewallProfile -ErrorAction Stop)) {
            if (-not $profile.Enabled) { Alert 'firewall_profile_disabled' $profile.Name }
        }
    } catch { Alert 'firewall_query_failed' $_.Exception.Message }
    foreach ($disk in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
        if ($disk.Size -gt 0 -and ($disk.FreeSpace -lt 2147483648 -or $disk.FreeSpace / $disk.Size -lt 0.10)) {
            Alert 'disk_low' "$($disk.DeviceID): $([math]::Round($disk.FreeSpace / 1GB,1)) GiB free"
        }
    }
    foreach ($set in $eventSets) {
        try {
            $latest = Get-WinEvent -LogName $set.Log -MaxEvents 1 -ErrorAction Stop
            $lastId = [long]($cursor.($set.Key))
            if ($latest.RecordId -lt $lastId) {
                Alert 'event_log_reset' "$($set.Log): record ID fell from $lastId to $($latest.RecordId)"
                $lastId = 0
            }
            $events = @(Get-WinEvent -FilterHashtable @{LogName=$set.Log; Id=$set.Ids; StartTime=$since} -MaxEvents 500 -ErrorAction Stop)
            if ($events.Count -ge 500) { Alert 'event_query_limit' "$($set.Log): 500 matching records; review log directly" }
            foreach ($event in $events | Sort-Object RecordId) {
                if ($event.RecordId -le $lastId) { continue }
                $detail = "$($set.Log) ID $($event.Id), record $($event.RecordId), $($event.TimeCreated.ToString('o')): $($event.Message)"
                if ($detail.Length -gt 600) { $detail = $detail.Substring(0,600) }
                Alert 'security_event' $detail
            }
            $cursor.($set.Key) = [math]::Max($lastId, [long]$latest.RecordId)
        } catch {
            if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') {
                Alert 'event_query_failed' "$($set.Log): $($_.Exception.Message)"
            }
        }
    }
    $cursor.LastTime = $now.ToUniversalTime().ToString('o')
    $temp = "$cursorPath.tmp"
    $cursor | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $cursorPath -Force
    Write-Host "Monitor pass complete: $($now.ToString('o')); alerts: $alertsPath"
}

do {
    Run-Pass
    if ($Watch) { Start-Sleep -Seconds $IntervalSeconds }
} while ($Watch)
