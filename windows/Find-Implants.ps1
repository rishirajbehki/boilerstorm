#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('CAI-DC01', 'CAI-WEB01')]
    [string]$ExpectedHost,
    [Parameter(Mandatory = $true)]
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ine $ExpectedHost) { throw 'Wrong host for implant hunt.' }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$suspiciousPath = '(?i)(\\Users\\Public\\|\\AppData\\|\\Temp\\|\\ProgramData\\[^\\]+\\|\\Windows\\Tasks\\)'

function Save-Data {
    param([string]$Name, [scriptblock]$Action)
    try {
        (& $Action 2>&1 | Out-String -Width 240) |
            Set-Content -LiteralPath (Join-Path $OutputDir "$Name.txt") -Encoding UTF8
    } catch {
        "ERROR: $($_.Exception.Message)" |
            Set-Content -LiteralPath (Join-Path $OutputDir "$Name.txt") -Encoding UTF8
    }
}

$services = @(Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName)
$services | Export-Csv -LiteralPath (Join-Path $OutputDir 'services.csv') -NoTypeInformation -Encoding UTF8
$exePaths = @($services | Where-Object State -EQ 'Running' | ForEach-Object {
    $raw = [Environment]::ExpandEnvironmentVariables([string]$_.PathName)
    $match = [regex]::Match($raw, '^\s*"([^"]+\.(?:exe|com))"|^\s*([A-Za-z]:\\.*?\.(?:exe|com))', 'IgnoreCase')
    if ($match.Success) {
        if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Groups[2].Value }
    }
} | Sort-Object -Unique)
$binaryRows = foreach ($path in $exePaths) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        try {
            [pscustomobject]@{
                Path=$path
                Exists=$true
                Sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
                SignatureStatus=(Get-AuthenticodeSignature -LiteralPath $path).Status
            }
        } catch {
            [pscustomobject]@{Path=$path; Exists=$true; Sha256=''; SignatureStatus="Unreadable: $($_.Exception.Message)"}
        }
    } else {
        [pscustomobject]@{Path=$path; Exists=$false; Sha256=''; SignatureStatus='Missing'}
    }
}
$binaryRows | Export-Csv -LiteralPath (Join-Path $OutputDir 'service-binaries.csv') -NoTypeInformation -Encoding UTF8
$tasks = @(Get-ScheduledTask | ForEach-Object {
    foreach ($action in $_.Actions) {
        [pscustomobject]@{TaskPath=$_.TaskPath; TaskName=$_.TaskName; State=$_.State; Execute=$action.Execute; Arguments=$action.Arguments}
    }
})
$tasks | Export-Csv -LiteralPath (Join-Path $OutputDir 'tasks.csv') -NoTypeInformation -Encoding UTF8

Save-Data 'triage-paths' {
    'Service paths requiring review (location alone is not proof):'
    $services | Where-Object PathName -Match $suspiciousPath | Format-Table Name, State, PathName -Wrap
    'Task paths requiring review (location alone is not proof):'
    $tasks | Where-Object { $_.Execute -match $suspiciousPath -or $_.Arguments -match $suspiciousPath } |
        Format-Table TaskPath, TaskName, Execute, Arguments -Wrap
}
Save-Data 'wmi-persistence' {
    Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Select-Object Name, Query
    Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | Select-Object Name, CommandLineTemplate
    Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | Select-Object Name, ScriptingEngine, ScriptText
    Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Select-Object Filter, Consumer
}
Save-Data 'run-keys' {
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )) {
        if (Test-Path $key) { $key; Get-ItemProperty $key | Format-List }
    }
}
Save-Data 'startup-folders' {
    foreach ($folder in @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )) {
        if (Test-Path $folder) { Get-ChildItem -LiteralPath $folder -Force | Select-Object FullName, Length, LastWriteTime }
    }
}
Save-Data 'defender' {
    Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, ExclusionPath, ExclusionProcess, ExclusionExtension
    Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 50 InitialDetectionTime, ThreatID, Resources, ActionSuccess
}
Save-Data 'recent-events' {
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688,4697,4720,4728,4732} -MaxEvents 100 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message
}
Save-Data 'connections' {
    Get-NetTCPConnection -State Established,Listen |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
}

if ($ExpectedHost -eq 'CAI-DC01') {
    Save-Data 'ad-privilege' {
        Import-Module ActiveDirectory
        foreach ($group in @('Domain Admins','Enterprise Admins','Administrators','DnsAdmins','Group Policy Creator Owners')) {
            "== $group =="
            Get-ADGroupMember $group -Recursive -ErrorAction Continue | Select-Object Name, SamAccountName, ObjectClass
        }
        Get-ADUser -LDAPFilter '(adminCount=1)' -Properties adminCount,Enabled,PasswordLastSet |
            Select-Object SamAccountName, Enabled, PasswordLastSet
    }
    Save-Data 'gpo-inventory' {
        Import-Module GroupPolicy
        Get-GPO -All | Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime
    }
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Get-GPOReport -All -ReportType Xml -Path (Join-Path $OutputDir 'all-gpos.xml') -ErrorAction Stop
    } catch {
        "ERROR: $($_.Exception.Message)" | Set-Content -LiteralPath (Join-Path $OutputDir 'all-gpos-error.txt')
    }
} else {
    Save-Data 'web-files' {
        Import-Module WebAdministration
        foreach ($site in Get-WebSite) {
            $root = [Environment]::ExpandEnvironmentVariables($site.PhysicalPath)
            "== $($site.Name): $root =="
            if (Test-Path -LiteralPath $root -PathType Container) {
                Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction Continue |
                    Where-Object { $_.Extension -in @('.aspx','.asp','.php','.config','.dll','.exe','.ps1') } |
                    Select-Object -First 3000 FullName, Length, LastWriteTime
            }
        }
    }
}

Write-Host "Read-only implant triage saved to $OutputDir"
Write-Host 'Review alerts against the expected image and app; do not remove a file solely because of its path.'
