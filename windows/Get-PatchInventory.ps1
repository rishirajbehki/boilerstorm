#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('CAI-DC01','CAI-WEB01')]
    [string]$ExpectedHost,
    [switch]$ScanPendingUpdates
)

$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ine $ExpectedHost) { throw "Expected $ExpectedHost; this is $env:COMPUTERNAME." }
$expectedYear = if ($ExpectedHost -eq 'CAI-DC01') { '2025' } else { '2022' }
if ((Get-CimInstance Win32_OperatingSystem).Caption -notmatch "Windows Server $expectedYear") { throw "Expected Windows Server $expectedYear." }
$root = Join-Path $env:ProgramData 'Boilerstorm\patch-inventory'
New-Item -ItemType Directory -Path $root -Force | Out-Null
if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing a reparse-point inventory directory.' }
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict inventory directory permissions.' }
$out = Join-Path $root (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Path $out -ErrorAction Stop | Out-Null
$os = Get-CimInstance Win32_OperatingSystem
$os | Select-Object Caption, Version, BuildNumber, LastBootUpTime |
    Format-List | Out-File -LiteralPath (Join-Path $out 'os.txt') -Encoding UTF8
Get-HotFix | Sort-Object InstalledOn -Descending |
    Select-Object HotFixID, InstalledOn, Description |
    Export-Csv -LiteralPath (Join-Path $out 'installed-hotfixes.csv') -NoTypeInformation -Encoding UTF8
try {
    Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
        AntivirusSignatureVersion, AntivirusSignatureLastUpdated, AMEngineVersion |
        Format-List | Out-File -LiteralPath (Join-Path $out 'defender.txt') -Encoding UTF8
} catch { $_.Exception.Message | Set-Content -LiteralPath (Join-Path $out 'defender-error.txt') }
$reboot = [ordered]@{
    ComponentBasedServicing = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    WindowsUpdate = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
}
$reboot | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'reboot-pending.json') -Encoding UTF8
if ($ScanPendingUpdates) {
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result = $searcher.Search("IsInstalled=0 and Type='Software'")
        $rows = for ($i=0; $i -lt $result.Updates.Count; $i++) {
            $update = $result.Updates.Item($i)
            [pscustomobject]@{ Title=$update.Title; Severity=$update.MsrcSeverity; RebootBehavior=$update.InstallationBehavior.RebootBehavior }
        }
        $rows | Export-Csv -LiteralPath (Join-Path $out 'pending-updates.csv') -NoTypeInformation -Encoding UTF8
    } catch {
        $_.Exception.Message | Set-Content -LiteralPath (Join-Path $out 'pending-updates-error.txt') -Encoding UTF8
        Write-Warning "Pending update scan failed: $($_.Exception.Message)"
    }
}
Write-Host "Patch inventory: $out"
Write-Host 'Review installed build and pending updates before scheduling a reboot or package installation.'
