#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('CAI-DC01', 'CAI-WEB01')]
    [string]$ExpectedHost,
    [Parameter(Mandatory = $true)]
    [string]$BackupDir,
    [Parameter(Mandatory = $true)]
    [string]$ServiceName
)

$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ine $ExpectedHost) { throw 'Wrong host. No service changed.' }
$allowed = if ($ExpectedHost -eq 'CAI-DC01') {
    @('DNS','NTDS','Netlogon','LanmanServer','WinRM','TermService')
} else {
    @('WAS','W3SVC','LanmanServer','WinRM','TermService')
}
if ($ServiceName -notin $allowed) { throw "Service $ServiceName is not a preselected business dependency for $ExpectedHost." }
$csv = Join-Path $BackupDir 'services.csv'
if (-not (Test-Path -LiteralPath $csv)) { throw "Service backup missing: $csv" }
$baseline = Import-Csv -LiteralPath $csv | Where-Object Name -EQ $ServiceName | Select-Object -First 1
if (-not $baseline -or $baseline.State -ne 'Running') { throw 'Service was not running in the saved snapshot. Review it manually.' }
$current = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if (-not $current) { throw 'Service no longer exists. Restore its package/configuration before starting it.' }
if ($current.PathName -ine $baseline.PathName) { throw 'Service executable path changed since backup. Investigate before starting it.' }
$rawPath = [Environment]::ExpandEnvironmentVariables([string]$current.PathName)
$match = [regex]::Match($rawPath, '^\s*"([^"]+\.exe)"|^\s*([A-Za-z]:\\.*?\.exe)', 'IgnoreCase')
if (-not $match.Success) { throw 'Could not identify the service executable. Review it manually.' }
$exePath = if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Groups[2].Value }
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { throw "Service executable missing: $exePath" }
$signature = Get-AuthenticodeSignature -LiteralPath $exePath
if ($signature.Status -ne 'Valid') { throw "Service executable is not validly signed: $exePath ($($signature.Status))" }
if ($current.StartMode -eq 'Disabled') {
    if ($baseline.StartMode -eq 'Auto') { Set-Service -Name $ServiceName -StartupType Automatic }
    elseif ($baseline.StartMode -eq 'Manual') { Set-Service -Name $ServiceName -StartupType Manual }
    else { throw 'Baseline start mode is not safe to restore automatically.' }
}
Start-Service -Name $ServiceName -ErrorAction Stop
Get-Service -Name $ServiceName | Select-Object Name, Status, StartType
Write-Host 'Check the real user workflow and Quotient result now.'
