#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$Apply,
    [switch]$UpdateSignatures,
    [switch]$DisableSmb1,
    [switch]$DisableDcSpooler,
    [switch]$RotateAdmin,
    [switch]$BackupServices,
    [string]$SystemStateTarget,
    [switch]$Hunt
)
if ($AuditOnly -and $PSBoundParameters.Count -ne 1) { throw '-AuditOnly cannot be combined with other options.' }
$firstRun = $PSBoundParameters.Count -eq 0
if ($firstRun) {
    $Apply = $true
    $RotateAdmin = $true
    $DisableSmb1 = $true
    $DisableDcSpooler = $true
}
& (Join-Path $PSScriptRoot 'Invoke-BoilerstormBaseline.ps1') -ExpectedHost CAI-DC01 -Apply:$Apply -UpdateSignatures:$UpdateSignatures -DisableSmb1:$DisableSmb1 -DisableDcSpooler:$DisableDcSpooler -RotateAdmin:$RotateAdmin -BackupServices:$BackupServices -SystemStateTarget $SystemStateTarget -Hunt:$Hunt
if (-not $?) { exit 1 }
if ($firstRun) {
    & (Join-Path $PSScriptRoot 'Invoke-BoilerstormBaseline.ps1') -ExpectedHost CAI-DC01 -Hunt -BackupServices
    if (-not $?) { exit 1 }
}
