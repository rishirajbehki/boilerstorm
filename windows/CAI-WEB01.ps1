#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$Apply,
    [switch]$UpdateSignatures,
    [switch]$DisableSmb1,
    [switch]$RotateAdmin,
    [switch]$BackupServices,
    [switch]$BackupWebContent,
    [switch]$Hunt
)
if ($AuditOnly -and $PSBoundParameters.Count -ne 1) { throw '-AuditOnly cannot be combined with other options.' }
$firstRun = $PSBoundParameters.Count -eq 0
if ($firstRun) {
    $Apply = $true
    $RotateAdmin = $true
    $DisableSmb1 = $true
}
if ($Apply -or $RotateAdmin) { $BackupServices = $true }
& (Join-Path $PSScriptRoot 'Invoke-BoilerstormBaseline.ps1') -ExpectedHost CAI-WEB01 -Apply:$Apply -UpdateSignatures:$UpdateSignatures -DisableSmb1:$DisableSmb1 -RotateAdmin:$RotateAdmin -BackupServices:$BackupServices -BackupWebContent:$BackupWebContent -Hunt:$Hunt
if (-not $?) { exit 1 }
if ($firstRun) {
    & (Join-Path $PSScriptRoot 'Invoke-BoilerstormBaseline.ps1') -ExpectedHost CAI-WEB01 -Hunt
    if (-not $?) { exit 1 }
}
