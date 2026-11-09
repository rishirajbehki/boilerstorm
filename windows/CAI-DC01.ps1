#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$UpdateSignatures,
    [switch]$DisableSmb1,
    [switch]$DisableDcSpooler,
    [switch]$RotateAdmin,
    [switch]$BackupServices,
    [string]$SystemStateTarget,
    [switch]$Hunt
)
& (Join-Path $PSScriptRoot 'Invoke-BoilerstormBaseline.ps1') -ExpectedHost CAI-DC01 -Apply:$Apply -UpdateSignatures:$UpdateSignatures -DisableSmb1:$DisableSmb1 -DisableDcSpooler:$DisableDcSpooler -RotateAdmin:$RotateAdmin -BackupServices:$BackupServices -SystemStateTarget $SystemStateTarget -Hunt:$Hunt
if (-not $?) { exit 1 }
