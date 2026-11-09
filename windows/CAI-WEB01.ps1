#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$UpdateSignatures,
    [switch]$DisableSmb1,
    [switch]$RotateAdmin,
    [switch]$BackupServices,
    [switch]$BackupWebContent,
    [switch]$Hunt
)
& (Join-Path $PSScriptRoot 'Invoke-BoilerstormBaseline.ps1') -ExpectedHost CAI-WEB01 -Apply:$Apply -UpdateSignatures:$UpdateSignatures -DisableSmb1:$DisableSmb1 -RotateAdmin:$RotateAdmin -BackupServices:$BackupServices -BackupWebContent:$BackupWebContent -Hunt:$Hunt
if (-not $?) { exit 1 }
