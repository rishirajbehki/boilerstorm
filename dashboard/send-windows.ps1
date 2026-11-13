#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('CAI-DC01','CAI-WEB01')]
    [string]$ExpectedHost,
    [string]$HubUrl,
    [switch]$Init,
    [switch]$Watch
)

$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ine $ExpectedHost) { throw "Expected $ExpectedHost; this is $env:COMPUTERNAME." }
$root = Join-Path $env:ProgramData 'Boilerstorm'
$keyDir = Join-Path $root 'dashboard'
$keyFile = Join-Path $keyDir 'key'
if ($Init) {
    if ((Test-Path -LiteralPath $root) -and ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Refusing a reparse-point output directory.' }
    New-Item -ItemType Directory -Path $keyDir -Force | Out-Null
    if ((Get-Item -LiteralPath $keyDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing a reparse-point key directory.' }
    & icacls.exe $keyDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict key directory permissions.' }
    if (Test-Path -LiteralPath $keyFile) { throw "Key already exists: $keyFile" }
    $secure = Read-Host "Enter the $ExpectedHost dashboard key printed by cai-db01" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    if ($key -cnotmatch '^[A-Za-z0-9_-]{22}$') { throw 'Expected a 22-character dashboard key.' }
    [IO.File]::WriteAllText($keyFile, $key, [Text.Encoding]::ASCII)
    Write-Host "Dashboard key saved: $keyFile"
    return
}
if (-not (Test-Path -LiteralPath $keyFile)) { throw 'Run this script with -Init first.' }
if (-not $HubUrl) { throw 'Provide -HubUrl with the cai-db01 LAN address.' }
$uri = $null
if (-not [Uri]::TryCreate($HubUrl, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'http' -or $uri.AbsolutePath -ne '/ingest') {
    throw 'HubUrl must be an internal HTTP URL ending in /ingest.'
}
$address = $null
if (-not [Net.IPAddress]::TryParse($uri.Host, [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'HubUrl must use a private IPv4 address.'
}
$octets = $address.GetAddressBytes()
if (-not ($octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or ($octets[0] -eq 192 -and $octets[1] -eq 168))) {
    throw 'HubUrl must use a private IPv4 address.'
}
if ((Get-Item -LiteralPath $keyFile).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing a reparse-point key file.' }
$key = [IO.File]::ReadAllText($keyFile, [Text.Encoding]::ASCII)
$services = if ($ExpectedHost -eq 'CAI-DC01') { @('DNS','NTDS','Netlogon') } else { @('WAS','W3SVC') }

function Clean([string]$value, [int]$limit) {
    $value = $value -replace '[\t\r\n]', ' '
    if ($value.Length -gt $limit) { return $value.Substring(0, $limit) }
    return $value
}

function Send-Pass {
    $monitorError = $null
    try { & (Join-Path $PSScriptRoot '..\windows\Monitor-Boilerstorm.ps1') -ExpectedHost $ExpectedHost }
    catch { $monitorError = $_.Exception.Message }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in $services) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        $state = if (-not $service) { 'unknown' } elseif ($service.Status -eq 'Running') { 'active' } else { 'inactive' }
        $lines.Add("service`t$name`t$state")
    }
    if ($monitorError) { $lines.Add("alert`t$(Get-Date -Format o)`tmonitor_failed`tReview locally on host") }
    $alerts = Join-Path $root 'monitor\alerts.jsonl'
    if (Test-Path -LiteralPath $alerts) {
        foreach ($line in @(Get-Content -LiteralPath $alerts -Tail 19 -ErrorAction SilentlyContinue)) {
            try {
                $alert = $line | ConvertFrom-Json
                $lines.Add("alert`t$(Clean $alert.Time 60)`t$(Clean $alert.Kind 80)`tReview locally on host")
            } catch { continue }
        }
    }
    $body = ($lines -join "`n") + "`n"
    $stamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
    $mac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::ASCII.GetBytes($key))
    try { $signature = [BitConverter]::ToString($mac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$stamp`n$body"))).Replace('-','').ToLowerInvariant() }
    finally { $mac.Dispose() }
    $request = [Net.HttpWebRequest][Net.WebRequest]::Create($uri)
    $request.Proxy = $null
    $request.Method = 'POST'
    $request.ContentType = 'text/plain; charset=utf-8'
    $request.Timeout = 5000
    $request.ContentLength = $bytes.Length
    $request.Headers['X-Host'] = $ExpectedHost
    $request.Headers['X-Time'] = $stamp
    $request.Headers['X-Signature'] = $signature
    $stream = $request.GetRequestStream()
    try { $stream.Write($bytes, 0, $bytes.Length) }
    finally { $stream.Dispose() }
    $response = [Net.HttpWebResponse]$request.GetResponse()
    try { if ($response.StatusCode -ne [Net.HttpStatusCode]::NoContent) { throw "Hub returned $($response.StatusCode)" } }
    finally { $response.Dispose() }
    Write-Host "Dashboard report sent: $ExpectedHost"
}

do {
    try { Send-Pass }
    catch { if (-not $Watch) { throw }; Write-Warning "Dashboard send failed: $($_.Exception.Message)" }
    if ($Watch) { Start-Sleep -Seconds 60 }
} while ($Watch)
