#!/usr/bin/env pwsh
# Tests Assert-ZipLayoutSafe from install.ps1 (zip-slip / path-traversal defense).
# Dot-sources install.ps1 -LoadFunctionsOnly and feeds it crafted archives.

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_zipslip_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null

function New-TestZip([string[]]$EntryNames) {
    $path = Join-Path $tmp ("z_" + [Guid]::NewGuid().ToString('N') + ".zip")
    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create)
    $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $EntryNames) {
            $e = $zip.CreateEntry($name)
            $w = New-Object System.IO.StreamWriter($e.Open())
            $w.Write("x"); $w.Dispose()
        }
    } finally { $zip.Dispose(); $fs.Dispose() }
    $path
}
function ShouldThrow([string]$zip, [string]$why) {
    $threw = $false
    try { Assert-ZipLayoutSafe -ZipPath $zip } catch { $threw = $true }
    Check $threw $why
}
function ShouldPass([string]$zip, [string]$why) {
    $ok = $true
    try { Assert-ZipLayoutSafe -ZipPath $zip } catch { $ok = $false; Write-Host "    (threw: $_)" }
    Check $ok $why
}

try {
    ShouldPass  (New-TestZip @('dcg.exe'))                              "flat archive with dcg.exe is accepted"
    ShouldPass  (New-TestZip @('dcg-x86_64-pc-windows-msvc/dcg.exe'))   "nested dcg.exe is accepted"
    ShouldThrow (New-TestZip @('../evil.exe', 'dcg.exe'))               "rejects a '..' traversal entry"
    ShouldThrow (New-TestZip @('sub/../../evil', 'dcg.exe'))            "rejects an embedded '..' segment"
    ShouldThrow (New-TestZip @('/etc/cron.d/evil', 'dcg.exe'))          "rejects an absolute (/) path"
    ShouldThrow (New-TestZip @('C:\Windows\System32vil.exe', 'dcg.exe')) "rejects a drive-letter path"
    ShouldThrow (New-TestZip @())                                       "rejects an empty archive"
    ShouldThrow (New-TestZip @('README.txt'))                           "rejects an archive missing dcg.exe"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Assert-ZipLayoutSafe tests passed." -ForegroundColor Green
