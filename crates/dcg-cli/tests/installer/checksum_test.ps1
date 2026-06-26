#!/usr/bin/env pwsh
# Tests install.ps1 checksum hardening (.4.4): Test-Sha256Token (64-hex),
# Get-SiblingUrl, and Resolve-ChecksumToken (per-file .sha256 -> SHA256SUMS.txt ->
# SHA256SUMS fallback, filename row match, junk rejection). Uses local files.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
$HASH = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"  # 64 hex
$OTHER = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

Write-Host "Test 1: Test-Sha256Token"
Check (Test-Sha256Token $HASH) "accepts a 64-hex token"
Check (Test-Sha256Token ($HASH.ToUpper())) "accepts upper-case hex"
Check (-not (Test-Sha256Token "deadbeef")) "rejects too-short"
Check (-not (Test-Sha256Token ($HASH + "0"))) "rejects too-long (65)"
Check (-not (Test-Sha256Token ($HASH.Substring(0,63) + "g"))) "rejects non-hex char"
Check (-not (Test-Sha256Token "")) "rejects empty"

Write-Host "Test 2: Get-SiblingUrl (http + file:// + local path)"
Check ((Get-SiblingUrl -Url "https://h/a/b/dcg.zip" -Leaf "SHA256SUMS.txt") -eq "https://h/a/b/SHA256SUMS.txt") "http sibling"
Check ((Get-SiblingUrl -Url "file:///x/y/dcg.zip" -Leaf "SHA256SUMS") -eq "file:///x/y/SHA256SUMS") "file:// sibling"
Check ((Get-SiblingUrl -Url "/x/y/dcg.zip" -Leaf "S") -eq "/x/y/S") "local-path sibling"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_csum_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp "dcg-x86_64-pc-windows-msvc.zip"
    Set-Content -LiteralPath $zip -Value "ZIP" -NoNewline

    Write-Host "Test 3: per-file .sha256 is the primary path"
    Set-Content -LiteralPath "$zip.sha256" -Value "$HASH  dcg-x86_64-pc-windows-msvc.zip" -NoNewline
    Check ((Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256") -eq $HASH) "resolves from per-file .sha256"
    Remove-Item -LiteralPath "$zip.sha256" -Force

    Write-Host "Test 4: fallback to SHA256SUMS.txt, selecting the matching filename row"
    $manifest = @(
        "$OTHER  some-other-file.tar.xz",
        "$HASH *dcg-x86_64-pc-windows-msvc.zip",   # coreutils binary marker '*'
        "deadbeef  malformed-line"
    ) -join "`n"
    Set-Content -LiteralPath (Join-Path $tmp "SHA256SUMS.txt") -Value $manifest
    # per-file absent -> falls through to the manifest
    Check ((Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256") -eq $HASH) "picks the matching row from SHA256SUMS.txt"
    Remove-Item -LiteralPath (Join-Path $tmp "SHA256SUMS.txt") -Force

    Write-Host "Test 5: fallback to bare SHA256SUMS"
    Set-Content -LiteralPath (Join-Path $tmp "SHA256SUMS") -Value "$HASH  dcg-x86_64-pc-windows-msvc.zip"
    Check ((Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256") -eq $HASH) "picks row from bare SHA256SUMS"
    Remove-Item -LiteralPath (Join-Path $tmp "SHA256SUMS") -Force

    Write-Host "Test 6: junk per-file content is rejected (no valid token -> throws)"
    Set-Content -LiteralPath "$zip.sha256" -Value "not-a-real-hash" -NoNewline
    $threw = $false
    try { Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256" | Out-Null } catch { $threw = $true }
    Check $threw "junk .sha256 with no manifest fallback throws"
} finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All checksum-resolution tests passed." -ForegroundColor Green
