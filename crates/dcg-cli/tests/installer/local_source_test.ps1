#!/usr/bin/env pwsh
# Tests install.ps1 local-artifact support: Resolve-LocalSourcePath /
# Copy-OrDownloadToFile / Read-OrDownloadText. These let -ArtifactUrl /
# -ChecksumUrl / -SigstoreBundleUrl point at a local file (or file:// URI) so
# the installer runs with no network (hermetic CI smoke / offline install).

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_localsrc_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp 'dcg-x86_64-pc-windows-msvc.zip'
    [System.IO.File]::WriteAllBytes($zip, [byte[]](0x50, 0x4B, 0x03, 0x04, 0x01, 0x02, 0x03))
    $sha = Join-Path $tmp 'dcg-x86_64-pc-windows-msvc.zip.sha256'
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
    Set-Content -LiteralPath $sha -Value "$hash  dcg-x86_64-pc-windows-msvc.zip" -NoNewline
    # A correctly-formed file:// URI for this path.
    $fileUri = ([System.Uri]("file://" + $zip)).AbsoluteUri

    Write-Host "Test 1: Resolve-LocalSourcePath"
    Check ((Resolve-LocalSourcePath -Source $zip) -eq $zip) "bare existing path resolves to itself"
    Check ((Resolve-LocalSourcePath -Source $fileUri) -eq $zip) "file:// URI resolves to its local path"
    Check ($null -eq (Resolve-LocalSourcePath -Source 'https://example.com/x.zip')) "https:// -> null (remote)"
    Check ($null -eq (Resolve-LocalSourcePath -Source 'http://example.com/x.zip')) "http:// -> null (remote)"
    Check ($null -eq (Resolve-LocalSourcePath -Source ($zip + '.nope'))) "nonexistent path -> null"
    Check ($null -eq (Resolve-LocalSourcePath -Source '')) "empty -> null"

    Write-Host "Test 2: Copy-OrDownloadToFile copies a local/file:// source byte-for-byte"
    $out1 = Join-Path $tmp 'out1.zip'
    Copy-OrDownloadToFile -Source $zip -OutFile $out1
    Check (Test-Path $out1) "bare path: output file created"
    $a = [System.IO.File]::ReadAllBytes($zip); $b = [System.IO.File]::ReadAllBytes($out1)
    Check (($a.Length -eq $b.Length) -and (-not (Compare-Object $a $b))) "bare path: bytes identical"
    $out2 = Join-Path $tmp 'out2.zip'
    Copy-OrDownloadToFile -Source $fileUri -OutFile $out2
    $c = [System.IO.File]::ReadAllBytes($out2)
    Check (($a.Length -eq $c.Length) -and (-not (Compare-Object $a $c))) "file:// URI: bytes identical"
    $threw = $false
    try { Copy-OrDownloadToFile -Source ($zip + '.missing') -OutFile (Join-Path $tmp 'x') } catch { $threw = $true }
    Check $threw "missing local source throws (not a silent empty file)"

    Write-Host "Test 3: Read-OrDownloadText reads a local/file:// checksum file"
    $txt = (Read-OrDownloadText -Source $sha).Trim().Split(' ')[0]
    Check ($txt -eq $hash) "bare path: checksum text read + parses to the hash"
    $txt2 = (Read-OrDownloadText -Source (([System.Uri]("file://" + $sha)).AbsoluteUri)).Trim().Split(' ')[0]
    Check ($txt2 -eq $hash) "file:// URI: checksum text read"
    $threw2 = $false
    try { Read-OrDownloadText -Source ($sha + '.missing') | Out-Null } catch { $threw2 = $true }
    Check $threw2 "missing checksum source throws"

    Write-Host "Test 4: default ChecksumUrl convention (`$url.sha256`) resolves locally"
    # The install body sets `$ChecksumUrl = "$url.sha256"` when -Checksum is absent;
    # for a local zip that must point at the co-located .sha256.
    $derived = "$zip.sha256"
    Check ((Resolve-LocalSourcePath -Source $derived) -eq $sha) "<zip>.sha256 resolves to the sidecar checksum"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All local-source tests passed." -ForegroundColor Green
