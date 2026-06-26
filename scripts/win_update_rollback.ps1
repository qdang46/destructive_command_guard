#!/usr/bin/env pwsh
# `dcg update --rollback` e2e (.7.2). Runs on windows-latest CI.
#
# Rollback ALWAYS restores the backup over current_exe() — the RUNNING, file-locked
# binary. On Windows that goes through swap_running_executable (rename current to
# <name>.exe.old, copy the backup in, restore-on-failure) — the exact path the bead
# wants validated. (On Unix the same op is a direct fs::copy which Linux refuses
# with ETXTBSY on a running binary; that is the Unix path, not what we validate.)
#
# Hermetic (NO network): we fabricate a backup under data_dir()\dcg\backups and run
# `dcg update --rollback`. Cross-platform parts (backup discovery, metadata parse,
# graceful behavior, binary stays intact) are checked everywhere; the actual
# running-binary swap success is asserted only on Windows.
#
# The real network `dcg update` shells to `powershell -NoProfile -ExecutionPolicy
# Bypass -File install.ps1`; that install path is covered by the install.ps1
# hermetic smoke, and its powershell/ExecutionPolicy requirements are documented in
# docs/windows.md. This script focuses on the rollback half.
#
# Usage: pwsh scripts/win_update_rollback.ps1 [-Binary PATH] [-Verbose]
# Exit: 0 pass | 1 fail | 2 setup error.

param([string]$Binary = "", [switch]$Verbose)
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$RepoRoot = Split-Path -Parent $PSScriptRoot

$script:fail = 0
function Note($m) { Write-Host "  $m" }
function Pass($m) { Write-Host "$([char]0x2713) $m" -ForegroundColor Green }
function Fail($m) { Write-Host "$([char]0x2717) $m" -ForegroundColor Red; $script:fail = 1 }

function Resolve-Bin {
    if ($Binary) { if (Test-Path $Binary) { return (Resolve-Path $Binary).Path } else { Write-Host "binary not found: $Binary" -ForegroundColor Red; exit 2 } }
    $exe = "dcg" + $(if ($env:OS -eq "Windows_NT" -or $IsWindows) { ".exe" } else { "" })
    $onPath = Get-Command $exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    foreach ($p in @("target/release/$exe", "target/debug/$exe")) {
        $full = Join-Path $RepoRoot $p; if (Test-Path $full) { return (Resolve-Path $full).Path }
    }
    Write-Host "dcg binary not found (cargo build?)" -ForegroundColor Red; exit 2
}
$srcBin = Resolve-Bin
$onWindows = ($env:OS -eq "Windows_NT") -or $IsWindows
$exeName = "dcg" + $(if ($onWindows) { ".exe" } else { "" })
Write-Host "Using binary: $srcBin (windows=$onWindows)"

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_rb_" + [Guid]::NewGuid().ToString('N'))
$data = Join-Path $work "data"
$bdir = Join-Path (Join-Path $data "dcg") "backups"
New-Item -ItemType Directory -Path $bdir -Force | Out-Null
$dest = Join-Path $work "bin"; New-Item -ItemType Directory -Path $dest | Out-Null
$destBin = Join-Path $dest $exeName
Copy-Item $srcBin $destBin -Force

# Fabricate a backup of an "older" version (a copy of the same binary so --version
# still works after the swap). data_dir(): %APPDATA% on Windows, $XDG_DATA_HOME (or
# ~/.local/share) on Linux — set both so the sandbox applies on either platform.
$ts = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 100  # culture-independent
$artname = "dcg-0.0.1-$ts"
Copy-Item $srcBin (Join-Path $bdir $artname) -Force
[pscustomobject]@{ version = "0.0.1"; created_at = $ts; original_path = $destBin } |
    ConvertTo-Json -Compress | Set-Content -Path (Join-Path $bdir "$artname.json") -Encoding utf8

$savedAppData = $env:APPDATA; $savedXdg = $env:XDG_DATA_HOME; $savedHome = $env:HOME; $savedUserProfile = $env:USERPROFILE
$env:APPDATA = $data
$env:XDG_DATA_HOME = $data
$env:HOME = $work
$env:USERPROFILE = $work

function Run-Dcg([string[]]$CmdArgs, [string]$Stdin = "") {
    $o = Join-Path $work "o.txt"; $e = Join-Path $work "e.txt"
    $inFile = $null
    if ($Stdin) { $inFile = Join-Path $work "i.txt"; Set-Content -Path $inFile -Value $Stdin -Encoding utf8 }
    $sp = @{ FilePath = $destBin; ArgumentList = $CmdArgs; RedirectStandardOutput = $o; RedirectStandardError = $e; PassThru = $true; NoNewWindow = $true }
    if ($inFile) { $sp.RedirectStandardInput = $inFile }
    $p = Start-Process @sp
    [void]$p.WaitForExit(60000)
    $out = ((Get-Content -Raw $o -ErrorAction SilentlyContinue) + "`n" + (Get-Content -Raw $e -ErrorAction SilentlyContinue))
    [pscustomobject]@{ Code = $p.ExitCode; Out = $out }
}

try {
    Write-Host ""
    Write-Host "=== Phase 1: backup discovery (cross-platform) ==="
    $lv = Run-Dcg @("update", "--list-versions")
    if ($lv.Code -eq 0 -and $lv.Out -match 'v?0\.0\.1') { Pass "fabricated backup discovered by 'update --list-versions' (v0.0.1)" }
    else { Fail "backup not discovered: exit $($lv.Code), out=$($lv.Out.Trim())" }

    Write-Host ""
    Write-Host "=== Phase 2: rollback restores the RUNNING binary ==="
    $rb = Run-Dcg @("update", "--rollback") "y`n"
    if ($onWindows) {
        if ($rb.Code -eq 0 -and $rb.Out -match 'rolled back|Successfully') {
            Pass "Windows: 'update --rollback' replaced the running, file-locked binary (rename-then-copy swap)"
        } else { Fail "Windows rollback failed: exit $($rb.Code), out=$($rb.Out.Trim())" }
        if (Test-Path $destBin) { $v = Run-Dcg @("--version"); if ($v.Code -eq 0) { Pass "rolled-back binary still runs (--version OK)" } else { Fail "rolled-back binary does not run" } }
        else { Fail "binary missing after rollback" }
        $stale = Get-ChildItem -Path $dest -Filter '*.old' -ErrorAction SilentlyContinue
        if (-not $stale) { Pass "no stale <name>.exe.old left behind after a successful swap" } else { Note "NOTE: leftover $($stale.Name) (cleaned on next run)" }
    } else {
        # Unix: fs::copy onto the running binary is refused (ETXTBSY) — this is the
        # Unix path, NOT the validated Windows swap. Assert it fails GRACEFULLY and
        # leaves the binary intact (rollback's restore-on-failure / atomicity).
        if ($rb.Code -ne 0 -and $rb.Out -match 'Text file busy|os error 26|Rollback failed') {
            Pass "Unix: rollback of the running binary fails gracefully (ETXTBSY) — the Windows rename-then-copy path is what CI validates"
        } else { Note "Unix rollback returned exit $($rb.Code) (out=$($rb.Out.Trim().Substring(0,[Math]::Min(120,$rb.Out.Trim().Length))))" }
        $v = Run-Dcg @("--version")
        if ($v.Code -eq 0) { Pass "binary remains intact + runnable after the failed Unix rollback (not corrupted)" }
        else { Fail "binary corrupted after failed rollback" }
    }

    Write-Host ""
    Write-Host "=== Phase 3: rollback with NO backups errors cleanly (no crash) ==="
    Remove-Item -Recurse -Force $bdir -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $bdir -Force | Out-Null
    $nb = Run-Dcg @("update", "--rollback") "y`n"
    if ($nb.Code -ne 0 -and $nb.Out -match 'No backup') { Pass "rollback with no backups -> clean 'No backup versions available' error (no crash)" }
    else { Fail "rollback-no-backup unexpected: exit $($nb.Code), out=$($nb.Out.Trim())" }
}
finally {
    $env:APPDATA = $savedAppData; $env:XDG_DATA_HOME = $savedXdg; $env:HOME = $savedHome; $env:USERPROFILE = $savedUserProfile
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

Write-Host ""
if ($script:fail -eq 0) { Write-Host "== update/rollback e2e: ALL CHECKS PASSED ==" -ForegroundColor Green; exit 0 }
else { Write-Host "== update/rollback e2e: FAILURES ==" -ForegroundColor Red; exit 1 }
