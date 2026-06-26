#!/usr/bin/env pwsh
# Concurrency / lock-release test for the dcg pending-exception store (.7.3).
# Runs on windows-latest CI (real Windows: pending_exceptions.rs uses
# `lock_exclusive()` -> Windows `LockFileEx`, which is MANDATORY locking — unlike
# Unix advisory `flock` — so off-lock access can raise sharing violations that
# never occur on Unix).
#
# Validates:
#   1. N concurrent blocked commands (each records a pending exception under the
#      exclusive lock) all succeed with NO lock-violation / sharing-violation.
#   2. The lock is released on process exit (a follow-up op proceeds).
#   3. Concurrent `dcg allow-once <code>` (read+write under the lock) also succeed.
#   4. The store lands at DCG_PENDING_EXCEPTIONS_PATH.
#
# Usage: pwsh scripts/win_pending_exception_concurrency.ps1 [-Binary PATH] [-Count N] [-Verbose]
# Exit: 0 pass | 1 fail | 2 setup error.

param([string]$Binary = "", [int]$Count = 24, [switch]$Verbose)
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
$bin = Resolve-Bin
Write-Host "Using binary: $bin"
Write-Host "Concurrent ops: $Count"

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_pendconc_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$store = Join-Path $work "pending_exceptions.json"
$cmd = "git " + "reset " + "--hard HEAD~3"
$inputFile = Join-Path $work "input.json"
([pscustomobject]@{ tool_name = "Bash"; tool_input = [pscustomobject]@{ command = $cmd } } | ConvertTo-Json -Compress) |
    Set-Content -Path $inputFile -Encoding utf8

$saved = $env:DCG_PENDING_EXCEPTIONS_PATH
$env:DCG_PENDING_EXCEPTIONS_PATH = $store

# Patterns that indicate a Windows mandatory-lock failure (or any off-lock access).
$lockViolation = 'lock violation|sharing violation|ERROR_LOCK_VIOLATION|being used by another process|os error 33|Access is denied|os error 5'

function Start-Block {
    param([int]$Idx)
    $e = Join-Path $work "err$Idx.txt"
    Start-Process -FilePath $bin -RedirectStandardInput $inputFile `
        -RedirectStandardOutput (Join-Path $work "out$Idx.txt") -RedirectStandardError $e -PassThru -NoNewWindow
}
function Get-LockViolations {
    $hits = @()
    foreach ($f in (Get-ChildItem -Path $work -Filter 'err*.txt' -ErrorAction SilentlyContinue)) {
        $t = Get-Content -Raw -LiteralPath $f.FullName -ErrorAction SilentlyContinue
        if ($t -and ($t -match $lockViolation)) { $hits += "$($f.Name): $($Matches[0])" }
    }
    $hits
}

try {
    Write-Host ""
    Write-Host "=== Phase 1: $Count concurrent pending-exception writers (exclusive lock) ==="
    $procs = @()
    for ($i = 0; $i -lt $Count; $i++) { $procs += Start-Block -Idx $i }
    foreach ($p in $procs) { [void]$p.WaitForExit(120000) }
    $bad = @($procs | Where-Object { $_.ExitCode -ne 0 })
    if ($bad.Count -eq 0) { Pass "all $Count concurrent blockers exited 0 (each acquired the exclusive lock, recorded, released)" }
    else { Fail "$($bad.Count) blocker process(es) exited non-zero" }

    $viol = Get-LockViolations
    if ($viol.Count -eq 0) { Pass "NO lock-violation / sharing-violation in any process's stderr" }
    else { Fail "lock/sharing violations detected: $($viol -join '; ')" }

    if ((Test-Path $store) -and ((Get-Item $store).Length -gt 0)) { Pass "store written at DCG_PENDING_EXCEPTIONS_PATH (non-empty)" }
    else { Fail "store missing/empty at $store" }

    # The store is append-only NDJSON (one record per line). Each line must be a
    # COMPLETE JSON object — torn / interleaved lines would mean the exclusive lock
    # failed to serialize concurrent appends.
    $code = $null
    $lines = @(Get-Content -LiteralPath $store | Where-Object { $_.Trim() })
    $torn = 0
    foreach ($ln in $lines) {
        try { $o = $ln | ConvertFrom-Json; if (-not $code -and $o.short_code) { $code = $o.short_code } }
        catch { $torn++ }
    }
    if ($torn -eq 0 -and $lines.Count -ge 1) {
        Pass "all $($lines.Count) appended records are complete JSON lines (no torn/interleaved writes under contention); short_code=$code"
    } else { Fail "$torn of $($lines.Count) store lines are torn (concurrent appends not serialized by the lock)" }

    Write-Host ""
    Write-Host "=== Phase 2: lock released on exit (follow-up op proceeds) ==="
    $follow = Start-Block -Idx 8000
    [void]$follow.WaitForExit(30000)
    if ($follow.HasExited -and $follow.ExitCode -eq 0) { Pass "follow-up blocker proceeded (exit 0) — lock was released on prior exits" }
    else { Fail "follow-up blocker did not proceed cleanly (lock not released?) — exit=$($follow.ExitCode)" }

    if ($code) {
        Write-Host ""
        Write-Host "=== Phase 3: concurrent allow-once reads+writes under the lock ==="
        $aps = @()
        for ($i = 0; $i -lt 6; $i++) {
            $aps += Start-Process -FilePath $bin -ArgumentList @('allow-once', $code) `
                -RedirectStandardOutput (Join-Path $work "ao_out$i.txt") -RedirectStandardError (Join-Path $work "ao_err$i.txt") -PassThru -NoNewWindow
        }
        foreach ($p in $aps) { [void]$p.WaitForExit(60000) }
        $aoViol = @()
        foreach ($f in (Get-ChildItem -Path $work -Filter 'ao_err*.txt')) {
            $t = Get-Content -Raw -LiteralPath $f.FullName -ErrorAction SilentlyContinue
            if ($t -and ($t -match $lockViolation)) { $aoViol += $f.Name }
        }
        if ($aoViol.Count -eq 0) { Pass "6 concurrent 'dcg allow-once' ops: no lock/sharing violations" }
        else { Fail "allow-once lock violations: $($aoViol -join ', ')" }
        $aoStuck = @($aps | Where-Object { -not $_.HasExited })
        if ($aoStuck.Count -eq 0) { Pass "all concurrent allow-once ops completed (no deadlock on the exclusive lock)" }
        else { Fail "$($aoStuck.Count) allow-once op(s) did not complete (deadlock?)" }
    }
}
finally {
    $env:DCG_PENDING_EXCEPTIONS_PATH = $saved
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

Write-Host ""
if ($script:fail -eq 0) { Write-Host "== pending-exception concurrency: ALL CHECKS PASSED ==" -ForegroundColor Green; exit 0 }
else { Write-Host "== pending-exception concurrency: FAILURES ==" -ForegroundColor Red; exit 1 }
