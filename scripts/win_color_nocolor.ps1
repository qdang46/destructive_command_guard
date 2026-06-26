#!/usr/bin/env pwsh
# NO_COLOR / non-TTY escape-leak guard (.7.4). Runs on windows-latest CI.
#
# The cross-terminal VISUAL check (correct colors render in cmd.exe / Windows
# PowerShell / Windows Terminal) genuinely needs human eyes on real consoles and
# stays a manual step (documented in docs/windows.md). What IS automatable — and
# is the high-risk regression the bead flags (update.rs hand-writes raw `\x1b[`
# escapes that would render literally as `<-[33m` on legacy conhost) — is:
# NO output surface may emit a raw ESC (0x1B) byte when color is disabled.
#
# This asserts ZERO 0x1B bytes across the deny panel, `dcg explain`, and
# `dcg scan` under NO_COLOR=1, DCG_NO_COLOR=1, and the default (non-TTY/redirected)
# context. A regression where any path hand-writes escapes unconditionally fails it.
#
# Usage: pwsh scripts/win_color_nocolor.ps1 [-Binary PATH] [-Verbose]
# Exit: 0 pass | 1 fail | 2 setup error.

param([string]$Binary = "", [switch]$Verbose)
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$RepoRoot = Split-Path -Parent $PSScriptRoot

$script:fail = 0
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

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_color_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$cmd = "git " + "reset " + "--hard HEAD~2"

function Test-NoEsc {
    # NOTE: do NOT name a parameter $Args — it is a PowerShell automatic variable
    # and shadows the passed value, silently running the binary with no args.
    param([string]$Label, [string[]]$CmdArgs = @(), [string]$Stdin = "", [hashtable]$EnvOverrides = @{})
    $o = Join-Path $work "o.bin"; $e = Join-Path $work "e.bin"
    Remove-Item -Force $o, $e -ErrorAction SilentlyContinue
    $saved = @{}
    foreach ($k in $EnvOverrides.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $EnvOverrides[$k]) }
    try {
        $sp = @{ FilePath = $bin; RedirectStandardOutput = $o; RedirectStandardError = $e; PassThru = $true; NoNewWindow = $true }
        # Start-Process rejects an EMPTY -ArgumentList, so only set it when non-empty
        # (the bare-hook case passes no args and reads the deny JSON from stdin).
        if ($CmdArgs.Count -gt 0) { $sp.ArgumentList = $CmdArgs }
        if ($Stdin) { $inFile = Join-Path $work "in.txt"; Set-Content -Path $inFile -Value $Stdin -Encoding utf8 -NoNewline; $sp.RedirectStandardInput = $inFile }
        $p = Start-Process @sp
        [void]$p.WaitForExit(30000)
    } finally { foreach ($k in $EnvOverrides.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) } }
    $bytes = @()
    foreach ($f in @($o, $e)) { if (Test-Path $f) { $bytes += [System.IO.File]::ReadAllBytes($f) } }
    $escCount = @($bytes | Where-Object { $_ -eq 0x1B }).Count
    if ($escCount -eq 0) { Pass "$Label : 0 raw ESC bytes" }
    else { Fail "$Label : $escCount raw ESC (0x1B) byte(s) leaked despite color disabled" }
}

try {
    # A staged file with a destructive command for `dcg scan`.
    $scanFile = Join-Path $work "danger.sh"
    Set-Content -Path $scanFile -Value "#!/bin/bash`n$cmd`n"
    $denyJson = [pscustomobject]@{ tool_name = "Bash"; tool_input = [pscustomobject]@{ command = $cmd } } | ConvertTo-Json -Compress

    foreach ($envName in @('NO_COLOR', 'DCG_NO_COLOR')) {
        Write-Host ""
        Write-Host "=== color disabled via $envName=1 ==="
        Test-NoEsc -Label "deny panel" -Stdin $denyJson -EnvOverrides @{ $envName = '1' }
        Test-NoEsc -Label "explain"    -CmdArgs @('explain', $cmd)              -EnvOverrides @{ $envName = '1' }
        Test-NoEsc -Label "explain -v" -CmdArgs @('explain', '--verbose', $cmd) -EnvOverrides @{ $envName = '1' }
        Test-NoEsc -Label "scan"       -CmdArgs @('scan', $scanFile)            -EnvOverrides @{ $envName = '1' }
    }

    Write-Host ""
    Write-Host "=== default (redirected / non-TTY) — color must auto-disable ==="
    Test-NoEsc -Label "deny panel (piped)" -Stdin $denyJson
    Test-NoEsc -Label "scan (piped)"       -CmdArgs @('scan', $scanFile)
}
finally { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }

Write-Host ""
if ($script:fail -eq 0) { Write-Host "== NO_COLOR / escape-leak guard: ALL CHECKS PASSED ==" -ForegroundColor Green; exit 0 }
else { Write-Host "== NO_COLOR / escape-leak guard: FAILURES ==" -ForegroundColor Red; exit 1 }
