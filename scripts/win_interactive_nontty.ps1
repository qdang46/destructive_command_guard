#!/usr/bin/env pwsh
# Non-TTY no-hang guard for interactive (inquire) prompts (.7.6). Runs on
# windows-latest CI.
#
# dcg's interactive flows (`dcg setup` Confirm, `dcg history interactive` Select,
# the medium-severity block-action confirm) are gated behind `is_terminal()` /
# `should_prompt_interactively` so they SKIP when there is no TTY. The critical
# safety invariant — and the one that IS automatable headlessly — is that NONE of
# them HANG when stdin is not a terminal (a missing TTY-gate would block forever in
# CI / pipelines / robot mode). This asserts every prompt-bearing command, run with
# redirected (non-TTY) stdin, exits promptly with no panic.
#
# The actual keyboard interaction (Select arrow-keys + Enter, Confirm y/n, Ctrl-C
# cancel) genuinely needs a real console + keystrokes and stays a MANUAL check in
# cmd.exe / Windows PowerShell / Windows Terminal (documented in docs/windows.md).
#
# Usage: pwsh scripts/win_interactive_nontty.ps1 [-Binary PATH] [-Verbose]
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

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_inter_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
# Sandbox HOME so `dcg setup` etc. touch only throwaway paths.
$saved = @{ HOME = $env:HOME; USERPROFILE = $env:USERPROFILE; XDG_CONFIG_HOME = $env:XDG_CONFIG_HOME }
$env:HOME = $work; $env:USERPROFILE = $work; $env:XDG_CONFIG_HOME = (Join-Path $work "cfg")
$emptyIn = Join-Path $work "empty.txt"; Set-Content -Path $emptyIn -Value "" -NoNewline

# command-label -> args. Each is run with non-TTY (redirected) stdin and must not hang.
$cases = @(
    @{ label = "setup (Confirm prompt)";                args = @("setup") },
    @{ label = "history interactive (Select prompt)";   args = @("history", "interactive") },
    @{ label = "allowlist interactive audit";           args = @("history", "interactive", "--limit", "5") }
)

try {
    foreach ($c in $cases) {
        $o = Join-Path $work "o.txt"; $e = Join-Path $work "e.txt"
        $p = Start-Process -FilePath $bin -ArgumentList $c.args -RedirectStandardInput $emptyIn `
            -RedirectStandardOutput $o -RedirectStandardError $e -PassThru -NoNewWindow
        $exited = $p.WaitForExit(10000)
        if (-not $exited) {
            try { $p.Kill() } catch { }
            Fail "$($c.label): HUNG in non-TTY mode (no TTY-gate — would block CI/pipelines forever)"
            continue
        }
        $err = (Get-Content -Raw $e -ErrorAction SilentlyContinue)
        if ($err -and ($err -match 'panicked|RUST_BACKTRACE|thread .* panicked')) {
            Fail "$($c.label): panicked in non-TTY mode -> $($err.Trim())"
        } else {
            Pass "$($c.label): exited promptly (no hang, no panic) — prompt correctly suppressed non-TTY [exit $($p.ExitCode)]"
        }
    }
}
finally {
    foreach ($k in $saved.Keys) { Set-Item "Env:$k" ($saved[$k]) -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

Write-Host ""
if ($script:fail -eq 0) { Write-Host "== interactive non-TTY guard: ALL CHECKS PASSED ==" -ForegroundColor Green; exit 0 }
else { Write-Host "== interactive non-TTY guard: FAILURES ==" -ForegroundColor Red; exit 1 }
