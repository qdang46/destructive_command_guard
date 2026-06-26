#!/usr/bin/env pwsh
# MCP stdio server smoke (.7.5). Drives `dcg mcp-server` as a minimal live MCP
# client over stdio and asserts the full handshake works with NO first-read hang
# — the specific Windows risk the bead flags (blocking console-handle reads /
# newline framing over Windows pipes). Runs on windows-latest CI.
#
#   initialize -> notifications/initialized -> tools/list -> tools/call
#
# Every read is timeout-guarded; a hang (the failure mode) is a FAIL, not a wedge.
#
# Usage: pwsh scripts/win_mcp_stdio.ps1 [-Binary PATH] [-Verbose]
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

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $bin
$psi.Arguments = "mcp-server"
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$proc = [System.Diagnostics.Process]::Start($psi)
# Drain stderr asynchronously so the child can never block on a full stderr pipe
# (which would starve stdout and turn a healthy server into a spurious "HANG").
$stderrDrain = $proc.StandardError.ReadToEndAsync()

function Send-Msg($obj) {
    $proc.StandardInput.WriteLine(($obj | ConvertTo-Json -Compress -Depth 10))
    $proc.StandardInput.Flush()
}
# Timeout-guarded readline: returns the line, or $null on HANG (the failure mode).
function Read-Resp([int]$TimeoutMs = 10000) {
    $task = $proc.StandardOutput.ReadLineAsync()
    if ($task.Wait($TimeoutMs)) { return $task.Result } else { return $null }
}

try {
    # 1. initialize — the first read is the critical anti-hang check.
    Send-Msg @{ jsonrpc = "2.0"; id = 1; method = "initialize"; params = @{ protocolVersion = "2024-11-05"; capabilities = @{}; clientInfo = @{ name = "dcg-ci"; version = "1" } } }
    $r1 = Read-Resp
    if ($null -eq $r1) { Fail "initialize: FIRST-READ HANG (no response within timeout) — the Windows-pipe risk" }
    else {
        try {
            $j = $r1 | ConvertFrom-Json
            if ($j.id -eq 1 -and $j.result.protocolVersion) { Pass "initialize OK (no first-read hang; protocolVersion=$($j.result.protocolVersion))" }
            else { Fail "initialize response malformed: $r1" }
        } catch { Fail "initialize response not JSON: $r1" }
    }

    # 2. initialized notification (no response expected).
    Send-Msg @{ jsonrpc = "2.0"; method = "notifications/initialized" }

    # 3. tools/list — assert the 3 dcg tools.
    Send-Msg @{ jsonrpc = "2.0"; id = 2; method = "tools/list" }
    $r2 = Read-Resp
    if ($null -eq $r2) { Fail "tools/list: HANG" }
    else {
        $j2 = $r2 | ConvertFrom-Json
        $names = @($j2.result.tools | ForEach-Object { $_.name })
        $expected = @('check_command', 'scan_file', 'explain_pattern')
        $missing = @($expected | Where-Object { $names -notcontains $_ })
        if ($missing.Count -eq 0) { Pass "tools/list returns all dcg tools: $($names -join ', ')" }
        else { Fail "tools/list missing tool(s): $($missing -join ', ') (got $($names -join ', '))" }
    }

    # 4. tools/call check_command on a DESTRUCTIVE command -> deny.
    $cmd = "git " + "reset " + "--hard"
    Send-Msg @{ jsonrpc = "2.0"; id = 3; method = "tools/call"; params = @{ name = "check_command"; arguments = @{ command = $cmd } } }
    $r3 = Read-Resp
    if ($null -eq $r3) { Fail "tools/call (deny): HANG" }
    else {
        $j3 = $r3 | ConvertFrom-Json
        $text = [string]$j3.result.content[0].text
        if ($text -match '"decision"\s*:\s*"deny"' -and $text -match 'core\.git:reset-hard') { Pass "tools/call check_command flags the destructive command (deny, core.git:reset-hard)" }
        else { Fail "tools/call deny result unexpected: $text" }
    }

    # 5. tools/call check_command on a SAFE command -> allow.
    Send-Msg @{ jsonrpc = "2.0"; id = 4; method = "tools/call"; params = @{ name = "check_command"; arguments = @{ command = "git status" } } }
    $r4 = Read-Resp
    if ($null -eq $r4) { Fail "tools/call (allow): HANG" }
    else {
        $j4 = $r4 | ConvertFrom-Json
        $text = [string]$j4.result.content[0].text
        if ($text -match '"decision"\s*:\s*"allow"' -or $text -match '"allowed"\s*:\s*true') { Pass "tools/call check_command allows a safe command" }
        else { Fail "tools/call allow result unexpected: $text" }
    }
}
finally {
    try { $proc.StandardInput.Close() } catch { }
    try { if (-not $proc.WaitForExit(3000)) { $proc.Kill() } } catch { }
}

Write-Host ""
if ($script:fail -eq 0) { Write-Host "== MCP stdio smoke: ALL CHECKS PASSED ==" -ForegroundColor Green; exit 0 }
else { Write-Host "== MCP stdio smoke: FAILURES ==" -ForegroundColor Red; exit 1 }
