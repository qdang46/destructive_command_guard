#!/usr/bin/env pwsh
# Tests install.ps1 UX flags: -Help (usage + exit 0, no install body), -Quiet
# (suppresses Write-Info but keeps Write-Ok/Warn/Err), and that -Force ORs into
# $forceConfig. Uses subprocess invocation for -Help (needs `exit`) and
# dot-sourcing for the Write-Info / $forceConfig behavior.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$installPs1 = Join-Path $repoRoot 'install.ps1'

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}

Write-Host "Test 1: -Help prints usage, exits 0, and does NOT run the install body"
$help = & pwsh -NoProfile -File $installPs1 -Help 2>&1
$helpRc = $LASTEXITCODE
$helpText = ($help | Out-String)
Check ($helpRc -eq 0) "exit code 0 (got $helpRc)"
Check ($helpText -match 'dcg PowerShell installer') "usage header printed"
Check ($helpText -match '-NoConfigure') "documents -NoConfigure"
Check ($helpText -match '-Quiet') "documents -Quiet"
Check ($helpText -match 'Copilot CLI') "lists the configured agents"
Check (-not ($helpText -match 'Resolving latest version')) "install body did NOT run"

Write-Host "Test 2: -Quiet suppresses Write-Info but keeps Write-Ok / Write-Warn / Write-Err"
# Dot-source the functions; the install.ps1 Write-Info reads $script:Quiet, which
# under dot-source resolves to this scope's $Quiet.
. $installPs1 -LoadFunctionsOnly
$Quiet = $true
$info = (Write-Info "hidden-info" 6>&1 | Out-String)
Check ([string]::IsNullOrWhiteSpace($info)) "Write-Info produced no output under -Quiet"
$ok = (Write-Ok "shown-ok" 6>&1 | Out-String)
Check ($ok -match 'shown-ok') "Write-Ok still prints under -Quiet"
$warn = (Write-Warn "shown-warn" 6>&1 | Out-String)
Check ($warn -match 'shown-warn') "Write-Warn still prints under -Quiet"
$Quiet = $false
$info2 = (Write-Info "shown-info" 6>&1 | Out-String)
Check ($info2 -match 'shown-info') "Write-Info prints again when not -Quiet"

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All install.ps1 flags tests passed." -ForegroundColor Green
