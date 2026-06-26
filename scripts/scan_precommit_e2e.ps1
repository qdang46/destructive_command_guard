#!/usr/bin/env pwsh
# E2E harness for `dcg scan --staged` (PowerShell port of scan_precommit_e2e.sh).
# Drives the scan SUBCOMMAND against throwaway git repos, asserting exit codes
# (--fail-on thresholds) and JSON findings. Detailed, greppable logging.
#
# Usage: pwsh scripts/scan_precommit_e2e.ps1 [-Verbose] [-Binary PATH]
# Exit: 0 all passed | 1 any failed | 2 binary-not-found / git-not-found.

param([switch]$Verbose, [string]$Binary = "")
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$RepoRoot = Split-Path -Parent $PSScriptRoot

$script:Total = 0; $script:Passed = 0; $script:Failed = 0
function Log-Section($t) { Write-Host ""; Write-Host "=== $t ===" -ForegroundColor Blue }
function Log-Start($d) { $script:Total++; if ($Verbose) { Write-Host "[TEST $($script:Total)] $d" -ForegroundColor Cyan } }
function Log-Pass($d) { $script:Passed++; Write-Host "$([char]0x2713) $d" -ForegroundColor Green }
function Log-Fail($d, $e, $a) {
    $script:Failed++; Write-Host "$([char]0x2717) $d" -ForegroundColor Red
    if ($e) { Write-Host "  Expected: $e" -ForegroundColor Yellow; Write-Host "  Actual:   $a" -ForegroundColor Yellow }
}
function Log-Info($m) { if ($Verbose) { Write-Host "  Info: $m" -ForegroundColor Cyan } }

function Resolve-Bin {
    if ($Binary) { if (Test-Path $Binary) { return (Resolve-Path $Binary).Path } else { Write-Host "binary not found: $Binary" -ForegroundColor Red; exit 2 } }
    $exe = "dcg" + $(if ($env:OS -eq "Windows_NT" -or $IsWindows) { ".exe" } else { "" })
    $onPath = Get-Command $exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    foreach ($p in @("target/release/$exe", "target/debug/$exe")) {
        $full = Join-Path $RepoRoot $p
        if (Test-Path $full) { return (Resolve-Path $full).Path }
    }
    Write-Host "dcg binary not found (cargo build?)" -ForegroundColor Red; exit 2
}
$script:Bin = Resolve-Bin
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Host "git not found" -ForegroundColor Red; exit 2 }
Write-Host "Using binary: $script:Bin"

# Run `dcg scan` with $ScanArgs from inside $RepoDir; return clean stdout + exit code.
function Invoke-Scan {
    param([string]$RepoDir, [string[]]$ScanArgs)
    $errFile = [System.IO.Path]::GetTempFileName()
    $prev = (Get-Location).Path
    try {
        Set-Location $RepoDir
        $out = (& $script:Bin @ScanArgs 2>$errFile | Out-String)
        $code = $LASTEXITCODE
    } finally { Set-Location $prev; Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue }
    [pscustomobject]@{ Out = $out; Code = $code }
}
function New-Repo {
    $d = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_scan_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $d | Out-Null
    & git -C $d init --quiet 2>$null | Out-Null
    & git -C $d config user.email "test@example.com" 2>$null | Out-Null
    & git -C $d config user.name "Test User" 2>$null | Out-Null
    Set-Content -Path (Join-Path $d "README.md") -Value "# Test`n"
    & git -C $d add README.md 2>$null | Out-Null
    & git -C $d commit --quiet -m "Initial commit" 2>$null | Out-Null
    $d
}
function Add-File($repo, $rel, $content) {
    $p = Join-Path $repo $rel
    $dir = Split-Path -Parent $p
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Set-Content -Path $p -Value $content
    & git -C $repo add $rel 2>$null | Out-Null
}
function Get-Json($out) { try { $out | ConvertFrom-Json } catch { $null } }

Log-Section "dcg scan --staged E2E"

# Test 1: empty staged -> exit 0, 0 findings
Log-Start "Empty staged returns exit 0 with 0 findings"
$r = New-Repo
try {
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--staged", "--format", "json")
    $j = Get-Json $res.Out
    if ($res.Code -eq 0 -and $j -and $j.summary.findings_total -eq 0) { Log-Pass "empty staged: exit 0, 0 findings" }
    else { Log-Fail "empty staged" "exit 0, 0 findings" "exit $($res.Code), $($j.summary.findings_total) findings" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 2: staged destructive shell script -> non-zero, finding on line 3
Log-Start "Staged destructive shell script -> error finding"
$r = New-Repo
try {
    Add-File $r "dangerous.sh" "#!/bin/bash`n# bad`ngit reset --hard HEAD~5`necho done`n"
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--staged", "--format", "json", "--fail-on", "error")
    $j = Get-Json $res.Out
    $f = if ($j) { $j.findings[0] } else { $null }
    if ($res.Code -ne 0 -and $f -and $f.file -eq "dangerous.sh" -and $f.line -eq 3 -and
        ($f.rule_id -match "git|reset") -and $f.extracted_command -match "git reset") {
        Log-Pass "destructive script: non-zero exit, finding at dangerous.sh:3 ($($f.rule_id))"
    } else { Log-Fail "destructive script" "exit!=0, dangerous.sh:3 git/reset" "exit $($res.Code), file=$($f.file) line=$($f.line) rule=$($f.rule_id)" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 3: data-only mention (README) -> exit 0, 0 findings
Log-Start "Data-only mention -> no findings"
$r = New-Repo
try {
    Add-File $r "DOCS.md" "# Avoid`n- ``git reset --hard`` loses changes`n- ``rm -rf /`` deletes everything`n"
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--staged", "--format", "json", "--fail-on", "error")
    $j = Get-Json $res.Out
    if ($res.Code -eq 0 -and $j.summary.findings_total -eq 0) { Log-Pass "data-only: exit 0, 0 findings" }
    else { Log-Fail "data-only" "exit 0, 0 findings" "exit $($res.Code), $($j.summary.findings_total) findings" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 4: mixed files (safe.sh + Dockerfile) -> finding only from Dockerfile
Log-Start "Mixed files -> finding only from Dockerfile"
$r = New-Repo
try {
    Add-File $r "safe.sh" "#!/bin/bash`necho hi`ngit status`n"
    Add-File $r "Dockerfile" "FROM ubuntu:22.04`nRUN apt-get update`nRUN git reset --hard`n"
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--staged", "--format", "json", "--fail-on", "error")
    $j = Get-Json $res.Out
    $files = @($j.findings | ForEach-Object { $_.file })
    if ($res.Code -ne 0 -and ($files -contains "Dockerfile") -and ($files -notcontains "safe.sh")) {
        Log-Pass "mixed: Dockerfile flagged, safe.sh clean"
    } else { Log-Fail "mixed files" "Dockerfile in, safe.sh out" "exit $($res.Code), files=$($files -join ',')" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 5: --fail-on policy (error -> non-zero; none -> 0)
Log-Start "--fail-on policy: error non-zero, none zero"
$r = New-Repo
try {
    Add-File $r "danger.sh" "#!/bin/bash`ngit reset --hard HEAD~10`n"
    $a = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--staged", "--format", "json", "--fail-on", "error")
    $b = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--staged", "--format", "json", "--fail-on", "none")
    if ($a.Code -ne 0 -and $b.Code -eq 0) { Log-Pass "--fail-on error=$($a.Code) none=$($b.Code)" }
    else { Log-Fail "--fail-on policy" "error!=0, none=0" "error=$($a.Code), none=$($b.Code)" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 6: JSON schema shape
Log-Start "JSON output schema"
$r = New-Repo
try {
    Add-File $r "test.sh" "#!/bin/bash`ngit push --force origin main`n"
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--staged", "--format", "json", "--fail-on", "none")
    $j = Get-Json $res.Out
    $f = if ($j) { $j.findings[0] } else { $null }
    $ok = $j -and ($j.schema_version -ge 1) -and ($null -ne $j.summary) -and ($null -ne $j.summary.files_scanned) -and
          ($null -ne $j.summary.findings_total) -and $f -and ($null -ne $f.file) -and ($null -ne $f.line) -and
          ($null -ne $f.extractor_id) -and ($null -ne $f.extracted_command) -and ($null -ne $f.severity)
    if ($ok) { Log-Pass "schema: schema_version+summary+finding fields present" }
    else { Log-Fail "JSON schema" "all required fields" "schema_version=$($j.schema_version) finding=$($f | ConvertTo-Json -Compress)" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 7: deterministic ordering (a_first before z_last, stable across runs)
Log-Start "Deterministic output ordering"
$r = New-Repo
try {
    Add-File $r "z_last.sh" "#!/bin/bash`nrm -rf /z`n"
    Add-File $r "a_first.sh" "#!/bin/bash`nrm -rf /a`n"
    $o1 = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--staged", "--format", "json", "--fail-on", "none")
    $o2 = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--staged", "--format", "json", "--fail-on", "none")
    $f1 = @((Get-Json $o1.Out).findings | ForEach-Object { $_.file })
    $f2 = @((Get-Json $o2.Out).findings | ForEach-Object { $_.file })
    if (($f1 -join ',') -eq ($f2 -join ',') -and $f1.Count -ge 2 -and $f1[0] -eq "a_first.sh") {
        Log-Pass "deterministic + alphabetical (a_first first): $($f1 -join ',')"
    } else { Log-Fail "ordering" "stable, a_first first" "run1=$($f1 -join ',') run2=$($f2 -join ',')" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 8: GitHub Actions workflow extraction
Log-Start "GitHub Actions workflow run: extraction"
$r = New-Repo
try {
    $wf = "name: CI`non: push`njobs:`n  build:`n    runs-on: ubuntu-latest`n    steps:`n      - run: git reset --hard HEAD~10`n      - run: echo hi`n"
    Add-File $r ".github/workflows/ci.yml" $wf
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--staged", "--format", "json", "--fail-on", "error")
    $j = Get-Json $res.Out
    if ($res.Code -ne 0 -and $j.summary.findings_total -gt 0 -and ($j.findings[0].extractor_id -match "github|actions|yaml|workflow")) {
        Log-Pass "workflow run: flagged (extractor=$($j.findings[0].extractor_id))"
    } else { Log-Fail "workflow extraction" "non-zero + github/actions extractor" "exit $($res.Code), total=$($j.summary.findings_total), extractor=$($j.findings[0].extractor_id)" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Blue
Write-Host "  Total:  $($script:Total)"
Write-Host "  Passed: $($script:Passed)" -ForegroundColor Green
Write-Host "  Failed: $($script:Failed)" -ForegroundColor $(if ($script:Failed) { 'Red' } else { 'Green' })
if ($script:Failed -gt 0) { exit 1 } else { exit 0 }
