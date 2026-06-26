#!/usr/bin/env pwsh
# E2E harness for `dcg scan --git-diff <range>` (PowerShell port of
# scan_gitdiff_e2e.sh). Builds throwaway git repos, makes commits, and asserts
# exit codes + JSON findings for added/modified/renamed/deleted files and
# multi-commit ranges. Detailed, greppable logging.
#
# Usage: pwsh scripts/scan_gitdiff_e2e.ps1 [-Verbose] [-Binary PATH]
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
    $d = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_gd_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $d | Out-Null
    & git -C $d init --quiet 2>$null | Out-Null
    & git -C $d config user.email "test@example.com" 2>$null | Out-Null
    & git -C $d config user.name "Test User" 2>$null | Out-Null
    Set-Content -Path (Join-Path $d "README.md") -Value "# Test`n"
    & git -C $d add README.md 2>$null | Out-Null
    & git -C $d commit --quiet -m "Initial commit" 2>$null | Out-Null
    $d
}
function Get-Head($repo) { (& git -C $repo rev-parse HEAD 2>$null).Trim() }
function Commit-File($repo, $rel, $content, $msg) {
    $p = Join-Path $repo $rel
    $dir = Split-Path -Parent $p
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Set-Content -Path $p -Value $content
    & git -C $repo add $rel 2>$null | Out-Null
    & git -C $repo commit --quiet -m $msg 2>$null | Out-Null
}
function Get-Json($out) { try { $out | ConvertFrom-Json } catch { $null } }
function Range($base) { "$base..HEAD" }

Log-Section "dcg scan --git-diff E2E"

# Test 1: empty diff (base == HEAD)
Log-Start "Empty diff -> exit 0, 0 findings"
$r = New-Repo
try {
    $base = Get-Head $r
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--format", "json")
    $j = Get-Json $res.Out
    if ($res.Code -eq 0 -and $j.summary.findings_total -eq 0) { Log-Pass "empty diff: exit 0, 0 findings" }
    else { Log-Fail "empty diff" "exit 0, 0 findings" "exit $($res.Code), $($j.summary.findings_total) findings" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 2: added file with destructive command
Log-Start "Added file with destructive command"
$r = New-Repo
try {
    $base = Get-Head $r
    Commit-File $r "deploy.sh" "#!/bin/bash`ngit reset --hard origin/main`necho ok`n" "Add deploy"
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--format", "json", "--fail-on", "error")
    $j = Get-Json $res.Out; $f = $j.findings[0]
    if ($res.Code -ne 0 -and $f.file -eq "deploy.sh" -and ($f.rule_id -match "git|reset")) { Log-Pass "added file flagged (deploy.sh / $($f.rule_id))" }
    else { Log-Fail "added file" "exit!=0, deploy.sh git/reset" "exit $($res.Code), file=$($f.file) rule=$($f.rule_id)" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 3: modified file (added a destructive line)
Log-Start "Modified file -> new destructive line flagged"
$r = New-Repo
try {
    Commit-File $r "build.sh" "#!/bin/bash`necho Building`ncargo build --release`n" "Add safe build"
    $base = Get-Head $r
    Commit-File $r "build.sh" "#!/bin/bash`necho Building`ngit clean -fdx`ncargo build --release`n" "Add aggressive clean"
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--format", "json", "--fail-on", "error")
    $j = Get-Json $res.Out; $f = $j.findings[0]
    if ($res.Code -ne 0 -and $f.file -eq "build.sh" -and $f.extracted_command -match "git clean") { Log-Pass "modified file flagged (build.sh / git clean)" }
    else { Log-Fail "modified file" "exit!=0, build.sh git clean" "exit $($res.Code), file=$($f.file) cmd=$($f.extracted_command)" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 4: renamed file -> finding attributed to the NEW path (not the old one).
# Use a BLOCKING command and rename+modify in one commit so there ARE added lines
# at the new path (a PURE rename has none to scan, which would make this vacuous).
Log-Start "Renamed file -> finding at the new path"
$r = New-Repo
try {
    Commit-File $r "old_script.sh" "#!/bin/bash`necho hi`n" "Add old script (safe)"
    $base = Get-Head $r
    & git -C $r mv old_script.sh new_script.sh 2>$null | Out-Null
    Set-Content -Path (Join-Path $r "new_script.sh") -Value "#!/bin/bash`necho hi`ngit reset --hard`n"
    & git -C $r add new_script.sh 2>$null | Out-Null
    & git -C $r commit --quiet -m "Rename + add destructive line" 2>$null | Out-Null
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--format", "json", "--fail-on", "error")
    $j = Get-Json $res.Out
    $files = @($j.findings | ForEach-Object { $_.file })
    if ($res.Code -ne 0 -and ($files -contains "new_script.sh") -and ($files -notcontains "old_script.sh")) {
        Log-Pass "renamed: finding attributed to the NEW path (new_script.sh), not old_script.sh"
    } else { Log-Fail "renamed file" "exit!=0, new_script.sh (not old)" "exit $($res.Code), files=$($files -join ',')" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 5: deleted file -> handled gracefully (exit 0, no crash)
Log-Start "Deleted file -> handled gracefully"
$r = New-Repo
try {
    Commit-File $r "temp_script.sh" "#!/bin/bash`necho temporary`n" "Add temp script"
    $base = Get-Head $r
    & git -C $r rm temp_script.sh 2>$null | Out-Null
    & git -C $r commit --quiet -m "Remove temp script" 2>$null | Out-Null
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--format", "json")
    if ($res.Code -eq 0) { Log-Pass "deleted file: exit 0 (graceful)" }
    else { Log-Fail "deleted file" "exit 0" "exit $($res.Code)" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 6: data-only added doc -> no error findings
Log-Start "Data-only added doc -> no findings"
$r = New-Repo
try {
    $base = Get-Head $r
    Commit-File $r "SECURITY.md" "# Security`n- ``git reset --hard`` loses changes`n- ``rm -rf /`` deletes everything`n" "Add security docs"
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--format", "json", "--fail-on", "error")
    $j = Get-Json $res.Out
    if ($res.Code -eq 0 -and $j.summary.findings_total -eq 0) { Log-Pass "data-only doc: exit 0, 0 findings" }
    else { Log-Fail "data-only doc" "exit 0, 0 findings" "exit $($res.Code), $($j.summary.findings_total) findings" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 7: deterministic ordering across runs (alphabetical)
Log-Start "Deterministic ordering across runs"
$r = New-Repo
try {
    $base = Get-Head $r
    Set-Content -Path (Join-Path $r "z_last.sh") -Value "#!/bin/bash`ngit reset --hard`n"
    Set-Content -Path (Join-Path $r "a_first.sh") -Value "#!/bin/bash`ngit push --force`n"
    Set-Content -Path (Join-Path $r "m_middle.sh") -Value "#!/bin/bash`ngit stash drop`n"
    & git -C $r add . 2>$null | Out-Null
    & git -C $r commit --quiet -m "Add multiple scripts" 2>$null | Out-Null
    $o1 = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--format", "json")
    $o2 = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--format", "json")
    $f1 = @((Get-Json $o1.Out).findings | ForEach-Object { $_.file })
    $f2 = @((Get-Json $o2.Out).findings | ForEach-Object { $_.file })
    if (($f1 -join ',') -eq ($f2 -join ',') -and $f1.Count -ge 3 -and $f1[0] -eq "a_first.sh") {
        Log-Pass "deterministic + alphabetical: $($f1 -join ',')"
    } else { Log-Fail "ordering" "stable, a_first first" "run1=$($f1 -join ',') run2=$($f2 -join ',')" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 8: --fail-on policy (error non-zero; none zero)
Log-Start "--fail-on policy: error non-zero, none zero"
$r = New-Repo
try {
    $base = Get-Head $r
    Commit-File $r "cleanup.sh" "#!/bin/bash`ngit reset --hard`n" "Add cleanup"
    $a = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--fail-on", "error")
    $b = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--fail-on", "none")
    if ($a.Code -ne 0 -and $b.Code -eq 0) { Log-Pass "--fail-on error=$($a.Code) none=$($b.Code)" }
    else { Log-Fail "--fail-on policy" "error!=0, none=0" "error=$($a.Code), none=$($b.Code)" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

# Test 9: multiple commits in range -> danger in middle commit flagged
Log-Start "Multiple commits in range"
$r = New-Repo
try {
    $base = Get-Head $r
    Commit-File $r "safe.sh" "echo safe`n" "Add safe script"
    Commit-File $r "danger.sh" "#!/bin/bash`ngit push --force`n" "Add danger script"
    Commit-File $r "safe2.sh" "echo more safe`n" "Add another safe script"
    $res = Invoke-Scan -RepoDir $r -ScanArgs @("scan", "--git-diff", (Range $base), "--format", "json", "--fail-on", "error")
    $j = Get-Json $res.Out
    $files = @($j.findings | ForEach-Object { $_.file })
    if ($res.Code -ne 0 -and ($files -contains "danger.sh")) { Log-Pass "multi-commit: danger.sh flagged across range" }
    else { Log-Fail "multiple commits" "exit!=0, danger.sh" "exit $($res.Code), files=$($files -join ',')" }
} finally { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Blue
Write-Host "  Total:  $($script:Total)"
Write-Host "  Passed: $($script:Passed)" -ForegroundColor Green
Write-Host "  Failed: $($script:Failed)" -ForegroundColor $(if ($script:Failed) { 'Red' } else { 'Green' })
if ($script:Failed -gt 0) { exit 1 } else { exit 0 }
