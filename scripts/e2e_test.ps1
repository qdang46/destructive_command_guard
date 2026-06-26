#!/usr/bin/env pwsh
#
# End-to-End Test Script for dcg (PowerShell port of scripts/e2e_test.sh).
#
# Exercises the dcg hook binary (dcg.exe) with real-world command scenarios,
# asserting BLOCK / ALLOW / WARN / SILENT verdicts with detailed, greppable logging.
# Parity port of the bash suite so Windows CI gets equivalent e2e coverage.
#
# Usage:
#   pwsh scripts/e2e_test.ps1 [-Verbose] [-Binary PATH] [-Json] [-Artifacts DIR] [-Full]
#
# Options:
#   -Verbose      Per-scenario log lines (test IDs, command, expected/actual, timing)
#   -Binary       Path to dcg(.exe) (default: Cargo target dirs, then PATH)
#   -Json         Machine-readable JSON results to stdout (suppresses human logs)
#   -Artifacts    Directory to write failure artifacts (stdout/stderr captures)
#   -Full         Run slow/expensive scenarios (reserved; parity with bash --full)
#   -Help         Show help and exit
#
# Exit codes: 0 all passed | 1 one or more failed | 2 binary-not-found / setup error
#
# Invocation model: the binary IS the hook (no subcommand). We pipe
# {"tool_name":"Bash","tool_input":{"command":"..."}} to STDIN. Unlike the bash
# script (which base64-round-trips to dodge host git-safety hooks), this port
# pipes the JSON directly: the destructive strings live in this file and on the
# child's stdin, never on a shell command line, so no PreToolUse hook inspects them.

param(
    [switch]$Verbose,
    [string]$Binary = "",
    [switch]$Json,
    [string]$Artifacts = "",
    [switch]$Full,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

if ($Help) {
    Write-Host @'
Usage: pwsh scripts/e2e_test.ps1 [-Verbose] [-Binary PATH] [-Json] [-Artifacts DIR] [-Full]

  -Verbose      Detailed per-scenario output (IDs, command, expected/actual, timing)
  -Binary PATH  Path to dcg.exe (default: Cargo target dirs, then PATH)
  -Json         Machine-readable JSON results (suppresses human logs)
  -Artifacts D  Directory for failure artifacts
  -Full         Run slow/expensive scenarios
  -Help         Show this help
'@
    exit 0
}

# UTF-8 + glyphs in the console.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$RepoRoot = Split-Path -Parent $PSScriptRoot

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
$script:TestsTotal = 0
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:CurrentId = ""
$script:CurrentSw = $null
$script:Results = [System.Collections.Generic.List[object]]::new()

# ---------------------------------------------------------------------------
# Logging helpers (suppressed under -Json)
# ---------------------------------------------------------------------------
function Write-Line { param([string]$Text, [string]$Color)
    if ($Json) { return }
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

function Log-Section { param([string]$Title)
    if ($Json) { return }
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Blue
}

function Log-Info { param([string]$Text)
    if ($Verbose -and -not $Json) { Write-Host "  i $Text" -ForegroundColor Cyan }
}

function Log-TestStart { param([string]$Desc)
    $script:TestsTotal++
    $script:CurrentId = "T$($script:TestsTotal)"
    $script:CurrentSw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($Verbose -and -not $Json) { Write-Host "[$($script:CurrentId)] $Desc" -ForegroundColor Cyan }
}

function Record { param([string]$Result, [string]$Desc, [string]$Expected, [string]$Actual)
    $ms = if ($script:CurrentSw) { [int]$script:CurrentSw.Elapsed.TotalMilliseconds } else { 0 }
    $script:Results.Add([pscustomobject]@{
        id = $script:CurrentId; desc = $Desc; result = $Result
        expected = $Expected; actual = $Actual; ms = $ms
    })
    $ms
}

function Log-Pass { param([string]$Desc)
    $script:TestsPassed++
    $ms = Record "pass" $Desc "" ""
    if (-not $Json) {
        if ($Verbose) { Write-Host "$([char]0x2713) $Desc " -ForegroundColor Green -NoNewline; Write-Host "(${ms}ms)" -ForegroundColor Cyan }
        else { Write-Host "$([char]0x2713) $Desc" -ForegroundColor Green }
    }
}

function Log-Fail { param([string]$Desc, [string]$Expected, [string]$Actual)
    $script:TestsFailed++
    $ms = Record "fail" $Desc $Expected $Actual
    if ($Artifacts) {
        if (-not (Test-Path $Artifacts)) { New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null }
        $f = Join-Path $Artifacts "$($script:CurrentId)_failure.txt"
        @("Test ID: $($script:CurrentId)", "Description: $Desc", "Expected: $Expected", "Actual: $Actual",
          "", "--- Raw Output ---", $Actual) | Set-Content -Path $f -Encoding utf8
    }
    if (-not $Json) {
        Write-Host "$([char]0x2717) $Desc " -ForegroundColor Red -NoNewline
        if ($Verbose) { Write-Host "(${ms}ms)" -ForegroundColor Cyan } else { Write-Host "" }
        Write-Host "  Expected: $Expected" -ForegroundColor Yellow
        Write-Host "  Actual:   $Actual" -ForegroundColor Yellow
    }
}

function Log-Skip { param([string]$Desc, [string]$Reason)
    $script:TestsPassed++
    [void](Record "skip" $Desc "" "")
    if (-not $Json) {
        $suffix = if ($Reason) { " ($Reason)" } else { "" }
        Write-Host "$([char]0x2298) SKIPPED: $Desc$suffix" -ForegroundColor Yellow
    }
}

function Get-Truncated { param([string]$S, [int]$Max = 160)
    if ($S.Length -le $Max) { $S } else { $S.Substring(0, $Max) + "..." }
}

# ---------------------------------------------------------------------------
# Binary discovery (+ stale-version guard) — MUST append .exe on Windows.
# ---------------------------------------------------------------------------
function Resolve-DcgBinary {
    if ($Binary) {
        if (-not (Test-Path $Binary)) { Write-Host "Binary not found: $Binary" -ForegroundColor Red; exit 2 }
        return (Resolve-Path $Binary).Path
    }
    $exeName = "dcg" + $(if ($env:OS -eq "Windows_NT" -or $IsWindows) { ".exe" } else { "" })
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($env:CARGO_TARGET_DIR) {
        $root = if ([System.IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) { $env:CARGO_TARGET_DIR } else { Join-Path $RepoRoot $env:CARGO_TARGET_DIR }
        $candidates.Add((Join-Path (Join-Path $root "release") $exeName))
        $candidates.Add((Join-Path (Join-Path $root "debug") $exeName))
    }
    $candidates.Add((Join-Path (Join-Path (Join-Path $RepoRoot "target") "release") $exeName))
    $candidates.Add((Join-Path (Join-Path (Join-Path $RepoRoot "target") "debug") $exeName))
    foreach ($c in $candidates) { if (Test-Path $c) { return (Resolve-Path $c).Path } }
    $onPath = Get-Command $exeName -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    Write-Host "dcg binary not found (built it? cargo build)" -ForegroundColor Red
    exit 2
}

function Assert-BinaryVersionFresh { param([string]$Bin)
    $cargoToml = Join-Path $RepoRoot "Cargo.toml"
    if (-not (Test-Path $cargoToml)) { return }
    $expected = (Select-String -Path $cargoToml -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches.Groups[1].Value
    if (-not $expected) { return }
    $verOut = (& $Bin --version 2>&1 | Out-String).Trim()
    if ($verOut -notmatch [regex]::Escape($expected)) {
        Write-Line "WARNING: binary version ($verOut) != Cargo.toml ($expected); may be STALE. Rebuild for accurate results." "Yellow"
    }
}

# ---------------------------------------------------------------------------
# Invocation: pipe JSON to the binary with per-call env overrides (restored after).
# ---------------------------------------------------------------------------
function Invoke-Dcg { param([string]$Json, [hashtable]$EnvOverrides = @{})
    $saved = @{}
    foreach ($k in $EnvOverrides.Keys) {
        $saved[$k] = [Environment]::GetEnvironmentVariable($k)
        [Environment]::SetEnvironmentVariable($k, $EnvOverrides[$k])
    }
    $errFile = [System.IO.Path]::GetTempFileName()
    try {
        $stdout = ($Json | & $script:Bin 2>$errFile | Out-String)
        $stderr = (Get-Content -Raw -LiteralPath $errFile -ErrorAction SilentlyContinue)
        if ($null -eq $stderr) { $stderr = "" }
    } finally {
        Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
        foreach ($k in $EnvOverrides.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
    }
    [pscustomobject]@{ StdOut = $stdout; StdErr = $stderr }
}

function New-HookJson { param([string]$Command)
    # ConvertTo-Json handles all JSON escaping correctly (quotes, backslashes, newlines).
    [pscustomobject]@{ tool_name = "Bash"; tool_input = [pscustomobject]@{ command = $Command } } |
        ConvertTo-Json -Compress -Depth 5
}

# Base env applied to every scenario: a sandboxed HOME/USERPROFILE/XDG + cleared
# system allowlist (hermetic, like the bash suite).
function Get-BaseEnv {
    @{
        HOME = $script:SandboxHome
        USERPROFILE = $script:SandboxHome
        XDG_CONFIG_HOME = $script:SandboxXdg
        DCG_ALLOWLIST_SYSTEM_PATH = ""
    }
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------
# verdict: 'block' | 'allow' | 'warn' | 'silent'
function Test-Verdict {
    param([string]$Cmd, [string]$Verdict, [string]$Desc, [string]$Packs, [string]$Policy)
    Log-TestStart $Desc
    if ($Verbose -and -not $Json) { Write-Host "  Command: $(Get-Truncated $Cmd)" -ForegroundColor Cyan }
    $env = Get-BaseEnv
    if ($Packs) { $env["DCG_PACKS"] = $Packs }
    if ($Policy) { $env["DCG_POLICY_DEFAULT_MODE"] = $Policy }
    $r = Invoke-Dcg -Json (New-HookJson $Cmd) -EnvOverrides $env
    $out = $r.StdOut; $err = $r.StdErr
    switch ($Verdict) {
        "block" {
            if (($out -match '"permissionDecision"') -and ($out -match '"deny"')) { Log-Pass "BLOCKED: $Desc" }
            else { Log-Fail "Should BLOCK: $Desc" 'JSON with permissionDecision: deny' $(if ([string]::IsNullOrWhiteSpace($out)) { "<empty>" } else { $out.Trim() }) }
        }
        "allow" {
            if ([string]::IsNullOrWhiteSpace($out)) { Log-Pass "ALLOWED: $Desc" }
            else { Log-Fail "Should ALLOW: $Desc" "<empty output>" $out.Trim() }
        }
        "warn" {
            if (($out -match '"ask"') -and ($err -match "dcg WARNING")) { Log-Pass "WARNED: $Desc" }
            else { Log-Fail "Should WARN: $Desc" 'stdout "ask" + stderr "dcg WARNING"' "stdout=$($out.Trim()) stderr=$($err.Trim())" }
        }
        "silent" {
            if ([string]::IsNullOrWhiteSpace($out) -and ($err -notmatch "dcg WARNING")) { Log-Pass "SILENT: $Desc" }
            else { Log-Fail "Should be SILENT: $Desc" "<empty stdout + no warning>" "stdout=$($out.Trim()) stderr=$($err.Trim())" }
        }
        default { Log-Fail "bad verdict '$Verdict'" "valid verdict" $Verdict }
    }
}

function Test-NonBashTool { param([string]$Tool, [string]$Desc)
    Log-TestStart $Desc
    $json = [pscustomobject]@{ tool_name = $Tool; tool_input = [pscustomobject]@{ file_path = "/etc/passwd" } } | ConvertTo-Json -Compress -Depth 5
    $r = Invoke-Dcg -Json $json -EnvOverrides (Get-BaseEnv)
    if ([string]::IsNullOrWhiteSpace($r.StdOut)) { Log-Pass "IGNORED non-Bash tool: $Desc" }
    else { Log-Fail "Should IGNORE tool $Tool" "<empty>" $r.StdOut.Trim() }
}

function Test-MalformedInput { param([string]$Raw, [string]$Desc)
    Log-TestStart $Desc
    $r = Invoke-Dcg -Json $Raw -EnvOverrides (Get-BaseEnv)
    if ([string]::IsNullOrWhiteSpace($r.StdOut)) { Log-Pass "HANDLED malformed: $Desc" }
    else { Log-Fail "Should ALLOW malformed: $Desc" "<empty>" $r.StdOut.Trim() }
}

# Project-allowlist scenario: write .dcg/allowlist.toml in a temp git repo and run
# the binary from that directory so the project allowlist is discovered.
function Test-Allowlist {
    param([string]$Cmd, [string]$Verdict, [string]$Desc, [string]$AllowlistToml, [hashtable]$ExtraEnv = @{})
    Log-TestStart $Desc
    $proj = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_e2e_al_" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $proj -Force | Out-Null
    $prevCwd = (Get-Location).Path
    try {
        if ($AllowlistToml) {
            $dcgDir = Join-Path $proj ".dcg"
            New-Item -ItemType Directory -Path $dcgDir -Force | Out-Null
            Set-Content -Path (Join-Path $dcgDir "allowlist.toml") -Value $AllowlistToml -Encoding utf8
        }
        & git -C $proj init --quiet 2>$null | Out-Null
        Set-Location $proj
        $env = Get-BaseEnv
        foreach ($k in $ExtraEnv.Keys) { $env[$k] = $ExtraEnv[$k] }
        $r = Invoke-Dcg -Json (New-HookJson $Cmd) -EnvOverrides $env
        $out = $r.StdOut
        if ($Verdict -eq "block") {
            if (($out -match '"permissionDecision"') -and ($out -match '"deny"')) { Log-Pass "BLOCKED (allowlist): $Desc" }
            else { Log-Fail "Should BLOCK (allowlist): $Desc" "deny" $(if ([string]::IsNullOrWhiteSpace($out)) { "<empty>" } else { $out.Trim() }) }
        } else {
            if ([string]::IsNullOrWhiteSpace($out)) { Log-Pass "ALLOWED (allowlist): $Desc" }
            else { Log-Fail "Should ALLOW (allowlist): $Desc" "<empty>" $out.Trim() }
        }
    } finally {
        Set-Location $prevCwd
        Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
    }
}

# ===========================================================================
# Setup
# ===========================================================================
$script:Bin = Resolve-DcgBinary
Assert-BinaryVersionFresh $script:Bin
Write-Line "Using binary: $script:Bin" "Cyan"

$script:SandboxRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_e2e_" + [Guid]::NewGuid().ToString("N"))
$script:SandboxHome = Join-Path $script:SandboxRoot "home"
$script:SandboxXdg = Join-Path $script:SandboxRoot "xdg"
New-Item -ItemType Directory -Path $script:SandboxHome -Force | Out-Null
New-Item -ItemType Directory -Path $script:SandboxXdg -Force | Out-Null

try {
    # -----------------------------------------------------------------------
    # Destructive git (BLOCK)
    # -----------------------------------------------------------------------
    Log-Section "Destructive Git (should BLOCK)"
    $destructiveGit = @(
        "git reset --hard", "git reset --hard HEAD~1", "git reset --hard origin/main", "git reset --merge",
        "git checkout -- file.txt", "git checkout -- .", "git checkout HEAD -- file.txt",
        "git restore file.txt", "git restore --worktree file.txt", "git restore -W file.txt",
        "git clean -f", "git clean -df", "git clean -fd",
        "git push --force", "git push -f", "git push origin main --force", "git push --force origin main",
        "git stash clear", '"git" reset --hard', '"/usr/bin/git" reset --hard'
    )
    foreach ($c in $destructiveGit) { Test-Verdict $c "block" $c }

    # -----------------------------------------------------------------------
    # Safe git (ALLOW)
    # -----------------------------------------------------------------------
    Log-Section "Safe Git (should ALLOW)"
    $safeGit = @(
        "git status", "git log", "git diff", "git add .", "git commit -m 'test'", "git push",
        "git push --force-with-lease", "git branch -d feature", "git checkout main", "git checkout -b feature",
        "git restore --staged file.txt", "git clean -n", "git clean --dry-run", "git merge feature",
        "git rebase main", "git reset --soft HEAD~1", "git reset --mixed HEAD", "git reset HEAD"
    )
    foreach ($c in $safeGit) { Test-Verdict $c "allow" $c }

    # -----------------------------------------------------------------------
    # Destructive filesystem (BLOCK) — flag ordering & path-traversal variants
    # -----------------------------------------------------------------------
    Log-Section "Destructive rm (should BLOCK)"
    $destructiveRm = @(
        "rm -rf /", "rm -rf -- /", "rm -rf /etc", "rm -rf /home", "rm -rf ~/", "rm -rf ~/Documents",
        "rm -rf ./build", "rm -rf node_modules", "rm -rf src",
        'rm -rf /tmp/../etc', 'rm -rf /var/tmp/../etc', 'rm -rf $TMPDIR/../etc', 'rm -rf ${TMPDIR}/../etc',
        'rm -rf "$TMPDIR/../etc"', "rm -r -f /tmp/../etc", "rm --recursive --force /tmp/../etc",
        "rm -fr /etc", "rm -Rf /home", "rm -r -f /etc", "rm -f -r /etc",
        "rm --recursive --force /etc", "rm --force --recursive /etc",
        '"rm" -rf /etc', '"/bin/rm" -rf /etc', 'echo hi; "rm" -rf /etc', 'sudo -u root "rm" -rf /etc'
    )
    foreach ($c in $destructiveRm) { Test-Verdict $c "block" $c }

    # -----------------------------------------------------------------------
    # Safe filesystem (ALLOW) — temp-dir rm
    # -----------------------------------------------------------------------
    Log-Section "Safe rm (temp dirs; should ALLOW)"
    $safeRm = @(
        "rm -rf /tmp/build", "rm -rf /tmp/test-dir", "rm -rf /tmp/foo..bar", "rm -rf /var/tmp/cache",
        "rm -fr /tmp/stuff", "rm -Rf /tmp/more", "rm -r -f /tmp/test", "rm -f -r /tmp/test",
        "rm --recursive --force /tmp/test", "rm --force --recursive /tmp/test",
        'rm -rf $TMPDIR/test', 'rm -rf ${TMPDIR}/test', 'rm -rf "$TMPDIR/test"',
        "rm file.txt", "rm -f file.txt", "rm -r directory", "rm -i file.txt"
    )
    foreach ($c in $safeRm) { Test-Verdict $c "allow" $c }

    # -----------------------------------------------------------------------
    # Non-git/rm quick-reject (ALLOW)
    # -----------------------------------------------------------------------
    Log-Section "Quick-reject non-destructive (should ALLOW)"
    $quickReject = @(
        "ls -la", "cat file.txt", "echo 'hello world'", "cargo build", "cargo test", "npm install",
        "python script.py", "node app.js", "docker ps", "kubectl get pods", "make all", "curl https://example.com"
    )
    foreach ($c in $quickReject) { Test-Verdict $c "allow" $c }

    # -----------------------------------------------------------------------
    # Absolute-path binaries
    # -----------------------------------------------------------------------
    Log-Section "Absolute-path binaries"
    Test-Verdict "/usr/bin/git reset --hard" "block" "/usr/bin/git reset --hard"
    Test-Verdict "/usr/local/bin/git checkout -- ." "block" "/usr/local/bin/git checkout -- ."
    Test-Verdict "/bin/rm -rf /etc" "block" "/bin/rm -rf /etc"
    Test-Verdict "/usr/bin/rm -rf /home" "block" "/usr/bin/rm -rf /home"
    Test-Verdict "/usr/bin/git checkout -b feature" "allow" "/usr/bin/git checkout -b feature"
    Test-Verdict "/bin/rm -rf /tmp/cache" "allow" "/bin/rm -rf /tmp/cache"
    Test-Verdict "/usr/bin/git status" "allow" "/usr/bin/git status"

    # -----------------------------------------------------------------------
    # Edge cases (arg-context git, sudo prefixes, quoted subcommands, heredoc)
    # -----------------------------------------------------------------------
    Log-Section "Edge cases"
    Test-Verdict "git add /usr/bin/something" "allow" "git in arg path is allowed"
    Test-Verdict "cat .gitignore" "allow" "'git' in filename"
    Test-Verdict "ls .git" "allow" "'git' in path"
    Test-Verdict "sudo rm -rf /" "block" "sudo + destructive rm"
    Test-Verdict "sudo git reset --hard" "block" "sudo + git reset --hard"
    Test-Verdict 'git "reset" --hard' "block" "quoted subcommand"
    Test-Verdict 'sudo "/bin/git" reset --hard' "block" "quoted binary path + sudo"

    # -----------------------------------------------------------------------
    # Non-Bash tools (IGNORED)
    # -----------------------------------------------------------------------
    Log-Section "Non-Bash tools (should be IGNORED)"
    foreach ($t in @("Read", "Write", "Edit", "Grep", "Glob")) { Test-NonBashTool $t "tool=$t ignored" }

    # -----------------------------------------------------------------------
    # Malformed input (ALLOW / fail-open)
    # -----------------------------------------------------------------------
    Log-Section "Malformed input (fail-open ALLOW)"
    Test-MalformedInput "" "empty input"
    Test-MalformedInput "not json" "plain text"
    Test-MalformedInput "{}" "empty object"
    Test-MalformedInput '{"tool_name":"Bash"}' "missing tool_input"
    Test-MalformedInput '{"tool_name":"Bash","tool_input":{}}' "missing command"
    Test-MalformedInput '{"tool_name":"Bash","tool_input":{"command":""}}' "empty command"
    Test-MalformedInput '{"tool_name":"Bash","tool_input":{"command":123}}' "command non-string"
    Test-MalformedInput '{"invalid json' "invalid JSON syntax"

    # -----------------------------------------------------------------------
    # Default severity (Medium -> WARN by default; no policy override)
    # -----------------------------------------------------------------------
    Log-Section "Default severity (Medium -> WARN)"
    Test-Verdict "git branch -D feature" "warn" "git branch -D (default warn)"
    Test-Verdict "git stash drop" "warn" "git stash drop (default warn)"
    Test-Verdict "git stash drop stash@{0}" "warn" "git stash drop <ref> (default warn)"

    # -----------------------------------------------------------------------
    # Policy override (deny/warn/log); Critical always blocks
    # -----------------------------------------------------------------------
    Log-Section "Policy override modes"
    Test-Verdict "git branch -D feature" "warn"   "branch -D respects policy=warn" $null "warn"
    Test-Verdict "git branch -D feature" "silent" "branch -D respects policy=log (silent)" $null "log"
    Test-Verdict "git reset --hard" "block" "Critical blocks even under policy=warn" $null "warn"
    Test-Verdict "rm -rf -- /" "block" "Critical rm blocks even under policy=warn" $null "warn"

    # -----------------------------------------------------------------------
    # Heredoc / inline-script extraction (Tier 1-3)
    # -----------------------------------------------------------------------
    Log-Section "Heredoc / inline script"
    Test-Verdict "node <<EOF`nconst fs = require('fs');`nfs.rmSync('/etc', { recursive: true });`nEOF`n" "block" "node heredoc rmSync /etc"
    Test-Verdict "python3 <<EOF`nimport shutil`nshutil.rmtree('/tmp/test')`nEOF`n" "block" "python3 heredoc shutil.rmtree (embedded code always blocked)"
    Test-Verdict "bash <<EOF`nrm -rf /etc`nEOF`n" "block" "bash heredoc rm -rf /etc"
    Test-Verdict "node <<EOF`nconsole.log('hello');`nEOF`n" "allow" "node heredoc safe"
    Test-Verdict 'bash -c "rm -rf /"' "block" "bash -c execution context"
    Test-Verdict "python -c `"import os; os.system('rm -rf /')`"" "block" "python -c execution context"
    Test-Verdict 'echo $(rm -rf /home/user)' "block" "command substitution"

    # -----------------------------------------------------------------------
    # Execution-context vs data-context regression
    # -----------------------------------------------------------------------
    Log-Section "Data vs execution context"
    Test-Verdict 'bd create --description="This pattern blocks rm -rf"' "allow" "rm -rf inside --description (data)"
    Test-Verdict 'git commit -m "Fix git push --force detection"' "allow" "git push --force in commit message (data)"
    Test-Verdict 'echo "example: kubectl delete namespace prod"' "allow" "destructive string in echo arg (data)"
    Test-Verdict 'rg -n "rm -rf" src/main.rs' "allow" "rm -rf as ripgrep pattern (data)"
    Test-Verdict 'sudo git commit -m "Fix rm -rf detection"' "allow" "sudo + data context commit message"
    Test-Verdict 'FOO=1 git commit -m "Fix rm -rf detection"' "allow" "env assignment + data context"
    Test-Verdict 'sudo bash -c "rm -rf /"' "block" "sudo + execution context"
    Test-Verdict 'env FOO=1 bash -c "rm -rf /"' "block" "env VAR + execution context"

    # -----------------------------------------------------------------------
    # Non-core packs (enabled via DCG_PACKS)
    # -----------------------------------------------------------------------
    Log-Section "Non-core packs (DCG_PACKS)"
    $packScenarios = @(
        @{ p = "containers.docker"; c = "docker system prune"; v = "block" },
        @{ p = "containers.docker"; c = "docker volume prune"; v = "block" },
        @{ p = "containers.docker"; c = "docker ps"; v = "allow" },
        @{ p = "kubernetes.kubectl"; c = "kubectl delete namespace production"; v = "block" },
        @{ p = "kubernetes.kubectl"; c = "kubectl drain node-1"; v = "block" },
        @{ p = "kubernetes.kubectl"; c = "kubectl get pods"; v = "allow" },
        @{ p = "storage.s3"; c = "aws s3 rb s3://bucket --force"; v = "block" },
        @{ p = "storage.s3"; c = "aws s3 rm s3://bucket --recursive"; v = "block" },
        @{ p = "storage.s3"; c = "aws s3 rm s3://bucket --recursive --dryrun"; v = "allow" },
        @{ p = "storage.s3"; c = "aws s3 ls s3://bucket"; v = "allow" },
        @{ p = "cloud.aws"; c = "aws ec2 terminate-instances --instance-ids i-123 --dry-run"; v = "allow" },
        @{ p = "cloud.aws"; c = "aws ec2 terminate-instances --instance-ids i-123 --dry-run=false"; v = "block" },
        @{ p = "cloud.aws"; c = "aws cloudformation delete-stack --stack-name prod --dry-run"; v = "block" },
        @{ p = "cloud.azure"; c = "az group delete --name prod --what-if"; v = "block" },
        @{ p = "cloud.azure"; c = "az deployment group what-if --resource-group rg --template-file main.bicep"; v = "allow" },
        @{ p = "remote.rsync"; c = "rsync --delete src/ dest/"; v = "block" },
        @{ p = "remote.rsync"; c = "rsync --list-only src/ dest/"; v = "allow" },
        @{ p = "remote.scp"; c = "scp -r ./data user@host:/"; v = "block" },
        @{ p = "remote.scp"; c = "scp user@host:/etc/hosts ."; v = "allow" },
        @{ p = "database.postgresql"; c = "psql -c 'DROP DATABASE production;'"; v = "block" },
        @{ p = "database.postgresql"; c = "psql -c 'TRUNCATE TABLE users RESTART IDENTITY;'"; v = "block" },
        @{ p = "database.postgresql"; c = "psql -c 'SELECT 1;'"; v = "allow" },
        @{ p = "database.sqlite"; c = "sqlite3 my.db 'DROP TABLE IF EXISTS users;'"; v = "block" },
        @{ p = "database.sqlite"; c = "sqlite3 my.db 'SELECT 1;'"; v = "allow" },
        @{ p = "database.redis"; c = "redis-cli FLUSHALL"; v = "block" },
        @{ p = "database.redis"; c = "redis-cli GET key"; v = "allow" },
        @{ p = "infrastructure.terraform"; c = "terraform destroy"; v = "block" },
        @{ p = "infrastructure.terraform"; c = "terraform plan"; v = "allow" },
        @{ p = "infrastructure.ansible"; c = "ansible-playbook --diff -i production deploy.yml"; v = "block" },
        @{ p = "infrastructure.ansible"; c = "ansible-playbook --check --diff -i production deploy.yml"; v = "allow" },
        @{ p = "cicd.github_actions"; c = "gh secret delete FOO"; v = "block" },
        @{ p = "cicd.github_actions"; c = "gh secret list"; v = "allow" },
        @{ p = "platform.gitlab"; c = "glab repo delete my/group"; v = "block" },
        @{ p = "platform.gitlab"; c = "glab repo list"; v = "allow" },
        @{ p = "dns.route53"; c = "aws route53 delete-hosted-zone --id Z123"; v = "block" },
        @{ p = "dns.route53"; c = "aws route53 list-hosted-zones"; v = "allow" },
        @{ p = "messaging.kafka"; c = "kafka-topics --bootstrap-server localhost:9092 --list --delete --topic orders"; v = "block" },
        @{ p = "messaging.kafka"; c = "kafka-topics --bootstrap-server localhost:9092 --list"; v = "allow" }
    )
    foreach ($s in $packScenarios) { Test-Verdict $s.c $s.v "[$($s.p)] $($s.c)" $s.p }
    # Multiple packs + core-only negative
    Test-Verdict "docker system prune" "block" "multi-pack: docker prune" "containers.docker,kubernetes.kubectl"
    Test-Verdict "kubectl delete namespace foo" "block" "multi-pack: kubectl delete" "containers.docker,kubernetes.kubectl"
    Test-Verdict "docker system prune" "allow" "core-only: docker prune allowed"
    Test-Verdict "kubectl delete namespace foo" "allow" "core-only: kubectl delete allowed"

    # -----------------------------------------------------------------------
    # Windows-native packs — comprehensive coverage (.9.11). Every destructive
    # Windows rule (cmd + PowerShell) gets a positive; every safe form a negative.
    # All windows packs enabled together (they are default-ON on real Windows).
    # -----------------------------------------------------------------------
    Log-Section "Windows-native packs (positive: every destructive rule)"
    $winAll = "core,windows.filesystem,windows.system,windows.misc,windows.powershell"
    $winBlock = @(
        # cmd.exe verbs
        "del /s /q C:\src", "rd /s /q C:\src", "rmdir /s /q C:\src", "format C: /q",
        "reg delete HKLM\Software\Foo /f", "net user attacker /delete", "robocopy C:\src C:\dst /MIR",
        "sc delete MyService", "cipher /w:C:\",
        "bcdedit /delete {current}", "vssadmin delete shadows /all /quiet", "wmic shadowcopy delete",
        "wsl --unregister Ubuntu", "diskpart /s clean.txt",
        # PowerShell cmdlets + aliases
        "Remove-Item -Recurse -Force C:\src", "Clear-Content C:\important.txt",
        "Clear-Disk -Number 1 -RemoveData", "Format-Volume -DriveLetter D",
        "Remove-Partition -DriveLetter D", "Initialize-Disk -Number 1", "Disable-ComputerRestore C:\",
        "Remove-VM -Name Prod",
        "Remove-Item HKLM:\Software\Foo", "Remove-ItemProperty -Path HKLM:\Foo -Name Bar",
        "Remove-LocalUser -Name attacker"
    )
    foreach ($c in $winBlock) { Test-Verdict $c "block" "win: $c" $winAll }

    # Reversible / less-catastrophic verbs WARN (medium) rather than block.
    $winWarn = @(
        "schtasks /delete /tn MyTask /f", "Clear-RecycleBin -Force", "Stop-Computer -Force",
        "Remove-AppxPackage Microsoft.Foo", "Remove-PSDrive -Name X",
        'Unregister-ScheduledTask -TaskName Foo -Confirm:$false'
    )
    foreach ($c in $winWarn) { Test-Verdict $c "warn" "win-warn: $c" $winAll }

    Log-Section "Windows-native packs (wrapped: cmd /c|/k, iex, -EncodedCommand)"
    Test-Verdict 'cmd /c "del /s /q C:\src"' "block" "wrapped: cmd /c del" $winAll
    Test-Verdict 'cmd /k "format C: /q"' "block" "wrapped: cmd /k format" $winAll
    Test-Verdict 'cmd /s /c "rd /s /q C:\Windows"' "block" "wrapped: cmd /s /c rd" $winAll
    Test-Verdict 'powershell -Command "Remove-Item -Recurse -Force C:\src"' "block" "wrapped: powershell -Command" $winAll
    Test-Verdict "pwsh -c 'rd /s /q C:\src'" "block" "wrapped: pwsh -c rd" $winAll
    Test-Verdict 'iex "Remove-Item -Recurse -Force C:\src"' "block" "wrapped: iex" $winAll
    Test-Verdict 'Invoke-Expression "rd /s /q C:\src"' "block" "wrapped: Invoke-Expression" $winAll
    Test-Verdict 'powershell -EncodedCommand UgBlAG0AbwB2AGUALQBJAHQAZQBtACAALQBSAGUAYwB1AHIAcwBlACAALQBGAG8AcgBjAGUAIABDADoAXABzAHIAYwA=' "block" "wrapped: -EncodedCommand" $winAll
    Test-Verdict 'powershell -enc UgBlAG0AbwB2AGUALQBJAHQAZQBtACAALQBSAGUAYwB1AHIAcwBlACAALQBGAG8AcgBjAGUAIABDADoAXABzAHIAYwA=' "block" "wrapped: -enc abbreviation" $winAll
    # value-taking flags before the encoded/command flag (canonical obfuscation)
    Test-Verdict 'powershell -ExecutionPolicy Bypass -EncodedCommand UgBlAG0AbwB2AGUALQBJAHQAZQBtACAALQBSAGUAYwB1AHIAcwBlACAALQBGAG8AcgBjAGUAIABDADoAXABzAHIAYwA=' "block" "wrapped: -ExecutionPolicy Bypass -EncodedCommand" $winAll
    Test-Verdict 'powershell -ExecutionPolicy Bypass -Command "Remove-Item -Recurse -Force C:\src"' "block" "wrapped: -ExecutionPolicy Bypass -Command" $winAll

    Log-Section "Windows-native packs (negative: safe forms + benign)"
    $winAllow = @(
        "del /s /q %TEMP%\foo", "del /?", "Remove-Item -Recurse -Force C:\src -WhatIf",
        "Format-Volume -DriveLetter D -WhatIf", "vssadmin list shadows", "reg query HKLM\Software\Foo",
        "sc query MyService", "schtasks /query", "wsl --list",
        "Get-ChildItem C:\", "New-Item foo.txt", "dir C:\", "copy a.txt b.txt"
    )
    foreach ($c in $winAllow) { Test-Verdict $c "allow" "win-safe: $c" $winAll }
    # Printed-not-executed: destructive text inside a <# #> block comment / quoted data.
    Test-Verdict 'Write-Output <# Remove-Item -Recurse -Force C:\src #>' "allow" "win: <# #> block comment not blocked" $winAll
    Test-Verdict "echo 'del /s /q C:\src'" "allow" "win: quoted del is data" $winAll

    # -----------------------------------------------------------------------
    # Project allowlist (TOML in .dcg/allowlist.toml)
    # -----------------------------------------------------------------------
    Log-Section "Project allowlist"
    Test-Allowlist "git reset --hard" "block" "baseline (no allowlist)" ""
    Test-Allowlist "git reset --hard" "allow" "rule match overrides deny" @"
[[allow]]
rule = "core.git:reset-hard"
reason = "Allowed for E2E testing"
added_by = "e2e_test.ps1"
"@
    Test-Allowlist "git clean -f" "block" "non-target rule remains blocked" @"
[[allow]]
rule = "core.git:reset-hard"
reason = "Only reset-hard is allowed"
added_by = "e2e_test.ps1"
"@
    Test-Allowlist "git reset --hard" "block" "expired entry does not apply" @"
[[allow]]
rule = "core.git:reset-hard"
reason = "Expired"
added_by = "e2e_test.ps1"
expires_at = "2020-01-01"
"@
    Test-Allowlist "git reset --hard" "allow" "future expiry applies" @"
[[allow]]
rule = "core.git:reset-hard"
reason = "Not yet expired"
added_by = "e2e_test.ps1"
expires_at = "2099-12-31"
"@
    Test-Allowlist "git reset --hard" "allow" "pack wildcard core.git:* applies" @"
[[allow]]
rule = "core.git:*"
reason = "Wildcard allows all rules in pack"
added_by = "e2e_test.ps1"
"@
    Test-Allowlist "git reset --hard" "block" "global wildcard *:pattern rejected" @"
[[allow]]
rule = "*:reset-hard"
reason = "Global wildcard must be rejected"
added_by = "e2e_test.ps1"
risk_acknowledged = true
"@
    Test-Allowlist "git reset --hard" "allow" "met CI condition applies" @"
[[allow]]
rule = "core.git:reset-hard"
reason = "Only in CI"
added_by = "e2e_test.ps1"
conditions = { CI = "true" }
"@ @{ CI = "true" }
    Test-Allowlist "git reset --hard" "block" "unmet CI condition skipped" @"
[[allow]]
rule = "core.git:reset-hard"
reason = "Only in CI"
added_by = "e2e_test.ps1"
conditions = { CI = "true" }
"@

} finally {
    Set-Location $RepoRoot 2>$null
    Remove-Item -Recurse -Force $script:SandboxRoot -ErrorAction SilentlyContinue
}

# ===========================================================================
# Summary
# ===========================================================================
if ($Json) {
    [pscustomobject]@{
        total = $script:TestsTotal
        passed = $script:TestsPassed
        failed = $script:TestsFailed
        binary = $script:Bin
        results = $script:Results
    } | ConvertTo-Json -Depth 6
} else {
    Write-Host ""
    Write-Host "=== Summary ===" -ForegroundColor Blue
    Write-Host "  Total:  $($script:TestsTotal)"
    Write-Host "  Passed: $($script:TestsPassed)" -ForegroundColor Green
    if ($script:TestsFailed -gt 0) { Write-Host "  Failed: $($script:TestsFailed)" -ForegroundColor Red }
    else { Write-Host "  Failed: 0" }
}

if ($script:TestsFailed -gt 0) { exit 1 } else { exit 0 }
