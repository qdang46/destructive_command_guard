#!/usr/bin/env pwsh
# Tests Add-DcgProfileCheck from install.ps1: appends a marker-guarded,
# syntactically-valid warning block to a PowerShell profile, idempotently.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_profile_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $profilePath = Join-Path $tmp 'sub\Microsoft.PowerShell_profile.ps1'  # parent dir must be created

    $s1 = Add-DcgProfileCheck -ProfilePath $profilePath
    Check ($s1 -eq 'added') "first run returns 'added' (got '$s1')"
    Check (Test-Path $profilePath) "profile created (incl. parent dir)"

    $content = Get-Content -Raw $profilePath
    Check ($content.Contains('# dcg: warn if the Claude Code hook')) "marker present"
    Check ($content.Contains('Hook missing from ~/.claude/settings.json')) "warning text present"

    $perr = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$perr)
    Check (($null -eq $perr) -or ($perr.Count -eq 0)) "appended profile parses as valid PowerShell"

    $s2 = Add-DcgProfileCheck -ProfilePath $profilePath
    Check ($s2 -eq 'already') "second run returns 'already' (got '$s2')"

    $count = ([regex]::Matches((Get-Content -Raw $profilePath), [regex]::Escape('# dcg: warn if the Claude Code hook'))).Count
    Check ($count -eq 1) "marker appears exactly once (idempotent)"
} finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Add-DcgProfileCheck tests passed." -ForegroundColor Green
