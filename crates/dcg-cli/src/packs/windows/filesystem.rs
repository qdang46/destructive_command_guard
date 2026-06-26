//! Windows core filesystem pack — the Windows analogue of `core.filesystem`.
//!
//! Blocks recursive/forced filesystem destruction in **cmd.exe** and
//! **PowerShell**, the single most valuable protection for a native-Windows
//! agent:
//!   - cmd: `del`/`erase` with `/s` (recursive), `rd`/`rmdir` with `/s`,
//!     `format <drive>:`.
//!   - PowerShell: `Remove-Item -Recurse -Force` and its aliases
//!     (`rm`/`del`/`rd`/`rmdir`/`ri`/`erase`), `Clear-Content` (empties a file),
//!     `Clear-RecycleBin` (purges the Recycle Bin so deletes become unrecoverable).
//!
//! Whitelist-first: PowerShell `-WhatIf` previews on cmdlets that actually honor
//! it and deletes scoped to temp dirs (`%TEMP%`/`$env:TEMP`/…) are allowed. A
//! broader Windows safe-pattern set is added by the `windows.safe` work
//! (`win-pack-safe-whitelist`).
//!
//! Every pattern carries an inline `(?i)` flag (Windows is case-insensitive) and
//! a stable rule id (e.g. `windows.filesystem:del-recursive`). See
//! `super`-module docs for the keyword-casing convention.

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

const DEL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "del /s /q <dir> /p",
        "Add /p to confirm each file, or scope the path precisely before deleting",
    ),
    PatternSuggestion::new(
        "Move-Item <dir> $env:TEMP\\trash",
        "Move to a temp/trash location instead of an irreversible recursive delete",
    ),
];

const REMOVE_ITEM_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "Remove-Item -Recurse -Force <path> -WhatIf",
        "Re-run with -WhatIf first to preview exactly what would be deleted",
    ),
    PatternSuggestion::new(
        "Move-Item <path> $env:TEMP\\trash",
        "Move to a temp/trash location instead of -Force deleting (Recycle Bin is bypassed by -Force)",
    ),
];

const FORMAT_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "Get-Volume",
    "List volumes and confirm the exact drive before any format — formatting is irreversible",
)];

const CLEAR_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "Get-Content <file>",
    "Read the file first; Clear-Content empties it in place with no undo",
)];

/// Create the Windows core filesystem pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "windows.filesystem".to_string(),
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
        name: "Windows Filesystem",
        description: "Protects against recursive/forced filesystem destruction on Windows: cmd \
                      `del /s`, `rd /s`, `format <drive>:`, and PowerShell `Remove-Item -Recurse \
                      -Force` (and aliases), `Clear-Content`, and `Clear-RecycleBin`.",
        // Realistic casings for the case-sensitive keyword quick-reject (see
        // super-module docs). cmd verbs: lower + UPPER. PowerShell cmdlets:
        // PascalCase + lower. Aliases (rm/ri/clc) included so PS alias forms gate.
        keywords: &[
            // cmd recursive delete / format
            "del",
            "DEL",
            "erase",
            "ERASE",
            "rd",
            "RD",
            "rmdir",
            "RMDIR",
            "format",
            "FORMAT",
            // PowerShell cmdlets + aliases
            "Remove-Item",
            "remove-item",
            "REMOVE-ITEM",
            "rm",
            "RM",
            "ri",
            "RI",
            "Clear-Content",
            "clear-content",
            "CLEAR-CONTENT",
            "clc",
            "CLC",
            "Clear-RecycleBin",
            "clear-recyclebin",
            "CLEAR-RECYCLEBIN",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // `-WhatIf` => preview/dry-run, but only for PowerShell verbs that honor
        // it. A stray `-WhatIf` argument must not whitelist cmd.exe `del`, `rd`,
        // `format`, or Unix/Git-Bash `rm`, because those tools would still
        // execute.
        safe_pattern!(
            "whatif-preview",
            r"(?i)^\s*(?:(?:remove-item|ri|clear-content|clc|clear-recyclebin)\b[^|&;\r\n]*\s-whatif\b|rm\b(?=[^|&;\r\n]*\s-recurse\b)(?=[^|&;\r\n]*\s-force\b)[^|&;\r\n]*\s-whatif\b)[^|&;\r\n]*$"
        ),
        // Deletes scoped to a temp directory are routine cleanup. Matches the
        // common Windows temp references when a delete verb is present.
        safe_pattern!(
            "del-temp",
            r"(?i)^\s*(?:del|erase|rd|rmdir|remove-item|ri|rm)\b[^|&;\r\n]*(?:%temp%|%tmp%|\$env:te?mp\b|\$env:localappdata\\+temp\b|\\appdata\\+local\\+temp\\|\\windows\\+temp\\|\[system\.io\.path\]::gettemppath)[^|&;\r\n]*$"
        ),
        // Read-only / preview cmd help on these verbs.
        safe_pattern!(
            "del-help",
            r"(?i)^\s*(?:del|rd|rmdir|format|erase)(?:\.exe)?\s+/\?\s*$"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // === cmd: recursive delete (del/erase /s) ===
        destructive_pattern!(
            "del-recursive",
            r"(?i)\b(?:del|erase)(?:\.exe)?\s+(?:[^|&\r\n]*\s+)?/s\b",
            "del /s recursively deletes every matching file in a directory tree.",
            Critical,
            "`del /s` recurses into subdirectories and deletes matching files; combined with `/q` \
             there is no per-file prompt and `/f` forces read-only files too. A wrong path or a \
             wildcard at a high level (e.g. `del /s /q C:\\src\\*`) destroys a whole tree with no \
             Recycle Bin and no undo.\n\n\
             Safer alternatives:\n\
             - Scope the path precisely and drop /q so deletions are confirmed\n\
             - Move the directory to %TEMP% instead of deleting it outright",
            DEL_SUGGESTIONS
        ),
        // === cmd: recursive directory removal (rd/rmdir /s) ===
        destructive_pattern!(
            "rd-recursive",
            r"(?i)\b(?:rd|rmdir)(?:\.exe)?\s+(?:[^|&\r\n]*\s+)?/s\b",
            "rd /s deletes a directory and its entire contents.",
            Critical,
            "`rd /s` (alias `rmdir /s`) removes a directory and every file and subfolder under it; \
             with `/q` it does so without confirmation. `rd /s /q C:\\path` is the Windows \
             equivalent of `rm -rf` and bypasses the Recycle Bin entirely.\n\n\
             Safer alternatives:\n\
             - Drop /q so the removal is confirmed\n\
             - Move the directory to %TEMP% first so it can be recovered",
            DEL_SUGGESTIONS
        ),
        // === PowerShell: Remove-Item -Recurse -Force (+ aliases) ===
        destructive_pattern!(
            "remove-item-recurse-force",
            r"(?i)\b(?:remove-item|rmdir|rd|ri|rm|del|erase)\b(?=[^|&\r\n]*\s(?:-recurse|-r)\b)(?=[^|&\r\n]*\s(?:-force|-f)\b)",
            "Remove-Item -Recurse -Force deletes a tree with no Recycle Bin and no prompt.",
            Critical,
            "`Remove-Item -Recurse -Force` (or an alias such as `rm`/`del`/`ri`) deletes a directory \
             and everything under it. `-Force` removes hidden/read-only items and `-Recurse` \
             descends the whole tree; together they bypass the Recycle Bin and any confirmation. \
             Pointed at a profile, repo, or drive root this is catastrophic and irreversible.\n\n\
             Safer alternatives:\n\
             - Re-run with -WhatIf to preview what would be removed\n\
             - Drop -Force so protected items and confirmations still apply\n\
             - Move-Item the target to a temp location instead of deleting",
            REMOVE_ITEM_SUGGESTIONS
        ),
        // === cmd: format a drive ===
        destructive_pattern!(
            "format-drive",
            r"(?i)\bformat(?:\.com|\.exe)?\s+(?:/\S+\s+)*[a-z]:(?:\s|\\|/|$)",
            "format <drive>: erases an entire volume.",
            Critical,
            "`format X:` re-creates the filesystem on a whole volume, destroying all data on it. \
             With `/q` (quick) and `/y` it proceeds with no confirmation. A wrong drive letter \
             formats the wrong disk.\n\n\
             Safer alternatives:\n\
             - Run `Get-Volume` / `wmic logicaldisk get name` and confirm the exact drive first\n\
             - Back up the volume before any format",
            FORMAT_SUGGESTIONS
        ),
        // === PowerShell: Clear-Content (empties a file in place) ===
        destructive_pattern!(
            "clear-content",
            r"(?i)\b(?:clear-content|clc)\b",
            "Clear-Content empties a file's contents in place with no undo.",
            High,
            "`Clear-Content` (alias `clc`) deletes everything inside a file while keeping the file \
             itself — the previous contents are gone with no Recycle Bin entry. Run against logs, \
             source, or config this silently destroys data.\n\n\
             Safer alternatives:\n\
             - Read or back up the file first (Get-Content / Copy-Item)\n\
             - If you must blank it, keep a copy: Copy-Item <f> <f>.bak first",
            CLEAR_SUGGESTIONS
        ),
        // === PowerShell: Clear-RecycleBin (makes prior deletes unrecoverable) ===
        destructive_pattern!(
            "clear-recyclebin",
            r"(?i)\bclear-recyclebin\b",
            "Clear-RecycleBin permanently purges the Recycle Bin.",
            Medium,
            "`Clear-RecycleBin` empties the Recycle Bin, permanently destroying every file that was \
             previously deleted into it — the usual last line of recovery for an accidental delete. \
             With `-Force` it does so without confirmation.\n\n\
             Safer alternatives:\n\
             - Restore or review the Recycle Bin contents before purging\n\
             - Leave the Recycle Bin intact so recent deletes remain recoverable",
            CLEAR_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "windows.filesystem");
        assert_eq!(pack.name, "Windows Filesystem");
        assert!(pack.keywords.contains(&"del"));
        assert!(pack.keywords.contains(&"Remove-Item"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn blocks_cmd_recursive_deletes() {
        let pack = create_pack();
        let checks = [
            ("del /s /q C:\\src", "del-recursive"),
            ("del /q /s C:\\src\\*", "del-recursive"),
            ("DEL /S /Q C:\\src", "del-recursive"),
            ("erase /s C:\\data", "del-recursive"),
            ("rd /s /q C:\\src", "rd-recursive"),
            ("RD /S /Q C:\\src", "rd-recursive"),
            ("rmdir /s C:\\build", "rd-recursive"),
        ];
        for (command, expected) in checks {
            assert_blocks_with_pattern(&pack, command, expected);
            assert_blocks_with_severity(&pack, command, Severity::Critical);
        }
    }

    #[test]
    fn blocks_powershell_recursive_force_and_aliases() {
        let pack = create_pack();
        let checks = [
            "Remove-Item -Recurse -Force C:\\src",
            "Remove-Item -Force -Recurse C:\\src",
            "remove-item -recurse -force C:\\src",
            "rm -Recurse -Force C:\\src",
            "rm -r -f C:\\src -WhatIf",
            "del -r -f C:\\src",
            "ri -Force -Recurse $env:USERPROFILE\\repo",
        ];
        for command in checks {
            assert_blocks_with_pattern(&pack, command, "remove-item-recurse-force");
            assert_blocks_with_severity(&pack, command, Severity::Critical);
        }
    }

    #[test]
    fn blocks_format_and_clear() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "format C: /q /y", "format-drive");
        assert_blocks_with_pattern(&pack, "format C: /q /y -WhatIf", "format-drive");
        assert_blocks_with_pattern(&pack, "format /fs:NTFS D:", "format-drive");
        assert_blocks_with_pattern(&pack, "Clear-Content C:\\app\\server.log", "clear-content");
        assert_blocks_with_pattern(&pack, "clc .\\notes.txt", "clear-content");
        assert_blocks_with_pattern(&pack, "Clear-RecycleBin -Force", "clear-recyclebin");
    }

    #[test]
    fn blocks_cmd_deletes_even_with_powershell_whatif_token() {
        let pack = create_pack();
        let checks = [
            ("del /s /q C:\\src -WhatIf", "del-recursive"),
            ("rd /s /q C:\\src -WhatIf", "rd-recursive"),
            ("rmdir /s C:\\build -whatif", "rd-recursive"),
        ];
        for (command, expected) in checks {
            assert_blocks_with_pattern(&pack, command, expected);
        }
    }

    #[test]
    fn keyword_quick_reject_passes_windows_verbs_both_cases() {
        // win-pack-quick-reject-keywords (.9.1): the keyword pre-filter must NOT
        // short-circuit Windows destructive commands (in either case) to ALLOW
        // before the (?i) regex runs, while still rejecting unrelated commands.
        // create_pack()'s might_match falls back to the same case-sensitive
        // keyword set the registry Aho-Corasick is built from, so this verifies
        // the realistic-casing convention covers the real forms.
        let pack = create_pack();
        for cmd in [
            "del /s /q C:\\src",
            "DEL /S /Q C:\\src",
            "rd /s /q C:\\src",
            "RD /S /Q C:\\src",
            "Remove-Item -Recurse -Force C:\\src",
            "remove-item -recurse -force C:\\src",
            "REMOVE-ITEM -RECURSE -FORCE C:\\src",
            "rm -Recurse -Force C:\\src",
            "format C: /q",
            "CLEAR-CONTENT C:\\app\\server.log",
            "CLEAR-RECYCLEBIN -Force",
        ] {
            assert!(pack.might_match(cmd), "keyword gate should admit: {cmd}");
        }
        for cmd in ["ls -la", "cargo build", "git status", "echo hello world"] {
            assert!(!pack.might_match(cmd), "keyword gate should skip: {cmd}");
        }
    }

    #[test]
    fn allows_safe_and_temp_and_whatif() {
        let pack = create_pack();
        let allowed = [
            // -WhatIf previews
            "Remove-Item -Recurse -Force C:\\src -WhatIf",
            "rm -Recurse -Force C:\\src -WhatIf",
            "Clear-Content C:\\app\\server.log -WhatIf",
            "Clear-RecycleBin -WhatIf",
            // temp-scoped cleanup (all the common Windows temp references)
            "del /s /q %TEMP%\\build",
            "rd /s /q %TMP%\\cache",
            "Remove-Item -Recurse -Force $env:TEMP\\build",
            "Remove-Item -Recurse -Force $env:TMP\\x",
            "Remove-Item -Recurse -Force $env:LOCALAPPDATA\\Temp\\dcg",
            "rd /s /q C:\\Users\\me\\AppData\\Local\\Temp\\proj",
            "rd /s /q C:\\Windows\\Temp\\stale",
            "Remove-Item -Recurse -Force ([System.IO.Path]::GetTempPath() + 'x')",
            // help / read-only
            "del /?",
            "rd /?",
            // non-recursive single-file ops are not in this pack's destructive set
            "del C:\\src\\one.txt",
            "rd C:\\empty-dir",
            // benign command with no windows.filesystem keyword at all
            "Get-ChildItem C:\\src",
        ];
        for command in allowed {
            assert_allows(&pack, command);
        }
        assert_no_safe_match(&pack, "rm -r -f C:\\src -WhatIf");
        // NOTE: a destructive verb appearing as DATA (e.g. `echo del /s /q ...`)
        // is matched at the raw-pack level here by design; the evaluator's
        // context classification is what prevents that false positive in
        // hook/e2e mode (covered by win-pack-tests-e2e), not the pack itself.
    }
}
