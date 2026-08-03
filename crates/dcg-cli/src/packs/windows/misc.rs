//! Windows miscellaneous-destruction pack — registry, accounts, services,
//! scheduled tasks, WSL, and mirror-copy operations.
//!
//! Rounds out the Windows-native coverage with destructive cmd.exe verbs that
//! are not plain filesystem or disk operations:
//!   - **Registry**: `reg delete` (deletes registry keys/values).
//!   - **Accounts / services / tasks**: `net user|localgroup /delete`,
//!     `sc delete` (deletes a service), `schtasks /delete`.
//!   - **WSL**: `wsl --unregister <distro>` — IRREVERSIBLY destroys a WSL
//!     distribution and its entire filesystem.
//!   - **Mirror copy**: `robocopy /MIR` (and `/PURGE`) — deletes files in the
//!     destination that are not present in the source (the Windows analogue of
//!     `rsync --delete`).
//!
//! All patterns are `(?i)` case-insensitive with stable rule ids. Read-only
//! forms (`reg query`, `wsl --list`, `sc query`) are whitelisted. PowerShell
//! registry/account cmdlets (`Remove-Item HKLM:\`, `Remove-LocalUser`, …) are
//! owned by the `windows.powershell` pack, not here.

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

const REG_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "reg export <key> backup.reg",
    "Export the key first so the deletion can be undone with `reg import`",
)];

const ACCOUNT_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "net user / sc query",
    "List the account/service first and confirm it is the intended target",
)];

const WSL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "wsl --export <distro> backup.tar",
        "Export the distribution to a tarball before unregistering — unregister deletes everything",
    ),
    PatternSuggestion::new(
        "wsl --list --verbose",
        "Confirm exactly which distribution you are targeting first",
    ),
];

const ROBOCOPY_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "robocopy <src> <dst> /E",
    "Use /E to copy subdirectories WITHOUT deleting extra files in the destination (/MIR deletes them)",
)];

/// Create the Windows miscellaneous-destruction pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "windows.misc".to_string(),
        name: "Windows Misc (registry/accounts/wsl)",
        description: "Protects against destructive Windows cmd operations: `reg delete`, \
                      `net user|localgroup /delete`, `sc delete`, `schtasks /delete`, \
                      `wsl --unregister` (destroys a WSL distro), and `robocopy /MIR` (mirror \
                      delete).",
        // Conventional keyword casings retained for readable metadata; the
        // quick-reject itself is ASCII case-insensitive. Short verbs
        // (reg/net/sc) are noisy substrings, but the `(?i)\b...\b` regexes
        // still gate precisely.
        keywords: &[
            "reg", "REG", "net", "NET", "sc", "SC", "schtasks", "SCHTASKS", "wsl", "WSL",
            "robocopy", "ROBOCOPY",
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
        // Read-only registry / service / WSL / account inspection.
        safe_pattern!(
            "reg-query",
            r"(?i)^\s*reg(?:\.exe)?\s+(?:query|export|save)\b[^|&;\r\n]*$"
        ),
        safe_pattern!(
            "sc-query",
            r"(?i)^\s*sc(?:\.exe)?\s+(?:query|qc|queryex|enumdepend)\b[^|&;\r\n]*$"
        ),
        safe_pattern!(
            "wsl-list",
            r"(?i)^\s*wsl(?:\.exe)?\s+(?:--list|-l|--export|--status)\b[^|&;\r\n]*$"
        ),
        safe_pattern!(
            "schtasks-query",
            r"(?i)^\s*schtasks(?:\.exe)?\s+/query\b[^|&;\r\n]*$"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // === Registry ===
        destructive_pattern!(
            "reg-delete",
            r"(?i)\breg(?:\.exe)?\s+delete\b",
            "reg delete removes registry keys/values, which can break apps or Windows.",
            High,
            "`reg delete <key>` removes a registry key and all of its values and subkeys; with `/f` \
             it does so without confirmation. The registry holds app and OS configuration, so a \
             wrong key can break software, services, or the boot path, and there is no Recycle Bin \
             for the registry.\n\n\
             Safer alternatives:\n\
             - reg export <key> backup.reg: back up the key first (undo with `reg import`)\n\
             - reg query <key>: confirm exactly what the key contains before deleting",
            REG_SUGGESTIONS
        ),
        // === Accounts / services / scheduled tasks ===
        destructive_pattern!(
            "net-account-delete",
            r"(?i)\bnet(?:\.exe)?\s+(?:user|localgroup)\s+(?:[^|&\r\n]*\s+)?/delete\b",
            "net user/localgroup /delete removes a user account or local group.",
            High,
            "`net user <name> /delete` deletes a local user account (and `net localgroup <name> \
             /delete` a group). The account, its group memberships, and access are removed with no \
             prompt; the user's profile/data can be orphaned.\n\n\
             Safer alternatives:\n\
             - net user <name>: review the account before deleting\n\
             - Disable instead of delete: net user <name> /active:no",
            ACCOUNT_SUGGESTIONS
        ),
        destructive_pattern!(
            "sc-delete",
            r"(?i)\bsc(?:\.exe)?\s+delete\b",
            "sc delete removes a Windows service.",
            High,
            "`sc delete <service>` permanently removes a Windows service registration. If it is a \
             service something depends on, that software stops working until the service is \
             reinstalled.\n\n\
             Safer alternatives:\n\
             - sc query <service>: confirm the service and its state first\n\
             - sc stop <service> / sc config <service> start= disabled: disable reversibly instead",
            ACCOUNT_SUGGESTIONS
        ),
        destructive_pattern!(
            "schtasks-delete",
            r"(?i)\bschtasks(?:\.exe)?\s+(?:[^|&\r\n]*\s+)?/delete\b",
            "schtasks /delete removes scheduled tasks.",
            Medium,
            "`schtasks /delete /tn <task> /f` removes a scheduled task with no prompt; `/tn *` can \
             remove many at once. Deleting a task that maintenance, backups, or apps rely on \
             silently stops that work from running.\n\n\
             Safer alternatives:\n\
             - schtasks /query /tn <task>: confirm the task first\n\
             - schtasks /change /tn <task> /disable: disable reversibly instead of deleting",
            ACCOUNT_SUGGESTIONS
        ),
        // === WSL ===
        destructive_pattern!(
            "wsl-unregister",
            r"(?i)\bwsl(?:\.exe)?\s+(?:[^|&\r\n]*\s+)?--unregister\b",
            "wsl --unregister irreversibly destroys a WSL distribution and its filesystem.",
            High,
            "`wsl --unregister <distro>` deregisters a WSL distribution and DELETES its entire \
             filesystem — every file, package, and change inside that Linux environment is gone with \
             no undo. It is a frequent footgun when a reset/restart was intended.\n\n\
             Safer alternatives:\n\
             - wsl --export <distro> backup.tar: back up the whole distro first\n\
             - wsl --terminate <distro>: stop it without destroying it",
            WSL_SUGGESTIONS
        ),
        // === Mirror copy (rsync --delete analogue) ===
        destructive_pattern!(
            "robocopy-mirror",
            r"(?i)\brobocopy(?:\.exe)?\b(?=[^|&\r\n]*\s(?:/mir|/purge)\b)",
            "robocopy /MIR deletes destination files that are not present in the source.",
            High,
            "`robocopy <src> <dst> /MIR` (mirror) and `/PURGE` delete files and directories in the \
             DESTINATION that do not exist in the source — the Windows equivalent of `rsync \
             --delete`. A wrong destination, or a source that is missing/empty, wipes the \
             destination's contents.\n\n\
             Safer alternatives:\n\
             - robocopy <src> <dst> /E: copy subdirectories WITHOUT deleting extras\n\
             - Add /L to /MIR first: list what WOULD change without touching anything",
            ROBOCOPY_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "windows.misc");
        assert!(pack.keywords.contains(&"reg"));
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn blocks_misc_destruction() {
        let pack = create_pack();
        let checks = [
            ("reg delete HKLM\\Software\\Foo /f", "reg-delete"),
            ("REG DELETE HKCU\\Bar", "reg-delete"),
            ("net user alice /delete", "net-account-delete"),
            ("net localgroup devs /delete", "net-account-delete"),
            ("sc delete MyService", "sc-delete"),
            ("schtasks /delete /tn MyTask /f", "schtasks-delete"),
            ("wsl --unregister Ubuntu", "wsl-unregister"),
            ("wsl --unregister Ubuntu-22.04", "wsl-unregister"),
            ("robocopy C:\\src D:\\dst /MIR", "robocopy-mirror"),
            ("robocopy C:\\src D:\\dst /E /PURGE", "robocopy-mirror"),
        ];
        for (command, expected) in checks {
            assert_blocks_with_pattern(&pack, command, expected);
        }
    }

    #[test]
    fn allows_read_only_and_safe_copy() {
        let pack = create_pack();
        let allowed = [
            "reg query HKLM\\Software\\Foo",
            "reg export HKLM\\Software\\Foo backup.reg",
            "sc query MyService",
            "wsl --list --verbose",
            "wsl --export Ubuntu backup.tar",
            "schtasks /query /tn MyTask",
            // robocopy WITHOUT /MIR or /PURGE is a normal copy
            "robocopy C:\\src D:\\dst /E",
            "net user alice",
        ];
        for command in allowed {
            assert_allows(&pack, command);
        }
    }

    #[test]
    fn read_only_safe_patterns_do_not_mask_compound_destructive_commands() {
        let pack = create_pack();
        let checks = [
            (
                "reg query HKLM\\Software\\Foo & reg delete HKLM\\Software\\Foo /f",
                "reg-delete",
            ),
            ("sc query MyService & sc delete MyService", "sc-delete"),
            (
                "schtasks /query /tn MyTask & schtasks /delete /tn MyTask /f",
                "schtasks-delete",
            ),
            (
                "wsl --list --verbose & wsl --unregister Ubuntu",
                "wsl-unregister",
            ),
        ];
        for (command, expected) in checks {
            assert_blocks_with_pattern(&pack, command, expected);
        }
    }
}
