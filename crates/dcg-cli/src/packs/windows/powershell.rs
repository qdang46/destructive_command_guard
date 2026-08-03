//! Windows PowerShell-cmdlet pack — destructive cmdlets beyond plain filesystem
//! and disk operations (those live in `windows.filesystem` / `windows.system`).
//!
//! Covers:
//!   - **Provider/registry deletes**: `Remove-Item` against a non-filesystem
//!     PSDrive (`HKLM:`/`HKCU:`/`Cert:`/`WSMan:`), `Remove-ItemProperty`,
//!     `Clear-Item`/`Clear-ItemProperty`, `Remove-PSDrive`.
//!   - **Accounts / tasks / system restore**: `Remove-LocalUser`,
//!     `Remove-LocalGroup`, `Unregister-ScheduledTask`, `Disable-ComputerRestore`,
//!     `Stop-Computer`/`Restart-Computer -Force`.
//!   - **Virtualization / apps**: `Remove-VM`, `Remove-VMSnapshot`,
//!     `Remove-AppxPackage`.
//!
//! Plain `Remove-Item -Recurse` (with or without `-Force`) lives in `windows.filesystem`;
//! `Format-Volume`/`Clear-Disk`/etc. live in `windows.system`. This pack is
//! OPT-IN (not default-on) — enable with `enabled = ["windows.powershell"]` or
//! the `windows` category.
//!
//! All patterns are `(?i)` case-insensitive with stable rule ids.

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

const REGISTRY_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "Get-ItemProperty <path>",
    "Inspect (and export) the registry path before removing it — there is no undo for the registry",
)];

const ACCOUNT_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "Get-LocalUser / Get-ScheduledTask",
    "List the account/task first; consider Disable-* instead of Remove-*",
)];

const SYSTEM_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "Checkpoint-Computer / Get-ComputerRestorePoint",
    "Confirm intent — disabling System Restore or forcing a shutdown loses state/recovery points",
)];

const VM_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "Get-VM / Export-VM",
    "Export or checkpoint the VM before removing it — Remove-VM deletes its configuration",
)];

/// Create the Windows PowerShell-cmdlet pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "windows.powershell".to_string(),
        name: "Windows PowerShell Cmdlets",
        description: "Protects against destructive PowerShell cmdlets: registry/provider deletes \
                      (`Remove-Item HKLM:\\`, `Remove-ItemProperty`, `Remove-PSDrive`), account/task \
                      removal (`Remove-LocalUser`, `Unregister-ScheduledTask`), `Disable-ComputerRestore`, \
                      forced `Stop-Computer`/`Restart-Computer`, and `Remove-VM`/`Remove-AppxPackage`.",
        // Cmdlets are PascalCase by convention; include lower for the
        // case-insensitive quick-reject. See packs::windows module docs.
        keywords: &[
            "Remove-Item",
            "remove-item",
            // `ri` is the Remove-Item alias used by the provider-delete pattern;
            // short/noisy substring but required so `ri HKLM:\...` isn't
            // quick-rejected (this pack is opt-in, so the cost is opt-in too).
            "ri",
            "RI",
            "Remove-ItemProperty",
            "remove-itemproperty",
            "Clear-Item",
            "clear-item",
            "Remove-PSDrive",
            "remove-psdrive",
            "Remove-LocalUser",
            "remove-localuser",
            "Remove-LocalGroup",
            "remove-localgroup",
            "Unregister-ScheduledTask",
            "unregister-scheduledtask",
            "Disable-ComputerRestore",
            "disable-computerrestore",
            "Stop-Computer",
            "stop-computer",
            "Restart-Computer",
            "restart-computer",
            "Remove-VM",
            "remove-vm",
            "Remove-AppxPackage",
            "remove-appxpackage",
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
        // -WhatIf previews any of these cmdlets, but only for a single command
        // segment. A previewed first command must not mask a later destructive
        // command separated by ;, &, or a pipeline.
        safe_pattern!("ps-whatif", r"(?i)^\s*[^|&;\r\n]*\s-whatif\b[^|&;\r\n]*$"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // === Provider / registry deletes ===
        destructive_pattern!(
            "remove-item-provider",
            r"(?i)\b(?:remove-item|ri)\b[^|&\r\n]*\b(?:hklm|hkcu|hkcr|hku|cert|wsman):",
            "Remove-Item against a registry/cert/WSMan provider path deletes that store entry.",
            High,
            "`Remove-Item HKLM:\\...` (or `HKCU:`/`Cert:`/`WSMan:`) deletes a registry key, \
             certificate, or WSMan config item — not a file. The registry/cert stores have no \
             Recycle Bin, and a wrong key can break apps, services, or trust.\n\n\
             Safer alternatives:\n\
             - Get-ItemProperty / Get-ChildItem on the path to confirm contents first\n\
             - Export the key (reg export) before removing it",
            REGISTRY_SUGGESTIONS
        ),
        destructive_pattern!(
            "remove-itemproperty-or-clear",
            r"(?i)\b(?:remove-itemproperty|clear-item|clear-itemproperty)\b",
            "Remove-ItemProperty / Clear-Item* deletes registry values or item contents.",
            High,
            "`Remove-ItemProperty` deletes a registry value; `Clear-Item`/`Clear-ItemProperty` wipe an \
             item's contents/value. Against the registry these silently remove configuration with no \
             undo.\n\n\
             Safer alternatives:\n\
             - Get-ItemProperty: read the value first\n\
             - Export the parent key before changing values",
            REGISTRY_SUGGESTIONS
        ),
        destructive_pattern!(
            "remove-psdrive",
            r"(?i)\bremove-psdrive\b",
            "Remove-PSDrive removes a PowerShell drive mapping.",
            Medium,
            "`Remove-PSDrive` removes a PowerShell drive. For a persistent or system drive this can \
             break scripts and access that depend on it.\n\n\
             Safer alternatives:\n\
             - Get-PSDrive: confirm which drive and whether anything relies on it",
            REGISTRY_SUGGESTIONS
        ),
        // === Accounts / tasks ===
        destructive_pattern!(
            "remove-localuser-or-group",
            r"(?i)\b(?:remove-localuser|remove-localgroup)\b",
            "Remove-LocalUser / Remove-LocalGroup deletes a local account or group.",
            High,
            "`Remove-LocalUser`/`Remove-LocalGroup` permanently deletes a local account or group and \
             its access. The user's profile/data can be orphaned and there is no undo.\n\n\
             Safer alternatives:\n\
             - Get-LocalUser: confirm the account first\n\
             - Disable-LocalUser: disable reversibly instead of deleting",
            ACCOUNT_SUGGESTIONS
        ),
        destructive_pattern!(
            "unregister-scheduledtask",
            r"(?i)\bunregister-scheduledtask\b",
            "Unregister-ScheduledTask deletes a scheduled task.",
            Medium,
            "`Unregister-ScheduledTask` deletes a scheduled task. If maintenance, backups, or apps \
             rely on it, that work silently stops running.\n\n\
             Safer alternatives:\n\
             - Get-ScheduledTask: confirm the task first\n\
             - Disable-ScheduledTask: disable reversibly instead",
            ACCOUNT_SUGGESTIONS
        ),
        // === System restore / power ===
        destructive_pattern!(
            "disable-computerrestore",
            r"(?i)\bdisable-computerrestore\b",
            "Disable-ComputerRestore turns off System Restore and discards restore points.",
            High,
            "`Disable-ComputerRestore` turns off System Restore for a drive and deletes its existing \
             restore points — removing a key local recovery path, much like deleting shadow copies.\n\n\
             Safer alternatives:\n\
             - Get-ComputerRestorePoint: review existing restore points first\n\
             - Checkpoint-Computer: create a restore point rather than disabling protection",
            SYSTEM_SUGGESTIONS
        ),
        destructive_pattern!(
            "force-stop-or-restart-computer",
            r"(?i)\b(?:stop-computer|restart-computer)\b(?=[^|&\r\n]*\s-force\b)",
            "Stop-Computer/Restart-Computer -Force shuts down/reboots without saving work.",
            Medium,
            "`Stop-Computer -Force` / `Restart-Computer -Force` powers off or reboots immediately, \
             bypassing apps' save/close prompts — unsaved work in any running program is lost, and on \
             a server it drops every session.\n\n\
             Safer alternatives:\n\
             - Drop -Force so applications can save and close cleanly\n\
             - Confirm no critical work/sessions are active before forcing",
            SYSTEM_SUGGESTIONS
        ),
        // === Virtualization / apps ===
        destructive_pattern!(
            "remove-vm-or-snapshot",
            r"(?i)\b(?:remove-vm|remove-vmsnapshot|remove-vmcheckpoint)\b",
            "Remove-VM / Remove-VMSnapshot deletes a virtual machine or its checkpoints.",
            High,
            "`Remove-VM` deletes a Hyper-V virtual machine's configuration; `Remove-VMSnapshot`/\
             `Remove-VMCheckpoint` deletes its checkpoints (a recovery path). Targeting the wrong VM \
             destroys it or its ability to roll back.\n\n\
             Safer alternatives:\n\
             - Get-VM: confirm the VM name first\n\
             - Export-VM / Checkpoint-VM before removing anything",
            VM_SUGGESTIONS
        ),
        destructive_pattern!(
            "remove-appxpackage",
            r"(?i)\bremove-appxpackage\b",
            "Remove-AppxPackage uninstalls an app package (potentially for all users).",
            Medium,
            "`Remove-AppxPackage` uninstalls a Windows app package; with `-AllUsers` it removes it for \
             everyone. Removing a provisioned/system app can break Windows features.\n\n\
             Safer alternatives:\n\
             - Get-AppxPackage: confirm the exact package first\n\
             - Avoid -AllUsers unless you intend a machine-wide removal",
            VM_SUGGESTIONS
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
        assert_eq!(pack.id, "windows.powershell");
        assert!(pack.keywords.contains(&"Remove-LocalUser"));
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn blocks_destructive_cmdlets() {
        let pack = create_pack();
        let checks = [
            ("Remove-Item HKLM:\\Software\\Foo", "remove-item-provider"),
            (
                "Remove-Item Cert:\\LocalMachine\\My\\ABC",
                "remove-item-provider",
            ),
            ("ri HKCU:\\Bar -Recurse", "remove-item-provider"),
            (
                "Remove-ItemProperty -Path HKLM:\\Foo -Name Bar",
                "remove-itemproperty-or-clear",
            ),
            ("Remove-PSDrive -Name X", "remove-psdrive"),
            ("Remove-LocalUser -Name alice", "remove-localuser-or-group"),
            ("Remove-LocalGroup devs", "remove-localuser-or-group"),
            (
                "Unregister-ScheduledTask -TaskName Foo -Confirm:$false",
                "unregister-scheduledtask",
            ),
            (
                "Disable-ComputerRestore -Drive C:\\",
                "disable-computerrestore",
            ),
            ("Stop-Computer -Force", "force-stop-or-restart-computer"),
            ("Restart-Computer -Force", "force-stop-or-restart-computer"),
            ("Remove-VM -Name TestVM", "remove-vm-or-snapshot"),
            (
                "Remove-VMSnapshot -VMName TestVM -Name Snap1",
                "remove-vm-or-snapshot",
            ),
            (
                "Remove-AppxPackage -AllUsers Microsoft.Foo",
                "remove-appxpackage",
            ),
        ];
        for (command, expected) in checks {
            assert_blocks_with_pattern(&pack, command, expected);
        }
    }

    #[test]
    fn allows_read_only_and_whatif() {
        let pack = create_pack();
        let allowed = [
            "Remove-Item HKLM:\\Software\\Foo -WhatIf",
            "Remove-LocalUser -Name alice -WhatIf",
            "Get-LocalUser",
            "Get-ItemProperty HKLM:\\Software\\Foo",
            // non-forced restart is not flagged by this pack
            "Restart-Computer",
            // filesystem Remove-Item (no provider, no -Force/-Recurse) is owned elsewhere
            "Remove-Item C:\\src\\one.txt",
        ];
        for command in allowed {
            assert_allows(&pack, command);
        }
    }

    #[test]
    fn whatif_safe_pattern_does_not_mask_compound_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "Remove-LocalUser -Name alice -WhatIf; Remove-VM -Name TestVM",
            "remove-vm-or-snapshot",
        );
        assert_blocks_with_pattern(
            &pack,
            "Remove-Item HKLM:\\Software\\Foo -WhatIf | Remove-PSDrive -Name X",
            "remove-psdrive",
        );
    }
}
