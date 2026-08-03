//! `scp` pack - protections for destructive SCP operations.
//!
//! Covers destructive CLI operations:
//! - Copying to critical system paths
//! - Recursive overwrites to sensitive directories

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScpSemanticDecision {
    Safe,
    Destructive(&'static str),
    NonDestructive,
    NoMatch,
}

fn normalize_absolute_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(component),
        }
    }
    let mut normalized = String::from("/");
    normalized.push_str(&components.join("/"));
    Some(normalized)
}

fn path_has_parent_component(path: &str) -> bool {
    path.split(['/', '\\']).any(|component| component == "..")
}

fn windows_system_destination(path: &str) -> Option<bool> {
    let normalized = path.replace('\\', "/");
    let mut candidate = normalized.as_str();
    if let Some(stripped) = candidate
        .strip_prefix("//?/")
        .or_else(|| candidate.strip_prefix("//./"))
    {
        candidate = stripped;
    }
    candidate = candidate.strip_prefix('/').unwrap_or(candidate);
    let bytes = candidate.as_bytes();
    let [drive, b':', b'/', ..] = bytes else {
        return None;
    };
    if !drive.is_ascii_alphabetic() {
        return None;
    }
    let tail = candidate.get(3..).unwrap_or_default();
    if tail.is_empty() {
        return Some(true);
    }
    let mut components = Vec::new();
    for component in tail.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(component),
        }
    }
    let lower = components.join("/").to_ascii_lowercase();
    Some(
        lower == "windows"
            || lower.starts_with("windows/")
            || lower == "window~1"
            || lower.starts_with("window~1/")
            || lower == "program files"
            || lower.starts_with("program files/")
            || lower == "program files (x86)"
            || lower.starts_with("program files (x86)/")
            || lower == "progra~1"
            || lower.starts_with("progra~1/")
            || lower == "progra~2"
            || lower.starts_with("progra~2/")
            || lower == "programdata"
            || lower.starts_with("programdata/")
            || lower == "progra~3"
            || lower.starts_with("progra~3/")
            || lower == "boot"
            || lower.starts_with("boot/")
            || lower == "efi"
            || lower.starts_with("efi/")
            || lower == "recovery"
            || lower.starts_with("recovery/")
            || lower == "system volume information"
            || lower.starts_with("system volume information/"),
    )
}

fn windows_drive_relative_destination(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let candidate = normalized.strip_prefix('/').unwrap_or(&normalized);
    let bytes = candidate.as_bytes();
    matches!(bytes, [drive, b':', tail @ ..] if drive.is_ascii_alphabetic() && !tail.starts_with(b"/"))
}

/// Classify a literal, single-process scp/pscp destination without compiling
/// the pack's regexes. Complex shell syntax retains the established matcher.
pub(crate) fn scp_semantic_decision(command: &str) -> ScpSemanticDecision {
    scp_semantic_decision_in_dialect(command, crate::normalize::ShellDialect::Unknown)
}

pub(crate) fn scp_semantic_decision_in_dialect(
    command: &str,
    dialect: crate::normalize::ShellDialect,
) -> ScpSemanticDecision {
    use crate::packs::careful_company_running_windows::transfer::{
        direct_scp_invocation_in_dialect, parse_scp_destination,
    };

    let Some(invocation) = direct_scp_invocation_in_dialect(command, dialect) else {
        return ScpSemanticDecision::NoMatch;
    };
    if invocation.help || matches!(invocation.destination.as_str(), "." | "./" | ".\\") {
        return ScpSemanticDecision::Safe;
    }
    if invocation.transfer_operand_count < 2 {
        return ScpSemanticDecision::NonDestructive;
    }
    if invocation.destination_is_windows_drive {
        return ScpSemanticDecision::NonDestructive;
    }
    if invocation.destination_is_dynamic {
        return ScpSemanticDecision::Destructive("scp-destination-unverified");
    }
    let Some(destination) = parse_scp_destination(&invocation.destination) else {
        return ScpSemanticDecision::Destructive("scp-destination-unverified");
    };
    let Some(path) = destination.path.as_deref() else {
        return ScpSemanticDecision::Destructive("scp-destination-unverified");
    };
    if (path == "~" || path.starts_with("~/")) && !path_has_parent_component(path) {
        return ScpSemanticDecision::Safe;
    }
    if destination.host.is_some()
        && let Some(system_target) = windows_system_destination(path)
        && system_target
    {
        return ScpSemanticDecision::Destructive("scp-to-windows-system");
    }
    if destination.host.is_some() && windows_drive_relative_destination(path) {
        return ScpSemanticDecision::Destructive("scp-destination-unverified");
    }
    if destination.host.is_some() && !path.starts_with('/') && path_has_parent_component(path) {
        return ScpSemanticDecision::Destructive("scp-relative-traversal");
    }
    let Some(path) = normalize_absolute_path(path) else {
        return ScpSemanticDecision::NonDestructive;
    };
    if path == "/tmp"
        || path.starts_with("/tmp/")
        || path == "/var/tmp"
        || path.starts_with("/var/tmp/")
    {
        return ScpSemanticDecision::Safe;
    }
    if path == "/" {
        return if invocation.recursive {
            ScpSemanticDecision::Destructive("scp-recursive-root")
        } else {
            ScpSemanticDecision::NonDestructive
        };
    }
    for (prefix, rule) in [
        ("/etc", "scp-to-etc"),
        ("/var", "scp-to-var"),
        ("/boot", "scp-to-boot"),
        ("/usr", "scp-to-usr"),
        ("/bin", "scp-to-bin"),
        ("/sbin", "scp-to-bin"),
        ("/lib", "scp-to-lib"),
        ("/lib64", "scp-to-lib"),
    ] {
        if path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.starts_with('/'))
        {
            return ScpSemanticDecision::Destructive(rule);
        }
    }
    ScpSemanticDecision::NonDestructive
}

/// Create the `scp` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "remote.scp".to_string(),
        name: "scp",
        description: "Protects against destructive SCP operations like overwrites to system paths.",
        keywords: &["scp", "pscp"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?!\S*\.\./)` in the target-path patterns blocks `..` directory-traversal
    // escapes. Without it, `scp file user@host:/tmp/../etc/passwd` would match
    // `scp-to-tmp` and bypass the `/etc` protection — the path starts with `/tmp/`
    // but resolves to `/etc/passwd` on the remote end.
    vec![
        // Version/help
        safe_pattern!("scp-help", r"scp\b.*\s--?h(elp)?\b"),
        // Downloading from remote (remote:path first, local second)
        safe_pattern!("scp-download", r"scp\b.*\s(?:\S+@)?\S+:\S+\s+\.\S*\s*$"),
        // Copy to home directory
        safe_pattern!(
            "scp-to-home",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?~/(?!\S*\.\./)\S+\s*$"
        ),
        // Copy to /tmp
        safe_pattern!(
            "scp-to-tmp",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/tmp/(?!\S*\.\./)\S*\s*$"
        ),
        // Copy to /var/tmp (safe scratch space under /var)
        safe_pattern!(
            "scp-to-var-tmp",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/var/tmp(?:/(?!\S*\.\./)\S*)?\s*$"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Semantic-only rules. Their bounded parsers run before regex
        // matching; the unsatisfiable expressions keep stable names,
        // severities, explanations, and allowlist identities in the ordinary
        // pack model without duplicating shell parsing in regex.
        destructive_pattern!(
            "scp-destination-unverified",
            r"(?!)",
            "scp/pscp has a runtime-dependent or malformed destination that cannot be verified before execution.",
            High,
            "A shell variable, expression, malformed URI, or otherwise unverified final operand can \
             resolve to a protected local path or an arbitrary remote host. Use a literal destination \
             so dcg can determine direction and target before the transfer runs."
        ),
        destructive_pattern!(
            "scp-relative-traversal",
            r"(?!)",
            "scp/pscp uses parent-directory traversal in a remote relative destination.",
            High,
            "Remote relative paths and tilde paths are resolved by the remote account. A `..` component \
             can escape the account's apparent home/staging directory and overwrite a protected system \
             location. Resolve the remote absolute path first and use a traversal-free destination."
        ),
        destructive_pattern!(
            "scp-to-windows-system",
            r"(?!)",
            "scp/pscp targets a protected Windows system directory on the remote host.",
            Critical,
            "Copying into a remote drive root, Windows, Program Files, ProgramData, Boot, or EFI tree can \
             overwrite operating-system files and make the destination host unusable. Stage the payload \
             in a non-system directory and install it through a reviewed deployment mechanism."
        ),
        // Recursive copy to root
        destructive_pattern!(
            "scp-recursive-root",
            r"scp\b.*\s-[A-Za-z0-9]*r[A-Za-z0-9]*\b.*\s(?:(?:\S+@)?\S+:)?/\s*$",
            "scp -r to root (/) is extremely dangerous.",
            Critical,
            "Recursive copy to the root filesystem can overwrite critical system files, \
             potentially rendering the system unbootable. This affects all system directories \
             including /etc, /bin, /lib, and /boot.\n\n\
             Safer alternatives:\n\
             - Specify a target subdirectory instead of /\n\
             - Use rsync with --dry-run to preview changes\n\
             - Copy to /tmp first and move files individually"
        ),
        // Copy to /etc
        destructive_pattern!(
            "scp-to-etc",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/etc(?:/\S*)?\s*$",
            "scp to /etc/ can overwrite system configuration.",
            High,
            "The /etc directory contains critical system configuration files including passwd, \
             shadow, fstab, and network settings. Overwriting these can lock you out of the \
             system or cause services to fail.\n\n\
             Safer alternatives:\n\
             - Copy to a staging directory first\n\
             - Back up existing files before overwriting\n\
             - Use configuration management tools (Ansible, etc.)"
        ),
        // Copy to /var
        destructive_pattern!(
            "scp-to-var",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/var(?:/\S*)?\s*$",
            "scp to /var/ can overwrite system data.",
            High,
            "The /var directory contains variable data including logs, databases, mail spools, \
             and application state. Overwriting this data can cause data loss and service \
             disruptions.\n\n\
             Safer alternatives:\n\
             - Use /var/tmp for temporary staging\n\
             - Stop affected services before modifying their data\n\
             - Back up existing data first"
        ),
        // Copy to /boot
        destructive_pattern!(
            "scp-to-boot",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/boot(?:/\S*)?\s*$",
            "scp to /boot/ can corrupt boot configuration.",
            Critical,
            "The /boot directory contains the kernel, initramfs, and bootloader configuration. \
             Corrupting these files will prevent the system from booting, requiring rescue \
             media to recover.\n\n\
             Safer alternatives:\n\
             - Use package manager for kernel updates\n\
             - Keep backup kernels available\n\
             - Test changes in a VM first"
        ),
        // Copy to /usr
        destructive_pattern!(
            "scp-to-usr",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/usr(?:/\S*)?\s*$",
            "scp to /usr/ can overwrite system binaries.",
            High,
            "The /usr directory contains system binaries, libraries, and shared resources. \
             Overwriting files here can break system utilities and installed applications.\n\n\
             Safer alternatives:\n\
             - Use /usr/local for custom installations\n\
             - Use package managers for system updates\n\
             - Install to user directories when possible"
        ),
        // Copy to /bin or /sbin
        destructive_pattern!(
            "scp-to-bin",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/(?:bin|sbin)(?:/\S*)?\s*$",
            "scp to /bin/ or /sbin/ can overwrite system binaries.",
            Critical,
            "The /bin and /sbin directories contain essential system binaries required for \
             basic operation. Overwriting these can make the system unusable and require \
             rescue mode recovery.\n\n\
             Safer alternatives:\n\
             - Install custom scripts to /usr/local/bin\n\
             - Use package managers for system updates\n\
             - Test binaries in user directories first"
        ),
        // Copy to /lib
        destructive_pattern!(
            "scp-to-lib",
            r"scp\b.*\s(?:(?:\S+@)?\S+:)?/lib(?:64)?(?:/\S*)?\s*$",
            "scp to /lib/ can overwrite system libraries.",
            Critical,
            "The /lib and /lib64 directories contain shared libraries required by system \
             binaries. Overwriting these can cause immediate system instability and prevent \
             commands from running.\n\n\
             Safer alternatives:\n\
             - Use package managers for library updates\n\
             - Install custom libraries to /usr/local/lib\n\
             - Use LD_LIBRARY_PATH for testing"
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
        assert_eq!(pack.id, "remote.scp");
        assert_eq!(pack.name, "scp");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"scp"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // Help
        assert_safe_pattern_matches(&pack, "scp --help");
        assert_safe_pattern_matches(&pack, "scp -h");
        // Download from remote
        assert_safe_pattern_matches(&pack, "scp user@host:file.txt .");
        assert_safe_pattern_matches(&pack, "scp -P 22 user@host:/path/file .");
        assert_safe_pattern_matches(&pack, "scp user@host:/etc/hosts .");
        // Copy to home
        assert_safe_pattern_matches(&pack, "scp file.txt user@host:~/documents/");
        // Copy to tmp
        assert_safe_pattern_matches(&pack, "scp file.txt /tmp/");
        assert_safe_pattern_matches(&pack, "scp file.txt user@host:/tmp/backup/");
        // Standard file copy (not to system paths)
        assert_allows(&pack, "scp file.txt user@host:/home/user/");
        assert_allows(&pack, "scp -r ./project user@host:/home/user/projects/");
    }

    #[test]
    fn blocks_copy_to_root() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp -r ./data user@host:/", "scp-recursive-root");
        assert_blocks_with_pattern(&pack, "scp -r backup/ root@server:/", "scp-recursive-root");
    }

    #[test]
    fn blocks_copy_to_etc() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp config.conf user@host:/etc/", "scp-to-etc");
        assert_blocks_with_pattern(&pack, "scp passwd root@server:/etc/passwd", "scp-to-etc");
    }

    #[test]
    fn blocks_copy_to_var() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp data.db user@host:/var/lib/", "scp-to-var");
        // But /var/tmp is allowed
        assert_allows(&pack, "scp file.txt user@host:/var/tmp/");
    }

    #[test]
    fn blocks_copy_to_boot() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp vmlinuz user@host:/boot/", "scp-to-boot");
    }

    #[test]
    fn blocks_copy_to_usr() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp binary user@host:/usr/local/bin/", "scp-to-usr");
    }

    #[test]
    fn blocks_copy_to_bin() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp script root@server:/bin/", "scp-to-bin");
        assert_blocks_with_pattern(&pack, "scp script root@server:/sbin/", "scp-to-bin");
    }

    #[test]
    fn blocks_copy_to_lib() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "scp libfoo.so user@host:/lib/", "scp-to-lib");
        assert_blocks_with_pattern(&pack, "scp libbar.so user@host:/lib64/", "scp-to-lib");
    }

    #[test]
    fn path_traversal_does_not_bypass_via_safe() {
        // `/tmp/../etc/passwd` resolves to `/etc/passwd` on the remote but the
        // old `/tmp/\S*` safe pattern would accept it, short-circuiting before
        // any destructive pattern ran. Verify the safe rules refuse `../`.
        let pack = create_pack();
        assert!(
            pack.matches_safe("scp file user@host:/tmp/stash/"),
            "normal /tmp copies remain safe"
        );
        assert!(
            !pack.matches_safe("scp file user@host:/tmp/../etc/passwd"),
            "traversal out of /tmp must NOT be treated as safe"
        );
        assert!(
            !pack.matches_safe("scp file user@host:/var/tmp/../root/.ssh/authorized_keys"),
            "traversal out of /var/tmp must NOT be treated as safe"
        );
        assert!(
            !pack.matches_safe("scp file user@host:~/../root/.bashrc"),
            "traversal out of ~ must NOT be treated as safe"
        );
    }

    #[test]
    fn semantic_direct_scp_preserves_safe_and_protected_destinations() {
        for command in [
            "scp --help",
            "scp -h",
            "scp user@host:/etc/hosts .",
            "scp file user@host:~/documents/",
            "scp file user@host:/tmp/stash/",
            "scp file user@host:/var/tmp/stash/",
        ] {
            assert_eq!(
                scp_semantic_decision(command),
                ScpSemanticDecision::Safe,
                "{command}"
            );
        }
        for (command, rule) in [
            ("scp file user@host:/etc/passwd", "scp-to-etc"),
            ("scp file user@host:\"/etc/important config\"", "scp-to-etc"),
            ("scp file \"user@host\":/etc/passwd", "scp-to-etc"),
            ("scp file user@host:/tmp/../etc/passwd", "scp-to-etc"),
            ("scp file user@host:/etc/[x]:passwd", "scp-to-etc"),
            ("scp data user@host:/var/lib/app", "scp-to-var"),
            ("scp image user@host:/boot/vmlinuz", "scp-to-boot"),
            ("scp binary user@host:/usr/local/bin/tool", "scp-to-usr"),
            ("scp binary user@host:/sbin/tool", "scp-to-bin"),
            ("scp library user@host:/lib64/library.so", "scp-to-lib"),
            ("scp -r tree user@host:/", "scp-recursive-root"),
            ("scp file --help user@host:/etc/passwd", "scp-to-etc"),
            (
                "scp -oStrictHostKeyChecking=no -r tree user@host:/",
                "scp-recursive-root",
            ),
            ("scp -rP2222 tree user@host:/", "scp-recursive-root"),
            ("scp -vrP 2222 tree user@host:/", "scp-recursive-root"),
            ("pscp -pw secret -r tree user@host:/", "scp-recursive-root"),
            (
                "pscp -load reviewed-session -r tree user@host:/",
                "scp-recursive-root",
            ),
            (
                "scp file user@host:staging/../../etc/passwd",
                "scp-relative-traversal",
            ),
            (
                "scp file user@host:~/../root/.ssh/authorized_keys",
                "scp-relative-traversal",
            ),
            (
                "scp file scp://user@host//tmp/%2e%2e/etc/passwd",
                "scp-to-etc",
            ),
            ("scp file scp://user@host/%2Fetc/passwd", "scp-to-etc"),
        ] {
            assert_eq!(
                scp_semantic_decision(command),
                ScpSemanticDecision::Destructive(rule),
                "{command}"
            );
        }
        for command in [
            "scp file user@outside.example:/home/user/",
            "scp C:\\data\\report.csv D:\\backup\\report.csv",
            "scp file user@host:/",
            "scp -oStrictHostKeyChecking=no file user@host:/",
            "scp file scp://user@host/etc/passwd",
            "scp user@host:/etc/passwd",
            "scp -r user@host:/",
            "scp file ./archive:name",
        ] {
            assert_eq!(
                scp_semantic_decision(command),
                ScpSemanticDecision::NonDestructive,
                "{command}"
            );
        }
        for command in [
            "scp file $destination",
            "scp file scp://user@host/path/%ZZ",
            "scp file scp://user@host/path/%00",
        ] {
            assert_eq!(
                scp_semantic_decision(command),
                ScpSemanticDecision::Destructive("scp-destination-unverified"),
                "{command}"
            );
        }
    }

    #[test]
    fn semantic_scp_uses_the_proven_windows_shell_dialect() {
        use crate::normalize::ShellDialect;

        for (command, dialect, rule) in [
            (
                r#"& "C:\Windows\System32\OpenSSH\scp.exe" C:\config user@host:/etc/config"#,
                ShellDialect::PowerShell,
                "scp-to-etc",
            ),
            (
                "scp.exe C:\\config user@host:/tmp/../etc/important` config",
                ShellDialect::PowerShell,
                "scp-to-etc",
            ),
            (
                r"pscp.exe C:\config user@host:/tmp/../etc/important^ config",
                ShellDialect::Cmd,
                "scp-to-etc",
            ),
            (
                r"scp.exe C:\config user@host:C:\Windows\System32 2>NUL",
                ShellDialect::Cmd,
                "scp-to-windows-system",
            ),
            (
                r"pscp.exe C:\config user@host:D:\ProgramData\vendor\settings.json",
                ShellDialect::Cmd,
                "scp-to-windows-system",
            ),
            (
                r"scp.exe C:\config user@host:E:\",
                ShellDialect::Cmd,
                "scp-to-windows-system",
            ),
            (
                r"scp.exe C:\config user@host:/C:/Windows/System32",
                ShellDialect::Cmd,
                "scp-to-windows-system",
            ),
            (
                r"scp.exe C:\config user@host:C:\Temp\..\Windows\System32",
                ShellDialect::Cmd,
                "scp-to-windows-system",
            ),
            (
                r"scp.exe C:\config user@host:\\?\C:\PROGRA~1\Vendor",
                ShellDialect::Cmd,
                "scp-to-windows-system",
            ),
            (
                r"scp.exe C:\config user@host:C:Windows\System32",
                ShellDialect::Cmd,
                "scp-destination-unverified",
            ),
        ] {
            assert_eq!(
                scp_semantic_decision_in_dialect(command, dialect),
                ScpSemanticDecision::Destructive(rule),
                "{command:?}"
            );
        }
        for (command, dialect) in [
            ("scp.exe C:\\config $destination", ShellDialect::PowerShell),
            (r"scp.exe C:\config %DESTINATION%", ShellDialect::Cmd),
            (r"pscp.exe C:\config !DESTINATION!", ShellDialect::Cmd),
        ] {
            assert_eq!(
                scp_semantic_decision_in_dialect(command, dialect),
                ScpSemanticDecision::Destructive("scp-destination-unverified"),
                "{command:?}"
            );
        }
        assert_eq!(
            scp_semantic_decision_in_dialect(
                r"scp.exe C:\config user@host:/C:/Users/analyst/staging",
                ShellDialect::Cmd,
            ),
            ScpSemanticDecision::NonDestructive
        );
    }
}
