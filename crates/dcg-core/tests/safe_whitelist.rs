//! Tests for safe command whitelist — Phase 2.2
use dcg_core::SafeCommandWhitelist;

#[test]
fn test_git_status_allowed() {
    let wl = SafeCommandWhitelist::new();
    assert!(wl.is_known_safe_command("git status"));
}

#[test]
fn test_git_log_allowed() {
    let wl = SafeCommandWhitelist::new();
    assert!(wl.is_known_safe_command("git log"));
    assert!(wl.is_known_safe_command("git log --oneline -n 10"));
}

#[test]
fn test_git_add_allowed() {
    let wl = SafeCommandWhitelist::new();
    assert!(wl.is_known_safe_command("git add ."));
}

#[test]
fn test_cargo_check_allowed() {
    let wl = SafeCommandWhitelist::new();
    assert!(wl.is_known_safe_command("cargo check"));
}

#[test]
fn test_cat_allowed() {
    let wl = SafeCommandWhitelist::new();
    assert!(wl.is_known_safe_command("cat file.txt"));
}

#[test]
fn test_ls_allowed() {
    let wl = SafeCommandWhitelist::new();
    assert!(wl.is_known_safe_command("ls -la"));
}

#[test]
fn test_git_reset_not_whitelisted() {
    let wl = SafeCommandWhitelist::new();
    // git reset can be destructive
    assert!(!wl.is_known_safe_command("git reset --hard"));
}

#[test]
fn test_rm_not_whitelisted() {
    let wl = SafeCommandWhitelist::new();
    assert!(!wl.is_known_safe_command("rm -rf /"));
}

#[test]
fn test_kubectl_get_allowed() {
    let wl = SafeCommandWhitelist::new();
    assert!(wl.is_known_safe_command("kubectl get pods"));
}

#[test]
fn test_unknown_command_not_whitelisted() {
    let wl = SafeCommandWhitelist::new();
    assert!(!wl.is_known_safe_command("some-random-command --flag"));
}