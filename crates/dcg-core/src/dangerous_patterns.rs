//! Dangerous pattern registry — Phase 2.7 (real implementation)
//!
//! This module provides the dangerous pattern checking that runs inside
//! [`Engine::fallthrough()`] when `safe_whitelist` did not match.
//!
//! ## Architecture
//!
//! The `DangerousPatternRegistry` is self-contained in dcg-core — it does not
//! depend on the full pack system in dcg-cli. This avoids circular crate
//! dependencies.
//!
//! Higher-level consumers (dcg-cli) that want the full pack library integrate
//! at the call site via `permission_modes.rs` — which calls `evaluate_command()`
//! (pack evaluator) first, then calls `engine.evaluate()` for mode policy.
//!
//! ## Pattern priority
//!
//! Dangerous patterns are checked after the safe whitelist. Commands like
//! `git reset --hard` that have no safe pattern will be evaluated here and blocked.

use crate::decision::Decision;
use crate::tool_call::ToolCall;

pub use Severity::{Critical, High, Low, Medium};

/// Result of checking a command against dangerous patterns.
#[derive(Clone, Debug)]
pub struct DangerousMatch {
    pub rule_id: &'static str,
    pub pack_id: &'static str,
    pub severity: Severity,
    pub reason: &'static str,
    pub remediation: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// Registry of dangerous command patterns.
///
/// Phase 2.7 replaces the Phase 2.1 stub with a real implementation
/// that checks commands against hardcoded core dangerous patterns.
#[derive(Clone, Debug, Default)]
pub struct DangerousPatternRegistry {
    patterns: Vec<CompiledPattern>,
}

impl DangerousPatternRegistry {
    /// Create a new registry with all built-in dangerous patterns.
    pub fn new() -> Self {
        Self { patterns: build_core_patterns() }
    }

    /// Check if a command matches any dangerous pattern.
    /// Returns `Some(DangerousMatch)` if a pattern matched, `None` otherwise.
    pub fn check(&self, cmd: &str) -> Option<DangerousMatch> {
        for p in &self.patterns {
            if p.matches(cmd) {
                return Some(DangerousMatch {
                    rule_id: p.rule_id,
                    pack_id: p.pack_id,
                    severity: p.severity,
                    reason: p.reason,
                    remediation: p.remediation,
                });
            }
        }
        None
    }

    /// Returns true if there are any patterns loaded.
    pub fn has_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }

    /// Number of loaded patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

/// A compiled dangerous pattern with its regex and metadata.
#[derive(Clone, Debug)]
struct CompiledPattern {
    rule_id: &'static str,
    pack_id: &'static str,
    severity: Severity,
    reason: &'static str,
    remediation: Option<&'static str>,
    regex: fancy_regex::Regex,
}

impl CompiledPattern {
    fn new(
        rule_id: &'static str,
        pack_id: &'static str,
        severity: Severity,
        reason: &'static str,
        remediation: Option<&'static str>,
        pattern: &'static str,
    ) -> Self {
        Self {
            rule_id,
            pack_id,
            severity,
            reason,
            remediation,
            regex: fancy_regex::Regex::new(pattern).expect("dangerous pattern should compile"),
        }
    }

    fn matches(&self, cmd: &str) -> bool {
        self.regex.is_match(cmd).unwrap_or(false)
    }
}

/// Core dangerous patterns — git and filesystem.
fn build_core_patterns() -> Vec<CompiledPattern> {
    vec![
        // =============================================================================
        // core.git — git destructive patterns
        // =============================================================================
        CompiledPattern::new(
            "core.git:reset-hard",
            "core.git",
            Severity::Critical,
            "git reset --hard destroys uncommitted changes",
            Some("Use 'git stash' to save your changes first"),
            r"(?i)\bgit\s+reset\s+--hard\b",
        ),
        CompiledPattern::new(
            "core.git:reset-merge",
            "core.git",
            Severity::High,
            "git reset --merge destroys uncommitted changes",
            Some("Use 'git stash' to save your changes first"),
            r"(?i)\bgit\s+reset\s+--merge\b",
        ),
        CompiledPattern::new(
            "core.git:checkout-discard",
            "core.git",
            Severity::High,
            "git checkout -- <path> discards uncommitted changes to the file",
            Some("Use 'git stash' to save your changes first"),
            r"(?i)\bgit\s+checkout\s+--\s+[^\-]",
        ),
        CompiledPattern::new(
            "core.git:restore-discard",
            "core.git",
            Severity::High,
            "git restore <path> (without --staged) discards uncommitted changes",
            Some("Use 'git restore --staged <path>' to unstage only"),
            r"(?i)\bgit\s+restore\b(?!\s+--staged\b|\s+-S\b)\s+\S+",
        ),
        CompiledPattern::new(
            "core.git:clean-force",
            "core.git",
            Severity::High,
            "git clean -f permanently removes untracked files",
            Some("Use 'git clean -n' to preview what would be deleted"),
            r"(?i)\bgit\s+clean\s+-[a-z]*f[a-z]*\b",
        ),
        // --force long form (word-bounded, excludes --force-with-lease)
        CompiledPattern::new(
            "core.git:force-push",
            "core.git",
            Severity::High,
            "git push --force can overwrite remote history",
            Some("Use 'git push --force-with-lease' for a safer force push"),
            r"(?i)\bgit\s+push\b.*\s--force\b(?!\s*-with-lease)",
        ),
        // -f short form (word-bounded, excludes -f followed by --force-with-lease)
        CompiledPattern::new(
            "core.git:force-push-f",
            "core.git",
            Severity::High,
            "git push -f can overwrite remote history",
            Some("Use 'git push --force-with-lease' for a safer force push"),
            r"(?i)\bgit\s+push\b.*\s-f\b(?!\s*-with-lease)",
        ),
        CompiledPattern::new(
            "core.git:branch-force-delete",
            "core.git",
            Severity::High,
            "git branch -D force-deletes a branch without merge check",
            Some("Use 'git branch -d' to safely delete merged branches"),
            r"(?i)\bgit\s+branch\s+-[D]\b",
        ),
        CompiledPattern::new(
            "core.git:stash-drop",
            "core.git",
            Severity::High,
            "git stash drop permanently removes a stash entry",
            Some("Use 'git stash list' to see stashes before modifying them"),
            r"(?i)\bgit\s+stash\s+drop\b",
        ),
        CompiledPattern::new(
            "core.git:stash-clear",
            "core.git",
            Severity::Critical,
            "git stash clear removes all stash entries permanently",
            Some("Use 'git stash list' to see stashes before clearing them"),
            r"(?i)\bgit\s+stash\s+clear\b",
        ),
        // =============================================================================
        // core.filesystem — filesystem destructive patterns
        // =============================================================================
        CompiledPattern::new(
            "core.filesystem:rm-rf-root",
            "core.filesystem",
            Severity::Critical,
            "rm -rf / or rm -rf ~ deletes system files or home directory",
            Some("Never use rm -rf on root or home directories"),
            r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(/|~)\b",
        ),
        CompiledPattern::new(
            "core.filesystem:rm-rf-general",
            "core.filesystem",
            Severity::High,
            "rm -rf outside temp directories can permanently delete data",
            Some("Verify the path is a temp directory before using rm -rf"),
            r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+[^\s]+",
        ),
    ]
}

/// Evaluate a tool call against dangerous patterns.
/// Returns `Some(Decision::Deny(...))` if a dangerous pattern matched.
pub fn evaluate_dangerous(
    registry: &DangerousPatternRegistry,
    tool: &ToolCall,
) -> Option<Decision> {
    let cmd = tool.command_string()?;
    let m = registry.check(cmd)?;
    Some(Decision::deny(format!(
        "{} [{}]",
        m.reason,
        m.remediation.unwrap_or("blocked by dcg")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_hard_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git reset --hard").is_some());
        assert!(r.check("GIT RESET --HARD").is_some());
        assert!(r.check("git reset --hard HEAD~5").is_some());
    }

    #[test]
    fn reset_merge_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git reset --merge").is_some());
    }

    #[test]
    fn checkout_discard_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git checkout -- file.txt").is_some());
        assert!(r.check("git checkout -- ./src/app.js").is_some());
    }

    #[test]
    fn checkout_staged_is_not_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git checkout --staged file.txt").is_none());
        assert!(r.check("git restore --staged file.txt").is_none());
    }

    #[test]
    fn restore_worktree_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git restore file.txt").is_some());
    }

    #[test]
    fn clean_force_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git clean -f").is_some());
        assert!(r.check("git clean -fd").is_some());
        assert!(r.check("git clean -n").is_none());
    }

    #[test]
    fn force_push_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git push --force").is_some());
        assert!(r.check("git push -f").is_some());
        assert!(r.check("git push origin main --force").is_some());
    }

    #[test]
    fn force_with_lease_is_not_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git push --force-with-lease").is_none());
    }

    #[test]
    fn branch_force_delete_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git branch -D feature").is_some());
    }

    #[test]
    fn stash_drop_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git stash drop").is_some());
    }

    #[test]
    fn stash_clear_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git stash clear").is_some());
    }

    #[test]
    fn rm_rf_root_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("rm -rf /").is_some());
        assert!(r.check("rm -rf ~").is_some());
        assert!(r.check("rm -rf /home").is_some());
    }

    #[test]
    fn rm_rf_general_is_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("rm -rf ./src").is_some());
        assert!(r.check("rm -rf /var/log").is_some());
    }

    #[test]
    fn safe_commands_not_blocked() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git status").is_none());
        assert!(r.check("git log").is_none());
        assert!(r.check("git add .").is_none());
        assert!(r.check("ls -la").is_none());
        assert!(r.check("cargo build").is_none());
    }

    #[test]
    fn registry_has_patterns() {
        let r = DangerousPatternRegistry::new();
        assert!(r.has_patterns());
        assert!(r.pattern_count() > 0);
    }

    #[test]
    fn evaluate_dangerous_returns_none_for_non_bash() {
        let r = DangerousPatternRegistry::new();
        assert!(evaluate_dangerous(&r, &ToolCall::read("/etc/passwd")).is_none());
        assert!(evaluate_dangerous(&r, &ToolCall::write("/tmp/foo")).is_none());
    }

    #[test]
    fn evaluate_dangerous_returns_deny_for_match() {
        let r = DangerousPatternRegistry::new();
        let result = evaluate_dangerous(&r, &ToolCall::bash("git reset --hard"));
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Decision::Deny { .. }));
    }
}
