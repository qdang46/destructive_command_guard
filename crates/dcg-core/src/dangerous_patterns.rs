//! Dangerous pattern registry — Phase 2.1 (stub)
//!
//! Phase 2.7 will integrate the full pack rule system here.
//! For now this is a minimal stub that returns no matches.
//!
//! The full implementation will:
//! - Load pack rules from config (Phase 2.6)
//! - Compile regex patterns lazily (once per pack)
//! - Check commands against dangerous patterns only when `safe_whitelist` didn't match
//! - Return `Match` with severity, `rule_id`, `pack_id`, and remediation

use crate::decision::Decision;
use crate::tool_call::ToolCall;

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
/// Phase 2.7 replaces the stub with real pack-loaded patterns.
#[derive(Clone, Debug, Default)]
pub struct DangerousPatternRegistry {
    // Phase 2.7: loaded packs with their compiled patterns
    _marker: (),
}

impl DangerousPatternRegistry {
    /// Create a new registry. Phase 2.7 will load packs here.
    pub fn new() -> Self {
        Self { _marker: () }
    }

    /// Check if a command matches any dangerous pattern.
    /// Returns `Some(DangerousMatch)` if a pattern matched, `None` otherwise.
    ///
    /// Phase 2.7 will:
    /// 1. Skip if tool is not a Bash command
    /// 2. Quick-reject with Aho-Corasick keyword filter
    /// 3. Run regex patterns from matched packs
    /// 4. Return first match with highest severity
    pub fn check(&self, _cmd: &str) -> Option<DangerousMatch> {
        // STUB: Phase 2.7 replaces this with real pattern matching.
        // For now, no dangerous patterns are checked — Phase 1.5 / 2.7
        // is responsible for wiring the full pack system.
        None
    }

    /// Returns true if there are any patterns loaded.
    /// Phase 2.7 sets this to true once packs are loaded.
    pub fn has_patterns(&self) -> bool {
        // STUB: always false until Phase 2.7 loads real packs
        false
    }

    /// Number of loaded patterns. Phase 2.7 updates this.
    pub fn pattern_count(&self) -> usize {
        0
    }
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
    fn stub_returns_no_match() {
        let r = DangerousPatternRegistry::new();
        assert!(r.check("git reset --hard").is_none());
        assert!(r.check("rm -rf /").is_none());
        assert!(r.check("").is_none());
    }

    #[test]
    fn stub_has_no_patterns() {
        let r = DangerousPatternRegistry::new();
        assert!(!r.has_patterns());
        assert_eq!(r.pattern_count(), 0);
    }

    #[test]
    fn evaluate_dangerous_returns_none_for_stub() {
        use crate::tool_call::ToolCall;
        let r = DangerousPatternRegistry::new();
        assert!(evaluate_dangerous(&r, &ToolCall::bash("git reset --hard")).is_none());
    }
}
