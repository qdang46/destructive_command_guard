//! Strict mode — Phase 2.5
//!
//! Strict mode is a one-way tightening: it disables fallthrough-allow and
//! forces an explicit allow decision. It is useful for high-security
//! environments where only explicitly whitelisted commands should be permitted.
//!
//! Unlike `Plan` mode (which is effect-based) and `DontAsk` (which escalates
//! denials to prompts), strict mode flat-out denies anything not on the
//! safe whitelist with no escalation path.

use crate::mode::Mode;

/// Returns the "strictened" version of a mode.
/// Strict mode is a one-way flag: it removes fallthrough-allow from any mode.
///
/// - `Default` → `Default` (strict Default still fallthrough-allows)
/// - `AcceptEdits` → stays `AcceptEdits` (Prompt on dangerous/protected, Allow on safe)
/// - `Plan` → stays `Plan` (effect-based denial)
/// - `DontAsk` → stays `DontAsk` (always deny, escalate to prompt)
/// - `BypassPermissions` → stays `BypassPermissions` (security bypass)
/// - `Auto` → `Auto` (trust-level driven)
///
/// The strict flag is currently a no-op in the engine — Phase 2.7 (pack
/// integration) will add the actual enforcement logic.
#[derive(Clone, Copy, Debug, Default)]
pub struct Strictness {
    pub enabled: bool,
}

impl Strictness {
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub const fn is_strict(self) -> bool {
        self.enabled
    }
}

/// Apply strict mode to a mode.
/// When strictness is enabled, modes that would normally fallthrough-allow
/// become stricter. Currently this is a stub — Phase 2.7 will implement
/// the actual enforcement.
pub const fn apply_strictness(mode: Mode, strictness: Strictness) -> Mode {
    if !strictness.is_strict() {
        return mode;
    }
    // STUB: For now, strictness doesn't change any mode's behavior.
    // Phase 2.7 will implement the one-way tightening:
    // - Default/AcceptEdits/Auto: remove fallthrough-allow → Prompt/Deny instead
    // - DontAsk/Plan: already deny/never-prompt, unchanged
    // - BypassPermissions: unchanged (security bypass)
    mode
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strictness_disabled_leaves_mode_unchanged() {
        let s = Strictness::new(false);
        assert!(!s.is_strict());
    }

    #[test]
    fn strictness_enabled_is_detected() {
        let s = Strictness::new(true);
        assert!(s.is_strict());
    }

    #[test]
    fn default_strictness_is_disabled() {
        let s = Strictness::default();
        assert!(!s.is_strict());
    }

    #[test]
    fn apply_strictness_stub_is_noop() {
        // Phase 2.7 will change this — for now stub is a no-op
        assert_eq!(apply_strictness(crate::Mode::DontAsk, Strictness::new(true)), crate::Mode::DontAsk);
        assert_eq!(apply_strictness(crate::Mode::Plan, Strictness::new(true)), crate::Mode::Plan);
        assert_eq!(apply_strictness(crate::Mode::AcceptEdits, Strictness::new(false)), crate::Mode::AcceptEdits);
    }
}

