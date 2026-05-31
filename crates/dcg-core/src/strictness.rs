//! Strict mode — Phase 2.5
//!
//! Strict mode is a one-way tightening: it removes fallthrough-allow and
//! forces an explicit allow decision. It is useful for high-security
//! environments where only explicitly whitelisted commands should be permitted.
//!
//! Unlike `Plan` mode (which is effect-based) and `DontAsk` (which escalates
//! denials to prompts), strict mode flat-out denies anything not on the
//! safe whitelist with no escalation path (unless escalation thresholds are hit).

use crate::mode::Mode;

/// Strictness configuration — Phase 2.5 real implementation.
///
/// When `enabled` is `true`, modes that would normally fallthrough-allow
/// an unknown command deny it instead. Safe-whitelist matches still allow;
/// dangerous-pattern matches still deny/prompt per severity.
#[derive(Clone, Copy, Debug, Default)]
pub struct Strictness {
    /// Enable one-way tightening (removes fallthrough-allow).
    pub enabled: bool,
    /// In strict mode, number of consecutive denials before escalation to Prompt.
    pub max_consecutive: u32,
    /// In strict mode, total denials before escalation to Prompt.
    pub max_total: u32,
    /// In strict mode, network operations escalate to Prompt instead of Deny.
    pub network_escalates_to_prompt: bool,
}

impl Strictness {
    /// Create a new strictness config with default thresholds.
    pub const fn new(enabled: bool) -> Self {
        Self {
            enabled,
            max_consecutive: 5,
            max_total: 5,
            network_escalates_to_prompt: false,
        }
    }

    /// Create a strictness config with custom thresholds.
    pub const fn with_thresholds(max_consecutive: u32, max_total: u32) -> Self {
        Self {
            enabled: true,
            max_consecutive,
            max_total,
            network_escalates_to_prompt: false,
        }
    }

    /// Returns `true` if strictness is active.
    pub const fn is_strict(self) -> bool {
        self.enabled
    }

    /// Returns `true` if strictness should remove fallthrough-allow for this mode.
    pub const fn mode_is_strictened(self, mode: Mode) -> bool {
        self.enabled && mode.fallthrough_allows()
    }
}

/// Apply strict mode to a mode.
///
/// When strictness is enabled, modes that would normally fallthrough-allow
/// (Default, Auto, AcceptEdits) effectively become stricter: unknown commands
/// are denied rather than allowed, with escalation to Prompt after the
/// configured thresholds are hit.
///
/// Modes that already deny/never-prompt (DontAsk, Plan) or bypass
/// (BypassPermissions) are unchanged — bypass remains a security bypass,
/// and protected-path PromptAlways entries still apply regardless of
/// strictness. The strictness flag is consulted in Engine::fallthrough().
pub const fn apply_strictness(mode: Mode, strictness: Strictness) -> Mode {
    if !strictness.is_strict() {
        return mode;
    }
    // DontAsk and Plan already deny non-whitelisted commands.
    // BypassPermissions is unchanged (protected-path checks run before
    // fallthrough regardless of mode).
    // For modes that fallthrough-allow (Default, Auto, AcceptEdits),
    // Engine::fallthrough() will deny instead of allow when strict.
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
    fn apply_strictness_returns_mode_unchanged() {
        // Strictness does not change the mode value — it changes Engine::fallthrough behavior.
        assert_eq!(
            apply_strictness(Mode::DontAsk, Strictness::new(true)),
            Mode::DontAsk
        );
        assert_eq!(
            apply_strictness(Mode::Plan, Strictness::new(true)),
            Mode::Plan
        );
        assert_eq!(
            apply_strictness(Mode::BypassPermissions, Strictness::new(true)),
            Mode::BypassPermissions
        );
    }

    #[test]
    fn mode_is_strictened_detects_fallthrough_allows() {
        let s = Strictness::new(true);
        assert!(s.mode_is_strictened(Mode::Default));
        assert!(s.mode_is_strictened(Mode::Auto));
        assert!(s.mode_is_strictened(Mode::AcceptEdits));
        assert!(!s.mode_is_strictened(Mode::DontAsk));
        assert!(!s.mode_is_strictened(Mode::Plan));
        assert!(!s.mode_is_strictened(Mode::BypassPermissions));
    }

    #[test]
    fn with_thresholds_enables_strict() {
        let s = Strictness::with_thresholds(3, 10);
        assert!(s.is_strict());
        assert_eq!(s.max_consecutive, 3);
        assert_eq!(s.max_total, 10);
    }

    #[test]
    fn disabled_strictness_does_not_stricten() {
        let s = Strictness::new(false);
        assert!(!s.mode_is_strictened(Mode::Default));
        assert!(!s.mode_is_strictened(Mode::AcceptEdits));
    }
}