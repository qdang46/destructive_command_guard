//! Performance budgets for dcg.
//!
//! This module defines explicit latency budgets for all dcg operations.
//! These constants serve as the source of truth for:
//! - CI benchmark enforcement (fail on regression)
//! - Runtime bounded-evaluation thresholds (heredoc analysis)
//! - Documentation and expectations
//!
//! # Budget Philosophy
//!
//! dcg runs on every Bash command, so performance is critical. We define:
//! - **Target**: Expected p99 latency under normal conditions
//! - **Warning**: Latency that triggers a CI warning
//! - **Panic**: Latency that fails CI or triggers the bounded fallback policy
//!
//! # Performance Tiers
//!
//! | Tier | Path | Target | Warning Above | Panic Above |
//! |------|------|--------|---------------|-------------|
//! | 0 | Quick reject | < 1μs | > 5μs | > 50μs |
//! | 1 | Fast path | < 75μs | > 150μs | > 500μs |
//! | 2 | Pattern match | < 100μs | > 250μs | > 1ms |
//! | 3 | Heredoc trigger | < 5μs | > 10μs | > 100μs |
//! | 4 | Heredoc extract | < 200μs | > 500μs | > 2ms |
//! | 5 | Language detect | < 20μs | > 50μs | > 200μs |
//! | 6 | Full heredoc pipeline | < 5ms | > 15ms | > 20ms |
//!
//! # Absolute Maximum
//!
//! Hook evaluation exceeding 200ms returns an explicit indeterminate decision;
//! it never turns incomplete analysis into a silent allow.
//! This ensures dcg never blocks a user's workflow indefinitely.

use std::time::{Duration, Instant};

/// Performance budget for a single operation tier.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Target p99 latency (expected performance).
    pub target: Duration,
    /// Warning threshold (triggers CI warning).
    pub warning: Duration,
    /// Panic threshold for benchmark/CI budget assertions.
    pub panic: Duration,
}

impl Budget {
    /// Create a new budget with the given thresholds.
    #[must_use]
    pub const fn new(target_us: u64, warning_us: u64, panic_us: u64) -> Self {
        Self {
            target: Duration::from_micros(target_us),
            warning: Duration::from_micros(warning_us),
            panic: Duration::from_micros(panic_us),
        }
    }

    /// Create a budget from milliseconds (for longer operations).
    #[must_use]
    pub const fn from_ms(target_ms: u64, warning_ms: u64, panic_ms: u64) -> Self {
        Self {
            target: Duration::from_millis(target_ms),
            warning: Duration::from_millis(warning_ms),
            panic: Duration::from_millis(panic_ms),
        }
    }

    /// Check if a duration exceeds the warning threshold.
    #[must_use]
    pub fn exceeds_warning(&self, duration: Duration) -> bool {
        duration > self.warning
    }

    /// Check if a duration exceeds the panic threshold.
    #[must_use]
    pub fn exceeds_panic(&self, duration: Duration) -> bool {
        duration > self.panic
    }

    /// Return the appropriate status for a duration.
    #[must_use]
    pub fn status(&self, duration: Duration) -> BudgetStatus {
        if duration > self.panic {
            BudgetStatus::Panic
        } else if duration > self.warning {
            BudgetStatus::Warning
        } else if duration > self.target {
            BudgetStatus::Elevated
        } else {
            BudgetStatus::Ok
        }
    }
}

/// Status result from budget check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetStatus {
    /// Duration is within target.
    Ok,
    /// Duration exceeds target but within warning.
    Elevated,
    /// Duration exceeds warning but within panic.
    Warning,
    /// Duration exceeds panic threshold.
    Panic,
}

// =============================================================================
// Deadline Type (for bounded, conservative safety evaluation)
// =============================================================================

/// A deadline for bounded operation completion.
///
/// The Deadline tracks when an operation started and how long it's allowed
/// to run. Callers choose the policy for exhaustion. Hook evaluation must
/// return an explicit indeterminate result so elapsed time is never mistaken
/// for proof that a command is safe.
///
/// # Example
///
/// ```
/// use dcg_cli::perf::Deadline;
/// use std::time::Duration;
///
/// let deadline = Deadline::new(Duration::from_millis(10));
/// // ... perform operations ...
/// if deadline.is_exceeded() {
///     // Stop remaining analysis and return the caller's bounded outcome.
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    /// When the deadline started.
    start: Instant,
    /// Maximum duration allowed.
    max_duration: Duration,
}

impl Deadline {
    /// Create a new deadline with the given maximum duration.
    #[must_use]
    pub fn new(max_duration: Duration) -> Self {
        Self {
            start: Instant::now(),
            max_duration,
        }
    }

    /// Create a deadline using the default absolute hook budget.
    #[must_use]
    pub fn hook_default() -> Self {
        Self::new(ABSOLUTE_MAX)
    }

    /// Check if the deadline has been exceeded.
    #[must_use]
    pub fn is_exceeded(&self) -> bool {
        self.start.elapsed() > self.max_duration
    }

    /// Get the remaining time before the deadline, or None if exceeded.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.max_duration.checked_sub(self.start.elapsed())
    }

    /// Get the elapsed time since the deadline started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get the maximum duration for this deadline.
    #[must_use]
    pub const fn max_duration(&self) -> Duration {
        self.max_duration
    }

    /// Check if there's enough time remaining for an operation with the given budget.
    ///
    /// Returns true if the remaining time exceeds the budget's panic threshold.
    #[must_use]
    pub fn has_budget_for(&self, budget: &Budget) -> bool {
        self.remaining().is_some_and(|r| r > budget.panic)
    }
}

// =============================================================================
// Tier 0: Quick Reject (no relevant keywords)
// =============================================================================

/// Budget for commands rejected by keyword gating (e.g., `ls -la`).
/// These should be nearly instant as no pattern matching occurs.
pub const QUICK_REJECT: Budget = Budget::new(
    1,  // target: 1μs
    5,  // warning: 5μs
    50, // panic: 50μs
);

// =============================================================================
// Tier 1: Fast Path (safe commands with relevant keywords)
// =============================================================================

/// Budget for safe commands that match keywords but pass safe patterns.
/// Example: `git status`, `docker ps`.
pub const FAST_PATH: Budget = Budget::new(
    75,  // target: 75μs
    150, // warning: 150μs
    500, // panic: 500μs
);

// =============================================================================
// Tier 2: Pattern Matching (full pack evaluation)
// =============================================================================

/// Budget for commands requiring full pattern evaluation.
/// Example: `git reset --hard`, `docker system prune`.
pub const PATTERN_MATCH: Budget = Budget::new(
    100,  // target: 100μs
    250,  // warning: 250μs
    1000, // panic: 1ms
);

// =============================================================================
// Tier 3: Heredoc Trigger Check
// =============================================================================

/// Budget for checking if a command might contain heredoc/inline scripts.
/// This is a quick regex check, not full extraction.
pub const HEREDOC_TRIGGER: Budget = Budget::new(
    5,   // target: 5μs
    10,  // warning: 10μs
    100, // panic: 100μs
);

// =============================================================================
// Tier 4: Heredoc Extraction
// =============================================================================

/// Budget for extracting heredoc content from a command.
/// Includes parsing heredoc markers and extracting body.
pub const HEREDOC_EXTRACT: Budget = Budget::new(
    200,  // target: 200μs
    500,  // warning: 500μs
    2000, // panic: 2ms
);

// =============================================================================
// Tier 5: Language Detection
// =============================================================================

/// Budget for detecting the language of embedded script content.
/// Uses shebang analysis and heuristics.
pub const LANGUAGE_DETECT: Budget = Budget::new(
    20,  // target: 20μs
    50,  // warning: 50μs
    200, // panic: 200μs
);

// =============================================================================
// Tier 6: Full Heredoc Pipeline
// =============================================================================

/// Budget for complete heredoc analysis (trigger + extract + analyze).
/// This is the slow path, used only when heredoc content is detected.
pub const FULL_HEREDOC_PIPELINE: Budget = Budget::from_ms(
    5,  // target: 5ms
    15, // warning: 15ms
    20, // panic: 20ms
);

// =============================================================================
// Absolute Hook Evaluation Budget
// =============================================================================

/// Absolute maximum time available to hook safety evaluation.
/// Exhaustion produces an explicit indeterminate result rather than an allow.
pub const ABSOLUTE_MAX: Duration = Duration::from_millis(200);

/// Hook evaluation time budget in milliseconds.
///
/// Typical commands should complete in <10ms, but heredoc/inline-script
/// analysis may take longer on pathological inputs. Exhaustion is surfaced as
/// indeterminate so clients can request review or block conservatively.
pub const HOOK_EVALUATION_BUDGET_MS: u64 = 200;

/// Hook evaluation time budget as a Duration.
pub const HOOK_EVALUATION_BUDGET: Duration = Duration::from_millis(HOOK_EVALUATION_BUDGET_MS);

/// Check whether a duration exceeds the absolute hook evaluation budget.
#[must_use]
pub fn exceeds_absolute_budget(duration: Duration) -> bool {
    duration > ABSOLUTE_MAX
}

// =============================================================================
// Summary Constants for External Use
// =============================================================================

/// Fast path maximum budget in microseconds (panic threshold).
/// Commands exceeding this trigger CI failures.
pub const FAST_PATH_BUDGET_US: u64 = 500;

/// Hook-mode slow-path deadline in milliseconds.
///
/// This mirrors the absolute hook deadline, not the Tier 6 benchmark panic
/// threshold. Tier-specific heredoc budgets are defined above.
pub const SLOW_PATH_BUDGET_MS: u64 = 200;

/// Minimum hook evaluation timeout in milliseconds.
///
/// Prevents `hook_timeout_ms = 0` (or an absurdly small value) from forcing
/// every request immediately into the indeterminate review/block path.
///
/// 10ms is enough for the fast path (quick-reject + safe pattern matching)
/// while being well below the default 200ms budget.
pub const MIN_HOOK_TIMEOUT_MS: u64 = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_status_classification() {
        let budget = Budget::new(10, 50, 100);

        assert_eq!(budget.status(Duration::from_micros(5)), BudgetStatus::Ok);
        assert_eq!(budget.status(Duration::from_micros(10)), BudgetStatus::Ok);
        assert_eq!(
            budget.status(Duration::from_micros(11)),
            BudgetStatus::Elevated
        );
        assert_eq!(
            budget.status(Duration::from_micros(50)),
            BudgetStatus::Elevated
        );
        assert_eq!(
            budget.status(Duration::from_micros(51)),
            BudgetStatus::Warning
        );
        assert_eq!(
            budget.status(Duration::from_micros(100)),
            BudgetStatus::Warning
        );
        assert_eq!(
            budget.status(Duration::from_micros(101)),
            BudgetStatus::Panic
        );
    }

    #[test]
    fn fail_open_threshold() {
        assert!(!exceeds_absolute_budget(Duration::from_millis(199)));
        assert!(!exceeds_absolute_budget(Duration::from_millis(200)));
        assert!(exceeds_absolute_budget(Duration::from_millis(201)));
    }

    #[test]
    fn budget_hierarchy_makes_sense() {
        // Quick reject should be faster than fast path
        assert!(QUICK_REJECT.panic < FAST_PATH.target);

        // Fast path should be faster than pattern match
        assert!(FAST_PATH.panic <= PATTERN_MATCH.panic);

        // Heredoc trigger should be fast
        assert!(HEREDOC_TRIGGER.panic < HEREDOC_EXTRACT.target);

        // Full heredoc pipeline should accommodate all components
        assert!(FULL_HEREDOC_PIPELINE.panic >= HEREDOC_EXTRACT.panic);
    }

    #[test]
    fn deadline_creation() {
        let deadline = Deadline::new(Duration::from_millis(100));
        assert!(!deadline.is_exceeded());
        assert!(deadline.remaining().is_some());
        assert_eq!(deadline.max_duration(), Duration::from_millis(100));
    }

    #[test]
    fn deadline_hook_default() {
        let deadline = Deadline::hook_default();
        assert_eq!(deadline.max_duration(), ABSOLUTE_MAX);
        assert!(!deadline.is_exceeded());
    }

    #[test]
    fn deadline_exceeded_with_zero_duration() {
        // Create a zero-duration deadline and ensure it's exceeded by sleeping
        // briefly to let the Instant pass the zero point.
        let deadline = Deadline::new(Duration::ZERO);
        std::thread::sleep(Duration::from_nanos(100));
        assert!(deadline.is_exceeded());
        assert!(deadline.remaining().is_none());
    }

    #[test]
    fn deadline_has_budget_for() {
        let deadline = Deadline::new(Duration::from_millis(100));
        let small_budget = Budget::new(1000, 5000, 10_000); // 10ms panic
        let large_budget = Budget::new(10_000, 50_000, 200_000); // 200ms panic

        // Should have budget for small operations
        assert!(deadline.has_budget_for(&small_budget));
        // Should not have budget for operations that take longer than the deadline
        assert!(!deadline.has_budget_for(&large_budget));
    }

    fn doc_duration(duration: Duration) -> String {
        let micros = duration.as_micros();
        if micros >= 1000 && micros.is_multiple_of(1000) {
            format!("{}ms", micros / 1000)
        } else {
            format!("{micros}μs")
        }
    }

    fn budget_row(tier: u8, path: &str, budget: Budget) -> String {
        format!(
            "| {tier} | {path} | < {} | > {} | > {} |",
            doc_duration(budget.target),
            doc_duration(budget.warning),
            doc_duration(budget.panic)
        )
    }

    #[test]
    fn budget_documentation_matches_source_of_truth() {
        let readme = include_str!("../../../README.md");
        let agents = include_str!("../../../AGENTS.md");
        let ci = include_str!("../../../.github/workflows/ci.yml");
        let bench = include_str!("../../../.github/workflows/bench.yml");

        for row in [
            budget_row(0, "Quick reject", QUICK_REJECT),
            budget_row(1, "Fast path", FAST_PATH),
            budget_row(2, "Pattern match", PATTERN_MATCH),
            budget_row(3, "Heredoc trigger", HEREDOC_TRIGGER),
            budget_row(4, "Heredoc extract", HEREDOC_EXTRACT),
            budget_row(5, "Language detect", LANGUAGE_DETECT),
            budget_row(6, "Full heredoc pipeline", FULL_HEREDOC_PIPELINE),
        ] {
            assert!(
                readme.contains(&row),
                "README performance budget table drifted; missing row: {row}"
            );
        }

        for expected in [
            "- Quick reject: < 50us panic",
            "- Fast path: < 500us panic",
            "- Pattern match: < 1ms panic",
            "- Heredoc extract: < 2ms panic",
            "- Full heredoc pipeline: < 20ms panic",
            "- Hook evaluation deadline: 200ms (exhaustion is indeterminate, never a silent allow)",
        ] {
            assert!(
                agents.contains(expected),
                "AGENTS.md benchmark budget prose drifted; missing: {expected}"
            );
        }

        for expected in [
            "# - Full heredoc pipeline: 20ms panic",
            "# - Hook evaluation deadline: 200ms (exhaustion is indeterminate, never a silent allow)",
            "Full heredoc pipeline benchmark exceeds 20ms budget",
        ] {
            assert!(
                ci.contains(expected),
                ".github/workflows/ci.yml budget prose drifted; missing: {expected}"
            );
        }

        assert!(
            bench.contains("- Full heredoc pipeline: < 20ms (panic threshold)"),
            ".github/workflows/bench.yml budget prose drifted"
        );
    }
}
