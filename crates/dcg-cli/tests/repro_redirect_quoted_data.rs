//! Regression tests for issue #225: `core.filesystem:redirect-truncate-root-home`
//! (and its `-dynamic-path` sibling) must not fire on a `>` that appears inside a
//! quoted argument string, where the `>` is a literal byte and not a shell
//! redirect operator.
//!
//! The distinction versus the anti-bypass case
//! (`tests/repro_redirection_bypass.rs`, `"git">/dev/null reset --hard`) is quote
//! membership: in the bypass the operator sits *outside* the quotes (an
//! executable span) and must still block; here the operator sits *inside* single
//! or double quotes (inert data) and must be allowed.

use dcg_cli::packs::REGISTRY;
use dcg_cli::{config::Config, evaluator::evaluate_command, load_default_allowlists};

fn allowed(cmd: &str) {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    let result = evaluate_command(cmd, &config, &keywords, &compiled_overrides, &allowlists);
    assert!(
        result.is_allowed(),
        "expected ALLOWED (redirect operator is quoted data): {cmd:?} -> {:?}",
        result.decision
    );
}

fn denied(cmd: &str) {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let enabled_packs = config.enabled_pack_ids();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    let result = evaluate_command(cmd, &config, &keywords, &compiled_overrides, &allowlists);
    assert!(
        result.is_denied(),
        "expected DENIED (genuine redirect / bypass): {cmd:?} -> {:?}",
        result.decision
    );
}

#[test]
fn redirect_inside_single_quotes_is_data_not_a_redirect() {
    // `>/` placeholder inside a single-quoted argument body.
    allowed("br create --title t --body 'see series/<digest>/ for layout'");
    // A SQL comparison operator inside a single-quoted `-c` payload.
    allowed("psql -c 'SELECT 1 where a>/etc/x'");
    // Bare `echo` with the operator wholly inside single quotes.
    allowed("echo 'a >/ b'");
    // `>~` (root-home tilde) inside single quotes.
    allowed("mytool --note 'x>~/foo'");
    // Non-allowlisted CLI whose quoted argument mentions `>$HOME`.
    allowed("somecli --value 'dump >$HOME/data'");
}

#[test]
fn redirect_inside_double_quotes_is_data_not_a_redirect() {
    // A literal `>` inside double quotes is never a shell redirect operator.
    allowed("echo \"a >/ b\"");
    allowed("mytool --note \"x>~/foo\"");
}

#[test]
fn genuine_redirects_outside_quotes_still_block() {
    // The controls from the issue: real truncating redirects must still deny.
    denied("echo data > /etc/passwd");
    // Quoted *target* with the operator outside the quotes is a real redirect.
    denied("echo data >\"/etc/passwd\"");
    denied("echo data >'/etc/passwd'");
    // Operator immediately followed by a sensitive path, no space.
    denied(":>/etc/passwd");
}

#[test]
fn anti_bypass_operator_outside_quotes_still_blocks() {
    // From repro_redirection_bypass.rs: the `>` is outside the quoted command
    // word, so the git-reset payload must remain reachable and blocked.
    denied("\"git\">/dev/null reset --hard");
    denied("git>/dev/null reset --hard");
}
