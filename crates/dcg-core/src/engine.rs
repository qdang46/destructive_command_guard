//! `Engine` — top-level entry point that combines [`Mode`], [`ToolCall`],
//! and pack rules into a [`Decision`].

use std::path::{Path, PathBuf};

use crate::dangerous_patterns::{DangerousPatternRegistry, evaluate_dangerous};
use crate::decision::Decision;
use crate::effect::Effect;
use crate::escalation::DenialConfig;
use crate::mode::{Mode, ModePreCheck};
use crate::network_policy::{NetworkPolicy, default_policy};
use crate::protected_paths::{ProtectedPathEntry, ProtectedPaths, ProtectedSeverity};
use crate::safe_whitelist::SafeCommandWhitelist;
use crate::session::Session;
use crate::strictness::Strictness;
use crate::tool_call::ToolCall;

// ---------------------------------------------------------------------------
// EngineConfig / EngineConfigBuilder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub(crate) working_dir: PathBuf,
    pub(crate) protected_paths_raw: Vec<String>,
    pub(crate) strictness: Strictness,
    /// Custom network policy. `None` means use [`default_policy`].
    pub(crate) network_policy: Option<NetworkPolicy>,
}

impl EngineConfig {
    #[must_use]
    pub fn builder() -> EngineConfigBuilder {
        EngineConfigBuilder::default()
    }

    #[must_use]
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    #[must_use]
    pub fn protected_paths(&self) -> &[String] {
        &self.protected_paths_raw
    }

    #[must_use]
    pub fn strictness(&self) -> Strictness {
        self.strictness
    }
}

#[derive(Debug, Default, Clone)]
pub struct EngineConfigBuilder {
    working_dir: Option<PathBuf>,
    protected_paths: Vec<String>,
    strictness: Strictness,
    network_policy: Option<NetworkPolicy>,
}

impl EngineConfigBuilder {
    #[must_use]
    pub fn working_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    #[must_use]
    pub fn protected_paths(mut self, paths: Vec<String>) -> Self {
        self.protected_paths = paths;
        self
    }

    #[must_use]
    pub fn add_protected_path<S: Into<String>>(mut self, path: S) -> Self {
        self.protected_paths.push(path.into());
        self
    }

    #[must_use]
    pub fn strictness(mut self, strictness: Strictness) -> Self {
        self.strictness = strictness;
        self
    }

    /// Set a custom network policy. If not called, [`default_policy`] is used.
    #[must_use]
    pub fn network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.network_policy = Some(policy);
        self
    }

    #[must_use]
    pub fn build(self) -> EngineConfig {
        let working_dir = self
            .working_dir
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        EngineConfig {
            working_dir,
            protected_paths_raw: self.protected_paths,
            strictness: self.strictness,
            network_policy: self.network_policy,
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self::builder().build()
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Engine {
    config: EngineConfig,
    protected: ProtectedPaths,
    safe_whitelist: SafeCommandWhitelist,
    dangerous_registry: DangerousPatternRegistry,
    denial_config: DenialConfig,
    network_policy: NetworkPolicy,
}

impl Engine {
    /// Create a new engine from the given config.
    ///
    /// - Protected paths are merged with built-in defaults:
    ///   credential paths (`~/.ssh`, `~/.aws`, `~/.gnupg`) always get
    ///   [`ProtectedSeverity::PromptAlways`].
    /// - The network policy defaults to [`default_policy`] unless overridden
    ///   via [`EngineConfigBuilder::network_policy`].
    /// - Strict mode uses a restricted safe-whitelist subset.
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        let protected = build_protected_paths(
            &config.protected_paths_raw,
            &config.working_dir,
        );
        let network_policy = config.network_policy.clone().unwrap_or_else(default_policy);
        Self {
            config: config.clone(),
            protected,
            safe_whitelist: SafeCommandWhitelist::new(),
            dangerous_registry: DangerousPatternRegistry::new(),
            denial_config: DenialConfig::default(),
            network_policy,
        }
    }

    /// Create an engine with an externally-built `ProtectedPaths`.
    ///
    /// Note: this does **not** merge in the built-in default `PromptAlways`
    /// entries — use [`Self::new`] for the full default experience, or
    /// call [`build_protected_paths`] yourself.
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    pub fn with_protected(config: EngineConfig, protected: ProtectedPaths) -> Self {
        let network_policy = config.network_policy.clone().unwrap_or_else(default_policy);
        Self {
            config: config.clone(),
            protected,
            safe_whitelist: SafeCommandWhitelist::new(),
            dangerous_registry: DangerousPatternRegistry::new(),
            denial_config: DenialConfig::default(),
            network_policy,
        }
    }

    #[must_use]
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    #[must_use]
    pub fn protected_paths(&self) -> &ProtectedPaths {
        &self.protected
    }

    #[must_use]
    pub fn strictness(&self) -> Strictness {
        self.config.strictness
    }

    #[must_use]
    pub fn network_policy(&self) -> &NetworkPolicy {
        &self.network_policy
    }

    /// Evaluate a tool call and return the policy decision.
    pub fn evaluate(
        &self,
        session: &mut Session,
        tool: &ToolCall,
        mode: Mode,
        effects: &[Effect],
    ) -> Decision {
        let path_in_protected = match tool.path() {
            Some(p) => {
                let resolved = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    session.working_dir.join(p)
                };
                self.protected.contains(&resolved)
            }
            None => false,
        };

        let pre_check = mode.pre_check(tool, effects, path_in_protected);

        // BypassPermissions short-circuits to Allow, but PromptAlways
        // protected paths (credentials) override even that.
        let final_pre_check =
            if pre_check == ModePreCheck::AllowImmediately && mode == Mode::BypassPermissions {
                let path = tool.path().map(|p| {
                    if p.is_absolute() {
                        p.to_path_buf()
                    } else {
                        session.working_dir.join(p)
                    }
                });
                if let Some(ref p) = path {
                    if self.protected.is_prompt_always(p) {
                        ModePreCheck::PromptImmediately
                    } else {
                        pre_check
                    }
                } else {
                    pre_check
                }
            } else {
                pre_check
            };

        match final_pre_check {
            ModePreCheck::AllowImmediately => Decision::Allow,
            ModePreCheck::DenyImmediately => Decision::deny(plan_deny_reason(mode, effects)),
            ModePreCheck::PromptImmediately => {
                let cmd_repr = tool_repr(tool);
                let code = session.generate_allow_once_code(&cmd_repr);
                Decision::prompt(prompt_reason(mode, path_in_protected, effects), code)
            }
            ModePreCheck::Continue => self.evaluate_fallthrough(session, tool, mode, effects),
        }
    }

    /// Fallthrough evaluation when no mode-level short-circuit applied.
    fn evaluate_fallthrough(
        &self,
        session: &mut Session,
        tool: &ToolCall,
        mode: Mode,
        effects: &[Effect],
    ) -> Decision {
        let is_strict = self.config.strictness.is_strict();
        let strict_mode_active = is_strict && mode.fallthrough_allows();

        // =================================================================
        // Phase 2.8: Network policy check
        // =================================================================
        if let ToolCall::Network { url, .. } = tool {
            return self.evaluate_network(session, tool, url, strict_mode_active);
        }

        if mode.fallthrough_allows() {
            if let Some(cmd) = tool.command_string() {
                // In strict mode, use the restricted whitelist.
                let is_safe = if strict_mode_active {
                    self.safe_whitelist.is_known_safe_command_strict(cmd)
                } else {
                    self.safe_whitelist.is_known_safe_command(cmd)
                };

                if is_safe {
                    session.reset_on_allow();
                    return Decision::Allow;
                }
                if let Some(decision) = evaluate_dangerous(&self.dangerous_registry, tool) {
                    return decision;
                }
            }
            // Strict mode: deny unknowns, with escalation.
            if strict_mode_active {
                return self.evaluate_strict_fallthrough(session, tool, mode, effects);
            }
            // Non-strict: allow unknown commands via fallthrough.
            session.reset_on_allow();
            Decision::Allow
        } else {
            // Non-fallthrough modes (DontAsk, Plan) — deny with escalation.
            self.evaluate_non_fallthrough(session, tool, mode)
        }
    }

    /// Evaluate a network tool call against the network policy.
    fn evaluate_network(
        &self,
        session: &mut Session,
        tool: &ToolCall,
        url: &str,
        strict_mode_active: bool,
    ) -> Decision {
        let severity = self.network_policy.evaluate_url(url);
        let short_code = network_short_code(tool);

        match severity {
            crate::network_policy::NetworkSeverity::Allowed => {
                session.reset_on_allow();
                Decision::Allow
            }
            crate::network_policy::NetworkSeverity::Suspicious => {
                session.bump_deny_counter(&tool_repr(tool));
                if self.config.strictness.network_escalates_to_prompt {
                    return Decision::prompt(
                        format!("network: suspicious destination ({url})"),
                        short_code,
                    );
                }
                if strict_mode_active {
                    return Decision::deny(
                        format!("network: suspicious destination ({url}) [strict mode]"),
                    );
                }
                Decision::prompt(
                    format!("network: suspicious destination ({url})"),
                    short_code,
                )
            }
            crate::network_policy::NetworkSeverity::Dangerous => {
                session.bump_deny_counter(&tool_repr(tool));
                Decision::deny(format!("network: denied destination ({url})"))
            }
            crate::network_policy::NetworkSeverity::Exfiltration => {
                session.bump_deny_counter(&tool_repr(tool));
                Decision::deny(format!("network: exfiltration pattern detected ({url})"))
            }
        }
    }

    /// Strict-mode fallthrough: deny unknowns, check escalation thresholds.
    fn evaluate_strict_fallthrough(
        &self,
        session: &mut Session,
        tool: &ToolCall,
        mode: Mode,
        effects: &[Effect],
    ) -> Decision {
        let cmd_repr = tool_repr(tool);
        session.bump_deny_counter(&cmd_repr);

        let is_network_effect = effects.contains(&Effect::Network);
        if self.config.strictness.network_escalates_to_prompt && is_network_effect {
            let code = session.generate_allow_once_code(&cmd_repr);
            return Decision::prompt(
                format!(
                    "strict mode: network operation not on safe list (consecutive: {}, total: {})",
                    session.consecutive_denials(),
                    session.total_denials()
                ),
                code,
            );
        }

        let should_escalate = session.consecutive_denials() >= self.config.strictness.max_consecutive
            || session.total_denials() >= self.config.strictness.max_total;

        if should_escalate {
            let code = session.generate_allow_once_code(&cmd_repr);
            Decision::prompt(
                format!(
                    "strict mode escalated: {} consecutive denials, {} total denials",
                    session.consecutive_denials(),
                    session.total_denials()
                ),
                code,
            )
        } else {
            Decision::deny(format!(
                "strict mode: command not on safe list (mode: {})",
                mode.as_str()
            ))
        }
    }

    /// Non-fallthrough mode evaluation (`DontAsk`, Plan) — deny with escalation.
    fn evaluate_non_fallthrough(
        &self,
        session: &mut Session,
        tool: &ToolCall,
        mode: Mode,
    ) -> Decision {
        let cmd_repr = tool_repr(tool);
        session.bump_deny_counter(&cmd_repr);

        if self.denial_config.should_escalate(session.consecutive_denials(), session.total_denials())
        {
            let code = session.generate_allow_once_code(&cmd_repr);
            Decision::prompt(
                format!(
                    "Escalated: {} consecutive denials, {} total denials",
                    session.consecutive_denials(),
                    session.total_denials()
                ),
                code,
            )
        } else {
            Decision::deny(format!(
                "tool call not on the explicit allow list (mode: {})",
                mode.as_str()
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Protected-paths helpers
// ---------------------------------------------------------------------------

/// Build `ProtectedPaths` by merging user-supplied entries with built-in
/// defaults that protect credential paths and project configuration files.
fn build_protected_paths(user_entries: &[String], working_dir: &Path) -> ProtectedPaths {
    let home = dirs::home_dir();
    let mut entries: Vec<ProtectedPathEntry> = Vec::new();

    // User-supplied entries — all get PromptInNonBypass by default.
    for raw in user_entries {
        let prefix = expand_path(raw, working_dir, home.as_deref());
        entries.push(ProtectedPathEntry::new(prefix, ProtectedSeverity::PromptInNonBypass));
    }

    // Built-in PromptAlways entries — override even BypassPermissions.
    if let Some(ref h) = home {
        for dir in &[".ssh", ".aws", ".gnupg"] {
            entries.push(ProtectedPathEntry::new(
                h.join(dir),
                ProtectedSeverity::PromptAlways,
            ));
        }
    }

    // Built-in PromptInNonBypass — always present for project config.
    for raw in &[".env", ".env.local", ".env.production",
        ".git", ".mcp.json", ".claude.json",
        ".claude", ".vscode"] {
        entries.push(ProtectedPathEntry::new(
            working_dir.join(raw),
            ProtectedSeverity::PromptInNonBypass,
        ));
    }

    ProtectedPaths::with_entries(entries)
}

/// Expand `~` and relative paths. Extracted for reuse.
fn expand_path(entry: &str, working_dir: &Path, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = entry.strip_prefix("~/") {
        return home.map_or_else(|| PathBuf::from(entry), |h| h.join(rest));
    }
    if entry == "~" {
        return home.map_or_else(|| PathBuf::from(entry), Path::to_path_buf);
    }
    let p = PathBuf::from(entry);
    if p.is_absolute() {
        p
    } else {
        working_dir.join(p)
    }
}

// ---------------------------------------------------------------------------
// Decision helpers
// ---------------------------------------------------------------------------

fn plan_deny_reason(mode: Mode, effects: &[Effect]) -> String {
    if mode == Mode::Plan {
        let bad: Vec<&str> = effects
            .iter()
            .filter(|e| !e.is_read_only())
            .map(|e| e.as_str())
            .collect();
        if bad.is_empty() {
            "plan mode: tool call is not read-only".to_string()
        } else {
            format!("plan mode: non-read-only effects ({})", bad.join(", "))
        }
    } else {
        format!("denied by {} mode", mode.as_str())
    }
}

fn prompt_reason(mode: Mode, path_in_protected: bool, effects: &[Effect]) -> String {
    if path_in_protected {
        return format!("{} mode: target path is in protected_paths", mode.as_str());
    }
    let dangerous: Vec<&str> = effects
        .iter()
        .filter(|e| matches!(e, Effect::Network | Effect::Spawn | Effect::Irreversible))
        .map(|e| e.as_str())
        .collect();
    if dangerous.is_empty() {
        format!("{} mode: confirmation required", mode.as_str())
    } else {
        format!(
            "{} mode: tool call has {} effect(s)",
            mode.as_str(),
            dangerous.join(", ")
        )
    }
}

fn tool_repr(tool: &ToolCall) -> String {
    match tool {
        ToolCall::Bash { cmd } => cmd.clone(),
        ToolCall::Edit { path } => format!("edit:{}", path.display()),
        ToolCall::Write { path } => format!("write:{}", path.display()),
        ToolCall::Read { path } => format!("read:{}", path.display()),
        ToolCall::Network { url, method } => format!("net:{method} {url}"),
    }
}

fn network_short_code(tool: &ToolCall) -> String {
    match tool {
        ToolCall::Network { url, method } => {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            url.hash(&mut h);
            format!("net:{}:{:x}", method.to_lowercase(), h.finish() & 0xFFFF)
        }
        _ => String::new(),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with_protected(paths: Vec<String>, work: &str) -> Engine {
        Engine::new(
            EngineConfig::builder()
                .working_dir(work)
                .protected_paths(paths)
                .build(),
        )
    }

    // =======================================================================
    // Existing tests — preserved
    // =======================================================================

    #[test]
    fn bypass_always_allows() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("rm -rf /"),
            Mode::BypassPermissions,
            &[Effect::Write, Effect::Fs, Effect::Irreversible],
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn plan_allows_read_only_bash() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("git status"),
            Mode::Plan,
            &[Effect::Read],
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn plan_denies_write() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::write("/work/output.txt"),
            Mode::Plan,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_deny(), "got {d:?}");
        assert!(d.reason().unwrap().contains("plan mode"));
    }

    #[test]
    fn accept_edits_allows_safe_write() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::edit("/work/src/foo.rs"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn accept_edits_prompts_in_protected_path() {
        let e = engine_with_protected(vec![".git".into()], "/work");
        let mut s = Session::with_id("test");
        s.working_dir = PathBuf::from("/work");
        let d = e.evaluate(
            &mut s,
            &ToolCall::write("/work/.git/config"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_prompt(), "got {d:?}");
        match d {
            Decision::Prompt { allow_once_code, .. } => {
                assert!(s.has_unused_allow_once(&allow_once_code));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn accept_edits_prompts_on_irreversible() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("rm -rf ./build"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs, Effect::Irreversible],
        );
        assert!(d.is_prompt(), "got {d:?}");
    }

    #[test]
    fn dont_ask_denies_unmatched_calls() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("anything"),
            Mode::DontAsk,
            &[Effect::Read],
        );
        assert!(d.is_deny(), "got {d:?}");
        assert_eq!(s.deny_count("anything"), 1);
    }

    #[test]
    fn default_falls_through_to_allow() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("git log"),
            Mode::Default,
            &[Effect::Read],
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn auto_routes_as_default_for_now() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("git log"),
            Mode::Auto,
            &[Effect::Read],
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn protected_path_relative_to_session_working_dir() {
        let e = engine_with_protected(vec![".git".into()], "/work");
        let mut s = Session::with_id("test");
        s.working_dir = PathBuf::from("/work");
        let d = e.evaluate(
            &mut s,
            &ToolCall::write(".git/config"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_prompt(), "got {d:?}");
    }

    // =======================================================================
    // Strictness tests — Phase 2.5
    // =======================================================================

    fn engine_with_strictness(paths: Vec<String>, work: &str, strictness: Strictness) -> Engine {
        Engine::new(
            EngineConfig::builder()
                .working_dir(work)
                .protected_paths(paths)
                .strictness(strictness)
                .build(),
        )
    }

    #[test]
    fn strict_mode_denies_unknown_command() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        let d = e.evaluate(&mut s, &ToolCall::bash("rm -rf /"), Mode::Default, &[Effect::Fs]);
        assert!(d.is_deny(), "strict mode should deny unknown commands, got {d:?}");
    }

    #[test]
    fn strict_mode_allows_safe_whitelisted_command() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("git status"),
            Mode::Default,
            &[Effect::Read],
        );
        assert!(d.is_allow(), "strict mode should allow whitelisted commands, got {d:?}");
    }

    #[test]
    fn strict_mode_dangerous_pattern_denies() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("git reset --hard"),
            Mode::Default,
            &[Effect::MutateVcs],
        );
        assert!(d.is_deny(), "strict mode should deny dangerous patterns, got {d:?}");
    }

    #[test]
    fn strict_mode_escalates_after_max_consecutive() {
        let e = engine_with_strictness(vec![], "/work", Strictness::with_thresholds(3, 10));
        let mut s = Session::with_id("test");

        for i in 1..=3 {
            let d = e.evaluate(
                &mut s,
                &ToolCall::bash("some-unknown-cmd"),
                Mode::Default,
                &[Effect::Read],
            );
            assert!(
                if i < 3 { d.is_deny() } else { d.is_prompt() },
                "denial {} should be {}, got {d:?}",
                i,
                if i < 3 { "deny" } else { "prompt" }
            );
        }

        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("another-unknown"),
            Mode::Default,
            &[Effect::Read],
        );
        assert!(d.is_prompt(), "after escalation, subsequent should stay prompt, got {d:?}");
    }

    #[test]
    fn strict_mode_escalates_after_max_total() {
        let e = engine_with_strictness(vec![], "/work", Strictness::with_thresholds(10, 3));
        let mut s = Session::with_id("test");

        for i in 1..=3 {
            let d = e.evaluate(
                &mut s,
                &ToolCall::bash("unknown-cmd"),
                Mode::Default,
                &[Effect::Read],
            );
            assert!(
                if i < 3 { d.is_deny() } else { d.is_prompt() },
                "denial {} should be {}, got {d:?}",
                i,
                if i < 3 { "deny" } else { "prompt" }
            );
        }
    }

    #[test]
    fn strict_mode_network_denies_by_default() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        // evil.com is not on the default allowed-hosts list → Suspicious → strict deny
        let d = e.evaluate(
            &mut s,
            &ToolCall::network("https://evil.com", "GET"),
            Mode::Default,
            &[Effect::Network],
        );
        assert!(d.is_deny(), "strict mode should deny network calls not on safe list, got {d:?}");
    }

    #[test]
    fn strict_mode_network_prompts_when_configured() {
        let mut strict = Strictness::new(true);
        strict.network_escalates_to_prompt = true;
        let e = engine_with_strictness(vec![], "/work", strict);
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::network("https://example.com/api", "POST"),
            Mode::Default,
            &[Effect::Network],
        );
        assert!(d.is_prompt(), "strict mode should prompt for network when configured, got {d:?}");
    }

    #[test]
    fn strict_mode_preserves_bypass_permissions() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("rm -rf /"),
            Mode::BypassPermissions,
            &[Effect::Write, Effect::Fs, Effect::Irreversible],
        );
        assert!(d.is_allow(), "BypassPermissions should bypass even in strict mode, got {d:?}");
    }

    #[test]
    fn strict_mode_accept_edits_denies_irreversible() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("rm -rf ./build"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs, Effect::Irreversible],
        );
        assert!(d.is_prompt(), "strict AcceptEdits should prompt on irreversible, got {d:?}");
    }

    #[test]
    fn strict_mode_does_not_affect_dont_ask() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("some-unknown"),
            Mode::DontAsk,
            &[Effect::Read],
        );
        assert!(d.is_deny(), "DontAsk should deny, got {d:?}");
    }

    #[test]
    fn non_strict_mode_allows_unknown_with_fallthrough() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(false));
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("random-unknown-cmd"),
            Mode::Default,
            &[Effect::Read],
        );
        assert!(d.is_allow(), "non-strict mode should allow unknown commands, got {d:?}");
    }

    #[test]
    fn strict_mode_safe_list_restricted_allow() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        // "ls" is on the strict whitelist (read-only, zero side-effects).
        let d = e.evaluate(&mut s, &ToolCall::bash("ls"), Mode::Default, &[Effect::Fs]);
        assert!(d.is_allow(), "ls is on the strict whitelist, got {d:?}");
    }

    // =======================================================================
    // NEW: Network policy wired into engine (Fix 3)
    // =======================================================================

    #[test]
    fn network_policy_default_allows_github() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::network("https://github.com/user/repo", "GET"),
            Mode::Default,
            &[Effect::Network],
        );
        assert!(d.is_allow(), "github.com should be allowed by default policy, got {d:?}");
    }

    #[test]
    fn network_policy_default_allows_npm() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::network("https://registry.npmjs.org/package", "GET"),
            Mode::Default,
            &[Effect::Network],
        );
        assert!(d.is_allow(), "registry.npmjs.org should be allowed, got {d:?}");
    }

    #[test]
    fn network_policy_default_denies_private_ip() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::network("http://10.0.0.1/api", "GET"),
            Mode::Default,
            &[Effect::Network],
        );
        assert!(d.is_deny(), "private IP 10.0.0.1 should be denied, got {d:?}");
    }

    #[test]
    fn network_policy_default_denies_exfiltration() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::network("telnet://evil.com", "GET"),
            Mode::Default,
            &[Effect::Network],
        );
        assert!(d.is_deny(), "telnet:// should be denied as exfiltration, got {d:?}");
    }

    #[test]
    fn network_policy_custom_override() {
        let mut custom = NetworkPolicy::new();
        custom.add_allowed_host("my-internal.com");
        let e = Engine::new(
            EngineConfig::builder()
                .working_dir("/work")
                .network_policy(custom)
                .build(),
        );
        let mut s = Session::with_id("test");
        // Custom policy allows my-internal.com but not github.com (empty allowed).
        let d = e.evaluate(
            &mut s,
            &ToolCall::network("https://my-internal.com/api", "GET"),
            Mode::Default,
            &[Effect::Network],
        );
        assert!(d.is_allow(), "custom allowed host should pass, got {d:?}");
    }

    // =======================================================================
    // NEW: Default PromptAlways protected paths (Fix 4)
    // =======================================================================

    #[test]
    fn prompt_always_overrides_bypass_for_ssh() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        // ~/.ssh should be PromptAlways by default.
        let home = dirs::home_dir().expect("home dir should exist");
        let ssh_config = home.join(".ssh").join("config");
        let d = e.evaluate(
            &mut s,
            &ToolCall::write(ssh_config.to_str().unwrap()),
            Mode::BypassPermissions,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_prompt(), "~/.ssh should prompt even in BypassPermissions, got {d:?}");
    }

    #[test]
    fn prompt_always_overrides_bypass_for_aws() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let home = dirs::home_dir().expect("home dir should exist");
        let aws_creds = home.join(".aws").join("credentials");
        let d = e.evaluate(
            &mut s,
            &ToolCall::write(aws_creds.to_str().unwrap()),
            Mode::BypassPermissions,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_prompt(), "~/.aws should prompt even in BypassPermissions, got {d:?}");
    }

    // =======================================================================
    // NEW: Strict mode restricted whitelist (Fix 5)
    // =======================================================================

    #[test]
    fn strict_mode_uses_restricted_whitelist_docker_denied() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        // docker ps is on the full whitelist but NOT the strict whitelist.
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("docker ps"),
            Mode::Default,
            &[Effect::Read],
        );
        assert!(d.is_deny(), "strict mode should deny docker ps, got {d:?}");
    }

    #[test]
    fn strict_mode_uses_restricted_whitelist_npm_denied() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("npm run test"),
            Mode::Default,
            &[Effect::Read],
        );
        assert!(d.is_deny(), "strict mode should deny npm, got {d:?}");
    }

    #[test]
    fn strict_mode_allows_git_status_on_restricted_list() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("git status"),
            Mode::Default,
            &[Effect::Read],
        );
        assert!(d.is_allow(), "strict mode should allow git status, got {d:?}");
    }

    #[test]
    fn strict_mode_allows_ls_on_restricted_list() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("ls -la"),
            Mode::Default,
            &[Effect::Fs],
        );
        assert!(d.is_allow(), "strict mode should allow ls, got {d:?}");
    }

    // =======================================================================
    // NEW: Compound command security through engine (Fix 1 verification)
    // =======================================================================

    #[test]
    fn compound_command_through_engine_denied() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        // "git status ; rm -rf /" should NOT be whitelisted.
        // It will fall through to dangerous pattern check (rm -rf matches).
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("git status ; rm -rf /"),
            Mode::Default,
            &[Effect::Read],
        );
        assert!(d.is_deny(), "compound command should be denied, got {d:?}");
    }
}
