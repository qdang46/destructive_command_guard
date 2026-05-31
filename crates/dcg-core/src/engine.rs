//! `Engine` — top-level entry point that combines [`Mode`], [`ToolCall`],
//! and pack rules into a [`Decision`].

use std::path::{Path, PathBuf};

use crate::dangerous_patterns::{DangerousPatternRegistry, evaluate_dangerous};
use crate::decision::Decision;
use crate::effect::Effect;
use crate::escalation::DenialConfig;
use crate::mode::{Mode, ModePreCheck};
use crate::network_policy::NetworkPolicy;
use crate::protected_paths::ProtectedPaths;
use crate::safe_whitelist::SafeCommandWhitelist;
use crate::session::Session;
use crate::strictness::Strictness;
use crate::tool_call::ToolCall;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub(crate) working_dir: PathBuf,
    pub(crate) protected_paths_raw: Vec<String>,
    pub(crate) strictness: Strictness,
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

    #[must_use]
    pub fn build(self) -> EngineConfig {
        let working_dir = self
            .working_dir
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        EngineConfig {
            working_dir,
            protected_paths_raw: self.protected_paths,
            strictness: self.strictness,
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self::builder().build()
    }
}

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
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        let protected = ProtectedPaths::new(
            config.protected_paths_raw.iter().cloned(),
            &config.working_dir,
        );
        let network_policy = NetworkPolicy::new();
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
    pub fn with_protected(config: EngineConfig, protected: ProtectedPaths) -> Self {
        let network_policy = NetworkPolicy::new();
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
            ModePreCheck::Continue => Self::fallthrough(
                session,
                tool,
                mode,
                effects,
                self.config.strictness,
                &self.safe_whitelist,
                &self.dangerous_registry,
                &self.denial_config,
                &self.network_policy,
            ),
        }
    }

    fn fallthrough(
        session: &mut Session,
        tool: &ToolCall,
        mode: Mode,
        effects: &[Effect],
        strictness: Strictness,
        safe_whitelist: &SafeCommandWhitelist,
        dangerous_registry: &DangerousPatternRegistry,
        denial_config: &DenialConfig,
        network_policy: &NetworkPolicy,
    ) -> Decision {
        let is_strict = strictness.is_strict();
        let strict_mode_active = is_strict && mode.fallthrough_allows();
        let is_network_effect = effects.iter().any(|e| *e == Effect::Network);

        // =====================================================================
        // Phase 2.8: Network policy check — runs before other fallthrough logic
        // =====================================================================
        if let ToolCall::Network { url, method } = tool {
            let severity = network_policy.evaluate_url(url);
            let short_code = format!("net:{}:{}", method.to_lowercase(), {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut h = DefaultHasher::new();
                url.hash(&mut h);
                format!("{:x}", h.finish() & 0xFFFF)
            });

            match severity {
                crate::network_policy::NetworkSeverity::Allowed => {
                    session.reset_on_allow();
                    return Decision::Allow;
                }
                crate::network_policy::NetworkSeverity::Suspicious => {
                    session.bump_deny_counter(&tool_repr(tool));
                    // network_escalates_to_prompt overrides strict mode to allow prompting instead of denying
                    if strictness.network_escalates_to_prompt {
                        return Decision::prompt(
                            format!("network: suspicious destination ({url})"),
                            short_code,
                        );
                    }
                    if strict_mode_active {
                        return Decision::deny(format!("network: suspicious destination ({url}) [strict mode]"));
                    }
                    return Decision::prompt(
                        format!("network: suspicious destination ({url})"),
                        short_code,
                    );
                }
                crate::network_policy::NetworkSeverity::Dangerous => {
                    session.bump_deny_counter(&tool_repr(tool));
                    return Decision::deny(format!("network: denied destination ({url})"));
                }
                crate::network_policy::NetworkSeverity::Exfiltration => {
                    session.bump_deny_counter(&tool_repr(tool));
                    return Decision::deny(format!("network: exfiltration pattern detected ({url})"));
                }
            }
        }

        if mode.fallthrough_allows() {
            if let Some(cmd) = tool.command_string() {
                if safe_whitelist.is_known_safe_command(cmd) {
                    session.reset_on_allow();
                    return Decision::Allow;
                }
                if let Some(decision) = evaluate_dangerous(dangerous_registry, tool) {
                    return decision;
                }
            }
            // In strict mode, unknown commands are denied and count toward escalation.
            if strict_mode_active {
                let cmd_repr = tool_repr(tool);
                session.bump_deny_counter(&cmd_repr);

                // Use strictness thresholds for escalation.
                let should_escalate = session.consecutive_denials() >= strictness.max_consecutive
                    || session.total_denials() >= strictness.max_total;

                // Network operations: escalate to prompt if configured.
                if strictness.network_escalates_to_prompt && is_network_effect {
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
            } else {
                session.reset_on_allow();
                Decision::Allow
            }
        } else {
            // Mode does not fallthrough-allow (DontAsk, Plan, etc.)
            let cmd_repr = tool_repr(tool);
            session.bump_deny_counter(&cmd_repr);

            // Use denial_config for escalation in non-strictDontAsk mode.
            if denial_config.should_escalate(session.consecutive_denials(), session.total_denials())
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
}

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
        s.working_dir = std::path::PathBuf::from("/work");
        let d = e.evaluate(
            &mut s,
            &ToolCall::write("/work/.git/config"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_prompt(), "got {d:?}");
        match d {
            Decision::Prompt {
                allow_once_code, ..
            } => {
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
        s.working_dir = std::path::PathBuf::from("/work");
        let d = e.evaluate(
            &mut s,
            &ToolCall::write(".git/config"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_prompt(), "got {d:?}");
    }

    // =============================================================================
    // Strictness tests — Phase 2.5
    // =============================================================================

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
        // Unknown command in Default mode with strictness should deny.
        let d = e.evaluate(&mut s, &ToolCall::bash("rm -rf /"), Mode::Default, &[Effect::Fs]);
        assert!(d.is_deny(), "strict mode should deny unknown commands, got {d:?}");
    }

    #[test]
    fn strict_mode_allows_safe_whitelisted_command() {
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        // git status is on the safe whitelist — should still be allowed.
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
        // git reset --hard matches a dangerous pattern — should deny even in strict mode.
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

        // With max_consecutive=3, escalation happens AT the 3rd denial (>= 3).
        // The first 2 denials stay as Deny; the 3rd escalates to Prompt.
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

        // A 4th denial should still be Prompt (already escalated).
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

        // 3 denials should reach max_total=3 and escalate.
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
        // Network call not on safe list — should deny (network_escalates_to_prompt=false by default).
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
        // Network call with network_escalates_to_prompt=true should prompt.
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
        // BypassPermissions should still bypass — strictness doesn't affect it.
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
        // AcceptEdits normally prompts on Irreversible; in strict mode it should still prompt
        // (not use fallthrough-allow), and the dangerous pattern check also runs.
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
        // DontAsk already denies non-whitelisted commands — strictness is a no-op for it.
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
        // Without strictness, unknown commands fall through to Allow.
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
        // In strict mode, only whitelisted commands are auto-allowed.
        // Non-whitelisted commands (even safe-looking ones) are denied.
        let e = engine_with_strictness(vec![], "/work", Strictness::new(true));
        let mut s = Session::with_id("test");
        // "cd /tmp" — cd is on the whitelist, so allowed.
        let d = e.evaluate(&mut s, &ToolCall::bash("cd /tmp"), Mode::Default, &[Effect::Fs]);
        assert!(d.is_allow(), "cd is whitelisted, got {d:?}");
    }
}
