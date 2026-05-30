//! `Engine` — top-level entry point that combines [`Mode`], [`ToolCall`],
//! and pack rules into a [`Decision`].

use std::path::{Path, PathBuf};

use crate::dangerous_patterns::{DangerousPatternRegistry, evaluate_dangerous};
use crate::decision::Decision;
use crate::effect::Effect;
use crate::escalation::DenialConfig;
use crate::mode::{Mode, ModePreCheck};
use crate::protected_paths::ProtectedPaths;
use crate::safe_whitelist::SafeCommandWhitelist;
use crate::session::Session;
use crate::tool_call::ToolCall;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub(crate) working_dir: PathBuf,
    pub(crate) protected_paths_raw: Vec<String>,
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
}

#[derive(Debug, Default, Clone)]
pub struct EngineConfigBuilder {
    working_dir: Option<PathBuf>,
    protected_paths: Vec<String>,
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
    pub fn build(self) -> EngineConfig {
        let working_dir = self
            .working_dir
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        EngineConfig {
            working_dir,
            protected_paths_raw: self.protected_paths,
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
}

impl Engine {
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        let protected = ProtectedPaths::new(
            config.protected_paths_raw.iter().cloned(),
            &config.working_dir,
        );
        Self {
            config,
            protected,
            safe_whitelist: SafeCommandWhitelist::new(),
            dangerous_registry: DangerousPatternRegistry::new(),
            denial_config: DenialConfig::default(),
        }
    }

    #[must_use]
    pub fn with_protected(config: EngineConfig, protected: ProtectedPaths) -> Self {
        Self {
            config,
            protected,
            safe_whitelist: SafeCommandWhitelist::new(),
            dangerous_registry: DangerousPatternRegistry::new(),
            denial_config: DenialConfig::default(),
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

        let final_pre_check = if pre_check == ModePreCheck::AllowImmediately
            && mode == Mode::BypassPermissions
        {
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
            ModePreCheck::Continue => Self::fallthrough(session, tool, mode, &self.safe_whitelist, &self.dangerous_registry, &self.denial_config),
        }
    }

    fn fallthrough(
        session: &mut Session,
        tool: &ToolCall,
        mode: Mode,
        safe_whitelist: &SafeCommandWhitelist,
        dangerous_registry: &DangerousPatternRegistry,
        denial_config: &DenialConfig,
    ) -> Decision {
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
            session.reset_on_allow();
            Decision::Allow
        } else {
            let cmd_repr = tool_repr(tool);
            session.bump_deny_counter(&cmd_repr);
            if denial_config.should_escalate(session.consecutive_denials(), session.total_denials()) {
                let code = session.generate_allow_once_code(&cmd_repr);
                Decision::prompt(
                    format!("Escalated: {} consecutive denials, {} total denials",
                        session.consecutive_denials(), session.total_denials()),
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
}