//! `dcg-core` — core library for [Destructive Command Guard][dcg] (dcg) v0.6.
//!
//! This crate provides the permission-modes API. Consumer applications
//! (`dcg` CLI, jcode, Codex, Hermes, Grok, …) link this crate directly
//! instead of shelling out to the `dcg` binary.
//!
//! # API surface
//!
//! - [`Engine`] — top-level command guard, built from [`EngineConfig`].
//! - [`Session`] — per-agent-run state (allow-once cache, deny counters).
//! - [`ToolCall`] — payload describing the tool the agent invoked.
//! - [`Mode`] — permission mode in effect for the evaluation.
//! - [`Effect`] — taxonomy of effects rules can declare and modes can filter on.
//! - [`Decision`] — three-state outcome (`Allow` / `Prompt` / `Deny`).
//!
//! # Example
//!
//! ```
//! use std::path::PathBuf;
//! use dcg_core::{Engine, EngineConfig, Mode, Session, ToolCall, Effect, Decision};
//!
//! let engine = Engine::new(
//!     EngineConfig::builder()
//!         .working_dir(PathBuf::from("/work/project"))
//!         .protected_paths(vec!["~/.ssh".into(), ".git".into()])
//!         .build(),
//! );
//! let mut session = Session::with_working_dir(PathBuf::from("/work/project"));
//!
//! let call = ToolCall::bash("git status");
//! let decision = engine.evaluate(&mut session, &call, Mode::Plan, &[Effect::Read]);
//! assert!(matches!(decision, Decision::Allow));
//! ```
//!
//! # Status
//!
//! `0.6.0-rc.1` — Phase A (core API + Session + tests). The pack-rule
//! evaluation layer will be wired in during Phase 2 (see project plan).
//!
//! [dcg]: https://github.com/Dicklesworthstone/destructive_command_guard

#![forbid(unsafe_code)]

pub mod dangerous_patterns;
pub mod decision;
pub mod effect;
pub mod engine;
pub mod escalation;
pub mod mode;
pub mod network_policy;
pub mod protected_paths;
pub mod safe_whitelist;
pub mod session;
pub mod strictness;
pub mod tool_call;

pub use dangerous_patterns::{DangerousMatch, DangerousPatternRegistry, Severity};
pub use decision::Decision;
pub use effect::{Effect, is_subset as is_effect_subset};
pub use engine::{Engine, EngineConfig, EngineConfigBuilder};
pub use escalation::DenialConfig;
pub use mode::{Mode, ModePreCheck};
pub use network_policy::{
    default_policy, NetworkPolicy, NetworkSeverity,
};
pub use protected_paths::{ProtectedPathEntry, ProtectedPaths, ProtectedSeverity};
pub use safe_whitelist::SafeCommandWhitelist;
pub use session::{ALLOW_ONCE_CODE_LEN, ALLOW_ONCE_TTL, AllowOnceEntry, Session};
#[allow(deprecated)]
pub use strictness::{Strictness, apply_strictness};
pub use tool_call::ToolCall;
