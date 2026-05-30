//! Tests for denial escalation — Phase 2.3
use dcg_core::{DenialConfig, Engine, EngineConfig, Mode, Session, ToolCall, Effect};

#[test]
fn test_default_escalation_thresholds() {
    let config = DenialConfig::default();
    assert_eq!(config.max_consecutive, 3);
    assert_eq!(config.max_total, 20);
}

#[test]
fn test_should_escalate_consecutive() {
    let config = DenialConfig::default();
    assert!(!config.should_escalate(2, 0));
    assert!(config.should_escalate(3, 0));
    assert!(config.should_escalate(10, 5));
}

#[test]
fn test_should_escalate_total() {
    let config = DenialConfig::default();
    assert!(!config.should_escalate(0, 19));
    assert!(config.should_escalate(0, 20));
    assert!(config.should_escalate(1, 20));
}

#[test]
fn test_custom_escalation_thresholds() {
    let config = DenialConfig::new(5, 10);
    assert!(!config.should_escalate(4, 9));
    assert!(config.should_escalate(5, 9));
    assert!(config.should_escalate(4, 10));
}

#[test]
fn test_session_consecutive_denials() {
    let mut session = Session::with_id("test");
    assert_eq!(session.consecutive_denials(), 0);
    assert_eq!(session.total_denials(), 0);
    
    session.bump_consecutive_denials();
    session.bump_consecutive_denials();
    assert_eq!(session.consecutive_denials(), 2);
    assert_eq!(session.total_denials(), 2);
}

#[test]
fn test_session_reset_on_allow() {
    let mut session = Session::with_id("test");
    session.bump_consecutive_denials();
    session.bump_consecutive_denials();
    assert_eq!(session.consecutive_denials(), 2);
    
    session.reset_on_allow();
    assert_eq!(session.consecutive_denials(), 0);
    assert_eq!(session.total_denials(), 2);
}

#[test]
fn test_escalation_triggers_prompt() {
    let config = EngineConfig::builder()
        .working_dir("/work")
        .build();
    let engine = Engine::new(config);
    let mut session = Session::with_id("test");
    
    // 2 denials should not escalate
    for _ in 0..2 {
        let d = engine.evaluate(&mut session, &ToolCall::bash("unknown-cmd"), Mode::DontAsk, &[Effect::Read]);
        assert!(d.is_deny(), "Expected deny, got {d:?}");
    }
    
    // 3rd denial should escalate to prompt (consecutive >= max_consecutive)
    let d = engine.evaluate(&mut session, &ToolCall::bash("another-unknown"), Mode::DontAsk, &[Effect::Read]);
    assert!(d.is_prompt(), "Expected prompt after escalation, got {d:?}");
}