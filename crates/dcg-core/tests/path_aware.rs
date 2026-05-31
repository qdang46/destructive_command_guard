//! Path-aware severity tests — `BypassPermissions` must still prompt for
//! `PromptAlways` paths like ~/.ssh/, credentials/, .env files.

use dcg_core::{
    Effect, Engine, EngineConfig, Mode, ProtectedPathEntry, ProtectedPaths, ProtectedSeverity,
    Session, ToolCall,
};

fn engine_with_severity_entries() -> (Engine, Session) {
    let entries = vec![
        ProtectedPathEntry::new(
            std::path::PathBuf::from("/home/test/.ssh"),
            ProtectedSeverity::PromptAlways,
        ),
        ProtectedPathEntry::new(
            std::path::PathBuf::from("/home/test/.aws"),
            ProtectedSeverity::PromptAlways,
        ),
        ProtectedPathEntry::new(
            std::path::PathBuf::from("/home/test/.gnupg"),
            ProtectedSeverity::PromptAlways,
        ),
        ProtectedPathEntry::new(
            std::path::PathBuf::from("/home/test/.git"),
            ProtectedSeverity::PromptInNonBypass,
        ),
        ProtectedPathEntry::new(
            std::path::PathBuf::from("/etc"),
            ProtectedSeverity::PromptInNonBypass,
        ),
        ProtectedPathEntry::new(
            std::path::PathBuf::from("/tmp"),
            ProtectedSeverity::AllowInBypass,
        ),
    ];

    let protected = ProtectedPaths::with_entries(entries);
    let config = EngineConfig::builder()
        .working_dir("/home/test/work")
        .protected_paths(vec![])
        .build();

    let engine = Engine::with_protected(config, protected);
    let mut session = Session::with_id("test");
    session.working_dir = std::path::PathBuf::from("/home/test/work");
    (engine, session)
}

#[test]
fn test_ssh_path_prompts_even_in_bypass() {
    let (engine, mut session) = engine_with_severity_entries();

    let tool = ToolCall::write("/home/test/.ssh/authorized_keys");
    let decision = engine.evaluate(
        &mut session,
        &tool,
        Mode::BypassPermissions,
        &[Effect::Write, Effect::Fs],
    );

    assert!(
        decision.is_prompt(),
        "SSH path should Prompt in `BypassPermissions`, got {decision:?}"
    );
}

#[test]
fn test_gnupg_path_prompts_even_in_bypass() {
    let (engine, mut session) = engine_with_severity_entries();

    let tool = ToolCall::write("/home/test/.gnupg/secring.gpg");
    let decision = engine.evaluate(
        &mut session,
        &tool,
        Mode::BypassPermissions,
        &[Effect::Write, Effect::Fs],
    );

    assert!(
        decision.is_prompt(),
        "GnuPG path should Prompt in `BypassPermissions`, got {decision:?}"
    );
}

#[test]
fn test_aws_path_prompts_even_in_bypass() {
    let (engine, mut session) = engine_with_severity_entries();

    let tool = ToolCall::write("/home/test/.aws/credentials");
    let decision = engine.evaluate(
        &mut session,
        &tool,
        Mode::BypassPermissions,
        &[Effect::Write, Effect::Fs],
    );

    assert!(
        decision.is_prompt(),
        "AWS credentials path should Prompt in `BypassPermissions`, got {decision:?}"
    );
}

#[test]
fn test_tmp_allowed_in_bypass() {
    let (engine, mut session) = engine_with_severity_entries();

    let tool = ToolCall::write("/tmp/build/output.txt");
    let decision = engine.evaluate(
        &mut session,
        &tool,
        Mode::BypassPermissions,
        &[Effect::Write, Effect::Fs],
    );

    assert!(
        decision.is_allow(),
        "Temp path should Allow in `BypassPermissions`, got {decision:?}"
    );
}

#[test]
fn test_git_dir_allowed_in_bypass() {
    let (engine, mut session) = engine_with_severity_entries();

    let tool = ToolCall::write("/home/test/.git/config");
    let decision = engine.evaluate(
        &mut session,
        &tool,
        Mode::BypassPermissions,
        &[Effect::Write, Effect::Fs],
    );

    assert!(
        decision.is_allow(),
        ".git path in `BypassPermissions` should Allow (`PromptInNonBypass`), got {decision:?}"
    );
}

#[test]
fn test_etc_allowed_in_bypass() {
    let (engine, mut session) = engine_with_severity_entries();

    let tool = ToolCall::write("/etc/passwd");
    let decision = engine.evaluate(
        &mut session,
        &tool,
        Mode::BypassPermissions,
        &[Effect::Write, Effect::Fs],
    );

    assert!(
        decision.is_allow(),
        "/etc in `BypassPermissions` should Allow (`PromptInNonBypass`), got {decision:?}"
    );
}

#[test]
fn test_bypass_allows_normal_paths() {
    let (engine, mut session) = engine_with_severity_entries();

    let tool = ToolCall::write("/home/test/work/src/main.rs");
    let decision = engine.evaluate(
        &mut session,
        &tool,
        Mode::BypassPermissions,
        &[Effect::Write, Effect::Fs],
    );

    assert!(
        decision.is_allow(),
        "Normal path should Allow in `BypassPermissions`, got {decision:?}"
    );
}

#[test]
fn test_bypass_allows_dangerous_effects_on_normal_path() {
    let (engine, mut session) = engine_with_severity_entries();

    let tool = ToolCall::bash("rm -rf /home/test/work/build");
    let decision = engine.evaluate(
        &mut session,
        &tool,
        Mode::BypassPermissions,
        &[Effect::Write, Effect::Fs, Effect::Irreversible],
    );

    assert!(
        decision.is_allow(),
        "`BypassPermissions` should Allow dangerous effects on non-`PromptAlways` paths, got {decision:?}"
    );
}

#[test]
fn test_check_severity_returns_correct_level() {
    let (engine, _) = engine_with_severity_entries();

    let ssh_severity = engine
        .protected_paths()
        .check_severity(std::path::Path::new("/home/test/.ssh/authorized_keys"));
    assert_eq!(
        ssh_severity,
        Some(ProtectedSeverity::PromptAlways),
        "SSH path should have PromptAlways severity"
    );

    let tmp_severity = engine
        .protected_paths()
        .check_severity(std::path::Path::new("/tmp/file.txt"));
    assert_eq!(
        tmp_severity,
        Some(ProtectedSeverity::AllowInBypass),
        "Tmp path should have AllowInBypass severity"
    );

    let git_severity = engine
        .protected_paths()
        .check_severity(std::path::Path::new("/home/test/.git/config"));
    assert_eq!(
        git_severity,
        Some(ProtectedSeverity::PromptInNonBypass),
        ".git path should have PromptInNonBypass severity"
    );

    let unknown_severity = engine
        .protected_paths()
        .check_severity(std::path::Path::new("/home/test/work/src/main.rs"));
    assert!(
        unknown_severity.is_none(),
        "Non-protected path should return None, got {unknown_severity:?}"
    );
}

#[test]
fn test_is_prompt_always() {
    let (engine, _) = engine_with_severity_entries();

    assert!(
        engine
            .protected_paths()
            .is_prompt_always(std::path::Path::new("/home/test/.ssh/authorized_keys")),
        "SSH path should be PromptAlways"
    );

    assert!(
        !engine
            .protected_paths()
            .is_prompt_always(std::path::Path::new("/tmp/file.txt")),
        "Tmp path should NOT be PromptAlways"
    );

    assert!(
        !engine
            .protected_paths()
            .is_prompt_always(std::path::Path::new("/home/test/work/src/main.rs")),
        "Non-protected path should NOT be PromptAlways"
    );
}
