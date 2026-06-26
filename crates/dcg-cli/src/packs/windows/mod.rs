//! Windows-native destructive-command packs (cmd.exe + PowerShell).
//!
//! Every other pack in dcg targets Unix-shaped commands (`rm -rf`, `git reset
//! --hard`) or platform-neutral tooling. A native-Windows agent in cmd.exe or
//! PowerShell has an entirely different destructive vocabulary that those packs
//! do not cover at all. These packs add that coverage.
//!
//! ## Case-insensitivity convention (IMPORTANT)
//!
//! Windows commands are case-insensitive (`RD /S /Q` == `rd /s /q`,
//! `Remove-Item` == `remove-item`). Two layers must account for this:
//!
//! 1. **Regex patterns** match case-insensitively via an inline `(?i)` flag on
//!    every pattern. This is the authoritative gate, so once a command reaches
//!    the regex stage any casing is matched.
//! 2. **Keyword quick-reject** (the hot-path pre-filter that decides whether a
//!    pack's regexes run at all) is a *case-sensitive* substring/Aho-Corasick
//!    match for zero-allocation performance on the Unix hot path (dcg's design
//!    guarantees no allocation there for safe commands). To avoid a pack being
//!    skipped before its `(?i)` regex runs, each pack enumerates the **realistic
//!    casings** of its keywords: lowercase + UPPERCASE for cmd verbs (agents and
//!    humans write `del` or `DEL`), and canonical PascalCase + lowercase for
//!    PowerShell cmdlets (`Remove-Item` / `remove-item`). Pathological mixed-case
//!    obfuscation (`dEl`) is intentionally out of scope — it is not a realistic
//!    honest mistake and falls under the documented "a determined attacker can
//!    bypass this hook" threat model. The `windows_keyword_casings` helper
//!    generates these casings so packs stay terse and consistent.
//!
//! ## Default enablement
//!
//! These packs are registered on every platform but default-ON only under
//! `cfg(windows)` (see `PacksConfig::enabled_pack_ids`), so a fresh Windows
//! install is protected with no config while Unix pays no quick-reject cost for
//! Windows verbs by default. They remain available (opt-in) on Unix for e.g.
//! scanning committed `.ps1`/`.cmd` scripts in CI.

pub mod filesystem;
pub mod misc;
pub mod powershell;
pub mod system;
