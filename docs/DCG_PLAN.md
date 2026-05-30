# DCG Plan — dcg-core Implementation

> What to build in `/data/projects/destructive_command_guard/crates/dcg-core/`
> Synthesized from 9-repo research, dcg-core analysis, 3 rounds QA interview, discussion
> Date: 2026-05-30
> Branch: experiment/dcg-permission-modes

---

## 0. Decisions Made

| Topic | Decision | Source |
|-------|----------|--------|
| **Dangerous patterns** | Build in dcg-core, not jcode | Round 2 QA |
| **Safe command whitelist** | Build in dcg-core | Round 2 QA |
| **Denial escalation** | Build in dcg-core | Round 2 QA |
| **Path-aware escalation** | Build in dcg-core | Round 3 QA |
| **Strict mode** | One-way tightening (from oh-my-claudecode) | Discussion |
| **Pack rules** | Integrate dcg-cli's 50+ security packs into dcg-core | Round 3 QA |
| **Per-tool overrides** | TOML config in dcg-core | Discussion |
| **Network policy** | Future consideration | Discussion |
| **YOLO** | ❌ NOT in dcg-core — built in jcode only. dcg is pure rule-based engine | Discussion |
| **LLM/provider** | ❌ NOT in dcg-core — consumer-specific | Discussion |
| **OS sandboxing** | ❌ NOT in dcg-core | Discussion |

---

## 1. Architecture

```
dcg-core (library)
─────────────────────────────────────────────────────
Engine::evaluate(session, tool_call, mode, effects)
    │
    ├─► Mode::pre_check() → AllowImmediately / Deny / Continue
    ├─► ProtectedPaths check (path-aware escalation)
    ├─► Pack rule evaluation (Phase 2 — from dcg-cli)
    ├─► Dangerous command patterns (26-50 regex + severity + alternatives)
    ├─► Safe command whitelist (~50 read-only commands)
    ├─► Denial escalation (3 consecutive / 20 total)
    └─► Decision: Allow / Prompt{reason,alternatives} / Deny{reason,alternatives}

Already has (v0.6.0-rc.1):
  ✅ Mode (6 variants + pre_check)
  ✅ Effect (7 variants + is_read_only + is_subset)
  ✅ ToolCall (5 variants: Bash/Edit/Write/Read/Network)
  ✅ Decision (Allow/Prompt/Deny with reasons + alternatives)
  ✅ Session (allow-once codes + per-command deny counter)
  ✅ ProtectedPaths (prefix matcher + ~ expansion)
  ✅ EngineConfig builder (working_dir + protected_paths)
```

---

## 2. Phase Breakdown

### Phase 2.1 — Dangerous Command Patterns [P0]

**What:** 26-50 regex patterns classifying bash commands by danger level.

**Source:** claude-code `DANGEROUS_BASH_PATTERNS`, oh-my-pi `CRITICAL_BASH_PATTERNS`, pi-agent-rust `DangerousCommandClass`, codex `command_might_be_dangerous()`.

**New types:**
```rust
pub struct DangerousPattern {
    pub pattern: Regex,
    pub severity: DangerSeverity,
    pub category: DangerCategory,
    pub reason: String,
    pub alternatives: Vec<String>,
}

pub enum DangerSeverity {
    Low,      // Unusual but not destructive (e.g., curl without pipe)
    Medium,   // Potentially harmful (e.g., git push --force)
    High,     // Destructive (e.g., rm -rf, sudo)
    Critical, // Irreversible/system-level (e.g., dd, mkfs, fork bomb)
}

pub enum DangerCategory {
    RecursiveDelete,
    DiskDestruction,
    ForkBomb,
    RemoteFetchAndExecute,
    PermissionEscalation,
    SystemShutdown,
    CredentialModification,
    ReverseShell,
    NetworkExfiltration,
    ForcePush,
    DatabaseDestroy,
}
```

**Patterns to include:**
```
RecursiveDelete:
  rm -rf /, rm -rf /*, rm -rf ~, rm -rf --no-preserve-root
  rm -rf .git, rm -rf node_modules, rm -rf target
  sudo rm -rf, sudo rm -rf /

DiskDestruction:
  dd if= of=/dev/sda, dd if=/dev/zero of=/dev/sda
  mkfs, mkfs.ext4, mkfs.xfs, wipefs
  shred, dd if=/dev/urandom of=

ForkBomb:
  :(){:|:&};:, bomb(), fork()
  perl -e 'fork while fork', python -c 'import os; [fork() for _ in range(100)]'

RemoteFetchAndExecute:
  curl | bash, curl | sh, wget | bash, wget -O - | sh
  pip install | python, pip3 install | python3
  fetch('http://') | bash

PermissionEscalation:
  sudo, su, sudo su, sudo -i
  chmod 777, chmod o+w, chmod +x
  chown, chgrp root

SystemShutdown:
  shutdown -h now, shutdown -r now, halt, poweroff, reboot
  systemctl poweroff, init 0

CredentialModification:
  .bashrc modify, .zshrc modify, .profile modify
  sshauthorized_keys modify, known_hosts modify

ReverseShell:
  nc -l -p, ncat -l, /dev/tcp/, bash -i >& /dev/tcp/
  mkfifo, /tmp/f

NetworkExfiltration:
  curl http://, wget http://
  nc host port, telnet host port

ForcePush:
  git push --force, git push --force-with-lease
  git push --force-with-lease origin, git push -f

DatabaseDestroy:
  DROP DATABASE, DROP TABLE, TRUNCATE TABLE
  DELETE FROM .*, mysql --force
```

**Integration:** `Engine::evaluate()` calls `DangerousPatternRegistry::check(&tool_call, &effects)`. High/Critical severity → escalate to Prompt or Deny regardless of mode.

---

### Phase 2.2 — Safe Command Whitelist [P0]

**What:** Explicit allowlist of known-safe read-only commands that auto-approve in all modes (except DontAsk deny-listed ones).

**Source:** codex `is_known_safe_command()`, claude-code `readOnlyCommandValidation.ts`.

**New types:**
```rust
pub struct SafeCommandEntry {
    pub command: &'static str,          // e.g., "git"
    pub allowed_subcommands: &'static [&'static str], // e.g., ["status", "log", "diff", "show", "branch"]
    pub safe_flags: &'static [&'static str],          // e.g., ["--oneline", "--color"]
}

pub fn is_known_safe_command(cmd: &str) -> bool;
```

**Commands to whitelist:**
```
cat, head, tail, less, more, wc, tr, cut, sort, uniq, rev, nl, paste, seq, stat
ls, find (safe flags only), pwd, whoami, which, test, [
grep, rg (safe flags only), ag (safe flags only)
git status, git log, git diff, git show, git branch, git reflog, git stash list
  git fetch, git pull (read-only operations)
  git log --oneline, git log --graph, git log --stat
  git diff --cached, git diff HEAD
  git show --stat, git show --pretty
  git branch -a, git branch -v
gh issue view, gh issue list, gh pr view, gh pr list, gh pr status
  gh run list, gh run view
npm run lint, npm run check, npm run typecheck, npm run test
  pnpm lint, pnpm check, pnpm typecheck
  yarn lint, yarn check, yarn type-check
cargo check, cargo clippy, cargo test, cargo bench (no --release)
  cargo build --lib, cargo build --tests
tsc --noEmit, tsc --check, eslint, prettier --check
  mypy, ruff check, ruff format --check
make -n, make -q (dry-run/diff-mode only)
docker build, docker run --dry-run
  docker ps, docker images, docker logs, docker inspect
kubectl get, kubectl describe, kubectl apply --dry-run=client
  kubectl diff, kubectl get events
aws s3 ls, aws s3api get-object
  aws ec2 describe-instances, aws lambda list-functions
base64, md5sum, sha256sum, sha1sum, shasum
```

**Integration:** `Engine::evaluate()` calls `SafeCommandWhitelist::check(&tool_call)` before dangerous pattern check. Safe commands → Allow even in Plan mode.

---

### Phase 2.3 — Denial Escalation [P1]

**What:** Wire existing `Session::deny_counter` into escalation behavior.

**New types:**
```rust
pub struct DenialConfig {
    pub max_consecutive: u32,  // default: 3
    pub max_total: u32,        // default: 20
}

pub fn total_denials(&self) -> u32;
pub fn consecutive_denials(&self) -> u32;
pub fn reset_consecutive(&mut self);  // called on any allow
```

**Behavior:** When `consecutive_denials >= max_consecutive` OR `total_denials >= max_total`, override mode decision to `Prompt` (force interactive).

**Note:** `Session` already tracks deny counter in v0.6.0-rc.1. This phase wires it into `Engine::evaluate()` decision output.

---

### Phase 2.4 — Path-Aware Escalation [P1]

**What:** Writing to sensitive paths triggers Prompt even in AcceptEdits mode.

**Source:** oh-my-claudecode `isSensitiveRepoRelativePath()`, claude-code `DANGEROUS_FILES`, `DANGEROUS_DIRECTORIES`.

**New paths to always-prompt (even bypass):**
```
.env, .env.*, .env.local, .env.production
.git/, .git/config, .git/hooks
.gitconfig, .bashrc, .bash_profile, .zshrc, .profile
.ssh/, .ssh/authorized_keys, .ssh/config
.aws/, .aws/credentials, .aws/config
.gnupg/, .gnupg/secring.gpg
.mcp.json, .claude.json, .claude/settings.json
.claude/, .claude/projects/
.vscode/settings.json
**/secrets/**, **/credentials/**, **/.env*
**/.ssh/**, **/.git/objects/**
```

**Integration:** Extend `ProtectedPaths` with severity levels. Some paths always Prompt (even in BypassPermissions). Others Prompt only in non-bypass modes.

---

### Phase 2.5 — Strict Mode / One-Way Tightening [P1]

**What:** A strictness level that can only tighten, never relax. From oh-my-claudecode.

**Source:** `src/lib/security-config.ts` `OMC_SECURITY=strict` in oh-my-claudecode.

**New types:**
```rust
pub enum StrictnessLevel {
    Default,  // normal operation
    Strict,   // tightens everything
}

pub struct EngineConfig {
    // ...existing fields...
    pub strictness: StrictnessLevel,
}

impl EngineConfig {
    pub fn with_strictness(mut self, level: StrictnessLevel) -> Self;
}
```

**Strict mode effects:**
- BypassPermissions cannot be activated
- `max_consecutive` reduced to 5 (from 3)
- `max_total` reduced to 5 (from 20)
- Safe command whitelist restricted to minimal set only
- All network operations → Prompt
- AcceptEdits auto-allow disabled
- `Strict` cannot be overridden by TOML config (one-way)

---

### Phase 2.6 — Per-Tool User Overrides (TOML) [P2]

**What:** TOML config for allow/deny/prompt per tool pattern.

**Config schema:**
```toml
[permissions]
default_mode = "default"

[permissions.protected_paths]
always_prompt = ["~/.ssh", "~/.aws", ".git", ".env"]
always_prompt_recursive = ["**/secrets/**", "**/.ssh/**"]

[permissions.tools]
bash = "prompt"           # Always prompt for bash
edit = "allow"            # Always allow edits
read = "allow"            # Always allow reads
webfetch = "prompt"       # Always prompt for network
"bash:git *" = "allow"   # Pattern-specific
"bash:rm *" = "deny"     # Pattern-specific: always deny

[permissions.denial]
max_consecutive = 3
max_total = 20

[permissions.safe_commands]
enabled = true
extra = ["just", "make check"]
deny = ["git branch -D"]
```

**Resolution chain:**
```
CLI flag > env var > project config.toml > user config.toml > Engine defaults
```

**Strict cannot be overridden** by config (one-way tightening).

---

### Phase 2.7 — Pack Rule Integration [P2]

**What:** Migrate dcg-cli's 50+ security packs into dcg-core.

**Source:** `/data/projects/destructive_command_guard/crates/dcg-cli/src/packs/`

**Components to migrate:**
- `PackRegistry` — Aho-Corasick keyword pre-filter + RegexSet batch matching
- `SafePattern` — 34 whitelist regex patterns
- `DestructivePattern` — blacklist with severity, alternatives, Tier-A effects
- 20+ categories: core, database, cloud, kubernetes, containers, system, infrastructure...
- Allowlist system (project `.dcg/allowlist.toml`, user `~/.config/dcg/allowlist.toml`, system)

**Integration:** Add `PackRuleEngine` to `Engine::evaluate()` pipeline after dangerous patterns check.

---

### Phase 2.8 — Network Policy [P3]

**What:** Host allowlist/denylist for network calls.

**Future consideration** — not blocking for MVP.

---

## 3. Dependency Map

```
Phase 2.1 Dangerous Patterns ─────┐
Phase 2.2 Safe Command Whitelist ─┤ (can run in parallel)
Phase 2.3 Denial Escalation ──────┤
Phase 2.4 Path-Aware Escalation ──┤
Phase 2.5 Strict Mode ────────────┘
    │
    ▼
Phase 2.6 Per-Tool Overrides (TOML)
Phase 2.7 Pack Rule Integration
    │
    ▼
Phase 2.8 Network Policy (Phase 3)
```

---

## 4. Success Criteria

- [ ] `DangerousPatternRegistry` with 26+ patterns + severity + alternatives
- [ ] `SafeCommandWhitelist::is_known_safe_command()` — 50+ commands whitelisted
- [ ] Denial escalation wired: 3 consecutive / 20 total → Prompt
- [ ] Protected paths always-prompt even in BypassPermissions
- [ ] Strict mode: one-way tightening, cannot be weakened by config
- [ ] TOML per-tool overrides work correctly
- [ ] Pack rule engine integrated (Phase 2)
- [ ] All existing tests pass
- [ ] New tests for all patterns + edge cases
- [ ] `cargo check` + `cargo test` pass with zero errors
