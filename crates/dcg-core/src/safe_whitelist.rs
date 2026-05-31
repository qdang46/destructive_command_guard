//! Safe command whitelist — Phase 2.2
//! Commands that are always allowed regardless of mode.
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct SafeCommandEntry {
    pub verb: &'static str,
    pub allowed_subcommands: &'static [&'static str],
}

#[derive(Clone, Debug)]
pub struct SafeCommandWhitelist {
    entries: Vec<SafeCommandEntry>,
    verb_index: HashMap<&'static str, usize>,
}

impl Default for SafeCommandWhitelist {
    fn default() -> Self {
        Self::new()
    }
}

impl SafeCommandWhitelist {
    #[allow(clippy::too_many_lines)]
    pub fn new() -> Self {
        let entries = vec![
            // Git (read and safe write operations)
            SafeCommandEntry {
                verb: "git",
                allowed_subcommands: &[
                    "status", "log", "diff", "show", "branch", "tag", "reflog", "shortlog", "add",
                    "commit", "merge", "rebase", "stash", "fetch", "pull", "clone", "init",
                    "config", "switch", "restore",
                ],
            },
            // File reading
            SafeCommandEntry {
                verb: "cat",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "head",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "tail",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "less",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "more",
                allowed_subcommands: &[],
            },
            // Search
            SafeCommandEntry {
                verb: "grep",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "rg",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "ag",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "find",
                allowed_subcommands: &[],
            },
            // Listing
            SafeCommandEntry {
                verb: "ls",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "tree",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "stat",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "file",
                allowed_subcommands: &[],
            },
            // System info
            SafeCommandEntry {
                verb: "pwd",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "whoami",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "id",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "uname",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "ps",
                allowed_subcommands: &[],
            },
            // Disk usage
            SafeCommandEntry {
                verb: "wc",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "du",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "df",
                allowed_subcommands: &[],
            },
            // Command location
            SafeCommandEntry {
                verb: "which",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "whereis",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "type",
                allowed_subcommands: &[],
            },
            // Network diagnostics
            SafeCommandEntry {
                verb: "ping",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "traceroute",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "netstat",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "ss",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "dig",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "nslookup",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "host",
                allowed_subcommands: &[],
            },
            // Build tools
            SafeCommandEntry {
                verb: "cargo",
                allowed_subcommands: &["check", "build", "test", "bench", "run", "fmt", "clippy"],
            },
            SafeCommandEntry {
                verb: "npm",
                allowed_subcommands: &["run", "install", "test", "start", "build", "lint"],
            },
            SafeCommandEntry {
                verb: "yarn",
                allowed_subcommands: &["run", "install", "test", "start", "build"],
            },
            SafeCommandEntry {
                verb: "pnpm",
                allowed_subcommands: &["run", "install", "test", "start", "build"],
            },
            SafeCommandEntry {
                verb: "pip",
                allowed_subcommands: &["install", "download", "list", "show"],
            },
            SafeCommandEntry {
                verb: "pip3",
                allowed_subcommands: &["install", "download", "list", "show"],
            },
            SafeCommandEntry {
                verb: "python",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "python3",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "go",
                allowed_subcommands: &["build", "test", "run", "get", "mod", "fmt", "vet"],
            },
            SafeCommandEntry {
                verb: "cmake",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "make",
                allowed_subcommands: &[],
            },
            // K8s (read ops)
            SafeCommandEntry {
                verb: "kubectl",
                allowed_subcommands: &[
                    "get", "describe", "logs", "top", "rollout", "status", "explain", "apply",
                    "create",
                ],
            },
            // Docker (read ops)
            SafeCommandEntry {
                verb: "docker",
                allowed_subcommands: &[
                    "pull", "build", "images", "ps", "inspect", "logs", "stats", "history",
                    "search", "login", "logout",
                ],
            },
            // AWS (read ops)
            SafeCommandEntry {
                verb: "aws",
                allowed_subcommands: &["s3", "ec2", "iam", "lambda", "rds", "eks", "logs", "sts"],
            },
            // Shell builtins
            SafeCommandEntry {
                verb: "echo",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "printf",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "test",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "cd",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "pushd",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "popd",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "alias",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "unalias",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "export",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "set",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "shopt",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "ulimit",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "umask",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "true",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "false",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "yes",
                allowed_subcommands: &[],
            },
            // SSH key gen
            SafeCommandEntry {
                verb: "ssh-keygen",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "ssh-add",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "ssh",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "scp",
                allowed_subcommands: &[],
            },
            SafeCommandEntry {
                verb: "rsync",
                allowed_subcommands: &[],
            },
        ];

        let mut verb_index: HashMap<&'static str, usize> = HashMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            verb_index.insert(entry.verb, idx);
        }
        Self {
            entries,
            verb_index,
        }
    }

    /// Parse command into verb + subcommand, check if whitelisted.
    /// Returns true for commands like "git status", "ls -la", "git reset --hard"
    pub fn is_known_safe_command(&self, cmd: &str) -> bool {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return false;
        }
        let verb = parts[0];

        if let Some(&idx) = self.verb_index.get(verb) {
            let entry = &self.entries[idx];
            if entry.allowed_subcommands.is_empty() {
                // No subcommand restriction — verb alone is whitelisted
                return true;
            }
            if parts.len() >= 2 {
                let subcommand = parts[1];
                // Check subcommand (handle leading dashes like "git log -n 5")
                let subcommand_clean = subcommand.trim_start_matches('-');
                for allowed in entry.allowed_subcommands {
                    if *allowed == subcommand_clean {
                        return true;
                    }
                }
            }
        }
        false
    }
}
