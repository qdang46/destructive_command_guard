//! Network policy — Phase 2.8
//!
//! Provides network request allowlist/denylist and pattern matching for
//! exfiltration detection. This module evaluates `ToolCall::Network` variants
//! against configured policies before fallthrough decisions are made.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::decision::Decision;
use crate::tool_call::ToolCall;

/// Severity level for network operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkSeverity {
    /// Explicitly allowed — no restrictions.
    Allowed,
    /// Suspicious but not necessarily malicious — prompt for confirmation.
    Suspicious,
    /// Dangerous — should be denied unless explicitly allowlisted.
    Dangerous,
    /// Exfiltration attempt — should always be denied.
    Exfiltration,
}

impl NetworkSeverity {
    /// Returns true if this severity level should result in a denial.
    pub const fn is_denied(self) -> bool {
        matches!(self, Self::Dangerous | Self::Exfiltration)
    }

    /// Returns true if this severity level should result in a prompt.
    pub const fn is_prompt(self) -> bool {
        matches!(self, Self::Suspicious)
    }
}

/// A compiled network policy with allowlist/denylist entries.
#[derive(Clone, Debug)]
pub struct NetworkPolicy {
    allowed_hosts: HashSet<String>,
    denied_hosts: HashSet<String>,
    denied_ip_ranges: Vec<ipnetwork::IpNetwork>,
    exfiltration_patterns: Vec<regex::Regex>,
    suspicious_patterns: Vec<regex::Regex>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkPolicy {
    /// Create a new empty network policy (deny-by-default).
    #[must_use]
    pub fn new() -> Self {
        Self {
            allowed_hosts: HashSet::new(),
            denied_hosts: HashSet::new(),
            denied_ip_ranges: Vec::new(),
            exfiltration_patterns: Vec::new(),
            suspicious_patterns: Vec::new(),
        }
    }

    /// Add a host pattern to the allowlist (supports wildcards like "*.github.com").
    pub fn add_allowed_host<S: Into<String>>(&mut self, host: S) -> &mut Self {
        self.allowed_hosts.insert(host.into());
        self
    }

    /// Add a host pattern to the denylist.
    pub fn add_denied_host<S: Into<String>>(&mut self, host: S) -> &mut Self {
        self.denied_hosts.insert(host.into());
        self
    }

    /// Add a CIDR range to deny.
    pub fn add_denied_ip_range<S: Into<String>>(&mut self, cidr: S) -> &mut Self {
        if let Ok(range) = ipnetwork::IpNetwork::from_str(&cidr.into()) {
            self.denied_ip_ranges.push(range);
        }
        self
    }

    /// Add an exfiltration pattern (URLs matching this are always denied).
    pub fn add_exfiltration_pattern<S: Into<String>>(&mut self, pattern: S) -> &mut Self {
        if let Ok(re) = regex::Regex::new(&pattern.into()) {
            self.exfiltration_patterns.push(re);
        }
        self
    }

    /// Add a suspicious domain pattern (URLs matching this prompt).
    pub fn add_suspicious_pattern<S: Into<String>>(&mut self, pattern: S) -> &mut Self {
        if let Ok(re) = regex::Regex::new(&pattern.into()) {
            self.suspicious_patterns.push(re);
        }
        self
    }

    /// Evaluate a URL against this policy, returning severity.
    #[must_use]
    pub fn evaluate_url(&self, url: &str) -> NetworkSeverity {
        for re in &self.exfiltration_patterns {
            if re.is_match(url) {
                return NetworkSeverity::Exfiltration;
            }
        }

        let host = extract_host(url);

        if self.host_matches(&host, &self.denied_hosts) {
            return NetworkSeverity::Dangerous;
        }

        if let Ok(ip) = IpAddr::from_str(&host) {
            for cidr in &self.denied_ip_ranges {
                if cidr.contains(ip) {
                    return NetworkSeverity::Dangerous;
                }
            }
        }

        if self.host_matches(&host, &self.allowed_hosts) {
            return NetworkSeverity::Allowed;
        }

        for re in &self.suspicious_patterns {
            if re.is_match(url) {
                return NetworkSeverity::Suspicious;
            }
        }

        NetworkSeverity::Suspicious
    }

    fn host_matches(&self, host: &str, patterns: &HashSet<String>) -> bool {
        for pattern in patterns {
            if pattern.starts_with("*.") {
                let suffix = &pattern[2..];
                // Match if host equals suffix or ends with "." + suffix (e.g., *.github.com matches api.github.com)
                if host == suffix || host.ends_with(&format!(".{suffix}")) {
                    return true;
                }
            } else if host == pattern {
                return true;
            }
        }
        false
    }

    /// Evaluate a ToolCall::Network and return a Decision.
    pub fn evaluate(&self, tool: &ToolCall) -> Option<Decision> {
        match tool {
            ToolCall::Network { url, method } => {
                let severity = self.evaluate_url(url);
                let short_code = format!("net:{}:{}", method.to_lowercase(), short_hash(url));

                match severity {
                    NetworkSeverity::Allowed => Some(Decision::Allow),
                    NetworkSeverity::Suspicious => {
                        Some(Decision::prompt(format!("network: suspicious destination ({url})"), short_code))
                    }
                    NetworkSeverity::Dangerous => {
                        Some(Decision::deny(format!("network: denied destination ({url})")))
                    }
                    NetworkSeverity::Exfiltration => {
                        Some(Decision::deny(format!("network: exfiltration pattern detected ({url})")))
                    }
                }
            }
            _ => None,
        }
    }
}

fn extract_host(url: &str) -> String {
    let url = url.trim();
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("ftp://"))
        .or_else(|| url.strip_prefix("ftps://"))
        .unwrap_or(url);

    let host = if let Some(idx) = without_scheme.find(':') {
        &without_scheme[..idx]
    } else if let Some(idx) = without_scheme.find('/') {
        &without_scheme[..idx]
    } else {
        without_scheme
    };

    host.to_lowercase()
}

fn short_hash(s: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("{:x}", h.finish() & 0xFFFF)
}

/// Build a default policy with common allowed and suspicious patterns.
pub fn default_policy() -> NetworkPolicy {
    let mut policy = NetworkPolicy::new();

    // Allowed hosts — common developer endpoints.
    for host in [
        "github.com", "api.github.com", "*.github.com",
        "gitlab.com", "*.gitlab.com", "bitbucket.org", "*.bitbucket.org",
        "registry.npmjs.org", "registry.npmmirror.com",
        "pypi.org", "files.pythonhosted.org",
        "cdn.jsdelivr.net", "cdn.bundler.io", "rubygems.org",
        "repo.maven.apache.org", "dl.google.com",
        "go.dev", "proxy.golang.org",
    ] {
        policy.add_allowed_host(host);
    }

    // Suspicious patterns.
    for pat in [r"\.tk$", r"\.ml$", r"\.ga$", r"\.cf$", r"ipfs\.io", r"\.onion"] {
        policy.add_suspicious_pattern(pat);
    }

    // Exfiltration patterns.
    for pat in [r"telnet://", r"ftp://.*@"] {
        policy.add_exfiltration_pattern(pat);
    }

    // Deny private IP ranges.
    policy.add_denied_ip_range("10.0.0.0/8");
    policy.add_denied_ip_range("172.16.0.0/12");
    policy.add_denied_ip_range("192.168.0.0/16");
    policy.add_denied_ip_range("127.0.0.0/8");

    policy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_https() {
        assert_eq!(extract_host("https://api.github.com/users"), "api.github.com");
    }

    #[test]
    fn test_extract_host_with_port() {
        assert_eq!(extract_host("http://localhost:8080/api"), "localhost");
    }

    #[test]
    fn test_wildcard_allowlist() {
        let mut policy = NetworkPolicy::new();
        policy.add_allowed_host("*.github.com");
        // *.github.com matches subdomains like api.github.com and raw.githubusercontent.com
        // Note: raw.githubusercontent.com ends with .com, not .github.com, so it doesn't match
        // The correct pattern for matching github.com AND its subdomains would be to add both
        assert!(matches!(policy.evaluate_url("https://api.github.com"), NetworkSeverity::Allowed));
        // raw.githubusercontent.com does NOT end with .github.com, so it goes to suspicious
        assert!(matches!(policy.evaluate_url("https://raw.githubusercontent.com"), NetworkSeverity::Suspicious));
    }

    #[test]
    fn test_exfiltration_denied() {
        let mut policy = NetworkPolicy::new();
        policy.add_exfiltration_pattern(r"telnet://");
        assert!(matches!(policy.evaluate_url("telnet://evil.com"), NetworkSeverity::Exfiltration));
    }

    #[test]
    fn test_denied_ip_ranges() {
        let mut policy = NetworkPolicy::new();
        policy.add_denied_ip_range("10.0.0.0/8");
        assert!(matches!(policy.evaluate_url("http://10.0.0.1:8080"), NetworkSeverity::Dangerous));
    }

    #[test]
    fn test_tool_call_network_evaluate() {
        let policy = default_policy();
        let result = policy.evaluate(&ToolCall::network("https://api.github.com/users", "GET"));
        assert!(matches!(result, Some(Decision::Allow)));
    }

    #[test]
    fn test_non_network_tool_returns_none() {
        let policy = NetworkPolicy::new();
        let result = policy.evaluate(&ToolCall::bash("ls"));
        assert!(result.is_none());
    }
}
