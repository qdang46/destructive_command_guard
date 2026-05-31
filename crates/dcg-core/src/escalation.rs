//! Denial escalation — Phase 2.3
//! Session `deny_counter` drives escalation from Deny to Prompt.

#[derive(Clone, Debug)]
pub struct DenialConfig {
    pub max_consecutive: u32,
    pub max_total: u32,
}

impl Default for DenialConfig {
    fn default() -> Self {
        Self {
            max_consecutive: 3,
            max_total: 20,
        }
    }
}

impl DenialConfig {
    pub fn new(max_consecutive: u32, max_total: u32) -> Self {
        Self {
            max_consecutive,
            max_total,
        }
    }

    pub fn should_escalate(&self, consecutive: u32, total: u32) -> bool {
        consecutive >= self.max_consecutive || total >= self.max_total
    }
}
