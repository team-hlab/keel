//! Core data model: `Event` (normalized hook input) and `Verdict` (normalized output).

use serde_json::Value;

/// A permission verdict. Ordering is most-restrictive-last.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    Allow,
    Pass,
    Ask,
    Deny,
}

impl Decision {
    /// Aggregation rank: deny > ask > pass > allow.
    pub fn rank(self) -> u8 {
        match self {
            Decision::Allow => 0,
            Decision::Pass => 1,
            Decision::Ask => 2,
            Decision::Deny => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Pass => "pass",
            Decision::Ask => "ask",
            Decision::Deny => "deny",
        }
    }
}

/// A verdict produced by a feature (or aggregated by the engine).
#[derive(Clone, Debug)]
pub struct Verdict {
    pub decision: Decision,
    pub reason: String,
    /// The feature that produced this verdict (consumed by audit-log / status in Phase 2).
    #[allow(dead_code)]
    pub source: String,
}

impl Verdict {
    pub fn new(decision: Decision, reason: impl Into<String>, source: impl Into<String>) -> Self {
        Verdict {
            decision,
            reason: reason.into(),
            source: source.into(),
        }
    }
}

/// A platform-neutral hook event. Adapters build it; features read it.
#[derive(Clone, Debug)]
pub struct Event {
    pub stage: String,
    pub tool: Option<String>,
    pub tool_input: Value,
    pub cwd: Option<String>,
    pub root: String,
    pub config: Value,
}

impl Event {
    pub fn file_path(&self) -> Option<&str> {
        self.tool_input.get("file_path").and_then(Value::as_str)
    }

    pub fn command(&self) -> Option<&str> {
        self.tool_input.get("command").and_then(Value::as_str)
    }
}
