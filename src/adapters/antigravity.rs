//! Google Antigravity adapter (Antigravity 2.0, CLI `agy`).
//!
//! Verified: binary is `agy` (official install.sh); global hooks live at
//! `~/.gemini/config/hooks.json` (see agent.rs); `PreToolUse` is a real event.
//! Best-effort (docs render client-side, unconfirmed): the input field names
//! (toolCall.args / workspacePaths) and the `{decision: ...}` output schema below.

use serde_json::{json, Map, Value};

use crate::model::{Decision, Event, Verdict};
use crate::runtime::find_root;

pub fn parse(raw: &Value, stage: &str) -> Event {
    let tool_call = raw.get("toolCall");
    let tool = raw
        .get("tool_name")
        .and_then(Value::as_str)
        .or_else(|| {
            tool_call
                .and_then(|t| t.get("name"))
                .and_then(Value::as_str)
        })
        .map(String::from);
    let tool_input = raw
        .get("tool_input")
        .cloned()
        .or_else(|| tool_call.and_then(|t| t.get("args")).cloned())
        .unwrap_or(Value::Object(Map::new()));
    let cwd = raw
        .get("cwd")
        .and_then(Value::as_str)
        .or_else(|| {
            raw.get("workspacePaths")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
        })
        .map(String::from);
    Event {
        stage: stage.to_string(),
        tool,
        tool_input,
        cwd: cwd.clone(),
        root: find_root(cwd.as_deref()),
        config: Value::Null,
    }
}

pub fn render(verdict: &Verdict, _stage: &str) -> String {
    match verdict.decision {
        Decision::Pass => json!({}).to_string(),
        d => json!({ "decision": d.as_str(), "reason": verdict.reason }).to_string(),
    }
}
