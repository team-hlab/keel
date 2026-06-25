//! OpenAI Codex adapter — best-effort vs developers.openai.com/codex/hooks (~May 2026). Verify live.

use serde_json::{json, Map, Value};

use crate::model::{Decision, Event, Verdict};
use crate::runtime::find_root;

pub fn parse(raw: &Value, stage: &str) -> Event {
    let cwd = raw.get("cwd").and_then(Value::as_str).map(String::from);
    Event {
        stage: stage.to_string(),
        tool: raw
            .get("tool_name")
            .and_then(Value::as_str)
            .map(String::from),
        tool_input: raw
            .get("tool_input")
            .cloned()
            .unwrap_or(Value::Object(Map::new())),
        cwd: cwd.clone(),
        root: find_root(cwd.as_deref()),
        config: Value::Null,
    }
}

pub fn render(verdict: &Verdict, stage: &str) -> String {
    let d = verdict.decision;
    if stage == "PermissionRequest" {
        return match d {
            Decision::Allow | Decision::Deny => json!({
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": { "behavior": d.as_str(), "reason": verdict.reason }
                }
            })
            .to_string(),
            _ => json!({}).to_string(),
        };
    }
    match d {
        Decision::Allow | Decision::Deny | Decision::Ask => json!({
            "hookSpecificOutput": {
                "hookEventName": stage,
                "permissionDecision": d.as_str(),
                "permissionDecisionReason": verdict.reason
            }
        })
        .to_string(),
        Decision::Pass => json!({}).to_string(),
    }
}
