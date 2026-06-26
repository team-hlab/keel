//! OpenAI Codex adapter.
//!
//! Verified (developers.openai.com/codex/hooks): input is snake_case — `tool_name`,
//! `tool_input.command`, `hook_event_name`; hooks live in `~/.codex/hooks.json`; tool names
//! (`Bash`, …) match Claude's. PreToolUse output `hookSpecificOutput.permissionDecision`
//! accepts `deny` (and `allow`, version-dependent); **`ask` is NOT valid at PreToolUse** —
//! Codex mediates confirmation via the separate `PermissionRequest` event, so we defer it.
//! Best-effort: the `PermissionRequest` output schema (undocumented at time of writing).
//! Gap: Codex's `Bash` tool is shell-gated, but its `apply_patch` edit tool isn't in keel's
//! write-tool set, so file-write gating doesn't apply to it yet (same shape as Antigravity).

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
        // `ask` isn't a valid PreToolUse decision in Codex — defer it (and Pass) so the
        // tool proceeds to Codex's own PermissionRequest flow, where keel's hook runs.
        Decision::Allow | Decision::Deny => json!({
            "hookSpecificOutput": {
                "hookEventName": stage,
                "permissionDecision": d.as_str(),
                "permissionDecisionReason": verdict.reason
            }
        })
        .to_string(),
        Decision::Ask | Decision::Pass => json!({}).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_reads_snake_case() {
        let raw = json!({"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/x"});
        let e = parse(&raw, "PreToolUse");
        assert_eq!(e.tool.as_deref(), Some("Bash"));
        assert_eq!(e.command(), Some("ls"));
    }

    #[test]
    fn pretooluse_deny_renders_but_ask_defers() {
        let deny = render(&Verdict::new(Decision::Deny, "no", "t"), "PreToolUse");
        assert!(deny.contains("\"permissionDecision\":\"deny\""));
        // ask is not a PreToolUse value in Codex → defer (empty object), never emit it
        assert_eq!(
            render(&Verdict::new(Decision::Ask, "", "t"), "PreToolUse"),
            "{}"
        );
        assert_eq!(
            render(&Verdict::new(Decision::Pass, "", "t"), "PreToolUse"),
            "{}"
        );
    }
}
