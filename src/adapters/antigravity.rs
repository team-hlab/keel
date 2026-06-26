//! Google Antigravity adapter (Antigravity 2.0, CLI `agy`).
//!
//! Verified: binary is `agy`; global hooks live at `~/.gemini/config/hooks.json`;
//! input is `toolCall.name` + `toolCall.args` (camelCase) with `workspacePaths`; the
//! shell tool is `run_command` with the command in `args.CommandLine`; output is
//! `{"decision": "allow"|"deny"|"ask", "reason": …}` and a non-zero exit = deny (so keel
//! always emits JSON + exits 0). Best-effort: write-tool arg field names (unconfirmed) —
//! so file-write gating doesn't yet apply on Antigravity; shell gating does.

use serde_json::{json, Map, Value};

use crate::model::{Decision, Event, Verdict};
use crate::runtime::find_root;

pub fn parse(raw: &Value, stage: &str) -> Event {
    let tool_call = raw.get("toolCall");
    let raw_tool = raw
        .get("tool_name")
        .and_then(Value::as_str)
        .or_else(|| {
            tool_call
                .and_then(|t| t.get("name"))
                .and_then(Value::as_str)
        })
        .map(String::from);
    let raw_input = raw
        .get("tool_input")
        .cloned()
        .or_else(|| tool_call.and_then(|t| t.get("args")).cloned())
        .unwrap_or(Value::Object(Map::new()));
    // Normalize Antigravity's tool taxonomy into keel's neutral model so the engine's
    // policy applies. Verified: the shell tool is `run_command`, command in `args.CommandLine`.
    let (tool, tool_input) = match raw_tool.as_deref() {
        Some("run_command") => {
            let mut m = Map::new();
            if let Some(c) = raw_input.get("CommandLine").and_then(Value::as_str) {
                m.insert("command".into(), json!(c));
            }
            (Some("Bash".to_string()), Value::Object(m))
        }
        _ => (raw_tool, raw_input),
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_run_command_to_bash() {
        let raw = json!({
            "toolCall": { "name": "run_command", "args": { "CommandLine": "rm -rf /" } },
            "workspacePaths": ["/repo"]
        });
        let e = parse(&raw, "PreToolUse");
        assert_eq!(e.tool.as_deref(), Some("Bash")); // so the shell policy runs
        assert_eq!(e.command(), Some("rm -rf /"));
        assert_eq!(e.cwd.as_deref(), Some("/repo"));
    }

    #[test]
    fn render_uses_decision_schema() {
        let deny = render(&Verdict::new(Decision::Deny, "no", "t"), "PreToolUse");
        assert!(deny.contains("\"decision\":\"deny\""));
        assert_eq!(
            render(&Verdict::new(Decision::Pass, "", "t"), "PreToolUse"),
            "{}"
        );
    }
}
