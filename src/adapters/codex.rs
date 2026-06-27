//! OpenAI Codex adapter.
//!
//! Verified (developers.openai.com/codex/hooks): input is snake_case — `tool_name`,
//! `tool_input.command`, `hook_event_name`; hooks live in `~/.codex/hooks.json`; tool names
//! (`Bash`, …) match Claude's. PreToolUse output `hookSpecificOutput.permissionDecision`
//! accepts `deny` (and `allow`, version-dependent); **`ask` is NOT valid at PreToolUse** —
//! Codex mediates confirmation via the separate `PermissionRequest` event, so we defer it.
//! Best-effort: the `PermissionRequest` output schema (undocumented at time of writing).
//! `apply_patch` (Codex's edit tool) is normalized to a Write — ALL patched paths
//! (`file_paths`) + the patch text — so file gating (most-restrictive across files) and
//! secret-scan both apply, and it's in the hook matcher so Codex fires keel for it.

use serde_json::{json, Map, Value};

use crate::model::{Decision, Event, Verdict};
use crate::runtime::find_root;

pub fn parse(raw: &Value, stage: &str) -> Event {
    let cwd = raw.get("cwd").and_then(Value::as_str).map(String::from);
    let tool = raw
        .get("tool_name")
        .and_then(Value::as_str)
        .map(String::from);
    let input = raw
        .get("tool_input")
        .cloned()
        .unwrap_or(Value::Object(Map::new()));
    let (tool, tool_input) = normalize(tool, input);
    Event {
        stage: stage.to_string(),
        tool,
        tool_input,
        cwd: cwd.clone(),
        root: find_root(cwd.as_deref()),
        config: Value::Null,
    }
}

/// `apply_patch` carries the whole V4A patch in `tool_input.command`. Surface every patched
/// path (`file_paths`, with `file_path` = the first for display) + the patch text under keel's
/// neutral keys so the file policy (most-restrictive across files) and secret-scan both apply.
fn normalize(tool: Option<String>, input: Value) -> (Option<String>, Value) {
    if tool.as_deref() != Some("apply_patch") {
        return (tool, input);
    }
    let patch = input.get("command").and_then(Value::as_str).unwrap_or("");
    let paths = patch_paths(patch);
    let mut m = Map::new();
    if let Some(first) = paths.first() {
        m.insert("file_path".into(), json!(first));
    }
    // ALL patched files — autopermit evaluates each (most-restrictive), so a protected file
    // can't slip through by listing a safe file first.
    if !paths.is_empty() {
        m.insert("file_paths".into(), json!(paths));
    }
    m.insert("content".into(), json!(patch));
    (Some("Write".to_string()), Value::Object(m))
}

/// Every file path in a V4A patch (`*** Add/Update/Delete File: <path>`), in order.
fn patch_paths(patch: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in patch.lines() {
        let t = line.trim_start();
        for marker in ["*** Add File: ", "*** Update File: ", "*** Delete File: "] {
            if let Some(p) = t.strip_prefix(marker) {
                out.push(p.trim().to_string());
            }
        }
    }
    out
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
    fn apply_patch_normalized_to_write() {
        // multi-file patch: a safe file first, a protected one second — both must be surfaced
        let patch = "*** Begin Patch\n*** Add File: worktrees/f/ok.py\n+a=1\n*** Update File: projects/foo/main/evil.py\n@@\n+b=2\n*** End Patch";
        let raw = json!({"tool_name":"apply_patch","tool_input":{"command":patch},"cwd":"/r"});
        let e = parse(&raw, "PreToolUse");
        assert_eq!(e.tool.as_deref(), Some("Write")); // gated as a write
        let paths = e
            .tool_input
            .get("file_paths")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(paths.len(), 2); // ALL patched files, not just the first
        assert_eq!(paths[1].as_str(), Some("projects/foo/main/evil.py"));
        assert!(e.tool_input.get("content").is_some()); // full patch → secret-scan sees it
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
