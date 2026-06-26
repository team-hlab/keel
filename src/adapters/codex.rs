//! OpenAI Codex adapter.
//!
//! Verified (developers.openai.com/codex/hooks): input is snake_case — `tool_name`,
//! `tool_input.command`, `hook_event_name`; hooks live in `~/.codex/hooks.json`; tool names
//! (`Bash`, …) match Claude's. PreToolUse output `hookSpecificOutput.permissionDecision`
//! accepts `deny` (and `allow`, version-dependent); **`ask` is NOT valid at PreToolUse** —
//! Codex mediates confirmation via the separate `PermissionRequest` event, so we defer it.
//! Best-effort: the `PermissionRequest` output schema (undocumented at time of writing).
//! `apply_patch` (Codex's edit tool) is normalized to a Write — first patched path + the
//! patch text — so file gating + secret-scan apply, and it's in the hook matcher so Codex
//! fires keel for it. Multi-file patches: the path policy checks the first file; secret-scan
//! sees all content.

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

/// `apply_patch` carries the whole V4A patch in `tool_input.command`. Surface the first
/// patched file path + the patch text under keel's neutral keys so the file policy and
/// secret-scan apply. A patch may touch several files; the path policy checks the first,
/// while secret-scan sees the entire patch.
fn normalize(tool: Option<String>, input: Value) -> (Option<String>, Value) {
    if tool.as_deref() != Some("apply_patch") {
        return (tool, input);
    }
    let patch = input.get("command").and_then(Value::as_str).unwrap_or("");
    let mut m = Map::new();
    if let Some(p) = first_patch_path(patch) {
        m.insert("file_path".into(), json!(p));
    }
    m.insert("content".into(), json!(patch));
    (Some("Write".to_string()), Value::Object(m))
}

/// First file path in a V4A patch (`*** Add/Update/Delete File: <path>`).
fn first_patch_path(patch: &str) -> Option<String> {
    for line in patch.lines() {
        let t = line.trim_start();
        for marker in ["*** Add File: ", "*** Update File: ", "*** Delete File: "] {
            if let Some(p) = t.strip_prefix(marker) {
                return Some(p.trim().to_string());
            }
        }
    }
    None
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
        let patch = "*** Begin Patch\n*** Update File: projects/foo/main/a.py\n@@\n+token = \"AKIAIOSFODNN7EXAMPLE\"\n*** End Patch";
        let raw = json!({"tool_name":"apply_patch","tool_input":{"command":patch},"cwd":"/r"});
        let e = parse(&raw, "PreToolUse");
        assert_eq!(e.tool.as_deref(), Some("Write")); // gated as a write
        assert_eq!(e.file_path(), Some("projects/foo/main/a.py")); // path from the patch
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
