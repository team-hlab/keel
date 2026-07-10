//! Google Antigravity adapter (Antigravity 2.0, CLI `agy`).
//!
//! Verified: binary is `agy`; global hooks live at `~/.gemini/config/hooks.json`;
//! input is `toolCall.name` + `toolCall.args` (camelCase) with `workspacePaths`; the
//! shell tool is `run_command` with the command in `args.CommandLine`; output is
//! `{"decision": "allow"|"deny"|"ask", "reason": …}` and a non-zero exit = deny (so keel
//! always emits JSON + exits 0). Write tools (`write_to_file`, `replace_file_content`,
//! `multi_replace_file_content`) and content-read tools (`view_file`, `search_in_file`,
//! `view_file_outline` via `args.AbsolutePath`; `view_code_item` via `args.File`) are
//! normalized into keel's neutral model so file/secret gating applies. keel registers under
//! the `keel` namespace in `~/.gemini/config/hooks.json` with a matcher on these tool names
//! (see agent.rs), so Antigravity fires keel for them.

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
    // Map Antigravity's tool taxonomy onto keel's neutral model so the engine's policy +
    // secret-scan apply (see `normalize`).
    let (tool, tool_input) = normalize(raw_tool, raw_input);
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

/// Map an Antigravity tool call onto keel's neutral model. Verified arg names: `run_command`
/// (`CommandLine`), `write_to_file` (`TargetFile`/`CodeContent`), `replace_file_content`
/// (`TargetFile`/`ReplacementContent`), `multi_replace_file_content` (`TargetFile` +
/// `ReplacementChunks[].ReplacementContent`).
fn normalize(tool: Option<String>, args: Value) -> (Option<String>, Value) {
    let s = |k: &str| args.get(k).and_then(Value::as_str);
    let mapped = match tool.as_deref() {
        Some("run_command") => Some(("Bash", arg_obj(&[("command", s("CommandLine"))]))),
        Some("write_to_file") => Some((
            "Write",
            arg_obj(&[
                ("file_path", s("TargetFile")),
                ("content", s("CodeContent")),
            ]),
        )),
        Some("replace_file_content") => Some((
            "Edit",
            arg_obj(&[
                ("file_path", s("TargetFile")),
                ("new_string", s("ReplacementContent")),
            ]),
        )),
        Some("multi_replace_file_content") => {
            let mut m = Map::new();
            if let Some(p) = s("TargetFile") {
                m.insert("file_path".into(), json!(p));
            }
            let edits: Vec<Value> = args
                .get("ReplacementChunks")
                .and_then(Value::as_array)
                .map(|cs| {
                    cs.iter()
                        .filter_map(|c| c.get("ReplacementContent").and_then(Value::as_str))
                        .map(|x| json!({ "new_string": x }))
                        .collect()
                })
                .unwrap_or_default();
            m.insert("edits".into(), Value::Array(edits));
            Some(("MultiEdit", Value::Object(m)))
        }
        // content reads (verified args): most use AbsolutePath, view_code_item uses File.
        Some("view_file" | "search_in_file" | "view_file_outline") => {
            Some(("Read", arg_obj(&[("file_path", s("AbsolutePath"))])))
        }
        Some("view_code_item") => Some(("Read", arg_obj(&[("file_path", s("File"))]))),
        _ => None,
    };
    match mapped {
        Some((t, input)) => (Some(t.to_string()), input),
        None => (tool, args),
    }
}

fn arg_obj(pairs: &[(&str, Option<&str>)]) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        if let Some(val) = v {
            m.insert((*k).to_string(), json!(val));
        }
    }
    Value::Object(m)
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
    fn normalizes_write_tools() {
        // write_to_file → Write{file_path, content}
        let e = parse(
            &json!({"toolCall":{"name":"write_to_file","args":{"TargetFile":"/r/x.py","CodeContent":"k=1"}}}),
            "PreToolUse",
        );
        assert_eq!(e.tool.as_deref(), Some("Write"));
        assert_eq!(e.file_path(), Some("/r/x.py"));
        assert_eq!(
            e.tool_input.get("content").and_then(|v| v.as_str()),
            Some("k=1")
        );

        // replace_file_content → Edit{file_path, new_string}
        let e = parse(
            &json!({"toolCall":{"name":"replace_file_content","args":{"TargetFile":"/r/y.py","ReplacementContent":"z=2"}}}),
            "PreToolUse",
        );
        assert_eq!(e.tool.as_deref(), Some("Edit"));
        assert_eq!(e.file_path(), Some("/r/y.py"));
        assert_eq!(
            e.tool_input.get("new_string").and_then(|v| v.as_str()),
            Some("z=2")
        );

        // multi_replace_file_content → MultiEdit{file_path, edits:[{new_string}]}
        let e = parse(
            &json!({"toolCall":{"name":"multi_replace_file_content","args":{"TargetFile":"/r/z.py","ReplacementChunks":[{"ReplacementContent":"a"},{"ReplacementContent":"b"}]}}}),
            "PreToolUse",
        );
        assert_eq!(e.tool.as_deref(), Some("MultiEdit"));
        assert_eq!(e.file_path(), Some("/r/z.py"));
        let edits = e
            .tool_input
            .get("edits")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(edits.len(), 2);
        assert_eq!(
            edits[0].get("new_string").and_then(|v| v.as_str()),
            Some("a")
        );
    }

    #[test]
    fn normalizes_read_tools() {
        // view_file → Read{file_path} from AbsolutePath (so read/secret gating applies)
        let e = parse(
            &json!({"toolCall":{"name":"view_file","args":{"AbsolutePath":"/r/.env","StartLine":1}}}),
            "PreToolUse",
        );
        assert_eq!(e.tool.as_deref(), Some("Read"));
        assert_eq!(e.file_path(), Some("/r/.env"));

        // view_code_item uses the `File` arg, not AbsolutePath
        let e = parse(
            &json!({"toolCall":{"name":"view_code_item","args":{"File":"/r/a.rs","NodePaths":["m::f"]}}}),
            "PreToolUse",
        );
        assert_eq!(e.tool.as_deref(), Some("Read"));
        assert_eq!(e.file_path(), Some("/r/a.rs"));
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
