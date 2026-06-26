//! audit-log — observer that appends every tool call + stage to a JSONL log.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::consts;
use crate::features::Feature;
use crate::model::{Event, Verdict};

// PreToolUse only: keel isn't registered as a PostToolUse hook (registering one by
// default would no-op on every tool call when audit-log is off — wasteful).
const STAGES: &[&str] = &["PreToolUse"];

pub struct AuditLog {
    path: Option<String>,
}

impl AuditLog {
    pub fn new(config: &Value) -> Self {
        AuditLog {
            path: config.get("path").and_then(Value::as_str).map(String::from),
        }
    }
}

fn append_line(path: &str, line: &str) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{line}")
}

impl Feature for AuditLog {
    fn name(&self) -> &'static str {
        "audit-log"
    }

    fn stages(&self) -> &'static [&'static str] {
        STAGES
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut rec = Map::new();
        rec.insert("ts".into(), json!(ts));
        rec.insert("stage".into(), json!(event.stage));
        rec.insert("tool".into(), json!(event.tool));
        rec.insert("cwd".into(), json!(event.cwd));
        if let Some(fp) = event.file_path() {
            rec.insert("file_path".into(), json!(fp));
        }
        if let Some(cmd) = event.command() {
            rec.insert(
                "command".into(),
                json!(cmd.chars().take(500).collect::<String>()),
            );
        }
        let path = self.path.clone().unwrap_or_else(|| {
            format!(
                "{}/{}/{}",
                event.root,
                consts::KEEL_DIR,
                consts::AUDIT_LOG_NAME
            )
        });
        let _ = append_line(&path, &Value::Object(rec).to_string()); // logging must never block
        None // observer: no verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn appends_jsonl() {
        let log = std::env::temp_dir().join(format!("keel-audit-{}.log", std::process::id()));
        let f = AuditLog {
            path: Some(log.to_string_lossy().into_owned()),
        };
        let event = Event {
            stage: "PreToolUse".into(),
            tool: Some("Bash".into()),
            tool_input: json!({ "command": "ls -la" }),
            cwd: Some("/repo".into()),
            root: String::new(),
            config: Value::Null,
        };
        assert!(f.evaluate(&event).is_none());
        // a second event appends a second line (file_path captured for non-Bash tools)
        let event2 = Event {
            stage: "PreToolUse".into(),
            tool: Some("Write".into()),
            tool_input: json!({ "file_path": "a.txt" }),
            cwd: Some("/repo".into()),
            root: String::new(),
            config: Value::Null,
        };
        assert!(f.evaluate(&event2).is_none());

        let txt = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = txt.lines().collect();
        assert_eq!(lines.len(), 2);
        let rec: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(rec["tool"], "Bash");
        assert_eq!(rec["command"], "ls -la");
        let rec2: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(rec2["file_path"], "a.txt");
        std::fs::remove_file(&log).ok();
    }
}
