//! secret-scan — confirm writes whose *content* looks like a credential.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::features::Feature;
use crate::model::{Decision, Event, Verdict};

static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), // AWS access key id
        Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(), // PEM private key
        Regex::new(r"gh[pousr]_[A-Za-z0-9]{20,}").unwrap(), // GitHub token
        Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(), // Slack token
        Regex::new(
            r#"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['"]?[A-Za-z0-9/+_\-]{12,}"#,
        )
        .unwrap(),
    ]
});
const STAGES: &[&str] = &["PreToolUse"];
const WRITE_TOOLS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];

// Full multi-line PEM block — the `PATTERNS` header regex only flags (`is_match`) the BEGIN
// line, which is enough for the Ask verdict but would leave the key body behind on redaction.
// redact() runs this first so the entire block (header + base64 body + footer) is scrubbed.
static PEM_BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
        .unwrap()
});

/// Replace anything matching a credential pattern with `[redacted]`, using the same
/// patterns the feature flags on (plus the full PEM block). Reused by carryover so stored
/// context never persists secrets to disk. Best-effort — known patterns only.
pub fn redact(text: &str) -> String {
    let mut out = PEM_BLOCK.replace_all(text, "[redacted]").into_owned();
    for r in PATTERNS.iter() {
        out = r.replace_all(&out, "[redacted]").into_owned();
    }
    out
}

pub struct SecretScan;

impl SecretScan {
    pub fn new(_config: &Value) -> Self {
        SecretScan
    }
}

fn content(tool_input: &Value) -> String {
    let mut parts = Vec::new();
    for k in ["content", "new_string", "new_str", "new_source"] {
        if let Some(s) = tool_input.get(k).and_then(Value::as_str) {
            parts.push(s.to_string());
        }
    }
    if let Some(edits) = tool_input.get("edits").and_then(Value::as_array) {
        for e in edits {
            if let Some(s) = e.get("new_string").and_then(Value::as_str) {
                parts.push(s.to_string());
            }
        }
    }
    parts.join("\n")
}

impl Feature for SecretScan {
    fn name(&self) -> &'static str {
        "secret-scan"
    }

    fn stages(&self) -> &'static [&'static str] {
        STAGES
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let tool = event.tool.as_deref()?;
        if !WRITE_TOOLS.contains(&tool) {
            return None;
        }
        let text = content(&event.tool_input);
        if !text.is_empty() && PATTERNS.iter().any(|r| r.is_match(&text)) {
            return Some(Verdict::new(
                Decision::Ask,
                "secret-scan: content looks like a credential — confirm",
                "secret-scan",
            ));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(tool: &str, ti: Value) -> Event {
        Event {
            stage: "PreToolUse".into(),
            tool: Some(tool.into()),
            tool_input: ti,
            cwd: None,
            root: String::new(),
            config: Value::Null,
        }
    }

    #[test]
    fn flags_credentials() {
        let f = SecretScan;
        assert_eq!(
            f.evaluate(&ev("Write", json!({ "content": "AKIAABCDEFGHIJKLMNOP" })))
                .unwrap()
                .decision,
            Decision::Ask
        );
        assert_eq!(
            f.evaluate(&ev(
                "Edit",
                json!({ "new_string": "api_key = 'abcdef123456ghijkl'" })
            ))
            .unwrap()
            .decision,
            Decision::Ask
        );
        assert_eq!(
            f.evaluate(&ev(
                "Write",
                json!({ "content": "-----BEGIN RSA PRIVATE KEY-----" })
            ))
            .unwrap()
            .decision,
            Decision::Ask
        );
    }

    #[test]
    fn ignores_clean_and_non_writes() {
        let f = SecretScan;
        assert!(f
            .evaluate(&ev("Write", json!({ "content": "hello world" })))
            .is_none());
        assert!(f
            .evaluate(&ev("Read", json!({ "file_path": "a" })))
            .is_none());
    }

    #[test]
    fn redact_scrubs_full_pem_block() {
        let body = "MIIEpAIBAAKCAQEAbase64keymaterialthatmustnotsurvive0123456789";
        let pem = format!("prefix\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\nsuffix");
        let out = redact(&pem);
        assert!(out.contains("[redacted]"));
        assert!(!out.contains(body), "key body survived redaction: {out}");
        assert!(!out.contains("BEGIN RSA PRIVATE KEY"));
        // inline tokens still scrubbed too
        assert!(!redact("k AKIAABCDEFGHIJKLMNOP z").contains("AKIA"));
    }
}
