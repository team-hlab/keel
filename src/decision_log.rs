//! Decision log — one JSONL line per hook call (op · resource · verdict · reason), so the
//! allow-set can be tuned from real usage instead of guesswork. Opt-in via `.keel.json`
//! (`log.enabled`); **zero cost when off** (one map lookup). When on it's O(1) per call —
//! a `stat` (for size-roll retention) + an append. `keel stats` summarizes it.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::consts;
use crate::model::{Event, Verdict};

fn default_path() -> PathBuf {
    crate::agent::home()
        .join(consts::KEEL_DIR)
        .join(consts::DECISION_LOG_NAME)
}

fn resolve_path(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => crate::agent::home().join(rest),
        None => PathBuf::from(p),
    }
}

fn op_of(tool: Option<&str>) -> &'static str {
    match tool {
        Some("Read" | "Glob" | "Grep" | "NotebookRead") => "read",
        Some("Write" | "Edit" | "MultiEdit" | "NotebookEdit") => "write",
        Some("Bash") => "exec",
        _ => "other",
    }
}

/// Append one decision record if `log.enabled` — cheap, and silent on any error (logging
/// must never affect the verdict). Returns immediately (one lookup) when disabled.
pub fn record(config: &Value, platform: &str, stage: &str, event: &Event, verdict: &Verdict) {
    let log = match config.get("log") {
        Some(l) if l.get("enabled").and_then(Value::as_bool) == Some(true) => l,
        _ => return,
    };
    let path = log
        .get("path")
        .and_then(Value::as_str)
        .map(resolve_path)
        .unwrap_or_else(default_path);
    let max_bytes = log.get("maxSizeMb").and_then(Value::as_u64).unwrap_or(5) * 1_048_576;

    // size-roll retention: past the cap, roll to `<name>.1` (overwrite the old one)
    if let Ok(m) = fs::metadata(&path) {
        if m.len() > max_bytes {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let _ = fs::rename(&path, path.with_file_name(format!("{name}.1")));
            }
        }
    }

    let resource = event
        .file_path()
        .or_else(|| event.command())
        .map(|s| s.chars().take(300).collect::<String>());
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rec = json!({
        "ts": ts, "platform": platform, "stage": stage,
        "op": op_of(event.tool.as_deref()), "tool": event.tool,
        "resource": resource, "verdict": verdict.decision.as_str(),
        "reason": verdict.reason, "source": verdict.source,
    });

    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }
    // 0600 on create: the log can contain command text (and thus secrets) — owner-only.
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
    {
        let _ = writeln!(f, "{rec}");
    }
}

/// The log path for `keel stats`: the CLI arg, else the `log.path` configured for the cwd's
/// project, else the default — so `keel stats` finds a custom path without repeating it.
fn stats_path(path_arg: Option<&str>) -> PathBuf {
    if let Some(p) = path_arg {
        return resolve_path(p);
    }
    let root = crate::runtime::find_root(None);
    crate::runtime::load_config(&root)
        .get("log")
        .and_then(|l| l.get("path"))
        .and_then(Value::as_str)
        .map(resolve_path)
        .unwrap_or_else(default_path)
}

fn top(map: &BTreeMap<String, u64>, n: usize) -> Vec<(&String, u64)> {
    let mut v: Vec<_> = map.iter().map(|(k, c)| (k, *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.truncate(n);
    v
}

/// Summarize the decision log for `keel stats`: verdict mix + what's driving `ask`
/// (the curation candidates for the allow-set).
pub fn summarize(path_arg: Option<&str>) -> String {
    let path = stats_path(path_arg);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => {
            return format!(
                "no decision log at {} — enable it in .keel.json:\n  {{ \"log\": {{ \"enabled\": true }} }}\n",
                path.display()
            )
        }
    };

    let mut total = 0u64;
    let mut verdicts: BTreeMap<String, u64> = BTreeMap::new();
    let mut ask_reasons: BTreeMap<String, u64> = BTreeMap::new();
    let mut ask_targets: BTreeMap<String, u64> = BTreeMap::new();
    for line in text.lines() {
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        total += 1;
        let verdict = v.get("verdict").and_then(Value::as_str).unwrap_or("?");
        *verdicts.entry(verdict.to_string()).or_default() += 1;
        if verdict == "ask" {
            if let Some(r) = v
                .get("reason")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                *ask_reasons.entry(r.to_string()).or_default() += 1;
            }
            if let Some(r) = v.get("resource").and_then(Value::as_str) {
                // key exec by its command word, files by their path
                let key = if v.get("op").and_then(Value::as_str) == Some("exec") {
                    r.split_whitespace().next().unwrap_or(r).to_string()
                } else {
                    r.to_string()
                };
                *ask_targets.entry(key).or_default() += 1;
            }
        }
    }

    let mut out = format!("keel decisions — {total} calls ({})\n", path.display());
    out.push_str("  verdicts: ");
    out.push_str(
        &["allow", "ask", "deny", "pass"]
            .iter()
            .map(|k| format!("{k} {}", verdicts.get(*k).copied().unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(" · "),
    );
    out.push('\n');
    if !ask_reasons.is_empty() {
        out.push_str("\n  top ask reasons:\n");
        for (r, c) in top(&ask_reasons, 10) {
            out.push_str(&format!("    {c:>5}  {r}\n"));
        }
        out.push_str("\n  top ask targets (allow-set candidates):\n");
        for (r, c) in top(&ask_targets, 15) {
            out.push_str(&format!("    {c:>5}  {r}\n"));
        }
    }
    out
}
