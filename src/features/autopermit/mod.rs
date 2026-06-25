//! autopermit feature — permit safe file/shell ops, confirm secrets, deny protected writes.

pub mod policy;
pub mod shell;

use regex::Regex;
use serde_json::Value;

use crate::features::Feature;
use crate::model::{Decision, Event, Verdict};
use crate::runtime::resolve_target;

const STAGES: &[&str] = &["PreToolUse", "PermissionRequest"];

pub struct AutoPermit {
    patterns: Vec<Regex>,
    regexes: Vec<Regex>,
}

impl AutoPermit {
    pub fn new(config: &Value) -> Self {
        let pats: Vec<String> = config
            .get("sensitiveFilePatterns")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                policy::DEFAULT_SENSITIVE
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            });
        let patterns = pats.iter().map(|g| policy::glob_to_regex(g)).collect();
        let worktrees = config
            .get("worktrees")
            .and_then(Value::as_str)
            .unwrap_or("worktrees");
        let projects = config
            .get("projects")
            .and_then(Value::as_str)
            .unwrap_or("projects");
        AutoPermit {
            patterns,
            regexes: policy::write_allow_regexes(worktrees, projects),
        }
    }
}

fn reason(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "safe read / worktree write / read-only command",
        Decision::Deny => "blocked — protected path or destructive command",
        Decision::Ask => "confirmation required — secret or unverified write",
        Decision::Pass => "",
    }
}

impl Feature for AutoPermit {
    fn name(&self) -> &'static str {
        "autopermit"
    }

    fn stages(&self) -> &'static [&'static str] {
        STAGES
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let resolve = |base: &str, path: &str| resolve_target(Some(base), path);
        let decision = if event.tool.as_deref() == Some("Bash") {
            shell::decide_bash(
                event.command(),
                event.cwd.as_deref(),
                &event.root,
                &self.patterns,
                &self.regexes,
                &resolve,
            )
        } else {
            let abs = event
                .file_path()
                .map(|fp| resolve_target(event.cwd.as_deref(), fp));
            policy::decide(
                event.tool.as_deref(),
                event.file_path(),
                abs.as_deref(),
                &event.root,
                &self.patterns,
                &self.regexes,
            )
        };
        match decision {
            Decision::Pass => None,
            d => Some(Verdict::new(d, reason(d), "autopermit")),
        }
    }
}
