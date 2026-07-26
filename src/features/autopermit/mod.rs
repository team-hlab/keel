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
    witnesses: Vec<String>, // concrete filenames the sensitive globs match (for glob operands)
    regexes: Vec<Regex>,
    protected: Decision, // verdict for an in-repo write outside the worktree areas
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
        let witnesses = pats.iter().map(|g| policy::glob_witness(g)).collect();
        let worktrees = config
            .get("worktrees")
            .and_then(Value::as_str)
            .unwrap_or("worktrees");
        let projects = config
            .get("projects")
            .and_then(Value::as_str)
            .unwrap_or("projects");
        // What to do with an in-repo write outside a worktree:
        //   deny  — strict, worktree-confined
        //   ask   — confirm (default; good interactively, but blocks headless/autonomous runs)
        //   pass  — defer to the agent's own permission model (best for autonomous use)
        //   allow — keel permits it outright
        // Catastrophic commands + protected branches still deny regardless.
        let protected = match config.get("protectedWrites").and_then(Value::as_str) {
            Some("deny") => Decision::Deny,
            Some("pass") => Decision::Pass,
            Some("allow") => Decision::Allow,
            _ => Decision::Ask,
        };
        AutoPermit {
            patterns,
            witnesses,
            regexes: policy::write_allow_regexes(worktrees, projects),
            protected,
        }
    }
}

/// Paths to gate for a file event: the multi-path `file_paths` list if present (e.g. Codex
/// apply_patch touches several files), else the single `file_path`.
fn write_paths(event: &Event) -> Vec<String> {
    if let Some(arr) = event.tool_input.get("file_paths").and_then(Value::as_array) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    event
        .file_path()
        .map(|p| vec![p.to_string()])
        .unwrap_or_default()
}

fn reason(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "safe read / worktree write / read-only command",
        Decision::Deny => "blocked — protected path or destructive command",
        Decision::Ask => "confirmation required — secret, or unverified read/write",
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
                &self.witnesses,
                &self.regexes,
                &resolve,
                self.protected,
            )
        } else {
            let paths = write_paths(event);
            if paths.is_empty() {
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
                    self.protected,
                )
            } else {
                // multi-path tools (e.g. Codex apply_patch) → most-restrictive across files,
                // so a protected file can't slip through behind a safe one.
                paths.iter().fold(Decision::Allow, |worst, p| {
                    let abs = resolve_target(event.cwd.as_deref(), p);
                    let d = policy::decide(
                        event.tool.as_deref(),
                        Some(p),
                        Some(&abs),
                        &event.root,
                        &self.patterns,
                        &self.regexes,
                        self.protected,
                    );
                    if d.rank() > worst.rank() {
                        d
                    } else {
                        worst
                    }
                })
            }
        };
        match decision {
            Decision::Pass => None,
            d => Some(Verdict::new(d, reason(d), "autopermit")),
        }
    }
}
