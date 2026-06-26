//! branch-guard — deny mutating git commands while HEAD is on a protected branch.

use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::consts;
use crate::features::Feature;
use crate::model::{Decision, Event, Verdict};

static GIT_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bgit\s+(-C\s+\S+\s+)?(commit|push|merge|rebase|reset|cherry-pick|am)\b").unwrap()
});
const DEFAULT_PROTECTED: &[&str] = &["main", "master", "develop"];
const STAGES: &[&str] = &["PreToolUse"];

pub struct BranchGuard {
    protected: Vec<String>,
}

impl BranchGuard {
    pub fn new(config: &Value) -> Self {
        let protected = config
            .get("protected")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_PROTECTED.iter().map(|s| s.to_string()).collect());
        BranchGuard { protected }
    }
}

/// Current branch from `.git/HEAD` (worktree-aware), or None if detached/unknown.
fn head_branch(cwd: Option<&str>) -> Option<String> {
    let start = match cwd {
        Some(c) => PathBuf::from(c),
        None => std::env::current_dir().ok()?,
    };
    let mut cur = std::fs::canonicalize(&start).unwrap_or(start);
    loop {
        let git = cur.join(consts::GIT_DIR);
        if git.exists() {
            let head_path = if git.is_file() {
                let content = std::fs::read_to_string(&git).ok()?;
                let gitdir = content.trim().trim_start_matches("gitdir: ").to_string();
                PathBuf::from(gitdir).join("HEAD")
            } else {
                git.join("HEAD")
            };
            let head = std::fs::read_to_string(&head_path).ok()?;
            return head
                .trim()
                .strip_prefix("ref: refs/heads/")
                .map(String::from);
        }
        if !cur.pop() {
            return None;
        }
    }
}

impl Feature for BranchGuard {
    fn name(&self) -> &'static str {
        "branch-guard"
    }

    fn stages(&self) -> &'static [&'static str] {
        STAGES
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        if event.tool.as_deref() != Some("Bash") {
            return None;
        }
        let cmd = event.command()?;
        if !GIT_WRITE.is_match(cmd) {
            return None;
        }
        let branch = head_branch(event.cwd.as_deref())?;
        if self.protected.iter().any(|p| p == &branch) {
            return Some(Verdict::new(
                Decision::Deny,
                format!("branch-guard: '{branch}' is protected — use a branch/PR"),
                "branch-guard",
            ));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(cmd: &str, cwd: &str) -> Event {
        Event {
            stage: "PreToolUse".into(),
            tool: Some("Bash".into()),
            tool_input: json!({ "command": cmd }),
            cwd: Some(cwd.into()),
            root: String::new(),
            config: Value::Null,
        }
    }

    #[test]
    fn denies_on_protected_branch() {
        let tmp = std::env::temp_dir().join(format!("keel-bg-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(consts::GIT_DIR)).unwrap();
        std::fs::write(tmp.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        let cwd = tmp.to_str().unwrap();

        let g = BranchGuard::new(&Value::Null);
        assert_eq!(
            g.evaluate(&event("git commit -m x", cwd)).unwrap().decision,
            Decision::Deny
        );
        assert_eq!(
            g.evaluate(&event("git push", cwd)).unwrap().decision,
            Decision::Deny
        );
        assert!(g.evaluate(&event("git status", cwd)).is_none());
        assert!(g.evaluate(&event("ls", cwd)).is_none());
        // non-Bash tools are ignored
        assert!(g
            .evaluate(&Event {
                tool: Some("Read".into()),
                ..event("ls", cwd)
            })
            .is_none());

        // the head-branch helper reads .git/HEAD
        assert_eq!(head_branch(Some(cwd)), Some("main".to_string()));

        // not protected when config narrows the set
        let g2 = BranchGuard::new(&json!({ "protected": ["release"] }));
        assert!(g2.evaluate(&event("git commit -m x", cwd)).is_none());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
