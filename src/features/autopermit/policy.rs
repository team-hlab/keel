//! Pure file-tool decisions. No I/O.

use regex::Regex;

use crate::model::Decision;

pub const READ_TOOLS: &[&str] = &["Read", "Glob", "Grep", "NotebookRead"];
pub const WRITE_TOOLS: &[&str] = &["Edit", "MultiEdit", "Write", "NotebookEdit"];
pub const DEFAULT_SENSITIVE: &[&str] = &[".env*", "*.key", "*.pem", "credentials*", "*secret*"];

/// Compile a basename glob (`*`, `?`) into a case-insensitive anchored regex.
pub fn glob_to_regex(glob: &str) -> Regex {
    let mut re = String::from("(?i)^");
    for ch in glob.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c if r".+^${}()|[]\".contains(c) => {
                re.push('\\');
                re.push(c);
            }
            c => re.push(c),
        }
    }
    re.push('$');
    Regex::new(&re).expect("glob regex")
}

pub fn basename(p: &str) -> &str {
    let t = p.trim_end_matches(['/', '\\']);
    t.rsplit(['/', '\\']).next().unwrap_or(t)
}

pub fn is_sensitive(file_path: Option<&str>, patterns: &[Regex]) -> bool {
    match file_path {
        Some(p) if !p.is_empty() => {
            let b = basename(p);
            patterns.iter().any(|r| r.is_match(b))
        }
        _ => false,
    }
}

pub fn is_inside(abs: &str, root: &str) -> bool {
    if abs.is_empty() || root.is_empty() {
        return false;
    }
    abs == root || abs.starts_with(&format!("{root}{}", std::path::MAIN_SEPARATOR))
}

pub fn write_allow_regexes(worktrees: &str, projects: &str) -> Vec<Regex> {
    let wt = regex::escape(worktrees.trim_matches('/'));
    let proj = regex::escape(projects.trim_matches('/'));
    vec![
        Regex::new(&format!(r"^{wt}/")).unwrap(),
        Regex::new(&format!(r"^{proj}/[^/]+/{wt}/")).unwrap(),
        Regex::new(&format!(r"^{proj}/[^/]+/[^/]+/{wt}/")).unwrap(),
        Regex::new(r"^\.lens/").unwrap(),
        Regex::new(r"^\.slack-digest/").unwrap(),
    ]
}

pub fn is_write_allowed(abs: &str, root: &str, regexes: &[Regex]) -> bool {
    let prefix = format!("{root}{}", std::path::MAIN_SEPARATOR);
    let rel = match abs.strip_prefix(&prefix) {
        Some(r) => r.replace(std::path::MAIN_SEPARATOR, "/"),
        None => return false,
    };
    regexes.iter().any(|r| r.is_match(&rel))
}

/// Pure file-tool verdict.
pub fn decide(
    tool: Option<&str>,
    file_path: Option<&str>,
    abs_path: Option<&str>,
    root: &str,
    patterns: &[Regex],
    regexes: &[Regex],
) -> Decision {
    let tool = tool.unwrap_or("");
    if READ_TOOLS.contains(&tool) {
        if is_sensitive(file_path, patterns) {
            return Decision::Ask;
        }
        return Decision::Allow;
    }
    if WRITE_TOOLS.contains(&tool) {
        let fp = match file_path {
            Some(p) if !p.is_empty() => p,
            _ => return Decision::Deny,
        };
        if is_sensitive(Some(fp), patterns) {
            return Decision::Ask;
        }
        let abs = abs_path.unwrap_or("");
        if is_write_allowed(abs, root, regexes) {
            return Decision::Allow;
        }
        if is_inside(abs, root) {
            return Decision::Deny;
        }
        return Decision::Pass;
    }
    Decision::Pass
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/repo";

    fn pats() -> Vec<Regex> {
        DEFAULT_SENSITIVE.iter().map(|g| glob_to_regex(g)).collect()
    }

    fn dec(tool: &str, rel: Option<&str>) -> Decision {
        let p = pats();
        let r = write_allow_regexes("worktrees", "projects");
        let abs = rel.map(|x| {
            if x.starts_with('/') {
                x.to_string()
            } else {
                format!("{ROOT}/{x}")
            }
        });
        decide(Some(tool), rel, abs.as_deref(), ROOT, &p, &r)
    }

    #[test]
    fn reads() {
        assert_eq!(dec("Read", Some("wiki/README.md")), Decision::Allow);
        assert_eq!(dec("Read", Some("x/.env")), Decision::Ask);
        assert_eq!(dec("Glob", None), Decision::Allow);
    }

    #[test]
    fn writes() {
        assert_eq!(dec("Write", Some("worktrees/x/a")), Decision::Allow);
        assert_eq!(dec("Edit", Some("projects/foo/main/A")), Decision::Deny);
        assert_eq!(dec("Write", Some("/tmp/x")), Decision::Pass);
        assert_eq!(dec("Write", Some("worktrees/x/.env")), Decision::Ask);
        assert_eq!(dec("Write", None), Decision::Deny);
    }

    #[test]
    fn other_tools_pass() {
        assert_eq!(dec("WebFetch", None), Decision::Pass);
    }

    #[test]
    fn sensitive_and_allow_helpers() {
        let p = pats();
        assert!(is_sensitive(Some("a/.env"), &p));
        assert!(!is_sensitive(Some("a/README.md"), &p));
        let r = write_allow_regexes("worktrees", "projects");
        assert!(is_write_allowed("/repo/worktrees/f/a", ROOT, &r));
        assert!(!is_write_allowed("/repo/projects/foo/main/a", ROOT, &r));
    }
}
