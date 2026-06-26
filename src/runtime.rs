//! I/O edges: stdin, project-root discovery, config load, realpath-style resolution.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::consts;

/// Read + parse the hook payload from stdin. None on any error.
pub fn read_input() -> Option<Value> {
    use std::io::Read;
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).ok()?;
    serde_json::from_str(&s).ok()
}

/// realpath-like: canonicalize the longest existing ancestor, re-append the missing tail.
/// Works on non-existent paths (a Write to a new file) and resolves symlinks like Python's realpath.
fn canon(path: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(path) {
        return c;
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        if cur.exists() {
            let mut base = std::fs::canonicalize(&cur).unwrap_or(cur);
            for c in tail.iter().rev() {
                base.push(c);
            }
            return base;
        }
        match cur.file_name() {
            Some(name) => tail.push(name.to_os_string()),
            None => return path.to_path_buf(),
        }
        if !cur.pop() {
            return path.to_path_buf();
        }
    }
}

fn as_string(p: PathBuf) -> String {
    p.to_string_lossy().into_owned()
}

/// Resolve the project root: $KEEL_ROOT, else walk up to the nearest `.git`
/// (back-tracking from a worktree `.git` file), else the cwd.
pub fn find_root(cwd: Option<&str>) -> String {
    if let Ok(env) = std::env::var(consts::ENV_ROOT) {
        if !env.is_empty() {
            return as_string(canon(Path::new(&env)));
        }
    }
    let base = canon(&match cwd {
        Some(c) => PathBuf::from(c),
        None => std::env::current_dir().unwrap_or_default(),
    });
    let mut cur = base.clone();
    loop {
        let git = cur.join(consts::GIT_DIR);
        if git.exists() {
            if git.is_file() {
                if let Ok(content) = std::fs::read_to_string(&git) {
                    let gitdir = content.trim().trim_start_matches("gitdir: ");
                    let main = Path::new(gitdir).join("..").join("..").join("..");
                    return as_string(canon(&main));
                }
            }
            return as_string(cur);
        }
        if !cur.pop() {
            break;
        }
    }
    as_string(base)
}

/// Load keel config: $KEEL_CONFIG, else `<root>/.keel.json`, else `{}`.
pub fn load_config(root: &str) -> Value {
    let path = std::env::var(consts::ENV_CONFIG)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{root}/{}", consts::CONFIG_FILE));
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| Value::Object(Map::new()))
}

/// Resolve a (possibly relative) path to an absolute, symlink-free string.
pub fn resolve_target(cwd: Option<&str>, path: &str) -> String {
    let base = match cwd {
        Some(c) => PathBuf::from(c),
        None => std::env::current_dir().unwrap_or_default(),
    };
    as_string(canon(&base.join(path)))
}
