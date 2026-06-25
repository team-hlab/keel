//! Per-agent harness application: detect an agent and merge keel's hooks into its
//! config, non-destructively (every keel-added entry carries `"__keel": true`).

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

pub struct Agent {
    pub name: &'static str,      // platform name used in `keel run <name> ...`
    pub bin: &'static str,       // the real CLI binary keel shims
    pub home: &'static str,      // config dir under $HOME (detection)
    pub hooks_rel: &'static str, // hooks file relative to the home dir
    pub antigravity_shape: bool, // registration shape
}

pub const AGENTS: &[Agent] = &[
    Agent {
        name: "claude",
        bin: "claude",
        home: ".claude",
        hooks_rel: "settings.json",
        antigravity_shape: false,
    },
    Agent {
        name: "codex",
        bin: "codex",
        home: ".codex",
        hooks_rel: "hooks.json",
        antigravity_shape: false,
    },
    Agent {
        name: "antigravity",
        // the real Antigravity CLI is `agy`; plain `antigravity` is the GUI IDE launcher
        bin: "agy",
        // verified: Antigravity's global hooks live at ~/.gemini/config/hooks.json
        home: ".gemini",
        hooks_rel: "config/hooks.json",
        antigravity_shape: true,
    },
];

const TOOL_MATCHER: &str = "Read|Glob|Grep|Edit|MultiEdit|Write|NotebookEdit|Bash";
const STAGES: &[(&str, bool)] = &[
    ("PreToolUse", true),
    ("PermissionRequest", true),
    ("SessionStart", false),
];

/// $KEEL_HOME (test/override) or $HOME.
pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("KEEL_HOME") {
        return PathBuf::from(h);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn agent_by_bin(bin: &str) -> Option<&'static Agent> {
    AGENTS.iter().find(|a| a.bin == bin)
}

/// Display label that surfaces the shimmed binary when it differs from the platform
/// name (e.g. `antigravity (agy)`), so init/doctor show what keel actually wraps.
pub fn label(a: &Agent) -> String {
    if a.bin == a.name {
        a.name.to_string()
    } else {
        format!("{} ({})", a.name, a.bin)
    }
}

pub fn agent_home(a: &Agent) -> PathBuf {
    home().join(a.home)
}

pub fn hooks_path(a: &Agent) -> PathBuf {
    agent_home(a).join(a.hooks_rel)
}

/// An agent is present if its config dir exists or its CLI is on PATH.
pub fn detect(a: &Agent) -> bool {
    agent_home(a).exists() || find_on_path(a.bin, None).is_some()
}

pub fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Find an executable named `bin` on PATH, optionally skipping `exclude` (the shim dir).
pub fn find_on_path(bin: &str, exclude: Option<&Path>) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if exclude == Some(dir.as_path()) {
            continue;
        }
        let cand = dir.join(bin);
        if is_executable(&cand) {
            return Some(cand);
        }
    }
    None
}

fn read_json(path: &Path) -> Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| Value::Object(Map::new()))
}

/// Load a config for *merging*. `None` means the file exists but can't be read or parsed —
/// the caller MUST NOT overwrite it (preserve the user's file). Missing file → empty object.
fn load_cfg(path: &Path) -> Option<Value> {
    if !path.exists() {
        return Some(Value::Object(Map::new()));
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

fn write_json(path: &Path, v: &Value) -> std::io::Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let s = serde_json::to_string_pretty(v).unwrap_or_default();
    std::fs::write(path, s + "\n")
}

fn ensure_obj(v: &mut Value) -> &mut Map<String, Value> {
    if !v.is_object() {
        *v = Value::Object(Map::new());
    }
    v.as_object_mut().unwrap()
}

fn entry_has_cmd(e: &Value, cmd: &str) -> bool {
    e.get("hooks")
        .and_then(Value::as_array)
        .map(|hs| {
            hs.iter()
                .any(|h| h.get("command").and_then(Value::as_str) == Some(cmd))
        })
        .unwrap_or(false)
}

fn apply_hooks_style(cfg: &mut Value, name: &str) -> bool {
    let mut changed = false;
    let root = ensure_obj(cfg);
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let hooks = ensure_obj(hooks);
    for (stage, needs_matcher) in STAGES {
        let cmd = format!("keel run {name} {stage}");
        let arr_v = hooks.entry(*stage).or_insert_with(|| Value::Array(vec![]));
        if !arr_v.is_array() {
            *arr_v = Value::Array(vec![]);
        }
        let arr = arr_v.as_array_mut().unwrap();
        if arr.iter().any(|e| entry_has_cmd(e, &cmd)) {
            continue;
        }
        let mut entry =
            json!({ "__keel": true, "hooks": [ { "type": "command", "command": cmd } ] });
        if *needs_matcher {
            entry
                .as_object_mut()
                .unwrap()
                .insert("matcher".into(), json!(TOOL_MATCHER));
        }
        arr.push(entry);
        changed = true;
    }
    changed
}

fn apply_antigravity(cfg: &mut Value, name: &str) -> bool {
    let mut changed = false;
    let root = ensure_obj(cfg);
    for (stage, _) in STAGES {
        let cmd = format!("keel run {name} {stage}");
        let arr_v = root.entry(*stage).or_insert_with(|| Value::Array(vec![]));
        if !arr_v.is_array() {
            *arr_v = Value::Array(vec![]);
        }
        let arr = arr_v.as_array_mut().unwrap();
        if arr
            .iter()
            .any(|e| e.get("command").and_then(Value::as_str) == Some(cmd.as_str()))
        {
            continue;
        }
        arr.push(json!({ "command": cmd, "__keel": true }));
        changed = true;
    }
    changed
}

/// Merge keel's hooks into the agent's config. Returns whether anything changed.
pub fn apply(a: &Agent) -> std::io::Result<bool> {
    let path = hooks_path(a);
    let mut cfg = match load_cfg(&path) {
        Some(v) => v,
        None => {
            // exists but unparseable/unreadable — never clobber the user's file
            eprintln!(
                "keel: {} could not be parsed — leaving it untouched (hooks not applied)",
                path.display()
            );
            return Ok(false);
        }
    };
    let changed = if a.antigravity_shape {
        apply_antigravity(&mut cfg, a.name)
    } else {
        apply_hooks_style(&mut cfg, a.name)
    };
    if changed {
        write_json(&path, &cfg)?;
    }
    Ok(changed)
}

fn strip_keel(map: &mut Map<String, Value>) {
    for v in map.values_mut() {
        if let Some(arr) = v.as_array_mut() {
            arr.retain(|e| e.get("__keel").and_then(Value::as_bool) != Some(true));
        }
    }
}

/// Remove only keel-tagged entries from the agent's config.
pub fn clean(a: &Agent) -> std::io::Result<()> {
    let path = hooks_path(a);
    if !path.exists() {
        return Ok(());
    }
    let mut cfg = match load_cfg(&path) {
        Some(v) => v,
        None => return Ok(()), // unparseable — leave it untouched
    };
    if a.antigravity_shape {
        if let Some(m) = cfg.as_object_mut() {
            strip_keel(m);
        }
    } else if let Some(h) = cfg.get_mut("hooks").and_then(Value::as_object_mut) {
        strip_keel(h);
    }
    write_json(&path, &cfg)
}

/// Count keel-tagged hook entries currently applied (for `status`/`doctor`).
pub fn applied_count(a: &Agent) -> usize {
    let cfg = read_json(&hooks_path(a));
    let container = if a.antigravity_shape {
        Some(&cfg)
    } else {
        cfg.get("hooks")
    };
    container
        .and_then(Value::as_object)
        .map(|obj| {
            obj.values()
                .filter_map(Value::as_array)
                .flatten()
                .filter(|e| e.get("__keel").and_then(Value::as_bool) == Some(true))
                .count()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // env mutation isn't thread-safe; serialize the tests that touch PATH/KEEL_HOME.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn agy_is_the_antigravity_binary() {
        assert_eq!(agent_by_bin("agy").unwrap().name, "antigravity");
        // plain `antigravity` is the GUI IDE launcher — must NOT be shimmed
        assert!(agent_by_bin("antigravity").is_none());
    }

    #[test]
    fn apply_idempotent_and_clean() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("keel-agent-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".claude")).unwrap();
        std::env::set_var("KEEL_HOME", &tmp);

        let claude = agent_by_bin("claude").unwrap();
        assert!(apply(claude).unwrap()); // first apply changes
        assert!(!apply(claude).unwrap()); // idempotent — no further change
        assert_eq!(applied_count(claude), 3);

        let txt = std::fs::read_to_string(hooks_path(claude)).unwrap();
        assert!(txt.contains("keel run claude PreToolUse"));
        assert!(txt.contains("__keel"));
        assert!(txt.contains(TOOL_MATCHER));

        clean(claude).unwrap();
        assert_eq!(applied_count(claude), 0);

        std::env::remove_var("KEEL_HOME");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn find_on_path_respects_exclude() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("keel-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("faketool");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        std::env::set_var("PATH", &dir);
        assert!(find_on_path("faketool", None).is_some());
        assert!(find_on_path("faketool", Some(dir.as_path())).is_none()); // excluded
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_preserves_malformed_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("keel-mal-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".claude")).unwrap();
        std::env::set_var("KEEL_HOME", &tmp);

        let claude = agent_by_bin("claude").unwrap();
        let path = hooks_path(claude);
        let garbage = "{ this is : not json ]";
        std::fs::write(&path, garbage).unwrap();

        // apply must refuse to touch a file it couldn't parse (non-destructive)
        assert!(!apply(claude).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        assert_eq!(applied_count(claude), 0);

        std::env::remove_var("KEEL_HOME");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
