//! Per-agent harness application: detect an agent and merge keel's hooks into its
//! config, non-destructively (every keel-added entry carries `"__keel": true`).

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::consts;

pub struct Agent {
    pub name: &'static str,      // platform name used in `keel run <name> ...`
    pub bin: &'static str,       // the real CLI binary keel shims
    pub home: &'static str,      // config dir under $HOME (detection + hooks)
    pub hooks_rel: &'static str, // hooks file relative to the home dir
    pub hooks_container: &'static str, // top-level key the per-stage hooks nest under
    pub tool_matcher: &'static str, // regex matched against the tool name (policy hooks)
    pub home_is_exclusive: bool, // is `home` unique to this agent? (else require the binary)
    pub carryover_stages: &'static [(&'static str, bool)], // (stage, wants write-matcher)
    pub write_matcher: &'static str, // write-only tools — carryover's PreToolUse capture
}

pub const AGENTS: &[Agent] = &[
    Agent {
        name: "claude",
        bin: "claude",
        home: ".claude",
        hooks_rel: "settings.json",
        hooks_container: "hooks",
        tool_matcher: TOOL_MATCHER,
        home_is_exclusive: true, // ~/.claude is Claude Code's alone
        carryover_stages: CLAUDE_CARRYOVER,
        write_matcher: WRITE_MATCHER,
    },
    Agent {
        name: "codex",
        bin: "codex",
        home: ".codex",
        hooks_rel: "hooks.json",
        hooks_container: "hooks",
        tool_matcher: TOOL_MATCHER,
        home_is_exclusive: true, // ~/.codex is Codex's alone
        carryover_stages: CODEX_CARRYOVER,
        write_matcher: WRITE_MATCHER,
    },
    Agent {
        name: "antigravity",
        // the real Antigravity CLI is `agy`; plain `antigravity` is the GUI IDE launcher
        bin: "agy",
        // verified: Antigravity's global hooks live at ~/.gemini/config/hooks.json
        home: ".gemini",
        hooks_rel: "config/hooks.json",
        // Antigravity nests hooks under a namespace key (not "hooks"), with a matcher on
        // its own tool names.
        hooks_container: "keel",
        tool_matcher: ANTIGRAVITY_MATCHER,
        // ~/.gemini is shared with the Gemini CLI, so it doesn't imply Antigravity —
        // require the `agy` binary on PATH to detect it.
        home_is_exclusive: false,
        carryover_stages: ANTIGRAVITY_CARRYOVER,
        write_matcher: ANTIGRAVITY_WRITE_MATCHER,
    },
];

// Claude/Codex tool names (`apply_patch` is Codex's edit tool; Claude never sends it).
const TOOL_MATCHER: &str = "Read|Glob|Grep|Edit|MultiEdit|Write|NotebookEdit|Bash|apply_patch";
// Antigravity's own tool names — the ones keel gates (shell · writes · content reads).
const ANTIGRAVITY_MATCHER: &str = "run_command|write_to_file|replace_file_content|multi_replace_file_content|view_file|view_code_item|search_in_file|view_file_outline|grep_search";
// Write tools only — carryover's PreToolUse captures mutations, so it need not fire on reads.
const WRITE_MATCHER: &str = "Edit|MultiEdit|Write|NotebookEdit|apply_patch";
const ANTIGRAVITY_WRITE_MATCHER: &str =
    "write_to_file|replace_file_content|multi_replace_file_content";
const STAGES: &[(&str, bool)] = &[
    ("PreToolUse", true),
    ("PermissionRequest", true),
    ("SessionStart", false),
];

// carryover's hook stages per agent — `(stage, wants_write_matcher)`, invoked as
// `keel carryover-hook <name> <stage>`. Inject stage differs: SessionStart for Claude/Codex,
// PreInvocation for Antigravity (it has no SessionStart).
const CLAUDE_CARRYOVER: &[(&str, bool)] = &[
    ("SessionStart", false),
    ("Stop", false),
    ("SessionEnd", false),
];
const CODEX_CARRYOVER: &[(&str, bool)] = &[
    ("SessionStart", false),
    ("UserPromptSubmit", false),
    ("Stop", false),
    ("PreToolUse", true),
];
const ANTIGRAVITY_CARRYOVER: &[(&str, bool)] = &[
    ("PreInvocation", false),
    ("Stop", false),
    ("PreToolUse", true),
];

/// $KEEL_HOME (test/override) or $HOME.
pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os(consts::ENV_HOME) {
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

/// An agent is present if its CLI is on PATH, or — for agents whose config dir is theirs
/// alone — that dir exists. Antigravity's `~/.gemini` is shared with the Gemini CLI, so it
/// requires the `agy` binary; a bare `~/.gemini` must not imply Antigravity.
pub fn detect(a: &Agent) -> bool {
    if a.home_is_exclusive && agent_home(a).exists() {
        return true;
    }
    find_on_path(a.bin, None).is_some()
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

/// Insert one `__keel`-tagged hook entry into `container[stage]` (idempotent by command).
fn insert_hook(
    container: &mut Map<String, Value>,
    stage: &str,
    cmd: &str,
    matcher: Option<&str>,
) -> bool {
    let arr_v = container
        .entry(stage.to_string())
        .or_insert_with(|| Value::Array(vec![]));
    if !arr_v.is_array() {
        *arr_v = Value::Array(vec![]);
    }
    let arr = arr_v.as_array_mut().unwrap();
    if arr.iter().any(|e| entry_has_cmd(e, cmd)) {
        return false;
    }
    let mut entry = json!({ "hooks": [ { "type": "command", "command": cmd } ] });
    let obj = entry.as_object_mut().unwrap();
    obj.insert(consts::KEEL_MARKER.into(), Value::Bool(true));
    if let Some(m) = matcher {
        obj.insert("matcher".into(), json!(m));
    }
    arr.push(entry);
    true
}

/// Merge keel's hooks into the agent's config under `a.hooks_container` → `<stage>` →
/// `[{matcher?, hooks:[{type:"command", command}], __keel}]` — the policy hooks (`keel run`)
/// plus carryover's (`keel carryover-hook`). Idempotent + non-destructive.
fn apply_hooks(cfg: &mut Value, a: &Agent) -> bool {
    let mut changed = false;
    let root = ensure_obj(cfg);
    let container = root
        .entry(a.hooks_container)
        .or_insert_with(|| Value::Object(Map::new()));
    let container = ensure_obj(container);
    // policy hooks (`keel run …`)
    for (stage, needs_matcher) in STAGES {
        let cmd = consts::hook_command(a.name, stage);
        let m = needs_matcher.then_some(a.tool_matcher);
        changed |= insert_hook(container, stage, &cmd, m);
    }
    // carryover hooks (`keel carryover-hook …`) — gated per-project at run time. PreToolUse
    // uses the WRITE-only matcher (capture only fires on mutations, not reads).
    for (stage, wants_write_matcher) in a.carryover_stages {
        let cmd = consts::carryover_command(a.name, stage);
        let m = wants_write_matcher.then_some(a.write_matcher);
        changed |= insert_hook(container, stage, &cmd, m);
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
    let changed = apply_hooks(&mut cfg, a);
    if changed {
        write_json(&path, &cfg)?;
    }
    Ok(changed)
}

fn strip_keel(map: &mut Map<String, Value>) {
    for v in map.values_mut() {
        if let Some(arr) = v.as_array_mut() {
            arr.retain(|e| e.get(consts::KEEL_MARKER).and_then(Value::as_bool) != Some(true));
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
    let mut container_empty = false;
    if let Some(c) = cfg
        .get_mut(a.hooks_container)
        .and_then(Value::as_object_mut)
    {
        strip_keel(c);
        // prune stage arrays that keel emptied, then note if the whole container is now empty
        c.retain(|_, v| !v.as_array().is_some_and(|arr| arr.is_empty()));
        container_empty = c.is_empty();
    }
    // remove the container key if it's left empty (keel created it) — restore byte-clean
    if container_empty {
        if let Some(m) = cfg.as_object_mut() {
            m.remove(a.hooks_container);
        }
    }
    write_json(&path, &cfg)
}

/// Count keel-tagged hook entries currently applied (for `status`/`doctor`).
pub fn applied_count(a: &Agent) -> usize {
    let cfg = read_json(&hooks_path(a));
    cfg.get(a.hooks_container)
        .and_then(Value::as_object)
        .map(|obj| {
            obj.values()
                .filter_map(Value::as_array)
                .flatten()
                .filter(|e| e.get(consts::KEEL_MARKER).and_then(Value::as_bool) == Some(true))
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
        std::env::set_var(consts::ENV_HOME, &tmp);

        let claude = agent_by_bin("claude").unwrap();
        assert!(apply(claude).unwrap()); // first apply changes
        assert!(!apply(claude).unwrap()); // idempotent — no further change
        assert_eq!(applied_count(claude), 6); // 3 policy + 3 carryover

        let txt = std::fs::read_to_string(hooks_path(claude)).unwrap();
        assert!(txt.contains("keel run claude PreToolUse"));
        assert!(txt.contains("keel carryover-hook claude Stop")); // carryover installed too
        assert!(txt.contains(consts::KEEL_MARKER));
        assert!(txt.contains(TOOL_MATCHER));

        clean(claude).unwrap();
        assert_eq!(applied_count(claude), 0);
        // byte-clean: the empty `hooks` container keel created is pruned (no residue)
        let after: Value =
            serde_json::from_str(&std::fs::read_to_string(hooks_path(claude)).unwrap()).unwrap();
        assert!(after.get("hooks").is_none(), "empty hooks residue: {after}");

        std::env::remove_var(consts::ENV_HOME);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn clean_preserves_a_users_own_hook() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("keel-clean-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".claude")).unwrap();
        std::env::set_var(consts::ENV_HOME, &tmp);
        let claude = agent_by_bin("claude").unwrap();
        let path = hooks_path(claude);
        std::fs::write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"foreign"}]}]}}"#,
        )
        .unwrap();
        apply(claude).unwrap();
        clean(claude).unwrap();
        let cfg: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        // keel's entries gone, the user's foreign hook + its container preserved
        assert_eq!(applied_count(claude), 0);
        assert_eq!(
            cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "foreign"
        );

        std::env::remove_var(consts::ENV_HOME);
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
    fn antigravity_needs_binary_not_just_gemini_dir() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("keel-det-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".gemini")).unwrap(); // shared with the Gemini CLI
        std::fs::create_dir_all(tmp.join(".claude")).unwrap();
        std::env::set_var(consts::ENV_HOME, &tmp);
        let orig_path = std::env::var_os("PATH");
        std::env::set_var("PATH", tmp.join("nobin")); // no agent binaries on PATH

        // a bare ~/.gemini must NOT imply Antigravity (the dir is shared)
        assert!(!detect(agent_by_bin("agy").unwrap()));
        // but an exclusive config dir does imply its agent
        assert!(detect(agent_by_bin("claude").unwrap()));

        match orig_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        std::env::remove_var(consts::ENV_HOME);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn apply_preserves_malformed_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("keel-mal-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".claude")).unwrap();
        std::env::set_var(consts::ENV_HOME, &tmp);

        let claude = agent_by_bin("claude").unwrap();
        let path = hooks_path(claude);
        let garbage = "{ this is : not json ]";
        std::fs::write(&path, garbage).unwrap();

        // apply must refuse to touch a file it couldn't parse (non-destructive)
        assert!(!apply(claude).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        assert_eq!(applied_count(claude), 0);

        std::env::remove_var(consts::ENV_HOME);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn claude_shape_matcher_only_on_tool_stages() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("keel-shape-c-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".claude")).unwrap();
        std::env::set_var(consts::ENV_HOME, &tmp);

        let claude = agent_by_bin("claude").unwrap();
        apply(claude).unwrap();
        let cfg: Value =
            serde_json::from_str(&std::fs::read_to_string(hooks_path(claude)).unwrap()).unwrap();
        let hooks = &cfg["hooks"];
        assert_eq!(
            hooks["PreToolUse"][0]["hooks"][0]["command"],
            "keel run claude PreToolUse"
        );
        assert!(hooks["PreToolUse"][0].get("matcher").is_some());
        assert_eq!(
            hooks["PermissionRequest"][0]["hooks"][0]["command"],
            "keel run claude PermissionRequest"
        );
        assert!(hooks["SessionStart"][0].get("matcher").is_none());

        std::env::remove_var(consts::ENV_HOME);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn codex_and_antigravity_registration_shapes() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("keel-shape-ca-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var(consts::ENV_HOME, &tmp);

        let codex = agent_by_bin("codex").unwrap();
        apply(codex).unwrap();
        let cfg: Value =
            serde_json::from_str(&std::fs::read_to_string(hooks_path(codex)).unwrap()).unwrap();
        assert_eq!(
            cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "keel run codex PreToolUse"
        );

        let antig = agent_by_bin("agy").unwrap();
        apply(antig).unwrap();
        let cfg: Value =
            serde_json::from_str(&std::fs::read_to_string(hooks_path(antig)).unwrap()).unwrap();
        // namespaced shape: cfg.keel.<stage>[0].hooks[0].command, with a tool matcher
        assert_eq!(
            cfg["keel"]["PreToolUse"][0]["hooks"][0]["command"],
            "keel run antigravity PreToolUse"
        );
        assert!(cfg["keel"]["PreToolUse"][0]
            .get("matcher")
            .and_then(|m| m.as_str())
            .is_some_and(|m| m.contains("run_command")));

        std::env::remove_var(consts::ENV_HOME);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn carryover_pretooluse_uses_write_only_matcher() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("keel-cvm-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var(consts::ENV_HOME, &tmp);

        let codex = agent_by_bin("codex").unwrap();
        apply(codex).unwrap();
        let cfg: Value =
            serde_json::from_str(&std::fs::read_to_string(hooks_path(codex)).unwrap()).unwrap();
        let cv = cfg["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["hooks"][0]["command"] == "keel carryover-hook codex PreToolUse")
            .expect("carryover PreToolUse entry");
        let matcher = cv["matcher"].as_str().unwrap();
        assert!(matcher.contains("Write") && matcher.contains("apply_patch"));
        assert!(
            !matcher.contains("Read"),
            "must not fire on reads: {matcher}"
        );

        std::env::remove_var(consts::ENV_HOME);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn apply_merges_into_existing_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("keel-merge-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".claude")).unwrap();
        std::env::set_var(consts::ENV_HOME, &tmp);

        let claude = agent_by_bin("claude").unwrap();
        let path = hooks_path(claude);
        std::fs::write(
            &path,
            r#"{"permissions":{"allow":["Read"]},"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"foreign"}]}]}}"#,
        )
        .unwrap();
        apply(claude).unwrap();

        let cfg: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg["permissions"]["allow"][0], "Read"); // unrelated key preserved
        let pre = cfg["hooks"]["PreToolUse"].as_array().unwrap();
        assert!(pre.iter().any(|e| e["hooks"][0]["command"] == "foreign")); // foreign hook kept
        assert!(pre
            .iter()
            .any(|e| e["hooks"][0]["command"] == "keel run claude PreToolUse")); // keel added

        std::env::remove_var(consts::ENV_HOME);
        std::fs::remove_dir_all(&tmp).ok();
    }
}
