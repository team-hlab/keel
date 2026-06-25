//! End-to-end tests: drive the compiled `keel` binary as a subprocess.
//! Covers the CLI, every stage, multi-feature aggregation, fail-open, all three
//! adapters, audit-log opt-in, and the busybox shim (incl. the fork-bomb guard).

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

static N: AtomicU32 = AtomicU32::new(0);

fn keel() -> &'static str {
    env!("CARGO_BIN_EXE_keel")
}

fn tmp(prefix: &str) -> PathBuf {
    let n = N.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("keel-e2e-{}-{}-{}", prefix, std::process::id(), n));
    fs::create_dir_all(&p).unwrap();
    p
}

/// A project root with a git HEAD on `main` and the usual dirs.
fn project_root() -> PathBuf {
    let root = tmp("root");
    for d in [".git", "worktrees/f", "projects/foo/main"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    root
}

struct Out {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run(args: &[&str], stdin: &str, envs: &[(&str, &str)]) -> Out {
    let mut cmd = Command::new(keel());
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    Out {
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        code: o.status.code().unwrap_or(-1),
    }
}

fn payload(tool: &str, key: &str, val: &str, root: &str) -> String {
    serde_json::json!({ "tool_name": tool, "cwd": root, "tool_input": { key: val } }).to_string()
}

/// PreToolUse verdict as a string ("allow"/"deny"/"ask"/"pass").
fn pre(platform: &str, p: &str, root: &str) -> String {
    let o = run(&["run", platform, "PreToolUse"], p, &[("KEEL_ROOT", root)]);
    assert_eq!(o.code, 0, "exit; stderr={}", o.stderr);
    let v: Value = serde_json::from_str(o.stdout.trim()).unwrap();
    v.get("hookSpecificOutput")
        .and_then(|h| h.get("permissionDecision"))
        .and_then(Value::as_str)
        .unwrap_or("pass")
        .to_string()
}

fn perm(p: &str, root: &str) -> String {
    let o = run(
        &["run", "claude", "PermissionRequest"],
        p,
        &[("KEEL_ROOT", root)],
    );
    let v: Value = serde_json::from_str(o.stdout.trim()).unwrap();
    v.get("hookSpecificOutput")
        .and_then(|h| h.get("decision"))
        .and_then(|d| d.get("behavior"))
        .and_then(Value::as_str)
        .unwrap_or("pass")
        .to_string()
}

// ---- CLI ----------------------------------------------------------------

#[test]
fn cli_features_lists_all() {
    let o = run(&["features"], "", &[]);
    for f in [
        "autopermit",
        "branch-guard",
        "secret-scan",
        "audit-log",
        "session-banner",
    ] {
        assert!(o.stdout.contains(f), "missing {f}");
    }
}

#[test]
fn cli_doctor_and_unknown() {
    let d = run(
        &["doctor"],
        "",
        &[("KEEL_HOME", tmp("h").to_str().unwrap())],
    );
    assert_eq!(d.code, 0);
    assert!(d.stdout.contains("keel") && d.stdout.contains("ok"));
    assert_eq!(run(&["frobnicate"], "", &[]).code, 2);
}

// ---- PreToolUse policy --------------------------------------------------

#[test]
fn pretooluse_files_and_bash() {
    let root = project_root();
    let r = root.to_str().unwrap();
    assert_eq!(
        pre("claude", &payload("Read", "file_path", "a.md", r), r),
        "allow"
    );
    assert_eq!(
        pre("claude", &payload("Read", "file_path", "x/.env", r), r),
        "ask"
    );
    assert_eq!(
        pre(
            "claude",
            &payload("Write", "file_path", "worktrees/f/a", r),
            r
        ),
        "allow"
    );
    assert_eq!(
        pre(
            "claude",
            &payload("Write", "file_path", "projects/foo/main/A", r),
            r
        ),
        "deny"
    );
    assert_eq!(
        pre("claude", &payload("Write", "file_path", "/var/tmp/x", r), r),
        "pass"
    );
    assert_eq!(
        pre(
            "claude",
            &payload("Bash", "command", "ls -la | grep x", r),
            r
        ),
        "allow"
    );
    assert_eq!(
        pre("claude", &payload("Bash", "command", "rm -rf /", r), r),
        "deny"
    );
    fs::remove_dir_all(&root).ok();
}

// ---- multi-feature aggregation ------------------------------------------

#[test]
fn branch_guard_aggregates_to_deny() {
    let root = project_root(); // HEAD on main
    let r = root.to_str().unwrap();
    // autopermit abstains on `git commit` outside a worktree; branch-guard denies → deny
    assert_eq!(
        pre(
            "claude",
            &payload("Bash", "command", "git commit -m x", r),
            r
        ),
        "deny"
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn secret_scan_aggregates_to_ask() {
    let root = project_root();
    let r = root.to_str().unwrap();
    // worktree write (autopermit→allow) + credential content (secret-scan→ask) ⇒ ask wins
    let p = serde_json::json!({
        "tool_name": "Write", "cwd": r,
        "tool_input": { "file_path": "worktrees/f/c.py", "content": "AKIAABCDEFGHIJKLMNOP" }
    })
    .to_string();
    assert_eq!(pre("claude", &p, r), "ask");
    fs::remove_dir_all(&root).ok();
}

// ---- PermissionRequest rendering ----------------------------------------

#[test]
fn permission_request_render() {
    let root = project_root();
    let r = root.to_str().unwrap();
    assert_eq!(perm(&payload("Read", "file_path", "a.md", r), r), "allow");
    assert_eq!(
        perm(&payload("Write", "file_path", "projects/foo/main/A", r), r),
        "deny"
    );
    // ask (secret read) → defer to the prompt = no decision
    let o = run(
        &["run", "claude", "PermissionRequest"],
        &payload("Read", "file_path", "x/.env", r),
        &[("KEEL_ROOT", r)],
    );
    assert_eq!(o.stdout.trim(), r#"{"continue":true}"#);
    fs::remove_dir_all(&root).ok();
}

// ---- fail-open ----------------------------------------------------------

#[test]
fn malformed_input_fails_open() {
    let o = run(&["run", "claude", "PreToolUse"], "}{ not json", &[]);
    assert_eq!(o.code, 0);
    assert_eq!(o.stdout.trim(), r#"{"continue":true}"#);
}

// ---- other adapters -----------------------------------------------------

#[test]
fn codex_and_antigravity_render() {
    let root = project_root();
    let r = root.to_str().unwrap();
    let cmd = payload("Bash", "command", "rm -rf /", r);

    let cx = run(&["run", "codex", "PreToolUse"], &cmd, &[("KEEL_ROOT", r)]);
    let v: Value = serde_json::from_str(cx.stdout.trim()).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");

    let ag = run(
        &["run", "antigravity", "PreToolUse"],
        &cmd,
        &[("KEEL_ROOT", r)],
    );
    let v: Value = serde_json::from_str(ag.stdout.trim()).unwrap();
    assert_eq!(v["decision"], "deny");
    fs::remove_dir_all(&root).ok();
}

// ---- session-banner -----------------------------------------------------

#[test]
fn session_start_banner_to_stderr() {
    let root = project_root();
    let r = root.to_str().unwrap();
    let o = run(
        &["run", "claude", "SessionStart"],
        r#"{"cwd":"."}"#,
        &[("KEEL_ROOT", r)],
    );
    assert!(o.stderr.contains("keel active"), "stderr={}", o.stderr);
    assert_eq!(o.stdout.trim(), r#"{"continue":true}"#);
    fs::remove_dir_all(&root).ok();
}

// ---- audit-log opt-in ---------------------------------------------------

#[test]
fn audit_log_is_opt_in() {
    let root = project_root();
    let r = root.to_str().unwrap();
    let read = payload("Read", "file_path", "a.md", r);

    // default: off → no log file
    let _ = pre("claude", &read, r);
    assert!(!root.join(".keel/audit.log").exists());

    // opt-in via .keel.json → log written
    fs::write(
        root.join(".keel.json"),
        r#"{"features":{"audit-log":{"enabled":true}}}"#,
    )
    .unwrap();
    let _ = pre("claude", &read, r);
    let log = fs::read_to_string(root.join(".keel/audit.log")).unwrap();
    let rec: Value = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(rec["tool"], "Read");
    fs::remove_dir_all(&root).ok();
}

// ---- busybox shim + fork-bomb guard -------------------------------------

#[cfg(unix)]
#[test]
fn shim_execs_real_agent_and_avoids_forkbomb() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let home = tmp("shimhome");
    fs::create_dir_all(home.join(".claude")).unwrap(); // detected agent
    let shim_dir = home.join("shimbin");
    let real_dir = home.join("realbin");
    fs::create_dir_all(&shim_dir).unwrap();
    fs::create_dir_all(&real_dir).unwrap();

    // shim 'claude' → the keel binary (busybox dispatch by argv[0])
    let shim_claude = shim_dir.join("claude");
    symlink(keel(), &shim_claude).unwrap();
    // a fake real 'claude' that proves it was exec'd
    let real_claude = real_dir.join("claude");
    fs::write(&real_claude, "#!/bin/sh\necho REAL_CLAUDE_OK \"$@\"\n").unwrap();
    fs::set_permissions(&real_claude, fs::Permissions::from_mode(0o755)).unwrap();

    // shim dir FIRST on PATH: only the fork-bomb self-exclusion prevents re-invoking keel
    let path = format!("{}:{}", shim_dir.display(), real_dir.display());
    let mut cmd = Command::new(&shim_claude);
    cmd.arg("--version")
        .env("PATH", &path)
        .env("KEEL_HOME", &home);
    let o = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        stdout.contains("REAL_CLAUDE_OK --version"),
        "shim didn't exec real agent: {stdout}"
    );
    fs::remove_dir_all(&home).ok();
}
