//! End-to-end tests: drive the compiled `keel` binary as a subprocess.
//! Covers the CLI, every stage, multi-feature aggregation, fail-open, all three
//! adapters, decision-log, and the busybox shim (incl. the fork-bomb guard).

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
        "ask" // in-repo write outside a worktree → ask by default (was deny)
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
    // shell content-read of a secret asks, same as the Read tool (no `cat .env` bypass)
    assert_eq!(
        pre("claude", &payload("Bash", "command", "cat x/.env", r), r),
        "ask"
    );
    assert_eq!(
        pre("claude", &payload("Bash", "command", "cat README.md", r), r),
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
    // strict mode so the in-repo write denies — exercises the deny render path
    fs::write(
        root.join(".keel.json"),
        r#"{"features":{"autopermit":{"protectedWrites":"deny"}}}"#,
    )
    .unwrap();
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

#[test]
fn write_tools_gated_on_codex_and_antigravity() {
    let root = project_root();
    let r = root.to_str().unwrap();
    // strict mode: assert these tools are recognized + gated to deny (default would be ask)
    fs::write(
        root.join(".keel.json"),
        r#"{"features":{"autopermit":{"protectedWrites":"deny"}}}"#,
    )
    .unwrap();

    // Codex apply_patch: a SAFE worktree file first, a PROTECTED file second → deny
    // (the protected write must not slip through behind the safe one).
    let patch = "*** Begin Patch\n*** Add File: worktrees/f/ok.py\n+a=1\n*** Update File: projects/foo/main/a.py\n@@\n+x=1\n*** End Patch";
    let cmd = payload("apply_patch", "command", patch, r);
    let o = run(&["run", "codex", "PreToolUse"], &cmd, &[("KEEL_ROOT", r)]);
    let v: Value = serde_json::from_str(o.stdout.trim()).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");

    // Antigravity write_to_file into a protected path → deny (TargetFile normalized)
    let ag = serde_json::json!({
        "toolCall": { "name": "write_to_file",
            "args": { "TargetFile": "projects/foo/main/b.py", "CodeContent": "ok" } },
        "workspacePaths": [r]
    })
    .to_string();
    let o = run(
        &["run", "antigravity", "PreToolUse"],
        &ag,
        &[("KEEL_ROOT", r)],
    );
    let v: Value = serde_json::from_str(o.stdout.trim()).unwrap();
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

// ---- decision log -------------------------------------------------------

#[test]
fn decision_log_records_verdict_when_enabled() {
    let root = project_root();
    let r = root.to_str().unwrap();
    let logp = root.join("decisions.jsonl");
    let read = payload("Read", "file_path", "a.md", r);

    // default: off → no log
    let _ = pre("claude", &read, r);
    assert!(!logp.exists());

    // opt-in via .keel.json (path contained in the test project)
    fs::write(
        root.join(".keel.json"),
        format!(
            r#"{{"log":{{"enabled":true,"path":"{}"}}}}"#,
            logp.display()
        ),
    )
    .unwrap();
    let _ = pre("claude", &read, r);
    let rec: Value = serde_json::from_str(fs::read_to_string(&logp).unwrap().trim()).unwrap();
    assert_eq!(rec["op"], "read"); // operation derived from the tool
    assert_eq!(rec["verdict"], "allow"); // the FINAL aggregated verdict is logged
    assert_eq!(rec["resource"], "a.md");
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

// ---- edge cases: malformed / odd input must fail open --------------------

#[test]
fn edge_inputs_fail_open() {
    let cont = r#"{"continue":true}"#;
    for stdin in [
        "", "[1,2,3]", "\"hi\"", "42", "{}", "}{ bad", "null", "true",
    ] {
        let o = run(&["run", "claude", "PreToolUse"], stdin, &[]);
        assert_eq!(o.code, 0, "stdin={stdin:?}");
        assert_eq!(o.stdout.trim(), cont, "stdin={stdin:?}");
    }
    // deeply nested JSON (past serde's recursion limit) → parse error → fail open
    let deep = format!("{}{}", "[".repeat(600), "]".repeat(600));
    let o = run(&["run", "claude", "PreToolUse"], &deep, &[]);
    assert_eq!(o.code, 0);
    assert_eq!(o.stdout.trim(), cont);
}

#[test]
fn missing_and_nonstring_fields_dont_crash() {
    let root = project_root();
    let r = root.to_str().unwrap();
    let go = |v: Value| -> Out {
        run(
            &["run", "claude", "PreToolUse"],
            &v.to_string(),
            &[("KEEL_ROOT", r)],
        )
    };
    let dec = |o: &Out| -> String {
        let v: Value = serde_json::from_str(o.stdout.trim()).unwrap();
        v.get("hookSpecificOutput")
            .and_then(|h| h.get("permissionDecision"))
            .and_then(Value::as_str)
            .unwrap_or("pass")
            .to_string()
    };
    // missing tool_name → pass
    assert_eq!(dec(&go(serde_json::json!({ "cwd": r }))), "pass");
    // missing tool_input → Read allow, Write deny
    assert_eq!(
        dec(&go(serde_json::json!({ "tool_name": "Read", "cwd": r }))),
        "allow"
    );
    assert_eq!(
        dec(&go(serde_json::json!({ "tool_name": "Write", "cwd": r }))),
        "deny"
    );
    // non-string file_path / command → no crash, sensible verdict
    assert_eq!(
        dec(&go(
            serde_json::json!({ "tool_name": "Read", "cwd": r, "tool_input": { "file_path": 123 } })
        )),
        "allow"
    );
    assert_eq!(
        dec(&go(
            serde_json::json!({ "tool_name": "Write", "cwd": r, "tool_input": { "file_path": 123 } })
        )),
        "deny"
    );
    let bash =
        go(serde_json::json!({ "tool_name": "Bash", "cwd": r, "tool_input": { "command": 123 } }));
    assert_eq!(bash.code, 0);
    assert_eq!(bash.stdout.trim(), r#"{"continue":true}"#);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn large_input_does_not_hang() {
    let root = project_root();
    let r = root.to_str().unwrap();
    let big = format!("echo {}", "a ".repeat(100_000)); // ~200 KB
    let o = run(
        &["run", "claude", "PreToolUse"],
        &payload("Bash", "command", &big, r),
        &[("KEEL_ROOT", r)],
    );
    assert_eq!(o.code, 0);
    serde_json::from_str::<Value>(o.stdout.trim()).expect("valid JSON, no hang/crash");
    fs::remove_dir_all(&root).ok();
}

// ---- fault tolerance: bad env / config / observer failure ----------------

#[test]
fn fault_tolerant_root_and_config() {
    // nonexistent KEEL_ROOT → still decides, no crash
    let o = run(
        &["run", "claude", "PreToolUse"],
        &payload("Read", "file_path", "a.md", "/repo"),
        &[("KEEL_ROOT", "/no/such/keel/root")],
    );
    assert_eq!(o.code, 0);

    let root = project_root();
    let r = root.to_str().unwrap();
    let read = payload("Read", "file_path", "a.md", r);

    // malformed .keel.json → ignored, default features still work
    fs::write(root.join(".keel.json"), "{ not json ]").unwrap();
    assert_eq!(pre("claude", &read, r), "allow");

    // non-object config → ignored
    fs::write(root.join(".keel.json"), "[]").unwrap();
    assert_eq!(pre("claude", &read, r), "allow");
    fs::remove_dir_all(&root).ok();
}

#[test]
fn decision_log_failure_does_not_break_verdict() {
    let root = project_root();
    let r = root.to_str().unwrap();
    // point the log at an un-writable path: a FILE stands where its parent dir would go
    fs::write(root.join("blocker"), "x").unwrap();
    let bad = root.join("blocker/decisions.jsonl");
    fs::write(
        root.join(".keel.json"),
        format!(r#"{{"log":{{"enabled":true,"path":"{}"}}}}"#, bad.display()),
    )
    .unwrap();
    // logging fails silently; the gating verdict is unaffected
    assert_eq!(
        pre("claude", &payload("Read", "file_path", "a.md", r), r),
        "allow"
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn cli_version() {
    let o = run(&["version"], "", &[]);
    assert_eq!(o.code, 0);
    assert!(o.stdout.trim().starts_with("keel "), "{}", o.stdout);
    assert!(o.stdout.contains(env!("CARGO_PKG_VERSION")));
}
