//! carryover — cross-agent session continuity.
//!
//! This module is the Rust port of `docs/explore/carryover-sim.py`: the capture core
//! plus a Claude Code transcript reader. It produces the two artifacts the live feature
//! will produce — a keel-owned `snapshot` (schema-first store) and the `digest` injected
//! into the next agent at SessionStart.
//!
//! Two entrypoints: `keel carryover <transcript.jsonl>` (dev — inspect a session offline)
//! and `keel carryover-hook <platform> <stage>` (live — driven by an agent's hooks). Claude
//! captures by batch-reading the transcript; Codex/Antigravity accumulate from inline hook
//! payloads. Still a spike (hand-installed hooks), not yet a registry-gated keel Feature.
//!
//! Capture rules (from the design):
//!   * goal   ← user prompts only (drop meta / tool-results / sidechains)
//!   * state  ← gitBranch + cwd (structural, free)
//!   * files  ← MUTATING tool calls only (Edit/Write/MultiEdit/NotebookEdit) — drop reads
//!   * result ← latest assistant text block
//!
//! Everything else is dropped at capture time — never stored.

use serde_json::{json, Value};

use crate::features::secret_scan;
use crate::model::Event;
use crate::{adapters, agent, runtime};

/// Tools that change the tree. A `PreToolUse` call to anything else is exploration noise.
const MUTATING: &[&str] = &["Edit", "MultiEdit", "Write", "NotebookEdit"];

/// Prompt-shaped records that aren't real user intent (injected wrappers).
const DROP_PREFIXES: &[&str] = &[
    "<local-command",
    "Caveat:",
    "<command-name>",
    "[Request interrupted",
];

/// How many recent prompts to retain as `goal` (rolling window).
const KEEP_PROMPTS: usize = 6;
/// How many recent distinct mutated files to retain — long sessions touch hundreds, so
/// `files` needs a recency cap just like `goal`, or the snapshot is no longer lightweight.
const KEEP_FILES: usize = 12;
/// Cap the stored answer so the snapshot stays a few KB.
const RESULT_CHARS: usize = 600;
/// Don't resume a snapshot older than this — a months-old session isn't "where you left off".
const FRESH_SECS: u64 = 7 * 24 * 3600;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The keel-owned, overwrite-in-place store. Only fields the hand-off admits.
#[derive(Debug, Default)]
pub struct Snapshot {
    pub root: Option<String>,
    pub root_hash: String,
    pub branch: Option<String>,
    pub goal: Vec<String>,
    pub files: Vec<String>,
    pub result: Option<String>,
    pub decisions: Option<String>, // T2: PreCompact harvest — not populated from a transcript
    pub by: Option<String>,        // capturing agent (provenance); None → "claude"
    pub updated: Option<u64>,      // unix secs, stamped at persist; drives freshness
}

/// What was kept vs dropped — the "no useless data" claim, measured.
#[derive(Debug, Default)]
pub struct Stats {
    pub records: usize,
    pub stored_signals: usize,
    pub dropped_noise: usize,
}

/// user `content` is a string or a list of blocks; return the prompt text, or None if it's
/// actually a tool-result turn.
fn prompt_text(content: &Value) -> Option<String> {
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(blocks) => {
            if blocks
                .iter()
                .any(|b| b.get("type").and_then(Value::as_str) == Some("tool_result"))
            {
                return None;
            }
            let texts: Vec<&str> = blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect();
            (!texts.is_empty()).then(|| texts.join("\n"))
        }
        _ => None,
    }
}

fn is_true(rec: &Value, key: &str) -> bool {
    rec.get(key).and_then(Value::as_bool) == Some(true)
}

/// A genuine user prompt → the unit of `goal`. (adapter: UserPromptSubmit parse)
fn real_prompt(rec: &Value) -> Option<String> {
    if rec.get("type").and_then(Value::as_str) != Some("user")
        || is_true(rec, "isMeta")
        || is_true(rec, "isSidechain")
    {
        return None;
    }
    let t = prompt_text(rec.get("message")?.get("content")?)?;
    let t = t.trim();
    if t.is_empty() || DROP_PREFIXES.iter().any(|p| t.starts_with(p)) {
        return None;
    }
    Some(t.to_string())
}

/// The assistant's prose for this turn. (adapter: Stop parse — transcript route)
fn assistant_text(rec: &Value) -> Option<String> {
    if rec.get("type").and_then(Value::as_str) != Some("assistant") {
        return None;
    }
    let blocks = rec.get("message")?.get("content")?.as_array()?;
    let texts: Vec<&str> = blocks
        .iter()
        .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|b| b.get("text").and_then(Value::as_str))
        .collect();
    let joined = texts.join("\n");
    let joined = joined.trim();
    (!joined.is_empty()).then(|| joined.to_string())
}

/// Append paths of mutating tool calls in this record. (feature: mutation-only filter)
fn collect_mutated(rec: &Value, out: &mut Vec<String>) {
    if rec.get("type").and_then(Value::as_str) != Some("assistant") {
        return;
    }
    let Some(blocks) = rec
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for b in blocks {
        if b.get("type").and_then(Value::as_str) != Some("tool_use") {
            continue;
        }
        let name = b.get("name").and_then(Value::as_str).unwrap_or("");
        if MUTATING.contains(&name) {
            if let Some(fp) = b
                .get("input")
                .and_then(|i| i.get("file_path"))
                .and_then(Value::as_str)
            {
                out.push(fp.to_string());
            }
        }
    }
}

/// Stable-by-contract hash for the on-disk store key (FNV-1a). NOT `DefaultHasher`, whose
/// algorithm the stdlib may change across releases — that would silently orphan every
/// snapshot on a toolchain bump.
fn root_hash(cwd: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in cwd.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")[..12].to_string()
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n).collect::<String>())
    } else {
        s.to_string()
    }
}

/// The capture core: a stream of transcript records → one Snapshot. (feature: carryover.rs)
pub fn capture<I: IntoIterator<Item = Value>>(records: I) -> (Snapshot, Stats) {
    let mut prompts: Vec<String> = Vec::new();
    let mut files: Vec<String> = Vec::new();
    let mut branch: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut result: Option<String> = None;
    let mut stats = Stats::default();

    for rec in records {
        stats.records += 1;
        if let Some(b) = rec.get("gitBranch").and_then(Value::as_str) {
            branch = Some(b.to_string());
        }
        if let Some(c) = rec.get("cwd").and_then(Value::as_str) {
            cwd = Some(c.to_string());
        }
        if let Some(p) = real_prompt(&rec) {
            prompts.push(p);
            continue;
        }
        let answer = assistant_text(&rec);
        let before = files.len();
        collect_mutated(&rec, &mut files);
        let got_files = files.len() > before;
        match answer {
            Some(a) => result = Some(a), // latest assistant text wins
            None if !got_files => stats.dropped_noise += 1, // useless — never stored
            None => {}
        }
    }

    // schema-first + bounded: distinct files by *most-recent* occurrence, then the last
    // KEEP_FILES — so a 300-file session still yields a few-KB snapshot.
    let mut seen = std::collections::HashSet::new();
    let mut recent: Vec<String> = files
        .iter()
        .rev()
        .filter(|f| seen.insert(f.as_str()))
        .cloned()
        .collect();
    recent.reverse();
    let files = recent.split_off(recent.len().saturating_sub(KEEP_FILES));

    // redact secrets before anything is stored to disk
    let goal: Vec<String> = prompts
        .split_off(prompts.len().saturating_sub(KEEP_PROMPTS))
        .iter()
        .map(|p| secret_scan::redact(p))
        .collect();
    let result = result
        .as_deref()
        .map(|r| truncate(&secret_scan::redact(r), RESULT_CHARS));
    stats.stored_signals = goal.len() + files.len() + usize::from(result.is_some());

    let snap = Snapshot {
        root_hash: root_hash(cwd.as_deref().unwrap_or("")),
        root: cwd,
        branch,
        goal,
        files,
        result,
        decisions: None,
        by: None,      // Claude batch capture
        updated: None, // stamped at persist()
    };
    (snap, stats)
}

impl Snapshot {
    /// The on-disk store record (`~/.keel/carryover/<root_hash>/snapshot.json`).
    pub fn to_json(&self) -> Value {
        json!({
            "root": self.root,
            "root_hash": self.root_hash,
            "branch": self.branch,
            "goal": self.goal,
            "files": self.files,
            "result": self.result,
            "decisions": self.decisions,
            "by": self.by.as_deref().unwrap_or("claude"),
            "updated": self.updated.unwrap_or(0),
        })
    }

    /// What the next agent receives at SessionStart. (feature: inject)
    pub fn render_digest(&self) -> String {
        let none = "(none)".to_string();
        let branch = self.branch.as_ref().unwrap_or(&none);
        let goal = if self.goal.is_empty() {
            "  (none captured)".to_string()
        } else {
            self.goal
                .iter()
                .map(|g| format!("  - {}", truncate(g, 160)))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let files = if self.files.is_empty() {
            "  (none)".to_string()
        } else {
            self.files
                .iter()
                .map(|f| format!("  - `{f}`"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let result = self.result.as_deref().unwrap_or("(no answer captured)");
        format!(
            "# ⟢ carryover — resuming prior session\n\
             _keel restored this automatically. Branch `{branch}` · {nfiles} files in flight._\n\n\
             ## Goal (recent intent)\n{goal}\n\n\
             ## Working state\n  branch: `{branch}`\n  files touched:\n{files}\n\n\
             ## Where it landed\n  {result}\n\n\
             ---\n\
             > ⚠️ **Verify, don't trust.** This is a reconstruction, not ground truth. Re-read the\n\
             > files above and validate against the actual code before continuing. Disk state wins.\n",
            nfiles = self.files.len(),
        )
    }
}

fn load_jsonl(path: &str) -> std::io::Result<Vec<Value>> {
    let txt = std::fs::read_to_string(path)?;
    Ok(txt
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

/// `keel carryover <transcript.jsonl> [out_dir]` — capture a real session, emit artifacts.
pub fn run_cli(args: &[String]) -> i32 {
    let Some(path) = args.first() else {
        eprintln!("usage: keel carryover <transcript.jsonl> [out_dir]");
        return 2;
    };
    let records = match load_jsonl(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("carryover: cannot read {path}: {e}");
            return 1;
        }
    };
    let (snap, stats) = capture(records);
    let json = serde_json::to_string_pretty(&snap.to_json()).unwrap_or_default();
    let digest = snap.render_digest();

    eprintln!("input transcript : {path}");
    eprintln!("records scanned  : {}", stats.records);
    eprintln!(
        "signals stored   : {}  (prompts + distinct mutated files + last answer)",
        stats.stored_signals
    );
    eprintln!(
        "noise dropped    : {}  (never written)",
        stats.dropped_noise
    );
    eprintln!(
        "snapshot size    : {} bytes",
        snap.to_json().to_string().len()
    );

    if let Some(dir) = args.get(1) {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(format!("{dir}/snapshot.json"), &json);
        let _ = std::fs::write(format!("{dir}/digest.md"), &digest);
        eprintln!("→ wrote {dir}/snapshot.json + {dir}/digest.md");
    }
    println!("{json}\n\n---- digest.md ----\n{digest}");
    0
}

/// The store dir for a project: `<keel-home>/.keel/carryover/<root_hash>/`.
/// Keyed by the git root (stable across subdirs), not the raw cwd.
fn store_dir(cwd: Option<&str>) -> std::path::PathBuf {
    let root = runtime::find_root(cwd);
    agent::home()
        .join(".keel")
        .join("carryover")
        .join(root_hash(&root))
}

/// Incremental capture — for agents that deliver context inline, one hook at a time
/// (Codex/Antigravity) rather than in a batch transcript (Claude).
impl Snapshot {
    fn from_json(v: &Value) -> Snapshot {
        let strs = |k: &str| {
            v.get(k)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(String::from);
        Snapshot {
            root: s("root"),
            root_hash: s("root_hash").unwrap_or_default(),
            branch: s("branch"),
            goal: strs("goal"),
            files: strs("files"),
            result: s("result"),
            decisions: s("decisions"),
            by: s("by"),
            updated: v.get("updated").and_then(Value::as_u64),
        }
    }
    fn is_empty(&self) -> bool {
        self.goal.is_empty()
            && self.files.is_empty()
            && self.result.is_none()
            && self.decisions.is_none()
    }
    fn push_prompt(&mut self, p: &str) {
        let p = secret_scan::redact(p.trim());
        if p.is_empty() {
            return;
        }
        self.goal.push(p);
        let start = self.goal.len().saturating_sub(KEEP_PROMPTS);
        self.goal = self.goal.split_off(start);
    }
    fn push_file(&mut self, f: &str) {
        self.files.retain(|x| x.as_str() != f); // move an existing path to most-recent
        self.files.push(f.to_string());
        let start = self.files.len().saturating_sub(KEEP_FILES);
        self.files = self.files.split_off(start);
    }
    fn set_result(&mut self, r: &str) {
        let r = secret_scan::redact(r.trim());
        if !r.is_empty() {
            self.result = Some(truncate(&r, RESULT_CHARS));
        }
    }
}

fn load_snapshot(dir: &std::path::Path) -> Snapshot {
    let path = dir.join("snapshot.json");
    let Ok(txt) = std::fs::read_to_string(&path) else {
        return Snapshot::default(); // no store yet
    };
    match serde_json::from_str::<Value>(&txt) {
        Ok(v) => Snapshot::from_json(&v),
        Err(_) => {
            // present but unparseable — preserve it instead of silently overwriting on the
            // next capture (that was a data-loss bug).
            let _ = std::fs::rename(&path, path.with_extension("json.corrupt"));
            Snapshot::default()
        }
    }
}

/// Atomic, private write: tmp file (0600) → rename. Prevents torn reads under concurrent
/// hooks and keeps the store from being world-readable.
fn write_private(path: &std::path::Path, data: &str) {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    if std::fs::write(&tmp, data).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    let _ = std::fs::rename(&tmp, path);
}

fn persist(snap: &Snapshot, dir: &std::path::Path) {
    let _ = std::fs::create_dir_all(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let mut v = snap.to_json();
    v["updated"] = json!(now_secs()); // stamp real time at write
    if let Ok(j) = serde_json::to_string_pretty(&v) {
        write_private(&dir.join("snapshot.json"), &j);
    }
    write_private(&dir.join("digest.md"), &snap.render_digest());
}

/// "Disk state wins": flag ways the snapshot no longer matches reality, so the resuming
/// agent treats stale claims with suspicion. Best-effort — absence of a note is not a promise.
fn drift_note(snap: &Snapshot, cwd: Option<&str>) -> Option<String> {
    let mut notes = Vec::new();
    if let (Some(was), Some(now)) = (snap.branch.as_deref(), git_branch(cwd).as_deref()) {
        if was != now {
            notes.push(format!(
                "branch changed since capture: was `{was}`, now `{now}`"
            ));
        }
    }
    let missing = snap
        .files
        .iter()
        .filter(|f| !std::path::Path::new(f).exists())
        .count();
    if missing > 0 {
        notes.push(format!(
            "{missing} of {} captured file(s) no longer exist on disk",
            snap.files.len()
        ));
    }
    if notes.is_empty() {
        return None;
    }
    let lines: Vec<String> = notes.iter().map(|n| format!("  - {n}")).collect();
    Some(format!(
        "\n## ⚠ Drift since capture (disk state wins)\n{}\n",
        lines.join("\n")
    ))
}

/// Best-effort current branch (regular checkout; a worktree `.git` *file* → None).
/// The branch of the working dir's *own* checkout — worktree-aware. A worktree's `.git` is a
/// FILE (`gitdir: …/.git/worktrees/<name>`) whose HEAD is the worktree's branch, not the main
/// repo's. Walk up from `cwd` to the nearest `.git` and read the right HEAD. (Resolving via
/// `find_root` and reading the main `.git/HEAD` reported the wrong branch inside a worktree.)
fn git_branch(cwd: Option<&str>) -> Option<String> {
    let mut cur = match cwd {
        Some(c) => std::path::PathBuf::from(c),
        None => std::env::current_dir().ok()?,
    };
    loop {
        let dotgit = cur.join(".git");
        if dotgit.is_dir() {
            return head_ref(&dotgit.join("HEAD"));
        }
        if dotgit.is_file() {
            let content = std::fs::read_to_string(&dotgit).ok()?;
            let gitdir = std::path::Path::new(content.trim().strip_prefix("gitdir: ")?);
            // git writes an absolute path by default; tolerate a relative one (resolve vs the
            // worktree dir).
            let gitdir = if gitdir.is_absolute() {
                gitdir.to_path_buf()
            } else {
                cur.join(gitdir)
            };
            return head_ref(&gitdir.join("HEAD"));
        }
        if !cur.pop() {
            return None;
        }
    }
}

fn head_ref(head_path: &std::path::Path) -> Option<String> {
    let h = std::fs::read_to_string(head_path).ok()?;
    h.trim().strip_prefix("ref: refs/heads/").map(String::from)
}

/// Normalized field access across vendors — Codex uses `cwd`/`tool_name`/`tool_input`;
/// Antigravity uses `workspacePaths`/`toolCall.name`/`toolCall.args` (best-effort per the
/// antigravity adapter — docs unscrapeable, field names version-sensitive).
/// Mutated file paths from a *normalized* Event. The adapters already translate each
/// vendor's edit tool into keel's neutral model — Codex `apply_patch` → `Write` with every
/// patched path under `file_paths`; Antigravity `write_to_file`/`TargetFile` → `Write.file_path`
/// — so carryover reuses that instead of re-guessing raw vendor shapes.
fn mutated_paths(event: &Event) -> Vec<String> {
    if !event.tool.as_deref().is_some_and(|t| MUTATING.contains(&t)) {
        return Vec::new();
    }
    if let Some(arr) = event.tool_input.get("file_paths").and_then(Value::as_array) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    event.file_path().map(String::from).into_iter().collect()
}

/// The injection payload — platform-specific envelope. Claude/Codex read a nested
/// `hookSpecificOutput.additionalContext`; Antigravity (`agy`) reads a **top-level**
/// `additionalContext` (the nested form fails agy schema validation).
fn render_injection(platform: &str, digest: &str) -> String {
    if platform == "antigravity" {
        json!({ "additionalContext": digest }).to_string()
    } else {
        json!({
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": digest,
            }
        })
        .to_string()
    }
}

/// Antigravity's `transcriptPath` points at `transcript.jsonl`; prefer the sibling
/// `transcript_full.jsonl` (untruncated) when present.
fn full_transcript(path: &str) -> String {
    let p = std::path::Path::new(path);
    if let Some(parent) = p.parent() {
        let full = parent.join("transcript_full.jsonl");
        if full.exists() {
            return full.to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

/// Parse an Antigravity transcript (JSONL step records) → (goal prompts, latest answer).
/// User prompt = `USER_EXPLICIT`/`USER_INPUT`; answer = `MODEL`/`PLANNER_RESPONSE` (some
/// MODEL steps are tool-/reasoning-only with no `content` — skip those). Redacted here.
fn capture_antigravity<I: IntoIterator<Item = Value>>(records: I) -> (Vec<String>, Option<String>) {
    let mut prompts: Vec<String> = Vec::new();
    let mut result: Option<String> = None;
    for rec in records {
        let source = rec.get("source").and_then(Value::as_str);
        let typ = rec.get("type").and_then(Value::as_str);
        let content = rec
            .get("content")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        match (source, typ, content) {
            (Some("USER_EXPLICIT"), Some("USER_INPUT"), Some(c)) => {
                prompts.push(secret_scan::redact(c));
            }
            (Some("MODEL"), Some("PLANNER_RESPONSE"), Some(c)) => {
                result = Some(truncate(&secret_scan::redact(c), RESULT_CHARS));
            }
            _ => {}
        }
    }
    let start = prompts.len().saturating_sub(KEEP_PROMPTS);
    (prompts.split_off(start), result)
}

/// SessionStart / PreInvocation injection: render the stored digest if fresh + non-empty.
/// Antigravity has no SessionStart, so it injects on `PreInvocation` — which fires every
/// model call, so we inject at most once per `conversationId`.
fn inject(platform: &str, dir: &std::path::Path, cwd: Option<&str>, conv: Option<&str>) -> i32 {
    let snap = load_snapshot(dir);
    if snap.is_empty() {
        return 0; // nothing worth injecting
    }
    if let Some(u) = snap.updated {
        if now_secs().saturating_sub(u) > FRESH_SECS {
            return 0; // too stale to be "where you left off"
        }
    }
    if platform == "antigravity" {
        if let Some(c) = conv {
            let marker = dir.join("injected_conv");
            if std::fs::read_to_string(&marker).ok().as_deref() == Some(c) {
                return 0; // already injected into this conversation
            }
            let _ = std::fs::write(&marker, c);
        }
    }
    let mut digest = snap.render_digest();
    if let Some(drift) = drift_note(&snap, cwd) {
        digest.push_str(&drift); // disk-state-wins warnings
    }
    print!("{}", render_injection(platform, &digest));
    0
}

/// Live hook entrypoint — `keel carryover-hook <platform> <stage>`. Reads the payload on stdin.
///
///   * inject stage (SessionStart, or PreInvocation for agy) → inject the stored digest.
///   * claude    → BATCH: read the transcript on Stop/SessionEnd/PreCompact.
///   * antigravity → BATCH goal/result from `transcript_full.jsonl` on Stop + incremental files.
///   * codex     → INCREMENTAL: prompt/answer/files inline, one hook at a time.
///
/// The store is agent-agnostic (keyed by git root), so a snapshot captured under one agent
/// injects into any other — that is the cross-vendor carry. Fails open on any error.
pub fn run_hook(platform: &str, stage: &str) -> i32 {
    let payload = runtime::read_input().unwrap_or(Value::Null);
    // Normalize via the vendor adapter: cwd (Antigravity uses workspacePaths) + neutral tool.
    let event = adapters::parse(platform, &payload, stage);
    let dir = store_dir(event.cwd.as_deref());

    // Injection: SessionStart for claude/codex; PreInvocation for antigravity (no SessionStart).
    let inject_stage = if platform == "antigravity" {
        "PreInvocation"
    } else {
        "SessionStart"
    };
    if stage == inject_stage {
        let conv = payload.get("conversationId").and_then(Value::as_str);
        return inject(platform, &dir, event.cwd.as_deref(), conv);
    }

    if platform == "claude" {
        // BATCH: only on session-boundary stages — else a mis-wired PreToolUse would re-read
        // the whole transcript on every tool call.
        if !matches!(stage, "Stop" | "SessionEnd" | "PreCompact") {
            return 0;
        }
        if let Some(tp) = payload.get("transcript_path").and_then(Value::as_str) {
            if let Ok(records) = load_jsonl(tp) {
                let (snap, _) = capture(records);
                persist(&snap, &dir);
            }
        }
        return 0;
    }

    // Codex + Antigravity share the store scaffolding.
    let mut snap = load_snapshot(&dir);
    if snap.root.is_none() {
        snap.root = event.cwd.clone();
    }
    if snap.root_hash.is_empty() {
        snap.root_hash = root_hash(&event.root);
    }
    if snap.branch.is_none() {
        snap.branch = git_branch(event.cwd.as_deref());
    }

    // Only persist when something was actually captured — a no-op hook (Read, missing field,
    // unknown stage) must not re-stamp `updated` (defeating freshness) or clobber `by`.
    let mut changed = false;
    if platform == "antigravity" {
        match stage {
            // BATCH goal/result from the transcript (agy has no inline prompt/answer hooks).
            "Stop" => {
                if let Some(tp) = payload.get("transcriptPath").and_then(Value::as_str) {
                    if let Ok(records) = load_jsonl(&full_transcript(tp)) {
                        let (goal, result) = capture_antigravity(records);
                        if !goal.is_empty() {
                            snap.goal = goal;
                            changed = true;
                        }
                        if result.is_some() {
                            snap.result = result;
                            changed = true;
                        }
                    }
                }
            }
            // files come inline via tool calls (normalized by the adapter).
            "PreToolUse" => {
                for fp in mutated_paths(&event) {
                    snap.push_file(&fp);
                    changed = true;
                }
            }
            _ => {}
        }
    } else {
        // Codex: prompt / answer / files all inline.
        match stage {
            "UserPromptSubmit" => {
                if let Some(p) = payload.get("prompt").and_then(Value::as_str) {
                    snap.push_prompt(p);
                    changed = true;
                }
            }
            "Stop" => {
                if let Some(r) = payload
                    .get("last_assistant_message")
                    .and_then(Value::as_str)
                {
                    snap.set_result(r);
                    changed = true;
                }
            }
            "PreToolUse" => {
                for fp in mutated_paths(&event) {
                    snap.push_file(&fp);
                    changed = true;
                }
            }
            _ => {}
        }
    }
    if changed {
        snap.by = Some(platform.to_string()); // provenance: codex / antigravity
        persist(&snap, &dir);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript() -> Vec<Value> {
        vec![
            // a real prompt → goal
            json!({"type":"user","gitBranch":"main","cwd":"/repo",
                   "message":{"role":"user","content":"port the oracle to rust"}}),
            // meta noise → dropped
            json!({"type":"user","isMeta":true,
                   "message":{"role":"user","content":"<system-reminder> ..."}}),
            // a tool-result user turn → not a prompt, dropped
            json!({"type":"user",
                   "message":{"role":"user","content":[{"type":"tool_result","content":"ok"}]}}),
            // assistant that only READS → exploration noise, dropped, no file kept
            json!({"type":"assistant","message":{"role":"assistant","content":[
                   {"type":"thinking","thinking":"hmm"},
                   {"type":"tool_use","name":"Read","input":{"file_path":"/repo/a.rs"}}]}}),
            // assistant that EDITS → file kept
            json!({"type":"assistant","message":{"role":"assistant","content":[
                   {"type":"tool_use","name":"Edit","input":{"file_path":"/repo/b.rs"}}]}}),
            // a later prompt → goal
            json!({"type":"user","message":{"role":"user","content":"now add a test"}}),
            // assistant prose → result
            json!({"type":"assistant","message":{"role":"assistant","content":[
                   {"type":"text","text":"done — ported and tested."}]}}),
        ]
    }

    #[test]
    fn captures_intent_state_and_result() {
        let (snap, _) = capture(transcript());
        assert_eq!(snap.goal, vec!["port the oracle to rust", "now add a test"]);
        assert_eq!(snap.files, vec!["/repo/b.rs"]); // Read dropped, Edit kept
        assert_eq!(snap.result.as_deref(), Some("done — ported and tested."));
        assert_eq!(snap.branch.as_deref(), Some("main"));
        assert_eq!(snap.root.as_deref(), Some("/repo"));
    }

    #[test]
    fn drops_noise_and_counts_it() {
        let (_, stats) = capture(transcript());
        assert_eq!(stats.records, 7);
        // meta user + tool_result user + read-only assistant = 3 dropped
        assert_eq!(stats.dropped_noise, 3);
        // 2 prompts + 1 file + 1 result
        assert_eq!(stats.stored_signals, 4);
    }

    #[test]
    fn digest_carries_verification_mandate() {
        let (snap, _) = capture(transcript());
        let d = snap.render_digest();
        assert!(d.contains("Verify, don't trust"));
        assert!(d.contains("/repo/b.rs"));
        assert!(d.contains("port the oracle to rust"));
    }

    // Secrets are redacted before anything reaches the snapshot (both prompt and answer).
    #[test]
    fn redacts_secrets_before_storing() {
        let recs = vec![
            json!({"type":"user","cwd":"/r","message":{"role":"user",
                   "content":"deploy with AKIAABCDEFGHIJKLMNOP now"}}),
            json!({"type":"assistant","message":{"role":"assistant","content":[
                   {"type":"text","text":"set token ghp_abcdefghijklmnopqrstuvwx ok"}]}}),
        ];
        let (snap, _) = capture(recs);
        assert!(snap.goal[0].contains("[redacted]") && !snap.goal[0].contains("AKIA"));
        let r = snap.result.as_deref().unwrap();
        assert!(r.contains("[redacted]") && !r.contains("ghp_abcdef"));
    }

    // Codex path: pieces arrive inline, one hook at a time, and accumulate into the snapshot.
    #[test]
    fn codex_incremental_accumulates_and_caps() {
        let mut s = Snapshot::default();
        for i in 0..8 {
            s.push_prompt(&format!("prompt {i}"));
        }
        s.push_file("/r/a.rs");
        s.push_file("/r/b.rs");
        s.push_file("/r/a.rs"); // dedup → moves a.rs to most-recent
        s.set_result("  built the codex path  ");
        assert_eq!(s.goal.len(), KEEP_PROMPTS); // capped
        assert_eq!(s.goal.first().unwrap(), "prompt 2"); // oldest dropped
        assert_eq!(s.files, vec!["/r/b.rs", "/r/a.rs"]); // dedup + recency order
        assert_eq!(s.result.as_deref(), Some("built the codex path"));
    }

    // mutated_paths pulls every patched file from a normalized Codex apply_patch event
    // (adapters::codex maps apply_patch → Write with `file_paths`); non-mutating tools yield none.
    #[test]
    fn mutated_paths_from_normalized_event() {
        let patch =
            "*** Begin Patch\n*** Update File: /r/a.rs\n*** Add File: /r/b.rs\n*** End Patch";
        let ev = adapters::parse(
            "codex",
            &json!({"tool_name":"apply_patch","tool_input":{"command":patch},"cwd":"/r"}),
            "PreToolUse",
        );
        assert_eq!(mutated_paths(&ev), vec!["/r/a.rs", "/r/b.rs"]);
        let read = adapters::parse(
            "codex",
            &json!({"tool_name":"shell","tool_input":{"command":"cat /r/a.rs"},"cwd":"/r"}),
            "PreToolUse",
        );
        assert!(mutated_paths(&read).is_empty());
    }

    // The store is agent-agnostic: a snapshot captured under Claude round-trips through the
    // on-disk JSON unchanged, so a Codex SessionStart injects the same content. Cross-vendor.
    #[test]
    fn store_is_agent_agnostic() {
        let (claude_snap, _) = capture(transcript());
        let reloaded = Snapshot::from_json(&claude_snap.to_json());
        assert_eq!(reloaded.goal, claude_snap.goal);
        assert_eq!(reloaded.files, claude_snap.files);
        assert_eq!(reloaded.result, claude_snap.result);
        assert_eq!(reloaded.branch, claude_snap.branch);
    }

    // Antigravity transcript: USER_EXPLICIT/USER_INPUT → goal, MODEL/PLANNER_RESPONSE with
    // content → result; content-less MODEL steps and other sources are skipped.
    #[test]
    fn antigravity_transcript_parse() {
        let recs = vec![
            json!({"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","content":"add a rate limiter"}),
            json!({"step_index":3,"source":"MODEL","type":"PLANNER_RESPONSE","content":"Added a token bucket."}),
            json!({"step_index":4,"source":"MODEL","type":"PLANNER_RESPONSE","tool_calls":[{"x":1}]}),
            json!({"step_index":5,"source":"SYSTEM","type":"CONVERSATION_HISTORY","content":"noise"}),
        ];
        let (goal, result) = capture_antigravity(recs);
        assert_eq!(goal, vec!["add a rate limiter"]);
        assert_eq!(result.as_deref(), Some("Added a token bucket."));
    }

    // A git worktree reports ITS OWN branch, not the main checkout's (the live-observed bug).
    #[test]
    fn git_branch_reads_worktree_head_not_main() {
        use std::fs;
        let base = std::env::temp_dir().join(format!("keel-wt-{}", std::process::id()));
        let (main, wt) = (base.join("main"), base.join("wt"));
        fs::create_dir_all(main.join(".git/worktrees/wt")).unwrap();
        fs::create_dir_all(&wt).unwrap();
        fs::write(main.join(".git/HEAD"), "ref: refs/heads/develop\n").unwrap();
        fs::write(
            main.join(".git/worktrees/wt/HEAD"),
            "ref: refs/heads/feature-x\n",
        )
        .unwrap();
        fs::write(
            wt.join(".git"),
            format!("gitdir: {}", main.join(".git/worktrees/wt").display()),
        )
        .unwrap();

        // plain repo → its own HEAD; worktree → the WORKTREE's branch, not main's
        assert_eq!(git_branch(main.to_str()).as_deref(), Some("develop"));
        assert_eq!(git_branch(wt.to_str()).as_deref(), Some("feature-x"));

        // a relative gitdir pointer is tolerated (resolved vs the worktree dir)
        let wt_rel = base.join("wt_rel");
        fs::create_dir_all(&wt_rel).unwrap();
        fs::write(wt_rel.join(".git"), "gitdir: ../main/.git/worktrees/wt").unwrap();
        assert_eq!(git_branch(wt_rel.to_str()).as_deref(), Some("feature-x"));

        fs::remove_dir_all(&base).ok();
    }

    // Detached HEAD (raw sha, no `ref: refs/heads/…`) → no branch, no crash.
    #[test]
    fn git_branch_none_on_detached_head() {
        use std::fs;
        let d = std::env::temp_dir().join(format!("keel-det-{}", std::process::id()));
        fs::create_dir_all(d.join(".git")).unwrap();
        fs::write(d.join(".git/HEAD"), "a1b2c3d4e5f6a7b8c9d0\n").unwrap();
        assert_eq!(git_branch(d.to_str()), None);
        fs::remove_dir_all(&d).ok();
    }

    // Injection envelope is platform-specific: nested for claude/codex, top-level for agy.
    #[test]
    fn injection_envelope_is_platform_specific() {
        let claude: Value = serde_json::from_str(&render_injection("claude", "d")).unwrap();
        assert!(claude["hookSpecificOutput"]["additionalContext"] == "d");
        let agy: Value = serde_json::from_str(&render_injection("antigravity", "d")).unwrap();
        assert!(agy["additionalContext"] == "d");
        assert!(agy.get("hookSpecificOutput").is_none());
    }
}
