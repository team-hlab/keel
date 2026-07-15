#!/usr/bin/env python3
"""
carryover-sim — a runnable simulation of keel's `carryover` feature.

This is NOT the product (the product is a Rust keel Feature reading hook payloads
live). It's an executable spec: it applies carryover's exact capture rules to a real
Claude Code transcript on disk and emits the two artifacts the feature produces —

  1. snapshot.json  — the keel-owned store (overwrite-in-place, schema-first)
  2. digest.md      — what the NEXT agent receives injected at SessionStart

Each function below maps 1:1 to a piece of the Rust implementation (noted inline).
Capture rules (from the design):
  • goal      ← user prompts only (drop meta / tool-results / sidechains)
  • state     ← gitBranch + cwd (structural, free)
  • files     ← MUTATING tool calls only (Edit/Write/MultiEdit/NotebookEdit) — drop reads
  • result    ← latest assistant text block
  • salience  ← we only ever read prompts / answers / mutations; everything else is dropped
"""
import json, sys, hashlib, time
from pathlib import Path

MUTATING = {"Edit", "MultiEdit", "Write", "NotebookEdit"}      # adapter: PreToolUse mutation filter
DROP_PREFIXES = ("<local-command", "Caveat:", "<command-name>", "[Request interrupted")

def load(path):
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            yield json.loads(line)

def text_of(content):
    """user content may be str or a list of blocks; return plain prompt text or None."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # if it carries any tool_result, it's a tool turn, not a real prompt → skip
        if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
            return None
        texts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
        return "\n".join(t for t in texts if t) or None
    return None

def is_real_prompt(rec):                                        # adapter: UserPromptSubmit parse
    if rec.get("type") != "user" or rec.get("isMeta") or rec.get("isSidechain"):
        return None
    t = text_of((rec.get("message") or {}).get("content"))
    if not t or t.startswith(DROP_PREFIXES):
        return None
    return t.strip()

def assistant_text(rec):                                        # adapter: Stop parse (transcript route)
    if rec.get("type") != "assistant":
        return None
    blocks = (rec.get("message") or {}).get("content") or []
    texts = [b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
    return ("\n".join(t for t in texts if t).strip()) or None

def mutated_files(rec):                                         # feature: mutation-only filter
    if rec.get("type") != "assistant":
        return
    for b in (rec.get("message") or {}).get("content") or []:
        if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") in MUTATING:
            fp = (b.get("input") or {}).get("file_path")
            if fp:
                yield fp

def capture(records, keep_prompts=6):                          # feature: carryover.rs core
    prompts, files, branch, cwd, result = [], [], None, None, None
    seen = 0; dropped = 0
    for rec in records:
        seen += 1
        if rec.get("gitBranch"): branch = rec["gitBranch"]
        if rec.get("cwd"):       cwd = rec["cwd"]
        p = is_real_prompt(rec)
        if p:
            prompts.append(p)
            continue
        a = assistant_text(rec)
        if a:
            result = a                                          # latest assistant text wins
        fs = list(mutated_files(rec))
        if fs:
            files.extend(fs)
        if not (p or a or fs):
            dropped += 1                                        # useless data — never stored
    # schema-first snapshot: only the fields the hand-off admits
    snap = {
        "root": cwd or "",
        "root_hash": hashlib.sha1((cwd or "").encode()).hexdigest()[:12],
        "branch": branch,
        "goal": prompts[-keep_prompts:],                        # rolling last-K prompts
        "files": sorted(set(files)),                            # distinct mutated files
        "result": (result[:600] + "…") if result and len(result) > 600 else result,
        "decisions": None,                                      # T2: PreCompact harvest (not in this transcript)
        "by": "claude",
        "updated": 1751000000,                                  # fixed stamp (sim is deterministic)
    }
    return snap, {"records": seen, "stored_signals": len(prompts) + len(set(files)) + (1 if result else 0),
                  "dropped_noise": dropped}

def render_digest(s):                                          # feature: SessionStart inject
    goal = "\n".join(f"  - {g[:160]}" for g in s["goal"]) or "  (none captured)"
    files = "\n".join(f"  - `{f}`" for f in s["files"]) or "  (none)"
    return f"""# ⟢ carryover — resuming prior session
_keel restored this automatically. Branch `{s['branch']}` · {len(s['files'])} files in flight._

## Goal (recent intent)
{goal}

## Working state
  branch: `{s['branch']}`
  files touched:
{files}

## Where it landed
  {s['result'] or '(no answer captured)'}

---
> ⚠️ **Verify, don't trust.** This is a reconstruction, not ground truth. Re-read the files
> above and validate against the actual code before continuing. Disk state wins over this note.
"""

if __name__ == "__main__":
    src = sys.argv[1]
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(".")
    snap, stats = capture(load(src))
    (out / "snapshot.json").write_text(json.dumps(snap, indent=2, ensure_ascii=False))
    (out / "digest.md").write_text(render_digest(snap))
    print(f"input transcript : {src}")
    print(f"records scanned  : {stats['records']}")
    print(f"signals stored   : {stats['stored_signals']}  (prompts + distinct mutated files + last answer)")
    print(f"noise dropped    : {stats['dropped_noise']}  (never written)")
    print(f"snapshot size    : {len(json.dumps(snap))} bytes")
    print("→ wrote snapshot.json + digest.md")
