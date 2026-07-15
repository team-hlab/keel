# Exploration: friend requests — central MCP + cross-agent context

> Worktree `explore/mcp-and-context`, branched off `test/port-oracle-to-rust` @ 56556ff.
> Two asks from friends, judged against keel's current identity.

## keel's identity today (the lens)

A **stateless, fail-open, per-call policy shim**: stdin → `Event` → features → aggregate
`deny>ask>pass>allow` → render → exit. ~1 MB static Rust, zero runtime deps. The
dependency arrow is always **keel → agent**. No daemon, no state between calls. `keel
init/apply` *projects config* into every detected agent (PATH-hijack symlinks + hook
wiring). Both requests must be judged on whether they keep that shape or break it.

---

## Request 1 — "let keel manage MCP calls, not each agent"

There are two very different readings. They are not the same project.

### (a) MCP **config projection** — STRONG FIT, ship it
Define MCP servers once in `.keel.json`; `keel apply` writes them into each agent's native
format (Claude `~/.claude.json` / `.mcp.json`, Codex `config.toml`, Antigravity config).
- This is *exactly* what `keel init/apply` already does for hooks — one more projection
  target. Stateless, no new runtime, zero-dep claim intact. Fully on-thesis: "write once,
  run on any agent."
- Solves the real pain (re-declaring the same MCP servers per agent), which is what the
  friend is actually feeling.
- **Recommendation: do this.** It's a `keel apply` extension + a `mcp` block in config.

### (b) MCP **runtime proxy/gateway** — OFF-THESIS, only for a governance goal
keel hosts/multiplexes the servers; agents connect to keel-as-MCP-server; keel forwards.
- Turns keel into a **long-running stateful daemon** — breaks "fail-open per-call shim,"
  process lifecycle to own, harder zero-dep story. A different product.
- The usual justification ("so every MCP tool call passes through keel's policy") **is
  already true without it**: in Claude Code, MCP tool calls fire `PreToolUse` with tool
  names like `mcp__server__tool`, so the engine already sees them. keel doesn't need to be
  in the data path to govern them — only to mediate transport.
- **Recommendation: skip unless** the explicit goal is cross-agent MCP *governance/observability*
  beyond what hooks give (e.g. response-side filtering, shared connection pooling). Then it's
  a deliberate, separate bet — not a quick win.

---

## Request 2 — "preserve context when switching agents"

The deepest stretch from keel's current identity, and the most novel if it lands. Split it:

### Cheap, on-thesis half — **context handoff injection**
keel already owns `SessionStart` (session-banner uses it). A `keel handoff` could write a
portable markdown digest (goal, recent files, decisions) and inject it at the next agent's
`SessionStart`, regardless of which agent that is. Stateless-ish: one file in, one file out.
This is the realistic first slice and it genuinely "fills the gap when you switch agents."

### Expensive half — **capture**
Producing that digest faithfully means reading each agent's transcript/session state — three
different formats, evolving APIs — and normalizing it. That is real, stateful, per-agent
work and is where the cost lives. Doing it *well* (not just "paste the last N messages")
likely wants an LLM summarization step, which adds a dependency keel has never had.

**Recommendation:** prototype the *injection* half first behind a manual `keel handoff`
(user/agent writes the digest; keel just carries+injects it). Prove the cross-agent SessionStart
plumbing. Defer automatic capture — flag it as a separate product surface, not a feature flag.

### UPDATE — friend already uses a manual hand-off
This changes the calculus. A manual hand-off **is the injection half done by a human**, so a
manual `keel handoff` wrapper adds almost nothing — same effort, nicer container. keel's
differentiated value is the two things a manual hand-off *cannot* do:
1. **Auto-capture** — read the outgoing agent's transcript/state and produce the digest, so
   the human never writes it. (This is the expensive, stateful half parked above — but it's
   the half that matters now, because injection is already solved by hand.)
2. **Agent-agnostic injection** — same captured context lands into *whichever* agent starts
   next, via its `SessionStart`, with no per-agent reformatting.

So for context, the real project is "**delete the human from the hand-off loop**" =
auto-capture + auto-inject across agents. The cheap manual slice is no longer worth building
on its own; it only earns its place as the *injection target* that auto-capture feeds.

### Why "Claude-only" — inject vs capture asymmetry
Hand-off has two directions with opposite difficulty. It is NOT Claude-only as a whole.
- **Inject (context IN)** — *already cross-agent*. `SessionStart` is wired into all three
  agents (`agent.rs` `STAGES` + `AGENTS` are global; `session-banner` fires on SessionStart
  everywhere). Injecting a digest into Codex/Antigravity is the same mechanism as Claude.
- **Capture (context OUT)** — the asymmetric half. Two strategies:
  - **(A) read native transcript** → richest (prose+reasoning), but per-agent format.
    **Claude-first** only because Claude Code's JSONL is the one format keel has *verified*;
    Codex/Antigravity adapters are self-flagged "best-effort, verify live." Knowledge gap,
    not an architecture limit — their stores just haven't been mapped.
  - **(B) accumulate from `PreToolUse` hooks** live → *cross-agent today* (stage wired
    everywhere), but lossy: tool calls + hook payloads only, no model prose/reasoning.

Framing: injection is cross-agent now; rich capture is Claude-first until Codex/Antigravity
session stores are reverse-engineered; lossy capture could ship cross-agent immediately on
the hooks keel already installs.

### RECOMMENDED PATH — `keel sync-context` (keel-owned store)
Reframe that dissolves the capture asymmetry: don't read any agent's transcript — have keel
accumulate context into **its own location/format** via the hooks that already fire on all
agents, then inject from it. Cross-agent *by construction* (no agent format is ever parsed).

`audit_log.rs` is already ~80% of this:
- already observes every `PreToolUse` across all agents, appends JSONL, fail-open, keyed by
  `event.root`, opt-in. sync-context = that capture loop, but:
  1. write to keel's **global** store `~/.keel/context/<root-hash>/events.jsonl` (shared
     across agents) instead of an in-repo file;
  2. add a **`SessionStart` read → roll up → inject** path (audit-log only writes);
  3. optionally richer signal via `UserPromptSubmit` (Claude supports it; not wired today);
  4. a **digest at inject** — heuristic/zero-dep (recent distinct files, recent commands,
     cwd, git branch, last K prompts). Optional LLM summary, off by default.

Two honest ceilings:
- **Fidelity** — hooks see *what was done* (+prompts if UserPromptSubmit wired), never model
  reasoning/prose. It's a **working-state memory**, not a transcript. Native-transcript
  capture (Claude JSONL) stays a complementary *enricher*, not a competitor.
- **Identity** — stays on the RIGHT side of the daemon fork: passive disk state appended by
  fire-and-forget hooks, exactly like audit-log. No daemon, fail-open + zero-dep intact.
  This is the key reason to prefer it over the MCP runtime proxy for cross-agent state.

"context" vs "memory" = same store, two read policies (hand-off tail vs durable project
memory). Ship hand-off scope first; memory is a later read-policy toggle.

**Net recommendation order:** (1) MCP config projection · (2) `keel sync-context` hand-off
scope, modeled on audit-log · (3, optional) Claude-JSONL enricher, then memory read-policy ·
(defer) MCP runtime proxy — the only ask that demands the daemon identity change.

### REFINEMENT — lightweight + semantic spine, and the prompt/answer asymmetry
Constraint added: **lightweight, store NO useless data.** This corrects "clone audit-log":
audit-log stores the tool-call firehose (every Read/Grep/Bash) — heavy and near-useless for
hand-off. Keep audit-log's *how* (fail-open append, root-keyed, opt-in); drop its *what*.
Store only the **semantic spine: user prompts + agent answers + minimal working-state**.

Mechanism correction (verified vs code.claude.com/docs hooks, 2026-06-25): keel observes via
the **hooks it installs**, NOT by sitting in stdin/stdout — the shim `exec`s the real agent
(same PID) and is then gone. A true I/O pipe would need a PTY-proxy parent → breaks
lightweight + same-PID transparency. So "it's a shim, therefore it intercepts I/O" is wrong;
"it installs hooks, therefore it sees hook payloads" is right.

Prompt vs answer is **asymmetric — and the asymmetry is per-agent, not universal.**
Verified hook capabilities (Claude via code.claude.com/docs; Codex via openai/codex generated
schemas; Antigravity via Google DevRel secondary sources — docs unscrapeable, med confidence):

| Agent | hook events | prompt inline | answer inline |
|---|---|---|---|
| Claude Code | 30+ (UserPromptSubmit, Stop, …) | ✅ `UserPromptSubmit.prompt` | ❌ `Stop`→`transcript_path` (read JSONL) |
| Codex | 10 (UserPromptSubmit, Stop, …) | ✅ `UserPromptSubmit.prompt` | ✅ **`Stop.last_assistant_message`** |
| Antigravity (`agy`) | ~5 (PreInvocation, Stop, …) | ❌ → read `transcriptPath` | ❌ `Stop`→`transcriptPath` |

Earlier draft was WRONG to call the answer uniformly Claude-coupled: **Codex delivers the
answer inline.** Reality: prompt inline on 2/3 (not Antigravity); answer inline on 1/3 (Codex
only). Antigravity is the *most* coupled — both halves need a transcript read.
Caveats: Codex hooks "GA but incomplete" (apply_patch/MCP coverage intermittent); Antigravity
field names version-sensitive. (Open-source *Gemini CLI* ≠ Antigravity `agy` — Gemini gives
both inline; agy does not.)

**This is a textbook ports-and-adapters fit.** Capture = an adapter responsibility: the core
wants normalized `{prompt, answer, working-state}`; each adapter sources it as the agent
allows — Codex reads the inline `Stop` field; Claude/Antigravity read the `transcript_path`
the `Stop` payload points to. Variance at the edge, one uniform keel-owned store. Stays light:
≤1 file-read/turn for the two transcript agents, storing only the extracted prompt+answer +
working-state — never the whole transcript.

Wiring cost: keel currently wires only PreToolUse/PermissionRequest/SessionStart. sync-context
adds `UserPromptSubmit` (Claude/Codex) + `Stop` (all three) to the wired stages, plus adapter
`parse` for those payloads (inline field vs transcript-read per agent).

### PROPER-CONTEXT RULE — the hand-off schema is the filter
No canonical hand-off artifact exists (no `/handoff` cmd/skill/file on disk) → we define it,
and the definition becomes the write-time filter. **Invert the audit-log instinct:** don't
log-then-summarize (stores useless data by construction). Capture *schema-first* — write only
fields the hand-off admits; never store the rest. "Proper" is decided at write-time, not read.

Keep **one overwrite-in-place snapshot per repo-root** (not a growing log) → lightweight by
construction, nothing to prune.

Schema + cheap source:
| field | source | cost |
|---|---|---|
| `goal` | rolling last-K **user prompts** (inline; highest signal-per-byte = stated intent) | free |
| `state.branch/cwd` | structural | free |
| `state.files` | **mutating tool calls only** (Write/Edit/MultiEdit/NotebookEdit, mutating Bash); DROP Read/Grep/Glob | free |
| `last_result`/`next` | answer at `Stop`, latest only (inline Codex / transcript Claude+Antigravity) | ~1 read/turn |
| `decisions/why` | hard field — tiered (below) | opt-in |

`state.files` = the "no useless data" rule concretized: keel sees every PreToolUse call but
records only mutations; exploration reads are dropped at the door, never written.

Salience gating — write snapshot ONLY on: `UserPromptSubmit` (refresh goal) · `Stop` (refresh
state/next) · `PreCompact` (bonus: agent is curating its own context — Claude+Codex fire it;
the compaction summary is free distilled "proper context"). All other events: mutation-filter
only, no write.

Tiering for `decisions/why` (ship without an LLM):
- T0 structural (branch/files/cwd) — free, always on
- T1 semantic-free (last-K prompts + latest answer) — free; *already a usable hand-off*
- T2 explicit markers (`keel checkpoint "decided X because Y"`) — opt-in, proper-by-construction
- T3 LLM distill — best quality, breaks zero-dep → off by default
**Ship T0+T1.** Prompts + mutated-files + last-answer reconstruct what/changed/where-landed
with zero AI at a few KB/project. T2/T3 are upgrades, not prerequisites.

Net rule: **schema-first snapshot + salience-gated writes + mutation-only filter +
overwrite-in-place.** You never filter useless data out — you never let it in.

### PRIOR ART — savepoint (dd3ok) + the "4-layer hand-off" article
Both reviewed. They sit at the OPPOSITE end of every axis from keel — which is precisely
keel's wedge, not a competitor.

| axis | savepoint / 4-layer | keel sync-context |
|---|---|---|
| trigger | **manual** (`/savepoint`, human discipline) | **automatic** (UserPromptSubmit/Stop/PreCompact hooks) |
| author | **the agent** (LLM writes the doc) | **keel** (structural, no LLM in core) |
| layer | **inside** agent (skill) | **below** agent (shim) |
| cross-agent | per-agent skill install | one binary, all agents |

The 4-layer article's own conclusion — *"hand-off is a habit, not a technology"* — names the
exact gap: it depends on discipline. **keel deletes the discipline requirement.** That is the
pitch.

Tension they expose: their quality comes from the LLM authoring Traps/Key-Decisions — pure
structural T0/T1 can't match that. **Resolution = the PreCompact insight, now load-bearing:**
keel needs no LLM of its own — it *harvests the agents' own summarization at the hook
boundary* (PreCompact = the agent's focused `/compact` summary; Stop = the answer). Savepoint-
quality semantic content, automatic capture, zero added dependency.

Steal outright:
1. **Their schema > mine** — add Traps-to-Avoid, Working Agreements, Relevant Files as
   `path:L10-L45 — why`, Open Work **state-descriptive not imperative**.
2. **Verification mandate** — handoff is *hypotheses not facts*; injection prompt must say
   "re-read files, validate against code, don't trust this."
3. **keel's unfair advantages** (manual in savepoint, automatic here, because keel is the
   policy layer): run existing **`secret-scan`** over stored context (redaction reuse);
   **git-drift check at `SessionStart`** (branch/HEAD/worktree drift → "disk state wins").
4. **Interop** — emit the same `SAVEPOINT.md` / `SAVEPOINT_V1` format → keel becomes the
   automatic capture engine feeding the format savepoint users already load. Complementary.

---

## The strategic read (say this to the friends)

Both asks pull keel in the same direction: from a **synchronous stateless policy filter**
toward a **stateful cross-agent control plane / session broker**. That's a legitimate and
exciting evolution — but it's a *fork in the product*, not two small features. The honest
sequencing:

1. **MCP config projection** — do now. Pure win, zero identity cost.
2. **Context handoff (injection only)** — prototype now, manual digest, proves the plumbing.
3. **MCP runtime proxy** + **automatic context capture** — the daemon/stateful tier. Only
   take these on as a conscious decision to make keel a control plane, with the zero-dep /
   fail-open guarantees explicitly renegotiated.

Don't let 1 and 2 (cheap, on-thesis) get blocked behind 3 (the architecture change).
```
synchronous policy filter ──projection──▶ same identity, more reach   (asks 1a, 2-inject)
                          ──daemon──────▶ new identity: control plane  (asks 1b, 2-capture)
```
