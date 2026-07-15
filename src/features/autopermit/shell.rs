//! Pure Bash / multi-command decision logic. Path resolution is injected, so it's
//! fully testable without a filesystem. Conservative: allow only confidently-safe,
//! deny only catastrophic, ask on secret writes, pass on anything uncertain.

use std::sync::LazyLock;

use regex::Regex;

use crate::features::autopermit::policy::{is_inside, is_sensitive, is_write_allowed};
use crate::model::Decision;

fn rx(p: &str) -> Regex {
    Regex::new(p).expect("static regex")
}

static COMMENT: LazyLock<Regex> = LazyLock::new(|| rx(r"^(#[^\n]*\n\s*)+"));
static ENV_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| rx(r"^(env\s+)?([A-Za-z_][A-Za-z0-9_]*=[^\s]*\s+)+"));
static SINGLE_QUOTED: LazyLock<Regex> = LazyLock::new(|| rx(r"'[^']*'"));
static EXPANSION: LazyLock<Regex> = LazyLock::new(|| rx(r"\$[A-Za-z_{(]"));
static FILE_WRITE: LazyLock<Regex> =
    LazyLock::new(|| rx(r"^(mkdir|cp|mv|rm|touch|chmod|ln|rsync|tee)\b"));
static GIT_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    rx(
        r"^git\s+(-C\s+\S+\s+)?(add|commit|push|checkout|switch|stash|merge|rebase|cherry-pick|restore|tag)\b",
    )
});
static GIT_C: LazyLock<Regex> = LazyLock::new(|| rx(r"\bgit\s+-C\s+(\S+)"));
static LEADING_CD: LazyLock<Regex> = LazyLock::new(|| rx(r"^\(?cd\s+(\S+)\s+&&"));
static OUTER_SUBSHELL: LazyLock<Regex> =
    LazyLock::new(|| rx(r"(?s)^\((.*)\)\s*(?:\d*>&\d+\s*|\|\|\s*(?:true|:)\s*)*$"));
static FD_REDIR: LazyLock<Regex> = LazyLock::new(|| rx(r"\d*>&\d+"));
static DEVNULL: LazyLock<Regex> = LazyLock::new(|| rx(r"\d*>\s*/dev/null"));
static REDIR: LazyLock<Regex> = LazyLock::new(|| rx(r">{1,2}\s*([^\s;|&]+)"));
static TEE: LazyLock<Regex> = LazyLock::new(|| rx(r"\|\s*tee\s+(?:-a\s+)?([^\s;|&]+)"));
static SED_INPLACE: LazyLock<Regex> = LazyLock::new(|| rx(r"^sed\s+-i"));
// Content-dumping reads. These print a file's bytes (the exfil path an agent falls back to
// when the Read tool is gated: `cat .env`, `base64 id_rsa`, `jq .k credentials.json`), so
// every file operand is checked for sensitivity even though the command itself is harmless.
// Transformers that read stdin (`tr`, `sort`) are included too; the `< file` input-redirect
// path is gated separately (see INPUT_REDIR). Metadata-only readers (ls/stat/file/wc) stay in
// SAFE and skip the check — they don't reveal contents.
static READ_CMDS: LazyLock<Regex> = LazyLock::new(|| {
    rx(
        r"^(cat|head|tail|less|more|nl|tac|xxd|od|hexdump|base64|base32|strings|grep|egrep|fgrep|rg|awk|sed|cut|sort|uniq|tr|jq|column|rev|fold|comm|join|paste|diff)\b",
    )
});
// Pattern-first readers: the first operand is a search pattern / script, not a file, so it's
// skipped when scanning read targets (`grep AKIA .env` → check `.env`, not `AKIA`).
static PATTERN_READ: LazyLock<Regex> = LazyLock::new(|| rx(r"^(grep|egrep|fgrep|rg|awk|sed)\b"));
// Transparent wrappers that exec the rest of the line unchanged. Stripped (repeatedly) before
// command matching so `command cat .env` / `timeout 5 cat .env` / `nohup base64 id_rsa` are
// gated on the wrapped command, not waved through. `command` is a POSIX alias-bypass primitive.
static WRAPPER: LazyLock<Regex> = LazyLock::new(|| {
    rx(
        r"^(command|env|nohup|time|unbuffer|stdbuf\s+-\S+|ionice(\s+-\S+)*|nice(\s+-n\s+\d+|\s+-\d+)?|timeout(\s+-\S+)*\s+[\d.]+[smhd]?)\s+",
    )
});
// A `find` action that runs a sub-command (which can dump file contents) — SAFE would
// otherwise allow it; we scan its tokens for sensitive targets instead.
static FIND_EXEC: LazyLock<Regex> = LazyLock::new(|| rx(r"^find\b.*\s-(exec|execdir|ok)\b"));
// Input redirect `< file` (not `<<` heredoc, `<&` fd-dup, or `<(` process-sub). The file's
// contents flow into the command's stdin, so a sensitive target is a read to gate.
static INPUT_REDIR: LazyLock<Regex> =
    LazyLock::new(|| rx(r"(?:^|[^<&0-9])<\s*([A-Za-z0-9_./~][^\s;|&<>]*)"));

static SAFE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        rx(
            r"^git\s+(-C\s+\S+\s+)?(status|diff|log|show|branch|fetch|remote|rev-parse|ls-files|ls-tree|describe|config\s+--get|stash\s+list|worktree\s+list|pull|show-ref|cat-file|tag\s+-l)\b",
        ),
        rx(
            r"^(ls|cat|head|tail|wc|find|grep|pwd|which|basename|dirname|realpath|date|file|stat|du|df|id|whoami|printenv|ps|tree|echo|cd|true|:)\b",
        ),
        rx(r"^sed\b"),
        rx(r"^(awk|tr|cut|jq|uniq|column|sort|diff|test)\b"),
        rx(r"^gh\s+(pr|issue|run|repo)\s+(view|list|checks|diff|status)\b"),
        rx(r"^gh\s+auth\s+status\b"),
    ]
});
static BUILD_TEST: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        rx(r"^\./gradlew\s"),
        rx(r"^npm\s+(test|run|install|ci|exec|ls)"),
        rx(r"^(npx|bunx)\s"),
        rx(r"^bun\s+(test|run|install|add|remove|x|pm)"),
        rx(r"^(yarn|pnpm)\s+(test|run|install|add|remove|exec)"),
        rx(r"^pytest\b"),
        rx(r"^python3?\s+-m\s+pytest\b"),
        rx(r"^(tsc|eslint|prettier|ruff)\b"),
    ]
});
static DENY: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        rx(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/|~|\$HOME|/\*)(\s|$)"),
        rx(r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r?\s+(/|~|\$HOME|/\*)(\s|$)"),
        rx(r"\bgit\s+(-C\s+\S+\s+)?push\b.*(--force\b|-f\b)"),
        rx(r"\bgit\s+(-C\s+\S+\s+)?reset\s+--hard\b"),
        rx(r"\bgit\s+(-C\s+\S+\s+)?clean\s+-[a-zA-Z]*f"),
        rx(r"\bsudo\s+rm\b"),
        rx(r"\bmkfs\b|\bdd\s+if=|\bshutdown\b|\breboot\b"),
        rx(r">\s*/dev/sd[a-z]"),
        rx(r":\(\)\s*\{"),
        rx(r"\bgh\s+pr\s+(merge|close)\b|\bgh\s+issue\s+close\b"),
    ]
});

fn worsen(worst: Decision, v: Decision) -> Decision {
    if v.rank() > worst.rank() {
        v
    } else {
        worst
    }
}

fn strip_comments(cmd: &str) -> String {
    COMMENT.replace(cmd.trim(), "").into_owned()
}

fn strip_env(cmd: &str) -> String {
    ENV_PREFIX.replace(cmd.trim(), "").into_owned()
}

fn has_expansion(cmd: &str) -> bool {
    let no_sq = SINGLE_QUOTED.replace_all(cmd, " ");
    no_sq.contains('`') || EXPANSION.is_match(&no_sq)
}

/// Split on top-level (depth 0, outside quotes) separators.
fn depth_aware_split(cmd: &str, two: &[&str], one: &[char]) -> Vec<String> {
    let chars: Vec<char> = cmd.chars().collect();
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut depth = 0i32;
    let mut q: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(qc) = q {
            buf.push(ch);
            if ch == qc {
                q = None;
            }
            i += 1;
            continue;
        }
        if ch == '"' || ch == '\'' {
            q = Some(ch);
            buf.push(ch);
            i += 1;
            continue;
        }
        if ch == '(' {
            depth += 1;
            buf.push(ch);
            i += 1;
            continue;
        }
        if ch == ')' {
            depth -= 1;
            buf.push(ch);
            i += 1;
            continue;
        }
        if depth == 0 {
            let mut matched = false;
            for sep in two {
                let s: Vec<char> = sep.chars().collect();
                if i + s.len() <= chars.len() && chars[i..i + s.len()] == s[..] {
                    out.push(buf.trim().to_string());
                    buf.clear();
                    i += s.len();
                    matched = true;
                    break;
                }
            }
            if matched {
                continue;
            }
            if one.contains(&ch) {
                out.push(buf.trim().to_string());
                buf.clear();
                i += 1;
                continue;
            }
        }
        buf.push(ch);
        i += 1;
    }
    out.push(buf.trim().to_string());
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

fn split_segments(cmd: &str) -> Vec<String> {
    let mut segs = Vec::new();
    for part in depth_aware_split(cmd, &["&&", "||"], &[';']) {
        for s in depth_aware_split(&part, &[], &['|']) {
            segs.push(s);
        }
    }
    segs
}

fn leading_cd(cmd: &str) -> Option<String> {
    LEADING_CD
        .captures(cmd)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn seg_exec_dir(seg: &str, base: &str, resolve: &dyn Fn(&str, &str) -> String) -> String {
    match GIT_C.captures(seg).and_then(|c| c.get(1)) {
        Some(m) => resolve(base, m.as_str()),
        None => base.to_string(),
    }
}

fn redirect_targets(seg: &str) -> Vec<String> {
    let clean = FD_REDIR.replace_all(seg, " ");
    let clean = DEVNULL.replace_all(&clean, " ");
    let mut out = Vec::new();
    for c in REDIR.captures_iter(&clean) {
        out.push(c[1].trim_matches(['"', '\'']).to_string());
    }
    for c in TEE.captures_iter(&clean) {
        out.push(c[1].trim_matches(['"', '\'']).to_string());
    }
    out
}

fn last_path_arg(s: &str) -> Option<String> {
    let parts: Vec<&str> = s
        .split_whitespace()
        .skip(1)
        .filter(|p| !p.starts_with('-'))
        .collect();
    parts.last().map(|p| p.to_string())
}

/// Whitespace-split respecting single/double quotes, with quotes removed. Keeps a quoted
/// argument (e.g. a `grep` pattern `'(A|B) x'`) as one token instead of shattering it on the
/// spaces/operators inside it — naive `split_whitespace` would mis-tokenize those.
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut has = false;
    let mut q: Option<char> = None;
    for ch in s.chars() {
        match q {
            Some(qc) => {
                if ch == qc {
                    q = None;
                } else {
                    buf.push(ch);
                }
                has = true;
            }
            None => match ch {
                '\'' | '"' => {
                    q = Some(ch);
                    has = true;
                }
                c if c.is_whitespace() => {
                    if has {
                        out.push(std::mem::take(&mut buf));
                        has = false;
                    }
                }
                c => {
                    buf.push(c);
                    has = true;
                }
            },
        }
    }
    if has {
        out.push(buf);
    }
    out
}

/// File operands a read command actually opens: all non-flag tokens after the command,
/// excluding redirect operators and their target tokens (handled separately). For
/// pattern-first readers the leading pattern/script operand is dropped.
fn read_operands(s: &str, skip_pattern: bool) -> Vec<String> {
    let toks = tokenize(s);
    let mut operands = Vec::new();
    let mut skip_next = false;
    for tok in toks.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if tok.starts_with('-') || tok == "&" || tok == "|" || tok == ";" {
            continue;
        }
        if tok.contains('<') || tok.contains('>') {
            // a bare redirect operator (`>`, `2>`, `>>`, `<`) consumes the next token as its
            // target; an attached one (`2>/dev/null`) carries its own — either way, not an operand
            let bare = tok.trim_start_matches(|c: char| c.is_ascii_digit());
            if matches!(bare, "<" | ">" | ">>" | "<<" | "&>" | ">&") {
                skip_next = true;
            }
            continue;
        }
        operands.push(tok.clone());
    }
    if skip_pattern && !operands.is_empty() {
        operands.remove(0);
    }
    operands
}

/// `< file` input-redirect targets (contents flow into the command as a read).
fn input_redir_targets(seg: &str) -> Vec<String> {
    INPUT_REDIR
        .captures_iter(seg)
        .map(|c| c[1].trim_matches(['"', '\'']).to_string())
        .collect()
}

/// Strip transparent wrappers (`command`, `env`, `nohup`, `timeout N`, `nice -n N`, …) and
/// env-assignment prefixes, repeatedly, so the wrapped command is what gets classified.
fn strip_prefixes(seg: &str) -> String {
    let mut s = seg.trim().to_string();
    for _ in 0..6 {
        let next = strip_env(&WRAPPER.replace(&s, ""));
        if next == s {
            break;
        }
        s = next;
    }
    s
}

fn classify_write(
    target: &str,
    exec_base: &str,
    root: &str,
    patterns: &[Regex],
    regexes: &[Regex],
    resolve: &dyn Fn(&str, &str) -> String,
    protected: Decision,
) -> Decision {
    if is_sensitive(Some(target), patterns) {
        return Decision::Ask;
    }
    let abs = resolve(exec_base, target);
    if is_write_allowed(&abs, root, regexes) {
        return Decision::Allow;
    }
    if is_inside(&abs, root) {
        return protected;
    }
    Decision::Pass
}

#[allow(clippy::too_many_arguments)]
fn classify_segment(
    seg: &str,
    base: &str,
    root: &str,
    patterns: &[Regex],
    regexes: &[Regex],
    resolve: &dyn Fn(&str, &str) -> String,
    protected: Decision,
) -> Decision {
    // DENY is enforced on the whole command in decide_bash, so it can't reach here.
    if has_expansion(seg) {
        return Decision::Pass;
    }
    // Real subshells/command-subst are too complex to reason about → pass. Quoted parens
    // (e.g. a `grep -E '(A|B)'` pattern) are not grouping, so strip quotes before this check.
    let unquoted = SINGLE_QUOTED.replace_all(seg, " ");
    if unquoted.contains('(') || unquoted.contains(')') {
        return Decision::Pass;
    }

    let exec_dir = seg_exec_dir(seg, base, resolve);
    let mut worst = Decision::Allow;
    for t in redirect_targets(seg) {
        worst = worsen(
            worst,
            classify_write(&t, &exec_dir, root, patterns, regexes, resolve, protected),
        );
    }
    // `< secret` feeds a file's contents into any command → gate it as a read.
    for t in input_redir_targets(seg) {
        if is_sensitive(Some(&t), patterns) {
            worst = worsen(worst, Decision::Ask);
        }
    }

    let s = strip_prefixes(seg);
    if FILE_WRITE.is_match(&s) {
        let v = match last_path_arg(&s) {
            Some(t) => classify_write(&t, &exec_dir, root, patterns, regexes, resolve, protected),
            None => Decision::Pass,
        };
        return worsen(worst, v);
    }
    // Content-dumping read → gate every file operand (sed -i is a write, handled elsewhere).
    // Without this, an agent blocked from `Read .env` just runs `cat .env` (or `cat a .env`).
    if READ_CMDS.is_match(&s) && !SED_INPLACE.is_match(&s) {
        let sensitive = read_operands(&s, PATTERN_READ.is_match(&s))
            .iter()
            .any(|t| is_sensitive(Some(t), patterns));
        let v = if sensitive {
            Decision::Ask
        } else {
            Decision::Allow // reading a non-secret (or stdin) is safe
        };
        return worsen(worst, v);
    }
    // `find … -exec/-ok <cmd>` runs a sub-command that can dump contents; SAFE would allow it.
    if FIND_EXEC.is_match(&s) && tokenize(&s).iter().any(|t| is_sensitive(Some(t), patterns)) {
        return worsen(worst, Decision::Ask);
    }
    let safe = SAFE.iter().any(|r| r.is_match(&s)) && !SED_INPLACE.is_match(&s);
    if safe {
        return worst;
    }
    if BUILD_TEST.iter().any(|r| r.is_match(&s)) || GIT_WRITE.is_match(&s) {
        let v = if is_write_allowed(&exec_dir, root, regexes) {
            Decision::Allow
        } else {
            Decision::Pass
        };
        return worsen(worst, v);
    }
    worsen(worst, Decision::Pass)
}

/// Decide a Bash command string.
#[allow(clippy::too_many_arguments)]
pub fn decide_bash(
    command: Option<&str>,
    cwd: Option<&str>,
    root: &str,
    patterns: &[Regex],
    regexes: &[Regex],
    resolve: &dyn Fn(&str, &str) -> String,
    protected: Decision,
) -> Decision {
    let command = match command {
        Some(c) => c,
        None => return Decision::Pass,
    };
    let cmd = strip_comments(command);
    if cmd.is_empty() {
        return Decision::Pass;
    }
    if DENY.iter().any(|r| r.is_match(command)) {
        return Decision::Deny;
    }

    let inner = match OUTER_SUBSHELL.captures(&cmd) {
        Some(c) => c
            .get(1)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| cmd.clone()),
        None => cmd.clone(),
    };

    let cwd = cwd.unwrap_or(".");
    let base = match leading_cd(&inner) {
        Some(d) => resolve(cwd, &d),
        None => resolve(cwd, "."),
    };

    let mut worst = Decision::Allow;
    for seg in split_segments(&inner) {
        worst = worsen(
            worst,
            classify_segment(&seg, &base, root, patterns, regexes, resolve, protected),
        );
        if matches!(worst, Decision::Deny) {
            break;
        }
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::autopermit::policy::write_allow_regexes;

    const ROOT: &str = "/repo";

    fn pats() -> Vec<Regex> {
        crate::features::autopermit::policy::DEFAULT_SENSITIVE
            .iter()
            .map(|g| crate::features::autopermit::policy::glob_to_regex(g))
            .collect()
    }

    // lexical normpath resolver (no filesystem) for deterministic tests
    fn normpath(base: &str, path: &str) -> String {
        let joined = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("{}/{}", base.trim_end_matches('/'), path)
        };
        let mut out: Vec<&str> = Vec::new();
        for part in joined.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    out.pop();
                }
                p => out.push(p),
            }
        }
        format!("/{}", out.join("/"))
    }

    fn d(cmd: &str, cwd: &str) -> Decision {
        d_p(cmd, cwd, Decision::Ask) // default: in-repo writes ask, not deny
    }
    fn d_p(cmd: &str, cwd: &str, protected: Decision) -> Decision {
        let p = pats();
        let r = write_allow_regexes("worktrees", "projects");
        decide_bash(Some(cmd), Some(cwd), ROOT, &p, &r, &normpath, protected)
    }

    #[test]
    fn safe_allow() {
        for c in [
            "ls -la",
            "cat f",
            "git status",
            "git -C x log",
            "pwd",
            "echo hi",
            "grep -r foo .",
            "cat f | grep x | wc -l",
            "VAR=1 ls",
            "sed -n 1p f",
        ] {
            assert_eq!(d(c, ROOT), Decision::Allow, "{c}");
        }
        assert_eq!(d("echo \"a; b && c\"", ROOT), Decision::Allow);
        assert_eq!(d("grep 'x && y' file", ROOT), Decision::Allow); // single quotes protect
    }

    #[test]
    fn deny_catastrophic() {
        for c in [
            "rm -rf /",
            "rm -rf ~",
            "rm -fr /*",
            "sudo rm -rf x",
            "git push --force",
            "git push -f origin m",
            "git reset --hard",
            "git clean -fd",
            "dd if=/dev/zero of=x",
            "mkfs.ext4 /dev/sda",
            "gh pr merge 3",
            "gh issue close 4",
            "ls && rm -rf /",   // deny anywhere in a chain
            "true || rm -rf ~", // ...including the || branch
        ] {
            assert_eq!(d(c, ROOT), Decision::Deny, "{c}");
        }
    }

    #[test]
    fn worktree_allow() {
        assert_eq!(d("echo hi > worktrees/f/a", ROOT), Decision::Allow);
        assert_eq!(d("ls | tee worktrees/f/log", ROOT), Decision::Allow);
        assert_eq!(d("mkdir worktrees/f/sub", ROOT), Decision::Allow);
        assert_eq!(d("cp a b", "/repo/worktrees/f"), Decision::Allow);
        assert_eq!(d("npm test", "/repo/worktrees/f"), Decision::Allow);
        assert_eq!(d("(cd worktrees/f && npm test)", ROOT), Decision::Allow);
        assert_eq!(
            d("cd worktrees/f && npm run build && echo ok > log", ROOT),
            Decision::Allow
        );
        assert_eq!(d("git -C worktrees/f add -A", ROOT), Decision::Allow);
    }

    #[test]
    fn protected_writes_default_ask_strict_deny() {
        // default: in-repo writes outside a worktree → ASK (not a hard block)
        assert_eq!(d("echo x > projects/foo/main/y", ROOT), Decision::Ask);
        assert_eq!(d("mkdir projects/foo/main/sub", ROOT), Decision::Ask);
        assert_eq!(d("echo x > CLAUDE.md", ROOT), Decision::Ask);
        // strict mode (protectedWrites="deny") → DENY
        assert_eq!(
            d_p("echo x > projects/foo/main/y", ROOT, Decision::Deny),
            Decision::Deny
        );
        assert_eq!(
            d_p("echo x > CLAUDE.md", ROOT, Decision::Deny),
            Decision::Deny
        );
        // catastrophic stays DENY regardless of the knob
        assert_eq!(d_p("rm -rf /", ROOT, Decision::Ask), Decision::Deny);
    }

    #[test]
    fn secret_ask() {
        assert_eq!(d("echo x > .env", ROOT), Decision::Ask);
        assert_eq!(d("echo x > worktrees/f/.env.local", ROOT), Decision::Ask);
        assert_eq!(d("ls | tee server.key", ROOT), Decision::Ask);
    }

    #[test]
    fn read_secret_ask() {
        // content-dumping a secret → ask (closes the `Read .env` → `cat .env` bypass)
        for c in [
            "cat .env",
            "cat x/.env",
            "cat ~/.ssh/id_rsa",
            "head server.pem",
            "tail -f app.key",
            "less credentials.json",
            "base64 id_ed25519",
            "xxd cert.p12",
            "strings vault.kdbx",
            "grep AKIA credentials.json", // pattern is first, file is last → gated
            "cat public.txt | grep pw .env", // secret target anywhere in a pipe
            "cat .npmrc",
            "cat .netrc",
            "cat kubeconfig",
            "jq .apiKey credentials.json", // transformer that prints file contents
            "sort app.key",
            "tr a-z A-Z < .env", // input-redirect (spaced)
            "base64 < id_rsa",   // ditto
            "diff old.txt .env", // prints differing secret lines
            // bypass variants (ultrareview merged_bug_001) — all must still ask:
            "cat .env README.md",               // secret not the last operand
            "cat README.md .env",               // secret is the last operand
            "diff .env old.txt",                // reversed operand order
            "cat .env 2>/dev/null",             // trailing redirect token
            "cat .env > /tmp/x",                // secret read + write elsewhere
            "command cat .env",                 // POSIX alias-bypass wrapper
            "env cat .env",                     // bare env wrapper (no NAME=VAL)
            "timeout 5 cat .env",               // timeout wrapper
            "nohup base64 id_rsa",              // nohup wrapper
            "nice -n 10 cat .env",              // nice wrapper
            "grep -E '(AKIA|SECRET)' .env",     // quoted-paren pattern (paren short-circuit)
            "cat <.env",                        // adjacent input redirect
            "< .env cat",                       // leading input redirect
            "find . -name .env -exec cat {} +", // find -exec dumper
            "find /h -name id_rsa -execdir base64 {} +",
        ] {
            assert_eq!(d(c, ROOT), Decision::Ask, "{c}");
        }
    }

    #[test]
    fn read_nonsecret_allow() {
        // reads of ordinary files (and stdin/pattern-only reads) stay allowed — no fatigue
        for c in [
            "cat README.md",
            "head -n 20 src/main.rs",
            "base64 logo.png",
            "grep secret notes.txt", // "secret" is the pattern, not the file → allow
            "grep -r AKIA .",        // no file target
            "cat",                   // stdin
            "xxd binary.bin",
            "sed -n 1p Cargo.toml",
            "jq . package.json",
            "sort names.txt | uniq",
            "cat a.md | tr -s ' '",
            // wrappers / find over a non-secret must not over-ask
            "command ls",
            "env cat README.md",
            "timeout 5 cat README.md",
            "grep -E '(foo|bar)' README.md", // quoted-paren pattern, ordinary file
            "find . -name '*.rs' -exec grep TODO {} +",
        ] {
            assert_eq!(d(c, ROOT), Decision::Allow, "{c}");
        }
    }

    #[test]
    fn pass_uncertain() {
        for c in [
            "weirdcmd --go",
            "npm test",
            "echo x > /tmp/out",
            "cp a /etc/x",                          // FILE_WRITE outside root
            "git -C projects/foo/main commit -m x", // git-write outside worktree
            "sed -i s/a/b/ f",
            "echo $HOME",
            "cat ${FILE}",
            "ls $(pwd)",
            "echo `date`",
        ] {
            assert_eq!(d(c, ROOT), Decision::Pass, "{c}");
        }
        assert_eq!(d("(cd a && (cd b && ls))", ROOT), Decision::Pass);
    }

    #[test]
    fn aggregation_precedence() {
        assert_eq!(d("ls && weirdcmd", ROOT), Decision::Pass);
        assert_eq!(d("ls && echo x > .env", ROOT), Decision::Ask);
        assert_eq!(d("weirdcmd && echo x > .env", ROOT), Decision::Ask); // pass+ask=ask
        assert_eq!(d("echo x > .env && rm -rf /", ROOT), Decision::Deny);
        assert_eq!(
            d("npm test && echo ok > worktrees/f/l", "/repo/worktrees/f"),
            Decision::Allow
        );
        assert_eq!(d("", ROOT), Decision::Pass);
    }

    #[test]
    fn malformed_and_none() {
        assert_eq!(d("   ", ROOT), Decision::Pass); // whitespace only
        assert_eq!(d("# comment", ROOT), Decision::Pass); // comment only
        let p = pats();
        let r = write_allow_regexes("worktrees", "projects");
        assert_eq!(
            decide_bash(None, Some(ROOT), ROOT, &p, &r, &normpath, Decision::Ask),
            Decision::Pass
        );
    }

    #[test]
    fn helper_redirect_targets() {
        assert_eq!(redirect_targets("echo x > a"), ["a"]);
        assert_eq!(redirect_targets("ls 2>&1 > b"), ["b"]); // fd-redirect stripped
        assert!(redirect_targets("ls > /dev/null").is_empty()); // devnull stripped
        assert_eq!(redirect_targets("ls | tee -a c"), ["c"]);
    }

    #[test]
    fn helper_split_segments() {
        assert_eq!(split_segments("a && b; c | d"), ["a", "b", "c", "d"]);
        assert_eq!(split_segments("echo \"a && b\""), ["echo \"a && b\""]); // quotes protect
    }

    #[test]
    fn helper_has_expansion() {
        assert!(has_expansion("echo $X"));
        assert!(has_expansion("echo `x`"));
        assert!(!has_expansion("echo plain"));
        assert!(!has_expansion("grep '$X' f")); // single-quoted expansion ignored
    }
}
