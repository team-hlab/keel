//! Pure Bash / multi-command decision logic. Path resolution is injected, so it's
//! fully testable without a filesystem. Conservative: allow only confidently-safe,
//! deny only catastrophic, ask on secret writes, pass on anything uncertain.

use std::sync::LazyLock;

use regex::Regex;

use crate::features::autopermit::policy::{
    is_inside, is_sensitive, is_sensitive_operand, is_write_allowed,
};
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
static REDIR: LazyLock<Regex> = LazyLock::new(|| rx(r">{1,2}\|?\s*([^\s;|&]+)"));
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
        r"^(command|builtin|exec|env|nohup|time|unbuffer|stdbuf\s+-\S+|ionice(\s+-\S+)*|nice(\s+-n\s+\d+|\s+-\d+)?|timeout(\s+-\S+)*\s+[\d.]+[smhd]?)\s+",
    )
});
// A `find` action that runs a sub-command (which can dump file contents) — SAFE would
// otherwise allow it; we scan its tokens for sensitive targets instead.
static FIND_EXEC: LazyLock<Regex> = LazyLock::new(|| rx(r"^find\b.*\s-(exec|execdir|ok)\b"));
// A shell invoked with `-c <script>`: the script is re-parsed and run, so we recurse into it
// (depth-bounded) rather than defer — `bash -c 'cat .env'` should gate like `cat .env`.
static SHELL_C: LazyLock<Regex> =
    LazyLock::new(|| rx(r"^(sh|bash|zsh|dash|ash|ksh)\s+(?:\S+\s+)*-c(\s|$)"));
// Input redirect `< file` / `N< file` (fd-numbered), but not `<<` heredoc, `<&` fd-dup, or
// `<(` process-sub. The file's contents flow into the command's stdin → a read to gate. The
// target char-class starting with a path char is what excludes `<<`/`<&`/`<(`.
static INPUT_REDIR: LazyLock<Regex> =
    LazyLock::new(|| rx(r"(?:^|[^<])\d*<\s*([A-Za-z0-9_./~*?\[][^\s;|&<>]*)"));

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

/// Blank out single/double-quoted regions (content + quotes → spaces). A real redirect operator
/// is never inside quotes, so masking before scanning kills false positives like `grep '=>' f`
/// or `grep '<x>' f` being read as writes/reads — without missing any real redirect.
fn mask_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut q: Option<char> = None;
    for c in s.chars() {
        match q {
            Some(qc) => {
                if c == qc {
                    q = None;
                }
                out.push(' ');
            }
            None => match c {
                '\'' | '"' => {
                    q = Some(c);
                    out.push(' ');
                }
                _ => out.push(c),
            },
        }
    }
    out
}

fn redirect_targets(seg: &str) -> Vec<String> {
    let masked = mask_quoted(seg);
    let clean = FD_REDIR.replace_all(&masked, " ");
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
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            // backslash escape: bash unescapes `\.` → `.`, so `cat \.env` reads `.env`
            '\\' => {
                if let Some(n) = chars.next() {
                    buf.push(n);
                    has = true;
                }
            }
            '\'' => {
                has = true;
                for c in chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    buf.push(c);
                }
            }
            '"' => {
                has = true;
                while let Some(c) = chars.next() {
                    if c == '"' {
                        break;
                    }
                    if c == '\\' {
                        if let Some(n) = chars.next() {
                            buf.push(n);
                        }
                    } else {
                        buf.push(c);
                    }
                }
            }
            // ANSI-C quoting `$'...'` — bash decodes `\056`→`.`, so `cat $'\056env'` reads `.env`
            '$' if chars.peek() == Some(&'\'') => {
                chars.next();
                has = true;
                let mut raw = String::new();
                while let Some(c) = chars.next() {
                    if c == '\'' {
                        break;
                    }
                    raw.push(c);
                    if c == '\\' {
                        if let Some(n) = chars.next() {
                            raw.push(n);
                        }
                    }
                }
                buf.push_str(&decode_ansi_c(&raw));
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
        }
    }
    if has {
        out.push(buf);
    }
    out
}

/// Decode `$'...'` ANSI-C escapes we care about (octal/hex/`\n` etc.); unknown escapes pass the
/// escaped char through. Only used to unmask an obfuscated filename, so byte→char is fine.
fn decode_ansi_c(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('x') => {
                let mut h = String::new();
                while h.len() < 2 {
                    match chars.peek() {
                        Some(d) if d.is_ascii_hexdigit() => {
                            h.push(*d);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                if let Ok(n) = u8::from_str_radix(&h, 16) {
                    out.push(n as char);
                }
            }
            Some(d) if d.is_digit(8) => {
                let mut o = d.to_string();
                while o.len() < 3 {
                    match chars.peek() {
                        Some(x) if x.is_digit(8) => {
                            o.push(*x);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                if let Ok(n) = u8::from_str_radix(&o, 8) {
                    out.push(n as char);
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// Expand one level of `{a,b,c}` comma-lists so `cat {.env,x}` yields `.env` as a candidate.
/// Bounded; ranges (`{1..9}`) and nesting aren't handled (they fall through as-is).
fn brace_expand(s: &str) -> Vec<String> {
    if let Some(open) = s.find('{') {
        let rest = &s[open + 1..];
        if let Some(rel) = rest.find('}') {
            let inner = &rest[..rel];
            if inner.contains(',') && !inner.contains('{') {
                let prefix = &s[..open];
                let suffix = &rest[rel + 1..];
                let mut out = Vec::new();
                for part in inner.split(',') {
                    for full in brace_expand(&format!("{prefix}{part}{suffix}")) {
                        out.push(full);
                        if out.len() >= 64 {
                            return out;
                        }
                    }
                }
                return out;
            }
        }
    }
    vec![s.to_string()]
}

/// Remove backslash escapes outside single quotes (`r\m` → `rm`) so the DENY scan can't be
/// dodged by escaping a letter of a catastrophic command.
fn unescape_outside_squotes(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    let mut in_sq = false;
    while let Some(c) = chars.next() {
        if in_sq {
            out.push(c);
            if c == '\'' {
                in_sq = false;
            }
        } else if c == '\'' {
            out.push(c);
            in_sq = true;
        } else if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// File operands a read command actually opens: all non-flag tokens after the command
/// (brace-expanded), excluding redirect operators and their target tokens. For pattern-first
/// readers (grep/awk/sed) the leading pattern/script operand is dropped — unless the pattern
/// came from a `-e`/`-f` flag, in which case a `-f FILE` value is itself a read target.
fn read_operands(s: &str, skip_pattern: bool) -> Vec<String> {
    let toks = tokenize(s);
    let mut operands: Vec<String> = Vec::new();
    let mut skip_next = false;
    let mut consume: Option<bool> = None; // grep/awk/sed flag value: Some(true)=file, Some(false)=pattern
    let mut pattern_from_flag = false;
    let push = |operands: &mut Vec<String>, t: &str| operands.extend(brace_expand(t));
    for tok in toks.iter().skip(1) {
        if let Some(is_file) = consume.take() {
            if is_file {
                push(&mut operands, tok); // `-f FILE`: grep/awk/sed read this file
            }
            continue; // `-e PATTERN`: consumed, not a file
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        // grep/awk/sed pattern/file flags — scoped to pattern-readers so `tail -f` is unaffected
        if skip_pattern {
            match tok.as_str() {
                "-f" | "--file" => {
                    consume = Some(true);
                    pattern_from_flag = true;
                    continue;
                }
                "-e" | "--regexp" | "--regex" => {
                    consume = Some(false);
                    pattern_from_flag = true;
                    continue;
                }
                _ => {}
            }
            if let Some(f) = tok.strip_prefix("-f") {
                if !f.is_empty() {
                    push(&mut operands, f); // glued `-fFILE`
                    pattern_from_flag = true;
                    continue;
                }
            }
            if tok.starts_with("-e") && tok.len() > 2 {
                pattern_from_flag = true; // glued `-ePATTERN`
                continue;
            }
        }
        if tok.starts_with('-') || tok == "&" || tok == "|" || tok == ";" {
            continue;
        }
        if tok.contains('<') || tok.contains('>') {
            // a filename glued to a redirect (`.env>x`) is still read — keep the left side
            let left: String = tok.chars().take_while(|c| *c != '<' && *c != '>').collect();
            if !left.is_empty() && !left.chars().all(|c| c.is_ascii_digit()) {
                push(&mut operands, &left);
            }
            // a bare redirect operator (`>`, `2>`, `>>`, `<`) consumes the next token as its
            // target; an attached one (`2>/dev/null`) carries its own — either way, not an operand
            let bare = tok.trim_start_matches(|c: char| c.is_ascii_digit());
            if matches!(bare, "<" | ">" | ">>" | "<<" | "&>" | ">&") {
                skip_next = true;
            }
            continue;
        }
        push(&mut operands, tok);
    }
    if skip_pattern && !pattern_from_flag && !operands.is_empty() {
        operands.remove(0);
    }
    operands
}

/// `< file` input-redirect targets (contents flow into the command as a read), brace-expanded.
fn input_redir_targets(seg: &str) -> Vec<String> {
    let masked = mask_quoted(seg);
    INPUT_REDIR
        .captures_iter(&masked)
        .flat_map(|c| brace_expand(c[1].trim_matches(['"', '\''])))
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
    witnesses: &[String],
    regexes: &[Regex],
    resolve: &dyn Fn(&str, &str) -> String,
    protected: Decision,
    depth: u8,
) -> Decision {
    // DENY is enforced on the whole command in decide_bash, so it can't reach here.
    if has_expansion(seg) {
        return Decision::Pass;
    }
    // Real subshells/command-subst are too complex to reason about → pass. Quoted parens
    // (a `grep -E '(A|B)'` pattern, an `awk` script, `if (x > 3)`) are not grouping, so mask
    // quoted regions before this check — otherwise every such command needlessly defers.
    let unquoted = mask_quoted(seg);
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
        if is_sensitive_operand(&t, patterns, witnesses) {
            worst = worsen(worst, Decision::Ask);
        }
    }

    let s = strip_prefixes(seg);
    // `sh -c '<script>'` re-parses and runs the script → recurse into it (depth-bounded) so it's
    // gated, not deferred. `$`/backtick scripts already bailed to Pass via has_expansion above.
    if SHELL_C.is_match(&s) {
        if depth < 3 {
            let toks = tokenize(&s);
            if let Some(script) = toks
                .iter()
                .position(|t| t == "-c")
                .and_then(|i| toks.get(i + 1))
            {
                let inner = decide_bash_at(
                    Some(script),
                    Some(base),
                    root,
                    patterns,
                    witnesses,
                    regexes,
                    resolve,
                    protected,
                    depth + 1,
                );
                return worsen(worst, inner);
            }
        }
        // depth exhausted, or no `-c` script token → can't inspect the inner command → defer.
        // Never fall through to the allow-ish branches with an un-inspected shell script.
        return worsen(worst, Decision::Pass);
    }
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
            .any(|t| is_sensitive_operand(t, patterns, witnesses));
        let v = if sensitive {
            Decision::Ask
        } else {
            Decision::Allow // reading a non-secret (or stdin) is safe
        };
        return worsen(worst, v);
    }
    // `find … -exec/-ok <cmd>` runs a sub-command that can dump contents; SAFE would allow it.
    if FIND_EXEC.is_match(&s)
        && tokenize(&s)
            .iter()
            .flat_map(|t| brace_expand(t))
            .any(|t| is_sensitive_operand(&t, patterns, witnesses))
    {
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
    witnesses: &[String],
    regexes: &[Regex],
    resolve: &dyn Fn(&str, &str) -> String,
    protected: Decision,
) -> Decision {
    decide_bash_at(
        command, cwd, root, patterns, witnesses, regexes, resolve, protected, 0,
    )
}

// `depth` bounds `sh -c`/`bash -c` recursion (see classify_segment).
#[allow(clippy::too_many_arguments)]
fn decide_bash_at(
    command: Option<&str>,
    cwd: Option<&str>,
    root: &str,
    patterns: &[Regex],
    witnesses: &[String],
    regexes: &[Regex],
    resolve: &dyn Fn(&str, &str) -> String,
    protected: Decision,
    depth: u8,
) -> Decision {
    let command = match command {
        Some(c) => c,
        None => return Decision::Pass,
    };
    // A real agent command is never hundreds of KB. Cap input so a pathological command
    // (e.g. thousands of redirect targets, each hitting the filesystem via `resolve`) can't
    // turn the hook into a latency sink — defer instead. Bounds every downstream loop at once.
    if command.len() > 64 * 1024 {
        return Decision::Pass;
    }
    let cmd = strip_comments(command);
    if cmd.is_empty() {
        return Decision::Pass;
    }
    // Scan DENY over normalized variants so escaping (`r\m -rf /`) or braces (`rm {-rf,} /`)
    // can't hide a catastrophic command. (Quoted `/` in `rm -rf "/"` is a known residual gap.)
    if brace_expand(&unescape_outside_squotes(command))
        .iter()
        .any(|v| DENY.iter().any(|r| r.is_match(v)))
    {
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
            classify_segment(
                &seg, &base, root, patterns, witnesses, regexes, resolve, protected, depth,
            ),
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

    fn wits() -> Vec<String> {
        crate::features::autopermit::policy::DEFAULT_SENSITIVE
            .iter()
            .map(|g| crate::features::autopermit::policy::glob_witness(g))
            .collect()
    }

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
        let w = wits();
        let r = write_allow_regexes("worktrees", "projects");
        decide_bash(Some(cmd), Some(cwd), ROOT, &p, &w, &r, &normpath, protected)
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
            "ls && rm -rf /",     // deny anywhere in a chain
            "true || rm -rf ~",   // ...including the || branch
            "nohup rm -rf /",     // deny survives a wrapper prefix
            "bash -c 'rm -rf /'", // ...and shell -c recursion
            "r\\m -rf /",         // ...backslash-escaped command word (unescape before DENY)
            "rm -r\\f /",
            "rm {-rf,} /", // ...brace expansion
        ] {
            assert_eq!(d(c, ROOT), Decision::Deny, "{c}");
        }
    }

    #[test]
    fn obfuscated_reads_ask() {
        // reviewers' adversarial dodges — an agent that read the diff would try these first
        for c in [
            "cat \\.env", // backslash escape
            "cat id_rs\\a",
            "base64 ~/.ssh/id_r\\sa",
            "cat $'\\056env'", // ANSI-C octal → ".env"
            "cat {.env,x}",    // brace expansion
            "cat README.md .{env,}",
            "cat 0< .env", // fd-numbered input redirect
            "cat 3< credentials.json",
            "cat < *.pem",            // glob input redirect
            "cat ~/.ssh/id_*",        // glob operand overlapping a secret family
            "grep -f .env other.txt", // -f reads .env as a pattern file (not dropped as pattern)
            "cat .env>/tmp/steal",    // glued redirect, exfil outside repo
        ] {
            assert_eq!(d(c, ROOT), Decision::Ask, "{c}");
        }
    }

    #[test]
    fn nested_sh_c_never_allows_secret() {
        // recursion gates a nested secret read (2-deep, properly quoted)
        assert_eq!(d("sh -c 'sh -c \"cat .env\"'", ROOT), Decision::Ask);
        // a shell -c we can't extract a script from must defer, never fall through to Allow
        assert_eq!(d("bash -c", ROOT), Decision::Pass);
        assert_eq!(d("sh -ec", ROOT), Decision::Pass);
    }

    #[test]
    fn no_fatigue_on_quoted_metachars() {
        // quoted redirect/paren metacharacters are data, not operators → must not ask/pass-noise
        for c in [
            "grep -c '=>' handlers.js", // arrow function, quoted `>`
            "grep -n 'if (x > 3)' src/main.rs",
            "grep '<tag>' file.xml",
            "awk '{if ($3 > 5) print}' data.txt",
            "cat *",     // bare glob — matches everything, so not "a secret glob"
            "cat src/*", // dir glob, no literal secret anchor
            "grep -E '(A|B)' README.md",
        ] {
            assert_eq!(d(c, ROOT), Decision::Allow, "{c}");
        }
        // a quoted mention of a catastrophic command is not that command
        assert_eq!(
            d("git commit -m 'reset --hard the bug'", ROOT),
            Decision::Pass
        );
    }

    #[test]
    fn big_input_defers() {
        let huge = format!("echo x{}", " > f".repeat(30_000));
        assert_eq!(d(&huge, ROOT), Decision::Pass); // capped, no per-target fs storm
    }

    #[test]
    fn helper_tokenize() {
        assert_eq!(tokenize("cat \\.env"), vec!["cat", ".env"]);
        assert_eq!(tokenize("cat 'a b' c"), vec!["cat", "a b", "c"]);
        assert_eq!(tokenize("a'b'c"), vec!["abc"]); // adjacent-quote concat
        assert_eq!(tokenize("cat $'\\056env'"), vec!["cat", ".env"]);
    }

    #[test]
    fn read_gating_precedes_safe_allow() {
        // Invariant: any content-dumper listed in SAFE must ALSO be caught by the READ_CMDS
        // branch (which runs first) — otherwise adding a reader to SAFE alone silently makes it
        // an ungated secret-read bypass. Probe each SAFE reader with a secret operand.
        for c in [
            "cat .env",
            "head .env",
            "tail .env",
            "grep x .env",
            "sed -n 1p .env",
            "awk '{print}' .env",
            "cut -f1 .env",
            "jq . .env",
            "sort .env",
            "uniq .env",
            "diff a .env",
        ] {
            assert_eq!(d(c, ROOT), Decision::Ask, "SAFE reader must gate: {c}");
        }
        // metadata-only SAFE commands intentionally do NOT gate (no content revealed)
        for c in ["ls .env", "stat .env", "wc -c .env", "file .env"] {
            assert_ne!(
                d(c, ROOT),
                Decision::Ask,
                "metadata-only must not gate: {c}"
            );
        }
    }

    #[test]
    fn helper_brace_and_unescape() {
        assert_eq!(brace_expand("{.env,x}"), vec![".env", "x"]);
        assert_eq!(brace_expand(".{env,}"), vec![".env", "."]);
        assert_eq!(brace_expand("plain"), vec!["plain"]);
        assert_eq!(unescape_outside_squotes("r\\m -rf /"), "rm -rf /");
        assert_eq!(unescape_outside_squotes("echo '\\x'"), "echo '\\x'"); // single-quoted kept
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
            // glob operands that expand onto secrets (shell expands; literal-match would miss):
            "cat ~/.ssh/id_*",
            "cat .en?",
            "base64 ~/.ssh/id_ed*",
            "cat *.pem",
            "cat .env>x",    // filename glued to a redirect, still a read
            "exec cat .env", // exec wrapper
            "builtin cat .env",
            "sh -c 'cat .env'", // shell -c recursion
            "bash -c \"base64 id_rsa\"",
            "timeout 5 bash -c 'cat .env'", // wrapper + recursion
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
            // ordinary globs that don't overlap any secret → still allowed (no fatigue)
            "cat *.log",
            "head src/*.rs",
            "cat build/*.txt",
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
        let w = wits();
        let r = write_allow_regexes("worktrees", "projects");
        assert_eq!(
            decide_bash(None, Some(ROOT), ROOT, &p, &w, &r, &normpath, Decision::Ask),
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
