"""autopermit.shell — pure Bash/multi-command decision logic (injected resolver)."""

import re

from keel.features.autopermit.policy import is_inside, is_sensitive, is_write_allowed

ENV_PREFIX = re.compile(r"^(env\s+)?([A-Za-z_][A-Za-z0-9_]*=[^\s]*\s+)+")

SAFE = [
    re.compile(
        r"^git\s+(-C\s+\S+\s+)?(status|diff|log|show|branch|fetch|remote|"
        r"rev-parse|ls-files|ls-tree|describe|config\s+--get|stash\s+list|"
        r"worktree\s+list|pull|show-ref|cat-file|tag\s+-l)\b"
    ),
    re.compile(
        r"^(ls|cat|head|tail|wc|find|grep|pwd|which|command|basename|dirname|"
        r"realpath|date|file|stat|du|df|id|whoami|printenv|ps|tree|echo|cd|true|:)\b"
    ),
    re.compile(r"^sed\s+(?!-i\b)"),
    re.compile(r"^(awk|tr|cut|jq|uniq|column|sort|diff|test)\b"),
    re.compile(r"^gh\s+(pr|issue|run|repo)\s+(view|list|checks|diff|status)\b"),
    re.compile(r"^gh\s+auth\s+status\b"),
]
FILE_WRITE = re.compile(r"^(mkdir|cp|mv|rm|touch|chmod|ln|rsync|tee)\b")
BUILD_TEST = [
    re.compile(r"^\./gradlew\s"),
    re.compile(r"^npm\s+(test|run|install|ci|exec|ls)"),
    re.compile(r"^(npx|bunx)\s"),
    re.compile(r"^bun\s+(test|run|install|add|remove|x|pm)"),
    re.compile(r"^(yarn|pnpm)\s+(test|run|install|add|remove|exec)"),
    re.compile(r"^pytest\b"),
    re.compile(r"^python3?\s+-m\s+pytest\b"),
    re.compile(r"^(tsc|eslint|prettier|ruff)\b"),
]
GIT_WRITE = re.compile(
    r"^git\s+(-C\s+\S+\s+)?(add|commit|push|checkout|switch|stash|"
    r"merge|rebase|cherry-pick|restore|tag)\b"
)

DENY = [
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/|~|\$HOME|/\*)(\s|$)"),
    re.compile(r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r?\s+(/|~|\$HOME|/\*)(\s|$)"),
    re.compile(r"\bgit\s+(-C\s+\S+\s+)?push\b.*(--force\b|-f\b)"),
    re.compile(r"\bgit\s+(-C\s+\S+\s+)?reset\s+--hard\b"),
    re.compile(r"\bgit\s+(-C\s+\S+\s+)?clean\s+-[a-zA-Z]*f"),
    re.compile(r"\bsudo\s+rm\b"),
    re.compile(r"\bmkfs\b|\bdd\s+if=|\bshutdown\b|\breboot\b"),
    re.compile(r">\s*/dev/sd[a-z]"),
    re.compile(r":\(\)\s*\{"),
    re.compile(r"\bgh\s+pr\s+(merge|close)\b|\bgh\s+issue\s+close\b"),
]


def strip_comments(cmd):
    return re.sub(r"^(#[^\n]*\n\s*)+", "", cmd.strip())


def strip_env(cmd):
    return ENV_PREFIX.sub("", cmd.strip())


def has_expansion(cmd):
    no_sq = re.sub(r"'[^']*'", " ", cmd)
    return bool(re.search(r"`", no_sq) or re.search(r"\$[A-Za-z_{(]", no_sq))


def _depth_aware_split(cmd, two_char, one_char):
    out, buf, depth, i, q = [], [], 0, 0, None
    while i < len(cmd):
        ch = cmd[i]
        if q:
            buf.append(ch)
            if ch == q:
                q = None
            i += 1
            continue
        if ch in "\"'":
            q = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "(":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch == ")":
            depth -= 1
            buf.append(ch)
            i += 1
            continue
        if depth == 0:
            if cmd[i : i + 2] in two_char:
                out.append("".join(buf))
                buf = []
                i += 2
                continue
            if ch in one_char:
                out.append("".join(buf))
                buf = []
                i += 1
                continue
        buf.append(ch)
        i += 1
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def split_segments(cmd):
    segs = []
    for part in _depth_aware_split(cmd, {"&&", "||"}, {";"}):
        segs.extend(_depth_aware_split(part, set(), {"|"}))
    return segs


def leading_cd(cmd):
    m = re.match(r"^\(?cd\s+(\S+)\s+&&", cmd)
    return m.group(1) if m else None


def seg_exec_dir(seg, base, resolve):
    m = re.search(r"\bgit\s+-C\s+(\S+)", seg)
    return resolve(base, m.group(1)) if m else base


def redirect_targets(seg):
    clean = re.sub(r"\d*>&\d+", " ", seg)
    clean = re.sub(r"\d*>\s*/dev/null", " ", clean)
    targets = re.findall(r">{1,2}\s*([^\s;|&]+)", clean)
    targets += re.findall(r"\|\s*tee\s+(?:-a\s+)?([^\s;|&]+)", clean)
    return [t.strip("\"'") for t in targets]


def _last_path_arg(s):
    parts = [p for p in s.split()[1:] if not p.startswith("-")]
    return parts[-1] if parts else None


def _classify_write(target_raw, exec_base, root, patterns, regexes, resolve):
    if is_sensitive(target_raw, patterns):
        return "ask"
    abs_path = resolve(exec_base, target_raw)
    if is_write_allowed(abs_path, root, regexes):
        return "allow"
    if is_inside(abs_path, root):
        return "deny"
    return "pass"


def _classify_segment(seg, base, root, patterns, regexes, resolve):
    # DENY is enforced on the whole command in decide_bash, so it can't reach here.
    if has_expansion(seg):
        return "pass"
    if "(" in seg or ")" in seg:
        return "pass"

    exec_dir = seg_exec_dir(seg, base, resolve)
    worst = "allow"
    rank = {"allow": 0, "pass": 1, "ask": 2, "deny": 3}

    def worsen(v):
        nonlocal worst
        if rank[v] > rank[worst]:
            worst = v

    for t in redirect_targets(seg):
        worsen(_classify_write(t, exec_dir, root, patterns, regexes, resolve))

    s = strip_env(seg)
    if FILE_WRITE.match(s):
        target = _last_path_arg(s)
        worsen(_classify_write(target, exec_dir, root, patterns, regexes, resolve) if target else "pass")
        return worst
    if any(p.match(s) for p in SAFE):
        return worst
    if any(p.match(s) for p in BUILD_TEST) or GIT_WRITE.match(s):
        worsen("allow" if is_write_allowed(exec_dir, root, regexes) else "pass")
        return worst
    worsen("pass")
    return worst


def decide_bash(command, cwd, root, patterns, regexes, resolve):
    """Return 'allow' | 'deny' | 'ask' | 'pass' for a Bash command string."""
    if not isinstance(command, str):
        return "pass"
    cmd = strip_comments(command)
    if not cmd:
        return "pass"
    if any(p.search(command) for p in DENY):
        return "deny"

    inner = cmd
    m = re.match(r"^\((.*)\)\s*(?:\d*>&\d+\s*|\|\|\s*(?:true|:)\s*)*$", cmd, re.S)
    if m:
        inner = m.group(1).strip()

    cd = leading_cd(inner)
    base = resolve(cwd or ".", cd) if cd else resolve(cwd or ".", ".")

    rank = {"allow": 0, "pass": 1, "ask": 2, "deny": 3}
    worst = "allow"
    for seg in split_segments(inner):
        v = _classify_segment(seg, base, root, patterns, regexes, resolve)
        if rank[v] > rank[worst]:
            worst = v
        if worst == "deny":
            break
    return worst
