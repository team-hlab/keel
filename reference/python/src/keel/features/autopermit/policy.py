"""autopermit.policy — pure file-tool permission decisions (no I/O)."""

import os
import re
from fnmatch import fnmatch

READ_TOOLS = frozenset({"Read", "Glob", "Grep", "NotebookRead"})
WRITE_TOOLS = frozenset({"Edit", "MultiEdit", "Write", "NotebookEdit"})

DEFAULT_SENSITIVE = (".env*", "*.key", "*.pem", "credentials*", "*secret*")
DEFAULT_WORKTREES = "worktrees"
DEFAULT_PROJECTS = "projects"


def is_sensitive(file_path, patterns):
    if not file_path:
        return False
    base = os.path.basename(str(file_path).rstrip("/\\")).lower()
    return any(fnmatch(base, str(p).lower()) for p in patterns)


def is_inside(abs_path, root):
    if not abs_path or not root:
        return False
    return abs_path == root or abs_path.startswith(root + os.sep)


def write_allow_regexes(worktrees=DEFAULT_WORKTREES, projects=DEFAULT_PROJECTS):
    wt = re.escape(str(worktrees).strip("/"))
    proj = re.escape(str(projects).strip("/"))
    return (
        re.compile(rf"^{wt}/"),
        re.compile(rf"^{proj}/[^/]+/{wt}/"),
        re.compile(rf"^{proj}/[^/]+/[^/]+/{wt}/"),
        re.compile(r"^\.lens/"),
        re.compile(r"^\.slack-digest/"),
    )


def is_write_allowed(abs_path, root, regexes):
    if not is_inside(abs_path, root):
        return False
    rel = os.path.relpath(abs_path, root).replace(os.sep, "/")
    return any(r.search(rel) for r in regexes)


def decide(tool, file_path, abs_path, root, patterns, regexes):
    """Pure file-tool verdict → 'allow' | 'deny' | 'ask' | 'pass'."""
    if tool in READ_TOOLS:
        if is_sensitive(file_path, patterns):
            return "ask"
        return "allow"

    if tool in WRITE_TOOLS:
        if not file_path:
            return "deny"
        if is_sensitive(file_path, patterns):
            return "ask"
        if is_write_allowed(abs_path, root, regexes):
            return "allow"
        if is_inside(abs_path, root):
            return "deny"
        return "pass"

    return "pass"
