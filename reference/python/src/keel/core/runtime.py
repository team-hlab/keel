"""I/O edges: stdin parsing, project-root discovery, config loading, path resolution."""

import json
import os
import sys


def read_input():
    try:
        return json.loads(sys.stdin.read())
    except (ValueError, OSError):
        return None


def find_root(cwd):
    """Resolve the project root.

    $KEEL_ROOT wins. Otherwise walk up from cwd to the nearest `.git`
    (back-tracking from a worktree `.git` *file* to the main repo). Falls back to cwd.
    realpath() makes comparisons OS-stable and defeats symlink escapes.
    """
    env = os.environ.get("KEEL_ROOT")
    if env:
        return os.path.realpath(env)

    base = os.path.realpath(cwd or os.getcwd())
    cur = base
    while True:
        git = os.path.join(cur, ".git")
        if os.path.exists(git):
            if os.path.isfile(git):
                try:
                    with open(git, encoding="utf-8") as f:
                        gitdir = f.read().strip().replace("gitdir: ", "")
                    return os.path.realpath(os.path.join(gitdir, "..", "..", ".."))
                except OSError:
                    pass
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return base
        cur = parent


def load_config(root):
    """Read keel config. $KEEL_CONFIG wins; else <root>/.keel.json; else {}."""
    path = os.environ.get("KEEL_CONFIG") or os.path.join(root, ".keel.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def resolve_target(cwd, path):
    """Resolve a path to absolute + symlink-free (or None)."""
    if not path:
        return None
    base = cwd or os.getcwd()
    return os.path.realpath(os.path.join(base, path))
