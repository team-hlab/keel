"""branch-guard — deny mutating git commands while HEAD is on a protected branch."""

import os
import re

from keel.core.model import DENY, Verdict
from keel.features.base import Feature

_GIT_WRITE = re.compile(r"\bgit\s+(-C\s+\S+\s+)?(commit|push|merge|rebase|reset|cherry-pick|am)\b")
_DEFAULT_PROTECTED = ("main", "master", "develop")


def head_branch(cwd):
    """Current branch name from .git/HEAD (worktree-aware), or None if detached/unknown."""
    cur = os.path.realpath(cwd or os.getcwd())
    while True:
        git = os.path.join(cur, ".git")
        if os.path.exists(git):
            if os.path.isfile(git):
                try:
                    gitdir = open(git, encoding="utf-8").read().strip().replace("gitdir: ", "")
                except OSError:
                    return None
                head_path = os.path.join(gitdir, "HEAD")
            else:
                head_path = os.path.join(git, "HEAD")
            try:
                ref = open(head_path, encoding="utf-8").read().strip()
            except OSError:
                return None
            prefix = "ref: refs/heads/"
            return ref[len(prefix):] if ref.startswith(prefix) else None
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


class BranchGuard(Feature):
    name = "branch-guard"

    def __init__(self, config=None):
        super().__init__(config)
        self.protected = set(self.config.get("protected", _DEFAULT_PROTECTED))

    def stages(self):
        return {"PreToolUse"}

    def evaluate(self, event):
        if event.tool != "Bash" or not isinstance(event.command, str):
            return None
        if not _GIT_WRITE.search(event.command):
            return None
        branch = head_branch(event.cwd)
        if branch in self.protected:
            return Verdict(DENY, f"branch-guard: '{branch}' is protected — use a branch/PR.", self.name)
        return None
