"""autopermit feature — auto-permit safe file/shell ops, confirm secrets, deny protected writes."""

from keel.core.model import ALLOW, ASK, DENY, PASS, Verdict
from keel.core.runtime import resolve_target
from keel.features.autopermit import policy, shell
from keel.features.base import Feature

_REASON = {
    ALLOW: "safe read / worktree write / read-only command",
    DENY: "blocked — protected path or destructive command",
    ASK: "confirmation required — secret or unverified write",
    PASS: "",
}


class AutoPermit(Feature):
    name = "autopermit"

    def __init__(self, config=None):
        super().__init__(config)
        self.patterns = self.config.get("sensitiveFilePatterns") or list(policy.DEFAULT_SENSITIVE)
        self.regexes = policy.write_allow_regexes(
            self.config.get("worktrees", policy.DEFAULT_WORKTREES),
            self.config.get("projects", policy.DEFAULT_PROJECTS),
        )

    def stages(self):
        return {"PreToolUse", "PermissionRequest"}

    def evaluate(self, event):
        if event.tool == "Bash":
            decision = shell.decide_bash(
                event.command, event.cwd, event.root, self.patterns, self.regexes, resolve_target
            )
        else:
            abs_path = resolve_target(event.cwd, event.file_path)
            decision = policy.decide(
                event.tool, event.file_path, abs_path, event.root, self.patterns, self.regexes
            )
        if decision == PASS:
            return None  # abstain → let other features / platform decide
        return Verdict(decision, _REASON[decision], self.name)
