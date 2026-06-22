"""Core data model: Event (normalized hook input) and Verdict (normalized output)."""

from dataclasses import dataclass, field

# decision vocabulary, most-restrictive last
ALLOW, DENY, ASK, PASS = "allow", "deny", "ask", "pass"
RANK = {ALLOW: 0, PASS: 1, ASK: 2, DENY: 3}


@dataclass
class Verdict:
    decision: str            # one of ALLOW / DENY / ASK / PASS
    reason: str = ""
    source: str = ""         # feature name that produced it


@dataclass
class Event:
    """A platform-neutral hook event. Adapters build this; features read it."""
    stage: str               # "PreToolUse" | "PermissionRequest" | "PostToolUse" | "SessionStart" | ...
    tool: str = None
    tool_input: dict = field(default_factory=dict)
    cwd: str = None
    root: str = ""           # resolved project root
    config: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    @property
    def file_path(self):
        return self.tool_input.get("file_path")

    @property
    def command(self):
        return self.tool_input.get("command")
