"""secret-scan — confirm writes whose *content* looks like a secret (not just the filename)."""

import re

from keel.core.model import ASK, Verdict
from keel.features.base import Feature

_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                                  # AWS access key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),                # PEM private key
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),                        # GitHub token
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),                      # Slack token
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{12,}"),
]


def _content(tool_input):
    parts = []
    for key in ("content", "new_string", "new_str"):
        v = tool_input.get(key)
        if isinstance(v, str):
            parts.append(v)
    for edit in tool_input.get("edits", []) or []:
        if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
            parts.append(edit["new_string"])
    return "\n".join(parts)


class SecretScan(Feature):
    name = "secret-scan"

    def stages(self):
        return {"PreToolUse"}

    def evaluate(self, event):
        if event.tool not in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            return None
        text = _content(event.tool_input)
        if text and any(p.search(text) for p in _PATTERNS):
            return Verdict(ASK, "secret-scan: content looks like a credential — confirm.", self.name)
        return None
