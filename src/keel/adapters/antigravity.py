"""Google Antigravity adapter — based on secondary sources for Antigravity 2.0 (~May 2026).

⚠ The official Antigravity docs render client-side and could not be machine-verified.
Field names (toolCall.args, workspacePaths) and the {decision: allow|deny|ask} output
are best-effort — confirm in a live Antigravity session before depending on this.
"""

import json

from keel.core.model import ALLOW, ASK, DENY, Event
from keel.core.runtime import find_root


def parse(raw, stage):
    tool_call = raw.get("toolCall") or {}
    tool = raw.get("tool_name") or tool_call.get("name")
    tool_input = raw.get("tool_input") or tool_call.get("args") or {}
    cwd = raw.get("cwd")
    if not cwd:
        paths = raw.get("workspacePaths") or []
        cwd = paths[0] if paths else None
    return Event(stage=stage, tool=tool, tool_input=tool_input, cwd=cwd,
                 root=find_root(cwd), raw=raw)


def render(verdict, stage):
    d, reason = verdict.decision, verdict.reason
    if d in (ALLOW, DENY, ASK):
        return json.dumps({"decision": d, "reason": reason})
    return json.dumps({})                            # pass → no decision
