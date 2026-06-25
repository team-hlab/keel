"""Claude Code adapter — fully verified against code.claude.com/docs (hooks & permissions)."""

import json

from keel.core.model import ALLOW, ASK, DENY, Event
from keel.core.runtime import find_root


def parse(raw, stage):
    return Event(
        stage=stage,
        tool=raw.get("tool_name"),
        tool_input=raw.get("tool_input") or {},
        cwd=raw.get("cwd"),
        root=find_root(raw.get("cwd")),
        raw=raw,
    )


def render(verdict, stage):
    d, reason = verdict.decision, verdict.reason

    if stage == "PermissionRequest":
        if d in (ALLOW, DENY):
            return json.dumps(
                {
                    "continue": True,
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": {"behavior": d, "reason": reason},
                    },
                }
            )
        return json.dumps({"continue": True})  # ask/pass → defer to the real prompt

    # PreToolUse-style stages carry allow/deny/ask
    if d in (ALLOW, DENY, ASK):
        return json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": stage,
                    "permissionDecision": d,
                    "permissionDecisionReason": reason,
                },
            }
        )
    return json.dumps({"continue": True})  # pass / observer stages
