"""OpenAI Codex adapter — based on developers.openai.com/codex/hooks (~May 2026).

Codex's PreToolUse/PermissionRequest hooks mirror Claude's shapes closely; this maps
to permissionDecision (pre) and decision.behavior (PermissionRequest). Verify against
the live docs for your Codex version before relying on it in production.
"""

import json

from keel.core.model import ALLOW, ASK, DENY, Event
from keel.core.runtime import find_root


def parse(raw, stage):
    ti = raw.get("tool_input") or {}
    return Event(
        stage=stage,
        tool=raw.get("tool_name"),
        tool_input=ti,
        cwd=raw.get("cwd"),
        root=find_root(raw.get("cwd")),
        raw=raw,
    )


def render(verdict, stage):
    d, reason = verdict.decision, verdict.reason
    if stage == "PermissionRequest":
        if d in (ALLOW, DENY):
            return json.dumps({"hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": d, "reason": reason}}})
        return json.dumps({})
    if d in (ALLOW, DENY, ASK):
        return json.dumps({"hookSpecificOutput": {
            "hookEventName": stage, "permissionDecision": d, "permissionDecisionReason": reason}})
    return json.dumps({})
