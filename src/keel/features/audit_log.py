"""audit-log — observer that appends every tool call (and its stage) to a JSONL log."""

import json
import os
import time

from keel.features.base import Feature


class AuditLog(Feature):
    name = "audit-log"

    def stages(self):
        return {"PreToolUse", "PostToolUse"}

    def _path(self, event):
        p = self.config.get("path")
        if p:
            return p
        return os.path.join(event.root or ".", ".keel", "audit.log")

    def evaluate(self, event):
        rec = {
            "ts": time.time(),
            "stage": event.stage,
            "tool": event.tool,
            "cwd": event.cwd,
        }
        if event.file_path:
            rec["file_path"] = event.file_path
        if isinstance(event.command, str):
            rec["command"] = event.command[:500]
        try:
            path = self._path(event)
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            pass  # logging must never block a tool call
        return None  # observer: no verdict
