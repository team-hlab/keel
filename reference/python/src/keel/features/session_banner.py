"""session-banner — SessionStart observer: announce active features + runtime status (to stderr)."""

import sys

from keel.features.base import Feature


class SessionBanner(Feature):
    name = "session-banner"

    def __init__(self, config=None):
        super().__init__(config)
        # injected by the CLI so the banner can list what's actually loaded
        self.active_features = self.config.get("_active", [])

    def stages(self):
        return {"SessionStart"}

    def evaluate(self, event):
        names = [n for n in self.active_features if n != self.name]
        line = "🛡  keel active — features: " + (", ".join(names) if names else "(none)")
        # stderr so we never corrupt a stdout JSON contract
        sys.stderr.write(line + "\n")
        return None
