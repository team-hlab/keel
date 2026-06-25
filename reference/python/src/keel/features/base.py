"""The Feature contract. A feature is a self-contained policy or observer plugin."""


class Feature:
    name = "base"

    def __init__(self, config=None):
        self.config = config or {}

    def stages(self):
        """Set of hook stages this feature subscribes to (e.g. {'PreToolUse'})."""
        return set()

    def evaluate(self, event):
        """Return a Verdict, or None to abstain. Observer features act and return None."""
        return None
