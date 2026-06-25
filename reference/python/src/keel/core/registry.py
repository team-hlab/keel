"""Feature registry: instantiate enabled features from config."""

from keel.features.audit_log import AuditLog
from keel.features.autopermit.feature import AutoPermit
from keel.features.branch_guard import BranchGuard
from keel.features.secret_scan import SecretScan
from keel.features.session_banner import SessionBanner

# order is irrelevant — the engine aggregates most-restrictive-wins
ALL = [AutoPermit, BranchGuard, SecretScan, AuditLog, SessionBanner]


def load(config):
    """Build the enabled feature instances. Each is on by default; disable via config."""
    feats_cfg = (config or {}).get("features") or {}

    def enabled(cls):
        return (feats_cfg.get(cls.name) or {}).get("enabled", True)

    chosen = [c for c in ALL if enabled(c)]
    active_names = [c.name for c in chosen]

    instances = []
    for cls in chosen:
        spec = dict(feats_cfg.get(cls.name) or {})
        if cls is SessionBanner:
            spec["_active"] = active_names
        instances.append(cls(spec))
    return instances
