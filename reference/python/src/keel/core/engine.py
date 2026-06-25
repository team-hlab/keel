"""The router: feed an Event to every subscribed feature, aggregate the verdicts."""

from keel.core.model import PASS, RANK, Verdict


def aggregate(verdicts):
    """Most-restrictive-wins: deny > ask > pass > allow. None → PASS."""
    chosen = None
    for v in verdicts:
        if v is None:
            continue
        if chosen is None or RANK[v.decision] > RANK[chosen.decision]:
            chosen = v
    return chosen or Verdict(PASS, "no feature opined")


def run(event, features):
    """Run every feature subscribed to event.stage; return the aggregated Verdict."""
    out = []
    for feature in features:
        if event.stage not in feature.stages():
            continue
        try:
            out.append(feature.evaluate(event))
        except Exception:
            # a misbehaving feature must never break the harness (fail-open per feature)
            continue
    return aggregate(out)
