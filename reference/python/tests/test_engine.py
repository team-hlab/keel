#!/usr/bin/env python3
"""Engine: aggregation + routing + per-feature fail-open."""

import unittest

import _bootstrap  # noqa: F401

from keel.core.engine import aggregate, run  # noqa: E402
from keel.core.model import ALLOW, ASK, DENY, PASS, Event, Verdict  # noqa: E402
from keel.features.base import Feature  # noqa: E402


class _Fixed(Feature):
    def __init__(self, name, stage, verdict):
        super().__init__()
        self.name = name
        self._stage = stage
        self._verdict = verdict

    def stages(self):
        return {self._stage}

    def evaluate(self, event):
        return self._verdict


class _Boom(Feature):
    name = "boom"

    def stages(self):
        return {"PreToolUse"}

    def evaluate(self, event):
        raise RuntimeError("feature blew up")


class TestAggregate(unittest.TestCase):
    def test_most_restrictive_wins(self):
        v = aggregate([Verdict(ALLOW), Verdict(DENY), Verdict(ASK)])
        self.assertEqual(v.decision, DENY)
        self.assertEqual(aggregate([Verdict(ALLOW), Verdict(ASK)]).decision, ASK)
        self.assertEqual(aggregate([Verdict(ALLOW), Verdict(PASS)]).decision, PASS)

    def test_ignores_none_and_defaults_pass(self):
        self.assertEqual(aggregate([None, None]).decision, PASS)
        self.assertEqual(aggregate([]).decision, PASS)
        self.assertEqual(aggregate([None, Verdict(ALLOW)]).decision, ALLOW)


class TestRun(unittest.TestCase):
    def _ev(self, stage="PreToolUse"):
        return Event(stage=stage)

    def test_only_subscribed_features_run(self):
        feats = [_Fixed("a", "PreToolUse", Verdict(ALLOW)), _Fixed("b", "SessionStart", Verdict(DENY))]
        self.assertEqual(run(self._ev("PreToolUse"), feats).decision, ALLOW)

    def test_aggregates_across_features(self):
        feats = [_Fixed("a", "PreToolUse", Verdict(ALLOW)), _Fixed("b", "PreToolUse", Verdict(DENY))]
        self.assertEqual(run(self._ev(), feats).decision, DENY)

    def test_misbehaving_feature_is_swallowed(self):
        feats = [_Boom(), _Fixed("a", "PreToolUse", Verdict(ALLOW))]
        self.assertEqual(run(self._ev(), feats).decision, ALLOW)

    def test_abstaining_feature(self):
        feats = [_Fixed("a", "PreToolUse", None)]
        self.assertEqual(run(self._ev(), feats).decision, PASS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
