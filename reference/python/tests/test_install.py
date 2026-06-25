#!/usr/bin/env python3
"""Tests for `keel install` — idempotent hook registration per platform."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import _bootstrap  # noqa: F401

from keel import install  # noqa: E402

ROOT = None


def setUpModule():
    global ROOT
    ROOT = tempfile.mkdtemp(prefix="keel-install-")


def tearDownModule():
    shutil.rmtree(ROOT, ignore_errors=True)


class TestPlan(unittest.TestCase):
    def test_claude_shape(self):
        _, cfg = install.plan("claude", ROOT)
        hooks = cfg["hooks"]
        self.assertEqual(hooks["PreToolUse"][0]["hooks"][0]["command"], "keel run claude PreToolUse")
        self.assertIn("matcher", hooks["PreToolUse"][0])  # tool stages carry a matcher
        self.assertNotIn("matcher", hooks["SessionStart"][0])  # SessionStart does not
        self.assertEqual(
            hooks["PermissionRequest"][0]["hooks"][0]["command"], "keel run claude PermissionRequest"
        )

    def test_codex_shape(self):
        _, cfg = install.plan("codex", ROOT)
        self.assertEqual(cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "keel run codex PreToolUse")

    def test_antigravity_shape(self):
        _, cfg = install.plan("antigravity", ROOT)
        self.assertEqual(cfg["PreToolUse"][0]["command"], "keel run antigravity PreToolUse")

    def test_command_prefix_override(self):
        _, cfg = install.plan("claude", ROOT, prefix="sh /x/keel.sh")
        self.assertEqual(
            cfg["hooks"]["SessionStart"][0]["hooks"][0]["command"], "sh /x/keel.sh run claude SessionStart"
        )


class TestApplyIdempotent(unittest.TestCase):
    def test_writes_and_does_not_duplicate(self):
        root = tempfile.mkdtemp(prefix="keel-apply-")
        try:
            path = install.apply("claude", root)
            self.assertTrue(os.path.exists(path))
            install.apply("claude", root)  # second run must not duplicate
            cfg = json.load(open(path))
            for stage in ("PreToolUse", "PermissionRequest", "SessionStart"):
                self.assertEqual(len(cfg["hooks"][stage]), 1, stage)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_merges_into_existing_config(self):
        root = tempfile.mkdtemp(prefix="keel-merge-")
        try:
            os.makedirs(os.path.join(root, ".claude"))
            pre = {
                "permissions": {"allow": ["Bash(ls)"]},
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-tool"}]}
                    ]
                },
            }
            with open(os.path.join(root, ".claude", "settings.json"), "w") as f:
                json.dump(pre, f)
            install.apply("claude", root)
            cfg = json.load(open(os.path.join(root, ".claude", "settings.json")))
            self.assertEqual(cfg["permissions"]["allow"], ["Bash(ls)"])  # preserved
            cmds = [h["command"] for e in cfg["hooks"]["PreToolUse"] for h in e["hooks"]]
            self.assertIn("other-tool", cmds)  # preserved
            self.assertIn("keel run claude PreToolUse", cmds)  # added
        finally:
            shutil.rmtree(root, ignore_errors=True)


class TestCli(unittest.TestCase):
    def test_install_print_does_not_write(self):
        root = tempfile.mkdtemp(prefix="keel-cli-")
        try:
            env = dict(os.environ, PYTHONPATH=_bootstrap.SRC)
            r = subprocess.run(
                [sys.executable, "-m", "keel", "install", "claude", "--print", "--dir", root],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(r.returncode, 0)
            self.assertIn("keel run claude PreToolUse", r.stdout)
            self.assertFalse(os.path.exists(os.path.join(root, ".claude", "settings.json")))
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
