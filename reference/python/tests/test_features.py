#!/usr/bin/env python3
"""Per-feature unit tests (autopermit, branch-guard, secret-scan, audit-log, session-banner)."""

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr

import _bootstrap  # noqa: F401

from keel.core.model import ALLOW, ASK, DENY, Event  # noqa: E402
from keel.features.audit_log import AuditLog  # noqa: E402
from keel.features.autopermit.feature import AutoPermit  # noqa: E402
from keel.features.branch_guard import BranchGuard, head_branch  # noqa: E402
from keel.features.secret_scan import SecretScan  # noqa: E402
from keel.features.session_banner import SessionBanner  # noqa: E402

ROOT = None


def setUpModule():
    global ROOT
    ROOT = os.path.realpath(tempfile.mkdtemp(prefix="keel-feat-"))
    for d in ("worktrees/f", "projects/foo/main", ".git"):
        os.makedirs(os.path.join(ROOT, d), exist_ok=True)
    with open(os.path.join(ROOT, ".git", "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")


def tearDownModule():
    shutil.rmtree(ROOT, ignore_errors=True)


def ev(tool, stage="PreToolUse", **ti):
    return Event(stage=stage, tool=tool, tool_input=ti, cwd=ROOT, root=ROOT)


class TestAutoPermit(unittest.TestCase):
    f = AutoPermit({})

    def test_file_verdicts(self):
        self.assertEqual(self.f.evaluate(ev("Read", file_path="a.md")).decision, ALLOW)
        self.assertEqual(self.f.evaluate(ev("Read", file_path="x/.env")).decision, ASK)
        self.assertEqual(self.f.evaluate(ev("Write", file_path="projects/foo/main/A")).decision, DENY)
        self.assertEqual(self.f.evaluate(ev("Write", file_path="worktrees/f/a")).decision, ALLOW)

    def test_bash_verdicts(self):
        self.assertEqual(self.f.evaluate(ev("Bash", command="rm -rf /")).decision, DENY)
        self.assertEqual(self.f.evaluate(ev("Bash", command="ls -la")).decision, ALLOW)

    def test_abstains_on_pass(self):
        self.assertIsNone(self.f.evaluate(ev("Write", file_path="/var/tmp/x")))
        self.assertIsNone(self.f.evaluate(ev("Bash", command="weirdcmd")))


class TestBranchGuard(unittest.TestCase):
    f = BranchGuard({})

    def test_head_branch(self):
        self.assertEqual(head_branch(ROOT), "main")

    def test_deny_on_protected(self):
        self.assertEqual(self.f.evaluate(ev("Bash", command="git commit -m x")).decision, DENY)
        self.assertEqual(self.f.evaluate(ev("Bash", command="git push")).decision, DENY)

    def test_ignores_non_git_and_reads(self):
        self.assertIsNone(self.f.evaluate(ev("Bash", command="git status")))
        self.assertIsNone(self.f.evaluate(ev("Bash", command="ls")))
        self.assertIsNone(self.f.evaluate(ev("Read", file_path="a")))

    def test_config_protected(self):
        g = BranchGuard({"protected": ["release"]})
        self.assertIsNone(g.evaluate(ev("Bash", command="git commit -m x")))  # main not protected here


class TestSecretScan(unittest.TestCase):
    f = SecretScan({})

    def test_flags_credential_content(self):
        self.assertEqual(self.f.evaluate(ev("Write", content="AKIAABCDEFGHIJKLMNOP")).decision, ASK)
        self.assertEqual(
            self.f.evaluate(ev("Edit", new_string="api_key = 'abcdef123456ghijkl'")).decision, ASK
        )
        pem = "-----BEGIN RSA PRIVATE KEY-----"
        self.assertEqual(self.f.evaluate(ev("Write", content=pem)).decision, ASK)

    def test_clean_content_abstains(self):
        self.assertIsNone(self.f.evaluate(ev("Write", content="hello world")))
        self.assertIsNone(self.f.evaluate(ev("Read", file_path="a")))


class TestAuditLog(unittest.TestCase):
    def test_appends_jsonl(self):
        log = os.path.join(ROOT, "audit-test.log")
        f = AuditLog({"path": log})
        self.assertIsNone(f.evaluate(ev("Bash", command="ls -la")))
        f.evaluate(ev("Write", stage="PostToolUse", file_path="a.md"))
        lines = open(log).read().strip().splitlines()
        self.assertEqual(len(lines), 2)
        rec = json.loads(lines[0])
        self.assertEqual(rec["tool"], "Bash")
        self.assertEqual(rec["command"], "ls -la")


class TestSessionBanner(unittest.TestCase):
    def test_writes_to_stderr(self):
        f = SessionBanner({"_active": ["autopermit", "session-banner"]})
        buf = io.StringIO()
        with redirect_stderr(buf):
            self.assertIsNone(f.evaluate(ev(None, stage="SessionStart")))
        self.assertIn("autopermit", buf.getvalue())
        self.assertIn("keel", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
