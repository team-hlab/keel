#!/usr/bin/env python3
"""End-to-end: drive `python -m keel run ...` as a subprocess, asserting platform output."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import _bootstrap  # noqa: F401

SRC = _bootstrap.SRC
TROOT = None
ENV = None


def setUpModule():
    global TROOT, ENV
    TROOT = os.path.realpath(tempfile.mkdtemp(prefix="keel-e2e-"))
    for d in ("worktrees/f", "projects/foo/main", ".git"):
        os.makedirs(os.path.join(TROOT, d), exist_ok=True)
    with open(os.path.join(TROOT, ".git", "HEAD"), "w") as f:
        f.write("ref: refs/heads/feature-x\n")        # non-protected → branch-guard stays quiet
    ENV = dict(os.environ, PYTHONPATH=SRC, KEEL_ROOT=TROOT)


def tearDownModule():
    shutil.rmtree(TROOT, ignore_errors=True)


def keel(args, payload=None, raw=None, env=None):
    data = raw if raw is not None else (json.dumps(payload) if payload is not None else "")
    return subprocess.run([sys.executable, "-m", "keel", *args], input=data,
                          capture_output=True, text=True, env=env or ENV)


def pre(tool=None, command=None, file_path=None, content=None):
    ti = {}
    if command is not None:
        ti["command"] = command
    if file_path is not None:
        ti["file_path"] = file_path
    if content is not None:
        ti["content"] = content
    out = keel(["run", "claude", "PreToolUse"], {"tool_name": tool, "cwd": TROOT, "tool_input": ti}).stdout
    o = json.loads(out)
    hso = o.get("hookSpecificOutput")
    return hso["permissionDecision"] if hso and "permissionDecision" in hso else "pass"


class TestClaudePreToolUse(unittest.TestCase):
    def test_file_paths(self):
        self.assertEqual(pre("Read", file_path="a.md"), "allow")
        self.assertEqual(pre("Read", file_path="x/.env"), "ask")
        self.assertEqual(pre("Write", file_path="worktrees/f/a"), "allow")
        self.assertEqual(pre("Write", file_path="projects/foo/main/A.kt"), "deny")
        self.assertEqual(pre("Write", file_path="/var/tmp/x"), "pass")

    def test_bash(self):
        self.assertEqual(pre("Bash", command="ls -la | grep x"), "allow")
        self.assertEqual(pre("Bash", command="rm -rf /"), "deny")
        self.assertEqual(pre("Bash", command="echo x > worktrees/f/log"), "allow")
        self.assertEqual(pre("Bash", command="weirdcmd"), "pass")

    def test_secret_scan_content(self):
        self.assertEqual(pre("Write", file_path="worktrees/f/c.py", content="AKIAABCDEFGHIJKLMNOP"), "ask")


class TestClaudePermissionRequest(unittest.TestCase):
    def _perm(self, tool, **ti):
        out = keel(["run", "claude", "PermissionRequest"],
                   {"tool_name": tool, "cwd": TROOT, "tool_input": ti}).stdout
        o = json.loads(out)
        hso = o.get("hookSpecificOutput")
        return hso["decision"]["behavior"] if hso and "decision" in hso else "pass"

    def test_allow_and_deny_render(self):
        self.assertEqual(self._perm("Read", file_path="a.md"), "allow")
        self.assertEqual(self._perm("Write", file_path="projects/foo/main/A"), "deny")

    def test_ask_defers_to_prompt(self):
        self.assertEqual(self._perm("Read", file_path="x/.env"), "pass")  # ask → continue-only


class TestBranchGuardE2E(unittest.TestCase):
    def test_protected_branch_denies(self):
        env = dict(ENV)
        # point HEAD at a protected branch via a second root
        root2 = os.path.realpath(tempfile.mkdtemp(prefix="keel-bg-"))
        os.makedirs(os.path.join(root2, ".git"))
        with open(os.path.join(root2, ".git", "HEAD"), "w") as f:
            f.write("ref: refs/heads/main\n")
        env["KEEL_ROOT"] = root2
        try:
            out = keel(["run", "claude", "PreToolUse"],
                       {"tool_name": "Bash", "cwd": root2, "tool_input": {"command": "git commit -m x"}},
                       env=env).stdout
            self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")
        finally:
            shutil.rmtree(root2, ignore_errors=True)


class TestCliMisc(unittest.TestCase):
    def test_features_lists_all(self):
        out = keel(["features"]).stdout
        for name in ("autopermit", "branch-guard", "secret-scan", "audit-log", "session-banner"):
            self.assertIn(name, out)

    def test_doctor(self):
        r = keel(["doctor"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("ok", r.stdout)

    def test_malformed_payload_fails_open(self):
        r = keel(["run", "claude", "PreToolUse"], raw="}{garbage")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout), {"continue": True})

    def test_unknown_command(self):
        self.assertEqual(keel(["frobnicate"]).returncode, 2)

    def test_session_start_banner_stderr(self):
        r = keel(["run", "claude", "SessionStart"], {"cwd": TROOT})
        self.assertIn("keel", r.stderr)
        self.assertEqual(json.loads(r.stdout), {"continue": True})


if __name__ == "__main__":
    unittest.main(verbosity=2)
