#!/usr/bin/env python3
"""autopermit.policy pure unit tests."""

import os
import unittest

import _bootstrap  # noqa: F401

from keel.features.autopermit.policy import (  # noqa: E402
    decide,
    is_sensitive,
    is_write_allowed,
    write_allow_regexes,
)

ROOT = "/repo"
PATTERNS = [".env*", "*.key", "*.pem", "credentials*", "*secret*"]
REGEXES = write_allow_regexes()


def d(tool, rel_or_abs):
    if rel_or_abs is None:
        abs_path, file_path = None, None
    elif rel_or_abs.startswith("/"):
        abs_path = file_path = rel_or_abs
    else:
        file_path = rel_or_abs
        abs_path = os.path.join(ROOT, rel_or_abs)
    return decide(tool, file_path, abs_path, ROOT, PATTERNS, REGEXES)


class TestSensitive(unittest.TestCase):
    def test_matches(self):
        for p in (
            ".env",
            ".env.local",
            "id.key",
            "server.pem",
            "credentials.json",
            "app-secrets.yaml",
            "MY_SECRET.txt",
        ):
            self.assertTrue(is_sensitive(p, PATTERNS), p)

    def test_non_matches(self):
        for p in ("README.md", "App.kt", "config.json", "env.example.md"):
            self.assertFalse(is_sensitive(p, PATTERNS), p)

    def test_basename_only(self):
        self.assertFalse(is_sensitive("secret-stuff/notes.md", PATTERNS))
        self.assertTrue(is_sensitive("any/dir/.env", PATTERNS))


class TestWriteAllowed(unittest.TestCase):
    def test_allowed(self):
        for p in (
            "worktrees/x/a.md",
            "projects/foo/worktrees/f/A.kt",
            "projects/g/foo/worktrees/f/A.kt",
            ".lens/s.md",
        ):
            self.assertTrue(is_write_allowed(f"{ROOT}/{p}", ROOT, REGEXES), p)

    def test_not_allowed(self):
        for p in ("projects/foo/main/A.kt", "CLAUDE.md"):
            self.assertFalse(is_write_allowed(f"{ROOT}/{p}", ROOT, REGEXES), p)
        self.assertFalse(is_write_allowed("/tmp/x.txt", ROOT, REGEXES))


class TestDecide(unittest.TestCase):
    def test_reads(self):
        self.assertEqual(d("Read", "wiki/README.md"), "allow")
        self.assertEqual(d("Read", "projects/foo/main/.env"), "ask")
        self.assertEqual(d("Glob", None), "allow")

    def test_writes(self):
        self.assertEqual(d("Write", "worktrees/x/a.md"), "allow")
        self.assertEqual(d("Edit", "projects/foo/main/A.kt"), "deny")
        self.assertEqual(d("Write", "/tmp/out.txt"), "pass")
        self.assertEqual(d("Write", "worktrees/x/.env.local"), "ask")
        self.assertEqual(d("Write", None), "deny")

    def test_other(self):
        self.assertEqual(d("Bash", "anything.sh"), "pass")
        self.assertEqual(d("WebFetch", None), "pass")


if __name__ == "__main__":
    unittest.main(verbosity=2)
