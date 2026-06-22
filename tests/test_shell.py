#!/usr/bin/env python3
"""autopermit.shell pure unit tests (injected resolver, no FS)."""
import os
import unittest

import _bootstrap  # noqa: F401

from keel.features.autopermit.policy import write_allow_regexes  # noqa: E402
from keel.features.autopermit.shell import (  # noqa: E402
    decide_bash, has_expansion, redirect_targets, split_segments,
)

ROOT = "/repo"
PATS = [".env*", "*.key", "*.pem", "credentials*", "*secret*"]
RGX = write_allow_regexes()
WT = ROOT + "/worktrees/f"


def resolve(base, path):
    return os.path.normpath(os.path.join(base or ".", path))


def D(cmd, cwd=ROOT):
    return decide_bash(cmd, cwd, ROOT, PATS, RGX, resolve)


class TestSafeAllow(unittest.TestCase):
    def test_readonly(self):
        for c in ("ls -la", "cat f", "git status", "git -C x log", "pwd", "echo hi",
                  "grep -r foo .", "cat f | grep x | wc -l", "sed -n 1p f", "VAR=1 ls"):
            self.assertEqual(D(c), "allow", c)

    def test_quotes_protect_separators(self):
        self.assertEqual(D('echo "a; b && c"'), "allow")
        self.assertEqual(D("grep 'x && y' file"), "allow")


class TestDeny(unittest.TestCase):
    def test_catastrophic(self):
        for c in ("rm -rf /", "rm -rf ~", "rm -fr /*", "sudo rm -rf x",
                  "git push --force", "git push -f origin m", "git reset --hard",
                  "git clean -fd", "dd if=/dev/zero of=x", "mkfs.ext4 /dev/sda",
                  "gh pr merge 3", "gh issue close 4"):
            self.assertEqual(D(c), "deny", c)

    def test_deny_anywhere_in_chain(self):
        self.assertEqual(D("ls && rm -rf /"), "deny")
        self.assertEqual(D("true || rm -rf ~"), "deny")


class TestWorktreeAllow(unittest.TestCase):
    def test_writes(self):
        self.assertEqual(D("echo hi > worktrees/f/a"), "allow")
        self.assertEqual(D("ls | tee worktrees/f/log"), "allow")
        self.assertEqual(D("mkdir worktrees/f/sub"), "allow")
        self.assertEqual(D("cp a b", cwd=WT), "allow")

    def test_build_and_git(self):
        self.assertEqual(D("npm test", cwd=WT), "allow")
        self.assertEqual(D("git -C worktrees/f add -A"), "allow")
        self.assertEqual(D("(cd worktrees/f && npm test)"), "allow")
        self.assertEqual(D("cd worktrees/f && npm run build && echo ok > log"), "allow")


class TestProtectedDeny(unittest.TestCase):
    def test_in_project_writes(self):
        self.assertEqual(D("echo x > projects/foo/main/y"), "deny")
        self.assertEqual(D("mkdir projects/foo/main/sub"), "deny")
        self.assertEqual(D("echo x > CLAUDE.md"), "deny")


class TestSecretAsk(unittest.TestCase):
    def test_targets(self):
        self.assertEqual(D("echo x > .env"), "ask")
        self.assertEqual(D("echo x > worktrees/f/.env.local"), "ask")
        self.assertEqual(D("ls | tee server.key"), "ask")


class TestPass(unittest.TestCase):
    def test_uncertain(self):
        for c in ("weirdcmd --go", "npm test", "git -C projects/foo/main commit -m x",
                  "echo x > /tmp/out", "cp a /etc/x", "sed -i s/a/b/ f"):
            self.assertEqual(D(c), "pass", c)

    def test_expansion(self):
        for c in ("echo $HOME", "cat ${FILE}", "ls $(pwd)", "echo `date`"):
            self.assertEqual(D(c), "pass", c)

    def test_nested_subshell(self):
        self.assertEqual(D("(cd a && (cd b && ls))"), "pass")


class TestAggregation(unittest.TestCase):
    def test_precedence(self):
        self.assertEqual(D("ls && weirdcmd"), "pass")
        self.assertEqual(D("ls && echo x > .env"), "ask")
        self.assertEqual(D("weirdcmd && echo x > .env"), "ask")
        self.assertEqual(D("echo x > .env && rm -rf /"), "deny")
        self.assertEqual(D("npm test && echo ok > worktrees/f/l", cwd=WT), "allow")


class TestMalformed(unittest.TestCase):
    def test_edges(self):
        self.assertEqual(D(""), "pass")
        self.assertEqual(D("   "), "pass")
        self.assertEqual(D("# comment"), "pass")
        self.assertEqual(decide_bash(None, ROOT, ROOT, PATS, RGX, resolve), "pass")
        self.assertEqual(decide_bash(123, ROOT, ROOT, PATS, RGX, resolve), "pass")


class TestHelpers(unittest.TestCase):
    def test_redirect_targets(self):
        self.assertEqual(redirect_targets("echo x > a"), ["a"])
        self.assertEqual(redirect_targets("ls 2>&1 > b"), ["b"])
        self.assertEqual(redirect_targets("ls > /dev/null"), [])
        self.assertEqual(redirect_targets("ls | tee -a c"), ["c"])

    def test_split_segments(self):
        self.assertEqual(split_segments("a && b; c | d"), ["a", "b", "c", "d"])
        self.assertEqual(split_segments('echo "a && b"'), ['echo "a && b"'])

    def test_has_expansion(self):
        self.assertTrue(has_expansion("echo $X"))
        self.assertTrue(has_expansion("echo `x`"))
        self.assertFalse(has_expansion("echo plain"))
        self.assertFalse(has_expansion("grep '$X' f"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
