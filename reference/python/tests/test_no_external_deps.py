#!/usr/bin/env python3
"""Guard: keel must import ONLY the Python standard library (+ itself)."""

import ast
import os
import sys
import unittest

import _bootstrap  # noqa: F401

PKG = os.path.join(_bootstrap.SRC, "keel")

# stdlib modules keel uses (explicit allowlist → works on every Python version)
STDLIB_OK = {
    "ast",
    "dataclasses",
    "enum",
    "fnmatch",
    "importlib",
    "io",
    "json",
    "os",
    "re",
    "shutil",
    "subprocess",
    "sys",
    "tempfile",
    "time",
    "typing",
    "contextlib",
}


def _top_level_imports(path):
    tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                mods.add(n.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:  # absolute import
                mods.add(node.module.split(".")[0])
    return mods


class TestNoExternalDeps(unittest.TestCase):
    def test_only_stdlib_and_self(self):
        # prefer the interpreter's own list when available (3.10+)
        stdlib = set(getattr(sys, "stdlib_module_names", set())) | STDLIB_OK
        offenders = {}
        for root, _, files in os.walk(PKG):
            for fn in files:
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(root, fn)
                for mod in _top_level_imports(path):
                    if mod == "keel" or mod in stdlib:
                        continue
                    offenders.setdefault(os.path.relpath(path, PKG), set()).add(mod)
        self.assertEqual(offenders, {}, f"non-stdlib imports found: {offenders}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
