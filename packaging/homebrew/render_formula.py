#!/usr/bin/env python3
"""Render the Homebrew binary formula for a released version.

Usage: render_formula.py <version e.g. 0.1.0>

Downloads the release tarballs, computes their sha256, and writes keel.rb.
Run by the release workflow after the GitHub Release exists; the rendered
keel.rb is then pushed to the tap (team-hlab/homebrew-keel → Formula/keel.rb).
"""

import hashlib
import os
import sys
import urllib.request

REPO = "team-hlab/keel"
TARGETS = {
    "arm_macos": "aarch64-apple-darwin",
    "intel_macos": "x86_64-apple-darwin",
    "intel_linux": "x86_64-unknown-linux-gnu",
}


def sha256_of(url: str) -> str:
    with urllib.request.urlopen(url) as r:  # noqa: S310 (trusted github release url)
        h = hashlib.sha256()
        for chunk in iter(lambda: r.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("usage: render_formula.py <version>")
    v = sys.argv[1].lstrip("v")
    base = f"https://github.com/{REPO}/releases/download/v{v}"
    urls = {k: f"{base}/keel-{t}.tar.gz" for k, t in TARGETS.items()}
    sha = {k: sha256_of(u) for k, u in urls.items()}

    formula = f"""class Keel < Formula
  desc "Lean hook harness for AI coding agents (permit/deny/ask)"
  homepage "https://github.com/{REPO}"
  version "{v}"
  license "MIT"

  on_macos do
    on_arm do
      url "{urls["arm_macos"]}"
      sha256 "{sha["arm_macos"]}"
    end
    on_intel do
      url "{urls["intel_macos"]}"
      sha256 "{sha["intel_macos"]}"
    end
  end

  on_linux do
    on_intel do
      url "{urls["intel_linux"]}"
      sha256 "{sha["intel_linux"]}"
    end
  end

  def install
    bin.install "keel"
  end

  def caveats
    <<~EOS
      Run `keel init` to attach keel to your installed agents
      (Claude Code, Codex, Antigravity).
    EOS
  end

  test do
    assert_match "ok", shell_output("#{{bin}}/keel doctor")
  end
end
"""
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keel.rb")
    with open(out, "w", encoding="utf-8") as f:
        f.write(formula)
    print(f"wrote {out} for v{v}")


if __name__ == "__main__":
    main()
