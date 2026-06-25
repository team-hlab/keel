# Homebrew binary formula for keel (tap: team-hlab/homebrew-keel → Formula/keel.rb).
# This committed copy is a placeholder; render_formula.py fills version + sha256 per release.
#
#   brew tap team-hlab/keel && brew install keel   # then: keel init
class Keel < Formula
  desc "Lean hook harness for AI coding agents (permit/deny/ask)"
  homepage "https://github.com/team-hlab/keel"
  version "0.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/team-hlab/keel/releases/download/v0.0.0/keel-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/team-hlab/keel/releases/download/v0.0.0/keel-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/team-hlab/keel/releases/download/v0.0.0/keel-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
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
    assert_match "ok", shell_output("#{bin}/keel doctor")
  end
end
