# Releasing keel

Releases are **automated on merge**. When a version-bumping change lands on
`develop`, CI builds the binaries, publishes a GitHub Release, and updates the
Homebrew tap. A merge with no version change is a no-op.

## Versioning

- **Single source of truth: `Cargo.toml` `version`.** The binary (`keel version`),
  the release workflow's gate, and the Homebrew formula all derive from it — they
  never disagree.
- **SemVer**: `patch` = bug/policy fixes, `minor` = new features/feature flags,
  `major` = breaking CLI/policy/config changes.
- **Bump it:** `scripts/bump.sh <x.y.z>` updates `Cargo.toml` + `Cargo.lock`. Then
  add a `CHANGELOG.md` entry. The version becomes the release tag `vX.Y.Z` on merge.

## Cut a release

1. Bump `version` in `Cargo.toml` (e.g. `0.1.0` → `0.1.1`) in your PR.
2. Merge the PR into `develop`.
3. [`release.yml`](../.github/workflows/release.yml) runs:
   - **gate** — if `vX.Y.Z` is already released, stop; otherwise continue.
   - **build** — macOS (arm64 + x86_64) and Linux (x86_64) binaries.
   - **release** — tag `vX.Y.Z` + GitHub Release with the tarballs.
   - **bump-tap** — render `Formula/keel.rb` and push it to `team-hlab/homebrew-keel`.

## One-time setup: `TAP_TOKEN`

The tap is a separate repo, so the workflow needs a cross-repo token to push the
formula (`GITHUB_TOKEN` can't write to another repo):

1. Create a fine-grained PAT with **Contents: write** on `team-hlab/homebrew-keel`.
2. `gh secret set TAP_TOKEN --repo team-hlab/keel --body <PAT>`

Until it's set, releases still build and publish — only the tap push is skipped.
You can then update the tap by hand:

```sh
python3 packaging/homebrew/render_formula.py <version>   # writes packaging/homebrew/keel.rb
# copy that into team-hlab/homebrew-keel as Formula/keel.rb and push
```

## Install (users)

```sh
brew tap team-hlab/keel
brew install keel
keel init
```
