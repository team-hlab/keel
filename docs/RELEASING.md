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

> **Caution:** a version bump publishes **whatever is currently on `develop`** — there is
> no separate stabilization branch. Only bump the version when `develop` is release-ready
> (ideally in a dedicated release PR).

## Cut a release

1. Bump `version` in `Cargo.toml` (e.g. `0.1.0` → `0.1.1`) in your PR.
2. Merge the PR into `develop`.
3. [`release.yml`](../.github/workflows/release.yml) runs:
   - **gate** — if `vX.Y.Z` is already released, stop; otherwise continue.
   - **build** — macOS (arm64 + x86_64) and Linux (x86_64) binaries.
   - **release** — tag `vX.Y.Z` + GitHub Release with the tarballs.
   - **bump-tap** — render `Formula/keel.rb` and push it to `team-hlab/homebrew-keel`.

## One-time setup: tap GitHub App

The tap is a separate repo, so the release needs cross-repo write (`GITHUB_TOKEN` can't
write to another repo). Rather than a long-lived PAT, `bump-tap` mints a **short-lived
token from a GitHub App** scoped to only `team-hlab/homebrew-keel` and auto-revoked when
the job ends — no standing credential.

1. Create a **GitHub App** (owner `team-hlab`) with **Repository permissions → Contents:
   Read and write**. Generate and download a **private key** (`.pem`).
2. **Install** the App on `team-hlab/homebrew-keel` only.
3. In `team-hlab/keel` → Settings → Environments → **`release`**, add:
   - **Variable** `TAP_APP_ID` = the App's numeric ID (not secret).
   - **Secret** `TAP_APP_PRIVATE_KEY` = the `.pem` contents.
   - (Recommended) a deployment protection rule limiting it to the `develop` branch.

Until the App is configured, releases still build and publish — only the tap push is
skipped (a `::warning::` is logged). You can update the tap by hand meanwhile:

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
