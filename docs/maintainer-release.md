# Maintainer release process

The `Release` GitHub Actions workflow is the only automation that creates and
publishes a v2link-client release. It is manually triggered, builds the exact
selected default-branch commit, and defaults to a non-publishing dry run.

## Prepare a release

1. Update `[project].version` in `pyproject.toml`.
2. Add the matching version section to `CHANGELOG.md`.
3. Create non-empty curated notes at `docs/releases/v<VERSION>.md`. The first
   heading must identify `v2link-client v<VERSION>`.
4. Commit, review, and merge the preparation changes into the repository's
   default branch.
5. Run the workflow with `dry_run` enabled.
6. Download and inspect the versioned workflow artifact. It contains the
   AppImage, Debian package, and `SHA256SUMS`.
7. Only after the dry run succeeds, run the workflow again with `dry_run`
   disabled and the exact confirmation `RELEASE`.
8. Confirm the GitHub Release and, when selected, the signed APT repository.

Do not create or push the release tag manually. The real workflow run creates
an annotated tag only after tests, builds, and final artifact verification pass.

## Run from the GitHub interface

Open:

```text
Actions
→ Release
→ Run workflow
→ Select the default branch
→ Enter the version without v
→ Choose stable or prerelease
→ Choose whether to publish APT
→ Start with dry_run enabled
```

Inputs:

- `version`: must exactly match `pyproject.toml`, without a `v` prefix.
- `release_channel`: `stable` or `prerelease`.
- `publish_apt`: publishes the verified `.deb` to the signed APT repository
  during a real run.
- `dry_run`: defaults to `true`; it never creates a tag, release, or APT update.
- `confirmation`: must be exactly `RELEASE` when `dry_run` is disabled.

The workflow rejects any run not selected from the default branch. Concurrency
protection permits only one release workflow at a time.

## Run with GitHub CLI

Determine the default branch:

```bash
gh repo view --json defaultBranchRef --jq .defaultBranchRef.name
```

Dry run, using the returned branch in place of `<DEFAULT_BRANCH>`:

```bash
gh workflow run release.yml \
  --ref <DEFAULT_BRANCH> \
  -f version=<VERSION> \
  -f release_channel=stable \
  -f publish_apt=true \
  -f dry_run=true
```

After that run succeeds and its artifacts have been inspected, start the real
release:

```bash
gh workflow run release.yml \
  --ref <DEFAULT_BRANCH> \
  -f version=<VERSION> \
  -f release_channel=stable \
  -f publish_apt=true \
  -f dry_run=false \
  -f confirmation=RELEASE
```

## Publication sequence and recovery

The workflow validates first, then tests, fetches checksum-pinned Xray-core,
builds both packages, verifies the extracted final artifacts, checks
`SHA256SUMS`, and uploads a versioned workflow artifact.

A real run then:

1. Creates the annotated tag if it is absent.
2. Creates or safely resumes a draft GitHub Release.
3. Uploads the exact verified, version-specific assets.
4. Optionally publishes the same verified `.deb` to the signed APT repository.
5. Publishes the draft only after the APT job succeeds or is intentionally
   skipped.

Build failures leave no tag or release. If a later stage fails, rerunning is
safe only when the existing tag points to the same commit and any release is
still a draft. A failed APT update leaves the GitHub Release as a draft.
Published releases and tags pointing to another commit are never replaced.

## Required repository configuration

Normal GitHub Release publication uses the built-in `GITHUB_TOKEN`. APT
publication requires these existing Actions secrets:

- `APT_GPG_PRIVATE_KEY`
- `APT_GPG_PASSPHRASE`

The workflow compares the imported private-key fingerprint with
`apt/public.key` and stops on a mismatch. Never print or copy secret values into
logs, issues, pull requests, or documentation.

For an additional approval gate, maintainers may add a protected GitHub
environment such as `release-production` and attach it to the publishing jobs.
Do this only after configuring its reviewers and testing that it does not block
the intended release recovery flow.
