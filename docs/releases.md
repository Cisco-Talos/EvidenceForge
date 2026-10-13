# Product releases and installers

EvidenceForge and Studio share the version in `pyproject.toml`. The Release workflow delivers
the macOS Apple Silicon DMG and native Linux ARM64/x86_64 AppImages, each with a SHA256 file.
Codex remains a separate install for authoring. The macOS installer has no Developer ID signature
or notarization; Intel macOS and Windows installers are not enabled. For 2.2.0a2, the user accepted
recent testing on all systems and explicitly waived repeating interactive smoke tests on October 12.
Automated release and packaged-installer checks remain required. See the
[release worklog](worklog/2026-10-12-release-2.2.0a2.md).
See [Studio installation](studio.md#macos-installation).

## Prepare the source

Choose the next stable version using the SemVer rules in `AGENTS.md`. For previews, append a
numbered canonical suffix: `2.2.0a1`, `2.2.0b1`, or `2.2.0rc1`. Update `pyproject.toml` and
`src/evidenceforge/__init__.py`, run `uv sync`, and run
`uv run python scripts/sync_studio_version.py`. Commit all Python and derived Studio version
files together with a nonempty `## vVERSION (YYYY-MM-DD)` section in `CHANGELOG.md`. Each release
uses its checked-in changelog section as its release notes, plus platform installation limitations.

Keep the release snapshot clean and commit all required source changes before tagging. Run the
applicable local release and native acceptance checks. Pushing a release tag authorizes the
automatic GitHub publication; preparing files or pushing to `dev` alone does not publish.

## Alpha, beta and release candidates

After the version commit is on remote `dev`, create and push an annotated tag for that exact
commit. For example, when the committed product version is `2.2.0a1`:

```sh
git tag -a v2.2.0a1 <release-commit-sha> -m "EvidenceForge v2.2.0a1"
git push origin refs/tags/v2.2.0a1
```

The workflow must be present in the tagged snapshot. GitHub runs the tag-push workflow even
before it is merged into the default branch. The pipeline rejects lightweight tags, mismatched
tag/version identities, stable tags on this entry point, and commits not reachable from remote
`dev`. `main` remains unchanged. The release is marked prerelease and is not marked latest.

## Stable releases

On `dev`, remove the prerelease suffix when preparing the stable release, synchronize versions
and add its changelog entry. Open the release PR to `main`. The existing protected-branch checks
remain in place. After merge, the pipeline runs the release gates and installer build on that
exact commit, creates its annotated stable tag, and publishes the complete GitHub Release as
latest. Do not manually push a stable tag to initiate this path.

## What the pipeline requires

1. Version/metadata consistency, a matching changelog entry and valid source/tag provenance.
2. Routine CI, 70% Linux routine coverage, native macOS and both Linux architectures' Studio/state
   recovery, all four slow shards without coverage, and Python checkpoint portability.
3. Native macOS Apple Silicon and Ubuntu 24.04 ARM64/x86_64 builds with locked Python/npm/Cargo
   dependencies, isolated packaged CLI/resource and checkpoint-enabled generation verification,
   bundled GStreamer appsink/scanner checks for AppImages, DMG integrity and all checksums.
4. Downloading this run's installer artifacts, staging a draft release, uploading missing assets,
   downloading and verifying them against the build, then publishing.

The publisher requires all six assets: `EvidenceForge-Studio-VERSION-aarch64.dmg`,
`EvidenceForge-Studio-VERSION-aarch64.AppImage`, `EvidenceForge-Studio-VERSION-x86_64.AppImage`,
and each installer's adjacent `.sha256`. Developer test builds retain the `-test` suffix.
Installer environment setup, local macOS/Linux build and verification commands, and
build-only CI dispatch/download instructions are maintained in
[CONTRIBUTING.md](../CONTRIBUTING.md#development-setup).
Both native Linux architectures use Ubuntu 24.04/glibc 2.39; other distro acceptance remains
open. The 2.2.0a2 manual acceptance decision is recorded in the release worklog above.

Building locally or dispatching the read-only installer workflow does not publish. Preview
builds keep the `-test` suffix; `--release` removes it without publishing. The workflow uses
the same native builders and packaged verification for previews and releases. Signing,
notarization and additional platform acceptance remain separate release work.

## Failed runs and retries

Build or test failures prevent publication. Upload/publication failures can leave an annotated
stable tag and a draft containing some verified assets. Use **Re-run failed jobs** on the original
Actions run to reuse its installer artifacts (retained for 14 days). Do not move the tag.

The publisher resumes only drafts bound to the same commit and release channel. It reuses matching
assets and refuses differing bytes or incomplete/unexpected assets. Rebuilding all jobs may produce
different installer bytes; use the original verified artifacts to recover that draft. If those
artifacts have expired, recovery requires maintainer inspection rather than automatic replacement.
After successful publication, a rerun verifies the existing assets and leaves the release unchanged.
Historical releases without the pipeline's commit marker require maintainer inspection.

If a failure before asset upload requires a workflow correction, commit that correction on dev.
The manual recovery entry point uses the updated workflow while checking out the existing
annotated prerelease tag for every test, installer build and publication step:

```sh
gh workflow run release.yml --ref dev -f tag=v2.2.0a1
```

This repeats every release gate and retains the tag's original source commit. It does not move
the tag or merge main. Instrumented Linux release coverage has a 60-minute job budget; routine
Linux checks retain their 25-minute budget. Prefer the original run's failed-job retry when a
draft already contains assets, since rebuilding can change installer bytes.

The build job uses a platform matrix. Additional platform support should add native build and
verification entries, versioned installer names and explicit required-asset validation. All enabled
platforms must succeed before the shared publication job exposes a release. Keep routine PR CI's
app ZIP artifacts separate from release installers.
