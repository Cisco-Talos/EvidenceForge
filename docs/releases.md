# Product releases and installers

EvidenceForge and Studio share the version in `pyproject.toml`. The Release workflow delivers
the macOS Apple Silicon DMG and its SHA256 file automatically. Codex remains a separate install
for authoring. Current installers have no Developer ID signature or notarization; Intel macOS,
Linux and Windows installers are not enabled. See [Studio installation](studio.md#macos-installation).

## Prepare the source

Choose the next stable version using the SemVer rules in `AGENTS.md`. For previews, append a
numbered canonical suffix: `2.2.0a1`, `2.2.0b1`, or `2.2.0rc1`. Update `pyproject.toml` and
`src/evidenceforge/__init__.py`, run `uv sync`, and run
`uv run python scripts/sync_studio_version.py`. Commit all Python and derived Studio version
files together with a nonempty `## vVERSION (YYYY-MM-DD)` section in `CHANGELOG.md`. Each release
uses its checked-in changelog section as its release notes, plus macOS installation limitations.

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
2. Routine CI, 70% Linux routine coverage, native macOS Studio/state recovery, all four slow
   shards without coverage, and Python checkpoint portability on the release snapshot.
3. An Apple Silicon macOS build with locked Python/npm/Cargo dependencies, packaged CLI/resource
   verification, DMG integrity and checksum checks.
4. Downloading this run's installer artifacts, staging a draft release, uploading missing assets,
   downloading and verifying them against the build, then publishing.

Released filenames are `EvidenceForge-Studio-VERSION-aarch64.dmg` and the corresponding
`.dmg.sha256`. Developer test builds retain the `-test` suffix. The release build command is:

```sh
uv run python scripts/package_studio_macos.py --build-app --release
```

Building locally does not publish. Automatic builds retain the current unsigned/unnotarized
packaging policy. Signing/notarization and additional platform acceptance are separate work.

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

The build job uses a platform matrix. Future Linux/Windows support should add native build and
verification entries, versioned installer names and explicit required-asset validation. All enabled
platforms must succeed before the shared publication job exposes a release. Keep routine PR CI's
app ZIP artifacts separate from release installers.
