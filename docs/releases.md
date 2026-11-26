# Product releases and installers

EvidenceForge and Studio share the version in `pyproject.toml`. The Release workflow delivers
the macOS Apple Silicon DMG, native Linux ARM64/x86_64 AppImages and the Windows 11 x86_64 NSIS
setup, each with a SHA256 file. Codex remains a separate install for authoring. The macOS
installer has no Developer ID signature or notarization, and the Windows installer is not
code-signed; Intel macOS and Windows ARM installers are not enabled. For 2.2.0a2, the user accepted
recent testing on all systems and explicitly waived repeating interactive smoke tests on October 12.
Automated release and packaged-installer checks remain required. See the
[release worklog](worklog/2026-10-12-release-2.2.0a2.md).
See [Studio installation](studio.md#macos-installation).

**3.0.0rc3** adds simulated macOS workstations and introduces EvidenceForge Studio.
The 2.2 alpha series led to this milestone. `3.0.0rc1` and `3.0.0rc2` were internal
release candidates. Traditional CLI and legacy-scenario workflows remain supported.

## Source capabilities and release scope

Installer host support is separate from simulated OS/log-source support. Releases since
2.2.0a6 include macOS 27 workstation process/helper and bounded filesystem evidence;
older installers do not gain capabilities added after their release. Release notes must state the
snapshot's admitted source profile and limits. Use the [platform/log matrix](../README.md#supported-log-formats)
and [Mac guide](macos.md) when preparing those notes.

Source-launched Mac/Studio acceptance was completed on November 9 for alpha 5.
The a5 tag was prepared but publication failed its slow determinism checks.
[A6 was published on November 10](https://github.com/Cisco-Talos/EvidenceForge/releases/tag/v2.2.0a6)
with the corrections and CI improvements; preserve the immutable a5 tag. See the
[a6 release handoff](worklog/2026-11-09-release-2.2.0a6.md).
Retain the final-snapshot automated release and packaged-installer checks. Launchd ULF,
Docker Desktop's complete helper graph, broader native filesystem behavior and external
Mac SIEM normalization remain explicit limits, rather than implied release capabilities.

## Prepare the source

Choose the next stable version using the SemVer rules in `AGENTS.md`. For previews, append a
numbered canonical suffix: `2.2.0a1`, `2.2.0b1`, or `2.2.0rc1`. Update `pyproject.toml` and
`src/evidenceforge/__init__.py`, run `uv sync`, and run
`uv run python scripts/sync_studio_version.py`. Commit all Python and derived Studio version
files together with a nonempty `## vVERSION (YYYY-MM-DD)` section in `CHANGELOG.md`. Each release
uses its checked-in changelog section as its release notes, plus platform installation limitations.

Keep the release snapshot clean and commit all required source changes. Run the applicable local
release and native acceptance checks. A new prerelease starts with an explicit Release dispatch.

## Alpha, beta and release candidates

After the version commit is on remote `dev` and publication is authorized, dispatch the
**Release** workflow from `dev` with the candidate's full commit SHA in `source-sha`:

```sh
candidate_sha=$(git rev-parse HEAD)
gh workflow run release.yml --ref dev -f source-sha="$candidate_sha"
```

The workflow validates that the SHA is reachable from `origin/dev` and has a synchronized,
unused prerelease version. It runs fresh release CI and extended tests, builds and verifies all
four installers for that SHA, and verifies the downloaded artifacts before creating the
annotated tag. It publishes those installers and their checksums from the same run with
**Pre-release** enabled and **Latest** disabled. After a source fix, dispatch the new commit SHA.

For installer review before publication approval, run the same workflow with `qualify-only=true`.
It runs fresh release CI and extended tests before building all four installers. The run uploads
the installers and checksums as Actions artifacts and skips tagging and release publication.

```sh
candidate_sha=$(git rev-parse HEAD)
gh workflow run release.yml --ref dev -f source-sha="$candidate_sha" -f qualify-only=true
gh run download RUN_ID --name release-installer-macos-aarch64 --dir dist/macos/RUN_ID
```

After approval, use the normal release dispatch on the reviewed SHA. That publishing run
produces and verifies its own installer artifacts.

## Stable releases

On `dev`, remove the prerelease suffix when preparing the stable release, synchronize versions
and add its changelog entry. Open the release PR to `main`. The existing protected-branch checks
remain in place. After merge, the pipeline runs the release gates and installer build on that
exact commit, creates its annotated stable tag, and publishes the complete GitHub Release as
latest. Do not manually push a stable tag to initiate this path.

## What the pipeline requires

1. Version/metadata consistency, a matching changelog entry and valid source/tag provenance.
2. Routine CI, 70% Linux routine coverage, native macOS, both Linux architectures' and Windows
   Studio/state recovery, all five slow shards without coverage, and Python checkpoint portability.
3. Native macOS Apple Silicon and Ubuntu 24.04 ARM64/x86_64 builds with locked Python/npm/Cargo
   dependencies, isolated packaged CLI/resource and checkpoint-enabled generation verification,
   a positive Mac-native CLI generation/evaluation smoke (ES/ULF/history and process census),
   bundled GStreamer appsink/scanner checks for AppImages, DMG integrity and all checksums.
   The native Windows x86_64 build installs the NSIS setup in both scopes on a disposable
   runner, verifies the packaged runtime, authoring guard, maintenance pages and uninstall
   cleanup inventory, and publishes only after its native service/recovery gate also passes.
4. Downloading this run's installer artifacts, staging a draft release, uploading missing assets,
   downloading and verifying them against the build, then publishing.

Mac reference-collector operation tests require POSIX paths, ownership, no-follow I/O
or Unix syscalls and run in macOS/Linux CI. Portable Mac simulation and record-codec
tests remain included in Windows routine checks. Specific reference-operation tests
declare their POSIX requirement; Windows does not provide a native Mac collector gate.

The publisher requires all eight assets: `EvidenceForge-Studio-VERSION-aarch64.dmg`,
`EvidenceForge-Studio-VERSION-aarch64.AppImage`, `EvidenceForge-Studio-VERSION-x86_64.AppImage`,
`EvidenceForge-Studio-VERSION-windows-x86_64-setup.exe`, and each installer's adjacent `.sha256`.
Developer test builds retain the `-test` suffix. Each snapshot's own `scripts/release_pipeline.py`
defines its required set, so tags created before Windows releases keep their six-asset contract.
Recovering such a tag through the manual entry point with a current dev workflow fails closed,
because its source tree cannot build a Windows release installer; rerun its original Actions run.
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

Build or test failures prevent the workflow from creating a release tag. Upload or publication
failures can leave an annotated tag and a draft containing some verified assets. Use
**Re-run failed jobs** on the original Actions run to reuse its installer artifacts (retained for
14 days). Do not move the tag.

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
the tag or merge main. Full Linux and Windows suites, including instrumented Linux release
coverage, have a 120-minute job budget.
Prefer the original run's failed-job retry when a
draft already contains assets, since rebuilding can change installer bytes.

The build job uses a platform matrix. Additional platform support should add native build and
verification entries, versioned installer names and explicit required-asset validation. All enabled
platforms must succeed before the shared publication job exposes a release. Keep routine PR CI's
app ZIP artifacts separate from release installers.
