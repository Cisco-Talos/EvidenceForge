# Product releases and installers

EvidenceForge and Studio share the version in `pyproject.toml`. The Release workflow delivers
the macOS Apple Silicon DMG and native Linux ARM64/x86_64 AppImages, each with a SHA256 file.
Codex remains a separate install for authoring. The macOS installer has no Developer ID signature
or notarization; Intel macOS and Windows installers are not enabled. Linux publication is prepared
for 2.2.0a2 and remains on hold until the user's x86_64 acceptance passes. See [Studio installation](studio.md#macos-installation).

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
and each installer's adjacent `.sha256`. Developer test builds retain the `-test` suffix. The release build command is:

```sh
uv run python scripts/package_studio_macos.py --build-app --release
```

Building locally does not publish. Automatic builds retain the current unsigned/unnotarized
packaging policy. Signing/notarization and additional platform acceptance are separate work.

## Local Linux AppImage builds

Local builds use the unpublished `-test` filename and native architecture; building does not
tag or upload anything. Use `--architecture x86_64` on a native x86_64 builder or
`--architecture aarch64` on a native ARM64 builder. `--release` removes the test filename suffix
but does not publish.
On the Ubuntu 24.04 builder, after `uv sync --frozen --extra studio --extra dev` and
`npm --prefix desktop-ui ci`, install the AppImage plugin build requirements and run:

```sh
sudo apt-get install patchelf gstreamer1.0-plugins-base gstreamer1.0-plugins-good
uv run --no-sync python scripts/package_studio_linux.py
```

The script reuses the macOS payload assembly path with a separate checksum-pinned Linux Python
lock, installs locked runtime dependencies, and bundles a native AppImage. Outputs go to
`dist/linux/` with a SHA256 file. GStreamer plugins and their scanner are bundled for WebKitGTK;
`patchelf` is a build dependency, not a requirement on users' machines.
Payload assembly verifies the source behavior manifest, rejects macOS transfer metadata in the
wheel, and checks the installed package against its generation behavior declaration before
creating runtime archives. The same integrity gates apply to local macOS assembly.
Native `aarch64` and `x86_64` builds are supported by the script;
CI uses `ubuntu-24.04-arm` and `ubuntu-24.04` respectively. Cross-compiling ARM AppImages is not
supported by the upstream bundler. The build baseline is Ubuntu 24.04/glibc 2.39; other distro
acceptance remains open. Manual x86_64 desktop acceptance must pass before the 2.2.0a2 release.
See [Tauri's native ARM requirement](https://v2.tauri.app/distribute/appimage/#appimages-for-arm-based-devices).

## Build-only CI artifacts

`installers.yml` shares the same native builders and packaged verification with Release, with
read-only repository permissions and no tag or publication steps. Packaging changes pushed to
`dev` build all three preview installers automatically. Manual builds select one platform:

```sh
gh workflow run installers.yml --ref dev -f platform=linux-x86_64
```

The workflow must first be registered by its `dev` push. Download the completed run's
`preview-installer-linux-x86_64` artifact (AppImage plus SHA256) from its Actions page, or:

```sh
gh run download RUN_ID --name preview-installer-linux-x86_64 --dir dist/linux
```

Preview Linux builders gate native helper lifecycle and state recovery, Rust shell contracts,
then inspect the actual AppImage without requiring FUSE. The extracted private runtime runs
without checkout/Python PATH entries in an isolated temporary home. The same runtime checks run
for macOS. These automated checks do not replace the user's desktop acceptance.

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

The build job uses a platform matrix. Future Linux/Windows support should add native build and
verification entries, versioned installer names and explicit required-asset validation. All enabled
platforms must succeed before the shared publication job exposes a release. Keep routine PR CI's
app ZIP artifacts separate from release installers.
