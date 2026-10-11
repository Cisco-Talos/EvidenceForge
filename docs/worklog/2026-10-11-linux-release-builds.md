# Linux release builds and x86_64 preview acceptance

## Scope and source

User requested switching the local checkout to `dev`, updating from remote, implementing
native Linux release jobs, release filenames, complete artifact verification/publication,
and Linux packaged-app and Studio recovery checks. Both Linux architectures must be buildable;
build x86_64 for the user to test before any release. No release tag or publication is authorized.

The checkout was clean. Switched from `codex/studio-linux-usability` to `dev` and fast-forwarded
to `origin/dev` at `32dbdb1d`, including PR #445's complete Studio/Linux source integration.
Product version remains `2.2.0a2`; no version bump is part of this work.

## Implementation

- Read-only `installers.yml` builds native macOS Apple Silicon, Ubuntu 24.04 ARM64 and Ubuntu
  24.04 x86_64. Release calls the same workflow on its validated SHA with release filenames;
  `dev` packaging pushes and manual dispatches create preview artifacts without publishing.
- Linux builder gains `--release`; previews keep the `-test` suffix. Runtime/interpreter hashes,
  locked dependencies, native architecture checks and bundled GStreamer remain in place.
- Publication requires all three installers and all three filename-bound SHA256 files. Builder
  verification checks one exact pair without requiring a release tag. Complete publication
  remains gated by CI, slow/portability checks and every installer job. Draft retry compares all
  retained bytes before any sibling upload; tags and published assets remain immutable.
- Common Unix runtime acceptance checks are shared by macOS and Linux, including isolated CLI,
  skills, catalogs, artifact operations, behavior manifest and checkpoint-enabled generation.
  Linux verification extracts the actual native AppImage, then confirms the bundled appsink
  plugin loads using its bundled scanner and an empty host-plugin search path.
- Studio and native state-recovery CI matrices now include both Linux architectures. Preview
  Linux builds also check helper lifecycle/state recovery and native Rust contracts.

## Validation and handoff

Local validation: repository-wide Ruff check/format, whitespace and product-version synchronization
passed. actionlint 1.7.12 validates all three edited workflows. Release-contract tests cover each
installer's absence, corruption, wrong checksum filename, symlinks and duplicates; publication
also checks each platform's downloaded bytes and rejects partial-release CLI options.

The shared packaged-runtime verifier passed against the existing macOS 2.2.0a2 app, including
behavior identity, relocated isolated CLI, skills/catalogs, artifact operations and
checkpoint-enabled generation.

Implementation commit `a21b7272` was pushed to `dev` without a tag. Build-only run:
https://github.com/Cisco-Talos/EvidenceForge/actions/runs/38164593678.
Both native Linux builders passed helper/state recovery and Rust contracts before assembly.
Manual x86_64 dispatch was proven with run `38164684862`, then that duplicate was canceled;
the original all-platform run continues.

Pending: native installer assembly/verification, artifact download and user desktop acceptance.
No tag, GitHub Release or publication workflow should run before explicit user approval after
testing the x86_64 preview. Ubuntu 24.04/glibc 2.39 remains the build baseline; other distro and
clean-machine acceptance are separate work.


## First native run: x86_64 bundle-name correction

Run `38164593678` passed Linux helper/state recovery and Rust shell contracts on both native
architectures. x86_64 compilation and AppImage bundling succeeded (132.49 MiB), but copying the
installer failed: Tauri names its x64 output `..._amd64.AppImage`, while the original local
builder searched for `..._x86_64.AppImage`. The ARM64-only local build had not exercised this.

Corrected discovery to use Tauri's `amd64` spelling only for the native x64 bundle, retaining
`x86_64` in the public installer filename and runtime identity. Added regression checks using
both real Tauri filename conventions and both preview/release names. Extended publication tests
to corrupt each downloaded platform image and to reject builder-only flags in publication.
No generation algorithm, dependency pin or product version changed.
