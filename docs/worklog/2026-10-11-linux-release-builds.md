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

Pending: final local checks, native build-only CI, artifact download and user desktop acceptance.
No tag, GitHub Release or publication workflow should run before explicit user approval after
testing the x86_64 preview. Ubuntu 24.04/glibc 2.39 remains the build baseline; other distro and
clean-machine acceptance are separate work.
