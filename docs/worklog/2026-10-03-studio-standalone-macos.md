# Studio standalone macOS package

## Authorized scope

October 3, 2026: implement the standalone packaging plan. The user's test Mac is
Apple Silicon running macOS 26. Developer ID signing and notarization are deferred
until a distribution release. The first artifact targets Apple Silicon. Universal
delivery remains planned after resolving Intel dependency availability (see below).
Codex is separately installed. Existing CLI and source-run workflows remain supported.

## Implementation order and contracts

1. Pin portable CPython 3.12.12 archives and checksums for both architectures.
   Assemble locked runtime dependencies and the EvidenceForge wheel, including
   catalogs, pack resources, skills and references. No virtual-environment copy.
2. Native launch installs the selected payload atomically into a versioned private
   runtime under Application Support. Helpers/jobs use that retained runtime, so
   replacing or relocating the app cannot remove their code. No automatic runtime
   deletion in this first package.
3. Add helper runtime identity and authenticated idle handoff. A different build
   cannot replace a helper while jobs or authoring are active. Verify exact process
   identity before termination; never stop an unrelated process.
4. Discover separately installed Codex without shell initialization and supply the
   private CLI to Studio's authoring process. Missing Codex leaves deterministic
   operations available.
5. Produce an app/DMG through reproducible build automation and native checks.
   Developer ID signing/notarization remain disabled for this test package.
6. Verify isolated install, import, validation, concurrent generation, reconnect,
   checkpoint/resume, evaluation, viewing/export, relocation and replacement.
   Developer-machine checks do not claim acceptance on the user's other Mac.

## Progress and evidence

Initial audit: the Rust launcher searches checkout `.venv` then PATH; Python workers
use `sys.executable`; the service descriptor has no runtime/build identity; Codex
discovery uses PATH or an explicit setting. Wheel packaging already includes canonical
skill/reference files and package-local configuration resources. Source tree clean
on `codex/gui` at session start.

### Implemented

- Pinned python-build-standalone CPython 3.12.12 release 20251028, with upstream
  SHA256 verification. `uv export --frozen` and binary-only hashed dependency
  installation assemble the project wheel, resources, licenses, and skills.
- Native launcher installs a checksummed archive atomically into a retained,
  content-addressed private runtime. CLI/helper/workers use that interpreter;
  Python environment injection is excluded. A relocatable `eforge` wrapper works
  from paths containing spaces and Unicode. No developer tools are used at launch.
- Runtime identities, authenticated idle handoff, exact process checks, and stale
  launchd registration replacement support upgrades. Active jobs and authoring
  across every workspace block replacement. Paused generations retain their inputs.
- Finder Codex discovery covers the separately installed Codex.app and common CLI
  paths. Studio supplies its absolute private CLI and subprocess PATH to authoring
  without changing the user's global shell/CLI/skill setup.
- Repeatable app/DMG assembly uses locked Cargo dependencies and explicitly skips
  Developer ID signing. Existing macOS Studio CI now builds/uploads the test image
  and verifies its packaged CLI/resources on Apple Silicon runners. Remote CI has
  not been run in this session.
- [Install/build instructions](../studio-standalone-macos.md) explain first launch,
  data locations, helper lifetime, updates, and acceptance on the other Mac.

### Architecture limitation

The initial two-runtime assembly failed for x86_64: the locked
`cryptography==50.0.1` distribution provides macOS arm64 wheels and no macOS Intel
wheel. `uv.lock` confirms that availability. Do not silently loosen the dependency
lock or use a different cryptography version only in the app. The default artifact
is therefore aarch64, matching the user's test Mac. Interpreter archives remain
pinned for both architectures; Intel packaging/acceptance stays open.

### Local acceptance

Host: Apple Silicon, macOS 27.0.1. Deployment floor is configured as macOS 13; it
has not been accepted on that floor or on the user's macOS 26 machine.

- Isolated packaged CLI/resource check passed: version, environment schema, pack
  inventory, project-local skill/reference installation, and scenario validation.
  Minimal system PATH and deliberately invalid PYTHONHOME/PYTHONPATH were used.
- Native app launched from a copied path containing spaces/Unicode into isolated
  app data and a disposable workspace. The helper executable was verified under
  the retained private runtime.
- Two independently queued generations completed. Closing/reopening the app and
  relocating its bundle reused the same helper PID and preserved both jobs.
- Packaged evaluation completed; manifest/file viewing, ground truth retrieval,
  and ZIP export passed.
- Checkpoint pause/resume completed. The first probe requested suspension before
  generator startup published `controller.json`; waiting for that readiness marker
  removed the probe race without changing generator behavior.
- Native replacement between two payload identities passed: old idle helper
  exited, new helper used the new retained runtime, old runtime stayed available.
  This exposed and fixed launchctl text-output handling; running registrations
  without a usable descriptor are explicitly refused.
- A stale input-capture test double did not accept the existing `context` keyword.
  Updated its signature/forwarding; production compilation semantics are unchanged.
- Seven Rust shell tests passed. Frontend production build, generated API type
  check, Rust formatting, complete Ruff check/format, and Git whitespace checks passed.
- Complete Studio/desktop regression set: 179 passed in 128.45 seconds, without
  coverage instrumentation. Final payload repeated every native lifecycle check above.

### Artifact

`dist/macos/EvidenceForge-Studio-2.1.2-aarch64-test.dmg`, companion SHA256 file,
and release app under `build/studio-macos/target/aarch64-apple-darwin/release/bundle/macos/`.
The app is about 35 MiB; its compressed private runtime is about 28 MiB.
Image integrity verification passed. DMG SHA256:
`9cc30677baefedc287d7e248788647782428194f39a3bbf27b651f6bd25b6746`.

### Remaining acceptance

User's macOS 26 field test, Codex sign-in/real authoring with the private CLI,
native scenario/pack import workflows, and target-system Gatekeeper approval remain.
Source import/authoring contracts have regression coverage; developer-machine
isolation does not claim a clean-machine field test. Intel, Linux/Windows packaging,
automatic updates/runtime cleanup, and release signing/notarization are deferred.

The user requested review-app cleanup explicitly. The old review window and legacy
source helper were stopped; the helper had zero active jobs/chats. Each isolated
native harness stops its own app, helper, workers, and launchd registration in a
`finally` block. Final process verification confirmed no Studio review app, helper,
or test worker remaining. Test artifacts stayed on disk for evidence; no application
is left running.
