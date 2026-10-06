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
Initial image integrity verification passed. Initial DMG SHA256:
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

## Follow-up: silent packaged authoring failure

October 3 field trial on the development Mac: validation worked, but “Fix in chat”
accepted prompts and briefly showed “Codex is working…” without a reply.

### Cause and evidence

- The native helper was using the packaged retained runtime, not checkout Python.
- Finder discovery selected Codex.app's `codex-cli 0.146.0-alpha.3.1`. Its model
  catalog default was `gpt-5.6-sol`; Homebrew's independently installed CLI was
  `0.160.0`. The user's shared Codex config selected `gpt-6.1-sol`.
- Studio's model picker displayed the catalog default while omitting an explicit
  model from thread/turn requests. Codex inherited `gpt-6.1-sol` and rejected it
  for that ChatGPT connection. Three terminal notifications contained that error.
- The UI ignored error notifications and failed-turn errors. This Codex version's
  `thread/read` returned those same turns as completed, with user messages only and
  no error. History reconciliation then cleared Studio's generic failure note.
- The [official app-server contract](https://learn.chatgpt.com/docs/app-server#turn-events)
  distinguishes completed, failed, and interrupted terminal statuses and includes
  failure details. A successful RPC submission is not successful model inference.

### Fix

- A conversation without an explicit model resolves and saves the same catalog
  default shown by the picker. Thread start/resume and turn start send it explicitly.
  The selected model's default reasoning effort is saved when no effort was selected.
  Explicit conversation choices remain intact; global Codex config is unchanged.
- Empty catalogs produce an actionable error before a turn can inherit another
  model. Saved choices absent from the current catalog are visibly marked unavailable.
- Failed turns render provider errors beside the accepted user message, including
  live non-retryable failures while history is pending. Retrying errors remain live.
  Nested provider JSON messages are displayed as readable text.
- Persisted terminal notifications restore status/error to returned history when
  Codex's rollout drops them. The existing conversation/thread identities scope
  this recovery; SQLite events remain authoritative and no schema migration is needed.

### Acceptance and delivery

- 185 Studio/desktop Python tests passed without coverage, including new/resumed
  default model selection, explicit-choice preservation, empty catalogs, and
  failed-history recovery after reopening.
- 188 frontend tests passed, including history/live failure rendering, retrying
  errors, and unavailable model choices. Production build and API type check passed.
- The rebuilt native app, launched with isolated app data, a minimal PATH, and
  Codex.app's same CLI, successfully returned `STUDIO_CHAT_OK` and
  `STUDIO_CHAT_RESUMED_OK` from two real ChatGPT authoring turns. Both explicitly
  used `gpt-5.6-sol`. Workspace skill installation used the bundled resources;
  the bounded prompts requested no tools or file changes. Evidence:
  `/private/var/folders/6j/v05n9sgs5tz_y4nmzrn4gmtc0000gn/T/eforge standalone chat ü adt_eh3t`.
- Packaged CLI/resource verification passed again. The original image is preserved
  as `dist/macos/EvidenceForge-Studio-2.1.2-aarch64-initial-test.dmg`.
- Replacement image retains the standard `EvidenceForge-Studio-2.1.2-aarch64-test.dmg`
  filename. Updated SHA256:
  `393bb3a8430ce16e02ba0374ea8bff038480c4dae8585b6f2018ac4ca1c2b4a2`.
- The disposable test app, helper, Codex subprocess, and launchd registration were
  stopped. The user's currently open old package is deliberately left running.
  Quit it, eject the old DMG, replace the Applications copy from the rebuilt image,
  and reopen to load the fix. Workspace data and conversations remain in place.

This closes the bounded real-reply acceptance gap from the first build. Full
scenario repair/authoring and the other Mac's macOS 26 field trial remain open.

## Follow-up: Finder icon and differing model catalogs

The user reported different Finder/Dock icons and different model choices between
the standalone app and `uv run eforge-studio`.

- Both the PNG Dock artwork and packaged ICNS have alpha transparency. The source
  app had custom Finder icon metadata and an `Icon\r` resource fork, but Python's
  macOS `copytree` dropped both during DMG staging. The installed copy also lacked
  them. Packaging now uses `ditto --rsrc --extattr` to retain the custom icon.
- Terminal PATH finds Homebrew Codex 0.160.0; Finder's minimal PATH fell back to
  Codex.app's 0.146.0-alpha.3.1 before trying Homebrew. Model choices come from the
  selected executable's live catalog. Finder fallback now prefers common standalone
  CLI locations before Codex.app. PATH and explicit setting/override precedence
  remain intact. Settings help and installation docs explain selection/reconnection.
- Production TypeScript/frontend and native app builds passed, along with complete
  Ruff check/format and Git whitespace checks. Minimal-PATH discovery on this Mac
  selects `/opt/homebrew/bin/codex`.
- Read-only inspection of the finished DMG confirmed byte-identical FinderInfo and
  the 1,748,239-byte custom icon resource fork compared with the build app. Its
  runtime archive contains the updated discovery implementation. DMG integrity
  verification passed; the inspection volume was ejected. No Studio app/helper
  was launched, and the user's running session was left open.
- The previous chat-fix image is preserved as
  `dist/macos/EvidenceForge-Studio-2.1.2-aarch64-chat-fix-test.dmg`.
  The standard test image now has SHA256
  `cef7f1be93bbed4a7dfe5bc6816e9485c22ec71c70a7a774d7cf73484332ca22`.
  Quit Studio, eject the old image, and replace the Applications copy to load it.

## October 5 field feedback: validation, headers, and history

The user reports that the standalone app works well on the other Mac. This is
positive field-use evidence; the exact OS revision and individual acceptance
workflows were not recorded. They requested four minor workflow changes.

- Workspace Validation now shows outcome, error/warning/info counts, freshness,
  checked time, and repair action in its overall header. Opening it reveals the
  findings directly. A successful result without findings remains a green check
  and does not create an empty fold. Import results also show findings directly.
- Workspace, library, job, inspection, import, and scorecard list headers use a
  contrasting blue background. Contents are inset to distinguish parent groups
  from individual rows. Existing groups with multiple choices remain available.
- Prepared-import validation records that a check was requested. On confirmation,
  Studio checks the final destination after publishing packs and configuring the
  scenario, then saves/emits a normal workspace validation with source/dependency
  freshness. Temporary preview paths and changed destination configuration cannot
  be presented as a current result. Imports without an optional check stay unchecked.
- Job center uses a split control: Clear Completed removes successful generations
  and evaluations with readable, passed acceptance; failed/unrated evaluations stay.
  Clear Finished removes completed, failed, stopped, and cancelled history entries.
  Both preserve queued/running/paused jobs and all bundles/reports. Evaluations that
  failed acceptance or have unreadable reports display failed badges/counts while
  retaining their report lifecycle and source links. Cleanup remains workspace/type
  scoped, and links can still reveal hidden history entries.
- Frontend/TypeScript and native macOS builds passed. Generated API types, complete
  Ruff check/format, Git whitespace, and DMG checksum checks passed. No automated
  behavior tests were added or run for this follow-up; these UI changes await the
  user's next field review. No Studio app or helper was launched during the work.
- The previous image is preserved as
  `dist/macos/EvidenceForge-Studio-2.1.2-aarch64-before-field-polish.dmg`.
  The standard test DMG was rebuilt with SHA256
  `6266829327f7cbb771e892503b9ef7c17f488d1c4c3bc1ae8651b4ca193f7e6c`.
