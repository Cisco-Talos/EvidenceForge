# EvidenceForge Studio — current state and standalone delivery handoff

**Updated:** October 2, 2026. **Branch:** `codex/gui`.
**Latest implementation commit at this handoff:** `cdfb1eb8`.

Read this first when resuming Studio work, then consult the relevant sections of
[the detailed rebuild worklog](2026-09-30-studio-rebuild.md). That log is chronological:
early descriptions of cards, tabs, Qt availability, overlay limitations, browser-only exports,
and oldest-first jobs have been superseded. This document summarizes the current state.

## Accepted architecture and compatibility boundaries

- Local Tauri desktop shell, React/TypeScript interface, authenticated Python application service
  on loopback with an ephemeral port, SQLite relationships/job records and JSON global settings.
- `eforge` remains deterministic. Interactive authoring uses existing skills through Codex
  app-server; generation never calls an LLM. Codex credentials remain in Codex storage.
- The user accepted the replacement and native core review on October 2. `eforge-desktop` and
  `eforge-studio` launch Studio. Qt UI/dependency retired; old app-data files are not deleted.
- Traditional CLI and ChatGPT/Claude native-harness skill workflows must remain compatible and
  easy to use. Studio must not become a required database or dependency for them. Optional shared
  capabilities belong in public file/CLI contracts with unchanged legacy defaults.
- Authored YAML, packs, overlays and generated bundle contents are authoritative files. Library
  projects are virtual organization; conversations, preferences and job relationships are indexed.
- Default workspace is Documents/EvidenceForge via platform conventions, or ~/EvidenceForge on
  Linux without a distinct configured Documents directory; never use the launch directory.
- App data stays outside the app/workspace: macOS Application Support/Logs/Caches; Linux XDG
  config/data/state/cache; Windows LOCALAPPDATA/EvidenceForge. See the source-run guide for paths.

## Work already delivered

### Libraries and scenario workspace

- Scenario library uses project-grouped, collapsible lists, initially collapsed, with project
  names, operation icons/tooltips, search, filters, saved views/collapse state and command menu.
  Scenarios can be created, renamed with valid-name checks, cloned, assigned/moved to projects,
  and imported. Project dragging and native drag behavior have been addressed.
- Shared projects also organize packs. Packs share one page, Industry first then Organization,
  alphabetized by name with newest numeric version first. Author/search/filter controls,
  validated creation details, conversation authoring, selective imports and portable .efpack
  exports are present. Imports review exact versions, publishers, conflicts and dependency closure.
- YAML import explicitly reviews nested includes, supporting assets and exact pack dependencies.
  Optional prepared validation is advisory; missing packs can be imported later. Source workspaces
  supply copies, not live dependencies. Checks refresh automatically plus a manual refresh action.
- Scenario workspace has compact collapsed Conversations, Environment, Validation and Runs sections
  with useful summary headers. YAML path is clickable into the built-in viewer with adjacent copy.
  No separate workspace Generation/Scoring/Bundles sections remain; global Bundles remains.
- Chronological lists are newest first. Runs/jobs use original submission time, unaffected by
  pause/resume. Bundles interleave owned/imported entries and sort groups by their latest entry.
  Conversations use latest update time; Continue opens the first visible conversation.

### Conversations, files, settings and lifecycle

- Persistent scenario-linked conversations with rename/delete, editable title, model/reasoning
  pickers, role-distinct messages, rendered Markdown/code and expandable tool activity summaries.
  Scenario context is supplied independently of the user message. Follow-up message identity,
  history readiness/recovery and Codex connection monitoring were repaired.
- Chat fits the window. It follows new output while at the bottom and preserves manual scroll-up
  until the user returns to the bottom. Status dot reflects service/Codex health with recovery.
- Built-in file viewer handles highlighted YAML/JSON/XML/code, Markdown and text/email artifacts,
  wider file navigation, exact source-line jumps/highlights and native Save/copy exports.
- Compact grouped Settings with help tooltips, clear checkbox controls, account identity/sign-out,
  configurable skill installation (global/all agents defaults), detected tools and saved-state
  feedback. Official logo, transparent Dock/.app icon and product-name menus are in place.
- Quit policies persist: Continue is default, queued generations/evaluations continue; checkpoint
  and pause defaults to close after durable handoff and lets evaluations finish; Kill preserves
  partial files by default. Authoring defaults to stopping active turns, with finish-background
  option. Approval/input is never automatically granted. Job ownership includes PID + creation
  time; unrelated terminal processes must never be stopped or deleted.
- macOS helper uses a transient user launchd service, with no helper Dock icon/login item;
  Linux uses a detached process. The October 6 lifecycle fix exits after the last window closes
  and background work finishes, with an eight-second idle grace period. Windows share settings,
  the selected workspace and generation concurrency. See the
  [helper lifecycle worklog](2026-10-06-studio-helper-lifecycle.md).
- October 6 account isolation validates private roots and actual helper UID/SID before token
  delivery or replacement. Private discovery is versioned; windows share limits within one
  account, while accounts retain independent helpers and limits. Real separate-account testing
  is deferred by the user; see the [isolation worklog](2026-10-06-studio-user-isolation.md).

### Environment, runs, evaluation and delivery

- Optional portable configuration contexts are implemented: explicit project root and ordered
  named overlays, available through public --context CLI selection and skills. Legacy CWD /
  --project-root behavior is unchanged. Studio supports disabled-by-default shared project patches
  and private scenario patches, inspection/chat editing, clone/import/export and confirmation
  for moves that change configured context. Full runtime leaf-value origins are not complete.
- Source declarations show values and source locations in collapsed paginated inspection;
  First/Previous/numbered pages/Next/Last controls and highlighted line navigation are present.
- Readable validation, saved freshness, contextual Fix in chat, dependency readiness and resource
  prediction are available. `eforge resources predict` is a public deterministic CLI command.
  Forecasts refresh/cached by input changes; cards/rows prefer measured size for fresh completed
  runs, otherwise explicitly marked estimates. Forecast dialog shows ranges/memory/disk/capacity.
- Queue publication captures immutable self-contained resolved inputs, including exact packs,
  includes, corpora and selected overlays. Regenerate captures current inputs into a new run;
  checkpoint resume retains the original run. Default generation concurrency is two; checkpoint
  interval is configurable, default 24 simulated hours. Each job has independent progress.
- Job center uses collapsible generation/evaluation rows, active-chat counts, pause/resume/retry,
  delete/history cleanup and grouped destructive choices. Global Bundles supports search/filter,
  sizes, viewing, ZIP export, safe owned deletion and read-only complete external-bundle import.
- Each workspace Run combines generation status, bundle management, evaluation action and latest
  saved scorecard. Header reflects latest owned run, score/quality outcome and input notices.
  Colored icons distinguish process success, quality acceptance and stale/unverified inputs.
  Pillars/subscores expand; raw reports remain viewable/exportable.
- Only latest valid completed evaluation retained per run. Crashed/interrupted/unreadable retries
  preserve prior scores; completed quality-failed reports replace them. This is Studio retention,
  not a change to CLI evaluation. Duplicate active evaluation of a run is prevented.

### October 5 asset workflow

Searchable, bounded asset lists with expandable rows, graphical origins and
reviewed scenario/pack editing are implemented. Pack edits create new versions;
scenario edits retain pack ownership through private overrides. See the
[asset worklog](2026-10-05-studio-assets.md) for scope, tests, limits and the updated
macOS field-test image. Broader origins and authoring beyond those categories
remain part of the workflow backlog.

## Remaining workflow work

Core replacement is accepted; the seven original stages are not all complete. Features have been
implemented across stages as feedback required. Reconcile against delivered behavior rather than
reimplementing completed slices.

| Stage | Delivered foundation | Remaining planned work |
| --- | --- | --- |
| 1 Find/resume | Projects, status/freshness, contextual excerpts, saved views, command menu | Final acceptance/completeness review rather than a new library rewrite |
| 2 Environment | Exact pack inspection/selection request, lifecycle/import/export, optional scopes, declarations | Guided structured pack/config editing and full effective-value origins |
| 3 Author/revise | Persistent conversations, scenario context, model controls, repair entry | Structured scenario preview, isolated draft diffs/acceptance, revision history and contextual repair integration |
| 4 Validate/preflight | Readable findings, dependency/freshness checks, resource forecasts; CLI reachability exists | In-place finding navigation/repair, richer reachability view, automatic validation of accepted revisions (proposed on) |
| 5 Generate/operate | Immutable inputs, concurrency, all-job progress, checkpoint/recovery, forecast | Resource-aware scheduling and richer per-run setup/overrides; evaluate-after-generation proposed on, verify current coverage before adding |
| 6 Evaluate/iterate | Run-linked expandable scorecards, raw report, progress | Evidence drill-down, comparisons between different runs and targeted repair; retain safety limits and latest-report policy |
| 7 Inspect/deliver | Bundle viewer, native exports, ZIP, complete external imports, context/reproducibility artifacts | Analyst/instructor answer-key-aware presets (analyst default), richer reproducibility view, remembered destination, incomplete external checkpoint imports |

Review recurring preferences before each substantive stage; keep one-off choices beside the task.
The user authorized autonomous progress/commits/helper restarts while not using the app; pause for
questions, user testing or meaningful stage feedback rather than repeating accepted core review.
The present request is to record the handoff, not to start packaging or another workflow stage.

## Standalone apps — agreed direction, NOT IMPLEMENTED

**October 3 update:** macOS implementation and current acceptance now live in the
[standalone worklog](2026-10-03-studio-standalone-macos.md). The user deferred signing
and notarization and confirmed an Apple Silicon macOS 26 test machine. The first
artifact is Apple Silicon; the locked cryptography dependency blocks Intel assembly.
The section below preserves the original planning context.

The user wants real-case testing on another Mac and accepted the following distribution approach:

| Platform | Initial delivery | Build environment |
| --- | --- | --- |
| macOS | One universal signed/notarized DMG containing EvidenceForge Studio.app; drag to Applications | macOS host/CI; test Intel and Apple Silicon |
| Linux | x64 AppImage initially; optional .deb/.rpm later | Linux CI/VM/container; desktop VM for acceptance |
| Windows | x64 signed setup EXE initially; optional MSI for managed deployment | Windows CI/VM; native interactive acceptance |

- Bundle the compiled frontend, private Python runtime, EvidenceForge CLI/service and dependencies,
  catalogs/templates, skills and references. No repo checkout, uv, Node/npm, Rust or separately
  installed Python required on the user's machine.
- Codex is installed separately by users. Preflight detects it and supports existing sign-in;
  missing Codex should disable authoring without blocking deterministic/library operations.
- macOS target is one universal shell with two private architecture-specific Python runtimes
  initially, selected automatically. Users choose no architecture and should need no Rosetta.
  This is an agreed initial design, not a verified build. A universal runtime is an alternative
  if all native dependencies can be verified for both architectures.
- Develop on the Mac; native OS CI builds provide Linux/Windows artifacts without requiring new
  physical development computers. Avoid Windows cross-compilation complexity. Each OS/architecture
  needs matching runtime/native libraries. Linux needs a tested distribution/system-library baseline;
  Windows installer must handle WebView2. Signing credentials are not yet confirmed available.
- Release launch uses embedded frontend assets and bundled runtime. It should open no terminal and
  run no npm/Vite/Cargo/source watchers. Service/worker diagnostics go to app logs; progress goes
  to GUI. Build-time output remains in developer/CI logs.
- Start with standalone macOS real-case package, then Linux, then optional Windows. Automatic
  updates and broader distribution are deferred. Source-run development remains supported.

### Packaging implementation sequence

1. Audit runtime/resource paths and dependency/license inventory; choose pinned private Python
   distribution and reproducible assembly. Current .app is NOT standalone: Rust locates repo
   .venv or python3; service/controller uses sys.executable; frozen CLI fallback searches PATH.
2. Bundle matching runtimes, EvidenceForge and assets. Provide reliable helper/CLI dispatch from
   Finder and make packaged eforge usable by Codex command tools without shell initialization or
   breaking an independently installed CLI/native skill workflow.
3. Adapt detached launchd/process startup to installed paths; preflight Codex and required runtime
   resources. Keep credentials external and writable state outside signed app contents.
4. Handle helper version identity, old-helper reuse, app relocation and replacing/updating the app
   while jobs run. Define safe behavior before claiming portable delivery; never kill unrelated jobs.
5. Produce universal Mac app/DMG, sign all executables and notarize with available credentials;
   verify dependency architectures and minimum OS. Then clean-machine acceptance with no repo/tools.
6. Add Linux and Windows native CI builds, platform installers/runtime checks, signing where
   appropriate, and native acceptance; expand architectures/formats afterward.

Clean-machine gates: fresh install/preflight, scenario/pack import, Codex sign-in/authoring/skills,
validation, two generations/progress, quit/reconnect policies, checkpoint/resume, evaluation,
viewer/export/file copy, configured paths, reinstall/update, relocation and paths with spaces /
non-ASCII. Build success alone is not native runtime acceptance.

### Technical references checked during this discussion

- [Tauri sidecars](https://v2.tauri.app/develop/sidecar/)
- [Universal macOS build](https://tauri.app/distribute/app-store/)
- [macOS signing](https://v2.tauri.app/distribute/sign/macos/)
- [AppImage compatibility](https://v2.tauri.app/distribute/appimage/)
- [Windows installers and WebView2](https://v2.tauri.app/distribute/windows-installer/)
- [Platform prerequisites](https://v2.tauri.app/start/prerequisites/)

## Verification and resume checklist

- Latest frontend gate: **184 tests in 14 files passed**, API types current, frontend/TypeScript
  compilation, full Ruff check/format and diff checks passed; macOS release app rebuilt.
- Recent unified-runs service gate: 94 focused Python tests passed. Earlier context integration
  gates: 122 shared/config/skill and 108 Studio context/import/service tests, plus narrow real CLI
  validation/prediction/generation/checkpoint/resume/evaluation and legacy byte comparison.
  These are dated feature gates, not a claim of a fresh full-repository or release-coverage run.
- macOS has repeated visual/native user review; Linux native CI configured but its current outcome
  must be inspected. Windows Studio packaging/native acceptance not complete. No standalone
  package/clean-machine acceptance yet; existing release .app still needs development runtime.
- Branch work is committed through cdfb1eb8. Three unrelated tracked deletions under
  scenarios/iteration-test-1_0 (ENVIRONMENT.md, email_corpus.yaml, scenario.yaml) were excluded.
  Do not restore, commit or delete further without establishing intent.
- Temporary review services/tabs were closed and viewport reset. User's normal helper/state remain
  separate. Screenshots in /private/tmp are disposable evidence, not durable implementation assets.
- Next session: read TODO and this handoff, inspect git status, choose packaging or the next workflow
  tranche with the user; follow detailed worklog for tests/contracts. No feature-branch version bump.
