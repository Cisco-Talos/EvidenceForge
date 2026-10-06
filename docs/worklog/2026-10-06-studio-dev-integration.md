# Studio integration into dev

On October 6, the user approved opening the cumulative `codex/gui` → `dev` PR and specified
**macOS as the only supported GUI platform for now**. Linux and Windows GUI support is deferred
for later exploration. This supersedes earlier three-platform Studio delivery and native recovery
requirements. Engine/CLI Linux and Windows support and native checkpoint gates remain unchanged.

## Integration changes

- Required Studio frontend/native builds and state recovery now run on macOS only. Linux/Windows
  engine jobs exclude Studio and former desktop tests; those tests remain in the macOS GUI gates.
  Simulated UID/SID and filesystem adapters remain available without claiming other GUI support.
- Required macOS recovery retains the full routine preservation and extended persistence-boundary
  crash matrix, helper lifecycle and account ownership tests. Real separate-account testing on
  macOS remains explicitly deferred because the user cannot create accounts on this host.
- CI builds the standalone Apple Silicon app with `--skip-dmg`, verifies its packaged CLI/resources,
  and archives the app as ZIP. This honors the earlier request to stop making DMGs. Manual DMG
  generation remains available; no DMG is built locally for this integration.
- Public Studio instructions, recovery release gates, current handoff and durable roadmap now
  reflect the macOS-only policy. Current Apple Silicon/OS acceptance limitations still apply.
- The PR covers the complete desktop replacement branch, including guided assets, immutable queued
  inputs, optional portable configuration, bundles/evaluation, backup/recovery and helper isolation.
  The application version is unchanged; the bump belongs to a later `dev` → `main` release PR.

## Validation and delivery

Previous subsystem evidence is recorded in the asset, standalone, upgrade, helper lifecycle and
account-isolation worklogs. Fresh integration checks and the PR link are recorded below once run.
CI must pass before merging; release coverage and outstanding field acceptance remain separate.

Fresh integration checks passed:

- Full Ruff lint and format checks (973 files), generated API-type check and diff whitespace check.
- Generation behavior declaration check against `origin/dev`: revision 158 and its expected digest.
- Shared configuration, resource prediction and deferred SSH regression tests: **34 passed**.
- CI YAML scope assertions: GUI/recovery macOS only; engine Linux/Windows and Windows checkpoint
  durability retained; both GUI jobs remain required by the aggregate gate.
- Engine test collection: **11,792 selected**, excluding GUI modules while retaining shared
  configuration/resource/behavior regressions. Collection is evidence of gate selection, not a
  claim that the full engine suite was rerun locally.
- Disposable mocked build-command check proves `--skip-dmg` retains app/icon build steps and
  creates no DMG/output volume. Packaging option parsing passed. Native packaged app verification
  will run in CI; no runtime download, full package rebuild or DMG occurred in this session.
- Refreshed remote refs; `origin/dev` is an ancestor of this branch, so integration is conflict-free.

## First CI run and test corrections

PR: [#435](https://github.com/Cisco-Talos/EvidenceForge/pull/435).
The first [CI run](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/37494240139)
passed lint, Linux engine tests, macOS state recovery and Windows checkpoint durability. It failed
on two environment frontend tests and two Windows Python tests. The user authorized fixing and
pushing these on October 6.

- Environment tests now route asset, environment and configuration requests separately. Delayed
  asset loads receive a valid typed page rather than an environment report. Pagination tests await
  asset rendering and scope declaration row/scalar checks to their own table. Environment refresh
  assertions count environment requests independently of asset requests; session storage is cleared.
- Configuration diagnostics are decoded from JSON before comparing native `Path` values, avoiding
  raw JSON escaping and Windows separator assumptions.
- The home-expansion fixture sets `HOME` and Windows `USERPROFILE` to the same disposable root.
  Assertions still require forecasts and actual output paths to agree without creating output.

These changes affect tests only. No tests are skipped, requirements weakened, application behavior
changed or DMGs built. Local validation: **216 frontend tests passed**, **31 affected Python tests
passed**, TypeScript/Vite build and generated API types passed, full Ruff lint/format and diff checks
passed. Native Windows validation remains the retriggered engine CI job; local macOS execution is
not claimed as Windows evidence.
