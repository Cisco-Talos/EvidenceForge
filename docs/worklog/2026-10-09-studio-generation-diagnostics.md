# Studio generation failure diagnostics

## Report and cause

The user validated the Mac scenario Maple Office - PowerShell Discovery
(`Test_scenario_1`, published 1.0.1) with one warning, then saw generation stop
twice without an explanation in Studio. Read the durable job records and logs
without modifying their output. Attempts `82a30d9b6897417da817abee49434a9c` and
`fdb4e9c64dfc4ef6ab90847bdda1489a` ended before engine progress began.

The warning was the missing firewall sensor; generation explicitly proceeded
past it. Both logs instead reported a generation behavior manifest mismatch:
declared `0114d1bad6b5748c549a4da2ae71298e4c51b1852c11bfaf0b81e1d0d33cab60`,
actual `bd9e13343c8fb72dfdbbb03a284357a3a0664d362c1b0503222bc76b2b6584d4`.
The earlier Studio publisher edit introduced `scoped_publisher` and delegated
the effective reader to it. Composition is covered by the behavior surface, so
that change required a declaration even though it does not alter rendering.

Updated `generation_behavior.yaml` to revision 161, recording impact `none`,
the scoped-reader change and the current digest. Kept the compatibility guard
and prior immutable history intact. Product version remains 2.2.0a1.

## User-visible diagnostics

Added an authenticated `/v1/jobs/{job_id}/diagnostics` endpoint scoped to the
current workspace. It reads only the canonical private job log, rejects
symlinks/noncanonical paths, and returns at most its last 32 KiB. It extracts
the last explicit CLI error paragraph, including Rich-wrapped lines, and strips
ANSI formatting. Missing or unreadable logs become unavailable diagnostics;
absence of a recorded error is not treated as proof of a failure cause.

Expanded job rows now display recorded errors for stopped/failed generation
and evaluation jobs, with View log, Refresh log and a copyable full-log path.
The request happens only when a row is expanded, not during startup or every
job reconciliation. Logs remain plain text. No database/job-model migration or
change to process ownership, resume policy, lifecycle status inference or
generated files. `Stopped` still means an exit without a completed bundle;
Studio cannot infer an exit code for a detached process it did not reap.

Updated `docs/studio.md` with the path to diagnostics and the distinction
between input validation and runtime success.

## Evidence and handoff

- Behavior manifest guard with `--base-ref HEAD` passed at revision 161.
- Ruff check/format passed for the changed Python files.
- Regenerated the API schema; TypeScript/Vite build passed.
- Native Mac source `.app` build passed using
  `npm --prefix desktop-ui run build:native -- --debug --bundles app -- --locked`.
- Opened the new source build and inspected the real failed run. Its expanded
  details visibly showed the captured fatal error, and View log displayed its
  saved CLI output. Left the scenario's stopped-run details open.
- No automated tests or generation rerun were performed. The user can select
  Regenerate to start a fresh run; both original attempts and logs are retained.

Sync these changes to the existing VM checkout using `scripts/sync_linux_vm.py`
so the same publisher code there has its matching behavior manifest. A fresh
Linux native build is needed to display the new frontend diagnostics there.

October 10 AppImage follow-up: the same error class later appeared with actual digest
`992bb31b...`, caused by an extra AppleDouble `composition/._publisher.py` from earlier source
transfers. The real behavior files still matched revision 161. The cleanup, wheel exclusions,
packaged-runtime build guard and verified rebuilt installer are recorded in
`2026-10-09-studio-a2-local-installers.md`; no further behavior revision was needed.
