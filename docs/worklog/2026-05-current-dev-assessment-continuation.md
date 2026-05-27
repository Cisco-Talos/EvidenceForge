# Current-Dev Assessment Continuation

## Status

Active handoff memory for the current-dev realism assessment continuation that
was previously tracked directly in `TODO.md`.

The central roadmap now points here instead of carrying loop-by-loop status
updates. Continue appending concise handoff notes here if another assessment loop
or follow-up batch is needed.

## Current Handoff

- The previous TODO history recorded current-dev assessment loops through a long
  branch-era sequence, including the 143+ loop series and later follow-up batches.
- The latest recorded generator-owned targets included bash-history/process
  timing alignment, web/proxy path-template diversity, richer TLS/X.509 SAN
  distributions, and continued reduction of overly tidy scenario-authored names
  when scenario edits are in scope.
- Scenario-authored name legibility was repeatedly identified as a broad tell,
  but was deferred unless scenario edits were explicitly authorized.
- Preserve per-loop artifacts under the scenario or assessment output directory
  chosen for that loop; do not use `TODO.md` for loop transcripts.

## 2026-05-27 Loop Batch Notes

- Loop 200 fixed eCAR endpoint file texture and installed-software registry
  identity stability (`ed4ab68a`, `88db6b22`). Automated eval passed at
  96.66140704016262 over 78539 records; the hard probe saw 419 eCAR FILE events
  across all 15 hosts and zero duplicate installed-software DisplayName/GUID
  groups.
- Loop 200 blind review remained synthetic-leaning: initial synthetic-confidence
  average 59.0, deliberated average 64.75. The strongest confirmed next targets
  are proxy file-transfer object identity/timing and Linux eCAR process-to-flow
  attribution.
- Loop 201 fixed explicit-proxy HTTP file-transfer identity/timing by sharing
  origin-form content identity across proxy legs, pairing client/origin
  `files.log` metadata, and delaying client-facing file observation until after
  proxy-origin fetch observation. Automated eval passed at 95.83681405251764
  over 78513 records; the hard probe saw zero hash/size mismatches and both
  Dell updater client observations started/finished after origin observation.
  Blind synthetic-confidence scores were 72/68/67/76, average 70.75. Next
  target: AD account-management lifecycle ordering, with UDP/123/NTP contracts
  and built-in service-account profile paths queued behind it.
- Loop 202 fixed AD account-management lifecycle ordering by recording
  account-create effect times and delaying later same-host storyline commands
  and group-membership effects until after the prior AD audit effect is visible.
  Automated eval passed at 95.83680366637293 over 78514 records; the hard probe
  confirmed `net user`/4720 now precede `net group`/4728 for `svc_mhsync` in
  DC Security, Sysmon, and eCAR. Blind synthetic-confidence scores were
  68/76/72/74, average 72.50. Next target: canonical endpoint process/file
  ownership, especially service/kernel principals on user profile paths and
  Sysmon terminal-session inheritance.

## Recent Completed Work Previously Kept in TODO

- Codex fix-family PR disposition and rework completed: rejected PRs were closed
  with rationale, acceptable PRs were merged, and accept-with-changes PRs were
  reworked.
- Full slow-suite regression cleanup completed after the recent fix-family work.
  The successful recorded run was `uv run pytest --no-cov --include-slow` with
  `3771 passed, 2 skipped`.
- Earlier assessment work completed many source-native realism fixes across
  Kerberos/DC evidence, X.509/DNS/TLS, eCAR/session/FLOW ownership, Linux
  syslog/bash texture, proxy/browser semantics, Zeek HTTP reuse, and Windows
  process/session timing.

## How to Continue

1. Start from the current `dev` state and read `TODO.md` for durable priorities.
2. Select the next assessment target from the latest verified blind-review or
   hard-probe findings.
3. Fix the owning layer, not an emitter symptom, unless the defect is truly
   source-local rendering.
4. Verify with focused tests, `uv run eforge validate-config`, Ruff checks, and
   normal `uv run pytest --no-cov` unless the loop specifically requires slow
   coverage.
5. Record only the concise loop outcome, next target, and validation result here.

## References

- `TODO.md` keeps the durable backlog.
- `CHANGELOG.md` keeps release history.
- Loop artifacts should remain in their scenario or temporary assessment output
  directories and be referenced here when needed.
