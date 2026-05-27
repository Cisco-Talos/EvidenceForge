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
- Loop 203 fixed service-principal endpoint profile artifacts and Sysmon
  terminal-session drift (`649fa9a6`). Automated eval passed at
  97.1909324170483 over 76333 records; the hard probe found zero service
  profile-path hits in eCAR/Sysmon, zero eCAR PID 4 interactive-profile
  contradictions, and zero Sysmon terminal-session drift cases. Blind scores
  were 68/55/44/72, average 59.75; deliberation final scores were
  72/66/50/76, average 66.00. Next target: eCAR process lifecycle ownership,
  especially module/process activity after native Security/Sysmon termination.
- Loop 204 fixed eCAR process lifecycle containment (`8f2881c2`, `2e9462a4`,
  `af62abd0`) by suppressing stale module loads after ended sessions, dropping
  or de-attributing stale eCAR process references after termination, and
  bounding parent/child termination repair so long-lived children do not drag
  parents hours forward. Automated eval passed at 96.7350560010721 over 78665
  records; the hard probe found zero eCAR modules, stale FLOW identities, or
  process terminates after matching Sysmon termination beyond the configured
  threshold. Blind scores were 47/64/35/52, average 49.50; deliberation final
  scores were 52/67/38/56, average 53.25. Next target: eCAR FILE
  source-native artifacts, especially Linux `/proc/<pid>/status` CREATE/WRITE
  rows and Windows Prefetch suffix morphology.
- Loop 205 fixed eCAR FILE source-native artifact pools (`2e86c4aa`) by moving
  Windows Prefetch templates to `{hex}` suffixes, removing generic Linux paths
  that could be paired with invalid churn actions, and adding `validate-config`
  guards for overlays. Automated eval passed at 96.83137893723699 over 76420
  records; the reviewer-finding probe confirmed zero decimal/non-hex Prefetch
  hits, zero Linux `/proc/<pid>/status` non-read hits, zero apache private-temp
  leaks, and zero service-principal `/etc/passwd` hits. Blind scores were
  42/38/64/63, average 51.75; deliberation final scores were 58/56/72/69,
  average 63.75. Next target: DNS source-native semantics, especially
  short-name/FQDN qtype behavior and resolver TTL modeling.
- Loop 206 fixed known internal DNS short-name semantics (`c95bd588`) by
  canonicalizing scenario host short names to internal FQDNs before resolver
  normalization and automatic lookup fan-out, and by rejecting MX owner context
  for single-label hostnames. Automated eval passed at 96.36440050584102 over
  78826 records; DNS probes confirmed zero internal short-name NOERROR rows,
  zero short-name MX rows, zero non-authoritative known internal FQDN rows, and
  zero public MX answers on internal names, with 7 remaining external RRset TTL
  increase cases inside 600 seconds. Blind scores were 28/36/68/66, average
  49.50; deliberation final scores were 58/61/72/70, average 65.25. The new
  highest-leverage target is TCP source-port lifecycle ownership: hard probes
  confirmed one same-sensor overlapping SMB 5-tuple in Zeek core and 32
  unmatched/stale eCAR FLOW examples after checking 9353 TCP flow rows.
- Loop 207 fixed SMB logon/transport ownership (`b7a9c0fa`) by binding
  companion Type 3 file-server logons to the just-emitted SMB transport source
  port and suppressing duplicate network evidence for that same session.
  Automated eval passed at 96.97058244405527 over 78480 records; hard probes
  confirmed zero same-sensor overlapping identical TCP tuple pairs and no
  recurrence of the loop-206 bad tuples. Valid blind scores were 48/30/34/33,
  average 36.25; deliberation final scores were 44/29/32/34, average 34.75.
  One initial detection review was discarded because the reviewer accidentally
  overwrote the frozen DC Security XML; the file was restored, data made
  read-only, and detection review rerun. The next target is texture rather than
  correctness: diversify Linux bash-history command pools by persona/role/host
  purpose and reduce exact-hour update/proxy/package traffic alignment.
- Loop 208 fixed exact Linux shell diagnostic repetition (`ca6ebca6`) by
  replacing broad exact diagnostic commands in the bash YAML pools, adding
  low-repeat command-family caps, and routing legacy activity-key shell commands
  through the shared command-memory selector. Automated eval passed at
  96.90138712062229 over 75650 records; rendered probes confirmed exact
  reviewer-cited command hits dropped from 30 in loop 207 to 1 in loop 208 and
  recent DNS/TCP tuple regression probes stayed clean. Blind scores were
  46/53/47/58, average 51.00. No deliberation was triggered because all
  reviewers agreed on Synthetic and score spread was small. The next
  highest-leverage target is Linux session semantics: reduce repeated named-user
  SSH fan-out across production Linux systems and eliminate unsupported generic
  eCAR `remote` successful sessions unless source-native SSH/PAM companion
  evidence exists.
- Loop 209 fixed Linux remote-session noise (`67bec768`) by keeping generic
  baseline Linux logon activity local/service, reducing organic SSH fan-out, and
  thinning ambient SSH noise while preserving SSH-bundle-owned remote sessions.
  Automated eval passed at 97.42953794362485 over 75679 records; rendered
  probes confirmed successful generic Linux `remote` eCAR sessions dropped from
  4 to 0 and successful SSH sessions dropped from 221 to 83. Blind scores were
  47/51/50/45, average 48.25. No deliberation was triggered because all
  reviewers agreed on Synthetic and score spread was small. The next
  highest-leverage target is multi-sensor Zeek timing texture: add per-sensor
  clock offset/drift, broader capture jitter, occasional missing companions, and
  packet-accounting variance.
- Loop 210 fixed multi-sensor Zeek timing texture (`f2b1c34b`) by widening
  flow-local sensor path-delay jitter inside configured timing bounds so
  duplicated core/DMZ observations no longer imply one fixed positive tap order.
  Automated eval passed at 97.42953794362485 over 75679 records; rendered probes
  showed paired core/DMZ conn offsets move from 1 negative / 2271 positive rows
  in loop 209 to 805 negative / 1467 positive rows in loop 210, with rounded
  offset buckets increasing from 25 to 91. Blind scores were 47/51/42/46,
  average 46.50. No deliberation was triggered because all reviewers agreed on
  Synthetic and score spread was small. The next highest-leverage target is
  Windows explicit-credential 4648 source/target semantics, with shell workflow
  texture close behind.
- Loop 211 fixed Windows explicit-credential 4648 source semantics (`c2c6a344`)
  by omitting synthetic local-host network endpoints from source-side 4648
  records while preserving authored modeled remote origins. Automated eval
  passed at 96.29214042141777 over 73942 records; the rendered probe showed
  loop 210 had 31/31 remote 4648 rows using the reporting host IP as
  `NetworkAddress`, while loop 211 had zero local-host-IP 4648 network
  addresses and only the authored attacker origin remained nonblank. Blind
  scores were 56/31/42/42, average 42.75. Deliberation was triggered by verdict
  disagreement and ended Inconclusive with final scores 50/38/42/44, average
  43.50. The next highest-leverage target is Windows remote-execution lifecycle
  texture, especially long-lived PsExec parentage and audit-log-clear 1102
  subject rendering.
- Loop 212 fixed Windows PsExec remote-execution lifecycle texture (`0ad5983c`,
  `b725f912`) by bounding `PSEXESVC.exe` lifetime, expiring stale PsExec service
  context, and emitting explicit wrapper termination. Automated eval passed at
  96.39589873896136 over 74657 records; the rendered probe showed loop 211 had
  8 PSEXESVC-parented child processes, 7 late children after two minutes, no
  termination, and 6 monitored later commands parented by PsExec, while loop
  212 had one immediate PsExec child, one termination, zero late children, and
  zero monitored later commands parented by PsExec. Blind scores were
  78/86/91/86, average 85.25. No deliberation was triggered because all
  reviewers agreed on Synthetic. The next highest-leverage target is endpoint
  source-native consistency, especially Windows Security channel `EventRecordID`
  monotonicity after log clear and eCAR FLOW/session/process lifecycle timing and
  identity pairing.
- Loop 213 fixed Windows Security channel `EventRecordID` monotonicity
  (`9ce3ad27`) by removing the renderer reset on Event ID 1102 while preserving
  the 1102 event. Automated eval passed at 96.39589873896136 over 74657 records;
  the rendered probe showed loop 212 had one non-increasing/decreasing Security
  record-ID transition on DC-01, from Event ID 4688 record `11619147` to Event
  ID 1102 record `2`, while loop 213 had zero non-increasing record IDs across
  7044 Security rows and still had one 1102 row. Blind scores were
  86/88/86/88, average 87.00. No deliberation was triggered because all
  reviewers agreed on Synthetic. The next highest-leverage target is
  source-observation realism for endpoint/network/proxy correlations: reduce
  same-second eCAR FLOW/Zeek/proxy completeness with realistic jitter, dropout,
  caching, and source-specific visibility gaps while preserving huntable pivots.
- Loop 214 fixed eCAR FLOW source-observation timing texture (`9895f149`) by
  widening the data-driven `source.ecar_flow` latency profile from 40-300ms to
  180-1800ms while preserving connection-interval clamps and remote-session FLOW
  ordering tests. Automated eval passed at 96.39580305774429 over 74653 records;
  the hard probe matched 13565 eCAR FLOW rows to Zeek tuples in both loop 213 and
  loop 214, with same-second matches dropping from 66.31% to 43.84%, within-one-
  second matches dropping from 99.42% to 70.61%, and p90 delta moving from
  0.573s to 1.649s. Blind scores were 68/64/67/74, average 68.25. No
  deliberation was triggered because all reviewers agreed on Synthetic and score
  spread was 10 points. The next highest-leverage targets are eCAR Linux
  local-session durability and file/process ownership, TLSv1.2 resumed-handshake
  consistency across `resumed`/`ssl_history`/certificate FUIDs, and Windows
  source-native texture for Defender paths and Sysmon `ProcessGuid` shape.

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
