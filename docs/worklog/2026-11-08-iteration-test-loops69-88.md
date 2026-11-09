# Iteration test loops 69–88

User requested 20 EvidenceForge realism assessment/fix loops, continuing after loop 68. This
worklog tracks loop 69 through loop 88. Do not edit `TODO.md` for this branch-local effort.
Preserve pre-existing uncommitted work and untracked loop44–68 artifacts. No commits requested.

All 20 loops are complete. The dashboard and final summary are in
`scenarios/iteration-test/blind-test/REPORT.md` and
`scenarios/iteration-test/blind-test/assessment-effectiveness-dashboard-last-20-loops.svg`.

## Completed

### Loop 69 — Linux foreground think time

- Changed `baseline.foreground_think` upper bound from 18s to 180s in
  `src/evidenceforge/config/activity/timing_profiles.yaml`; behavior revision 489.
- Added focused timing-profile coverage. 11 tests passed; config, Ruff and behavior checks passed.
- Fixed-seed output probe found no repeated 94–98s gaps in 14 WS-LNGUYEN editor/build gaps.
- Evaluation: 96.7911 PASS, 135,860 records. Four standalone reviews all inconclusive, mean
  synthetic-confidence 48.5. A/B loop68 vs loop69 split two ties / one preference each way;
  do not treat comparative scores as trend scores.
- Full report and artifacts: `scenarios/iteration-test/blind-test/loop-69/`.

### Loop 70 — UDP firewall state expiry

- Loop69 reproduced 11 ASA UDP/514 build/teardown pairs with zero displayed duration, while
  one-way Zeek UDP rows correctly remained durationless `S0` (33 rows, eight multipacket).
- Changed `source.firewall.datagram_teardown` to a right-skewed 1s–120s idle expiry after last
  observed datagram; Zeek duration semantics remain unchanged. Behavior revision 490.
- Targeted tests: 39 `test_network_observation.py` and 71 `test_cisco_asa_emitter.py` passed.
  Scenario validation passed with existing warning/info notices; 101 config files valid; Ruff,
  behavior manifest and diff checks passed. Full routine suite not run.
- Fixed-seed probe: 11 matched ASA UDP/514 pairs now show 7–78s duration, zero zero-duration;
  33 Zeek rows remain `S0` without `duration`. Evaluation 96.7911 PASS, 135,860 records.
- Four independent reviewers disagreed (Inconclusive / Synthetic / Real / Inconclusive), with
  synthetic-confidence scores 57 / 66 / 24 / 34, mean 45.25. Deliberation preserved the split;
  it identified Linux sysstat cadence and PID progression as unresolved and context-dependent.
- Full report and artifacts: `scenarios/iteration-test/blind-test/loop-70/`.

### Loop 71 — Windows session-specific SMSS ownership

- The loop65/68 session-parent finding reproduced in loop70: Winlogon starts from multiple
  terminal sessions shared one exact SMSS parent identity. Added per-session SMSS ownership to
  baseline interactive and RDP session bootstrap, with Winlogon parented to that identity.
- The first loop71 generated candidate exposed a teardown gap in the RDP bundle: session SMSS
  used the SYSTEM LUID and was outside the user's session process set. Added it to the RDP exact
  target-close plan and allowed the exact RDP terminal projection to authenticate that SYSTEM
  SMSS lifecycle. Re-generated and blind-reviewed the final candidate; the first-pass reports are
  retained under `loop-71/pre-fix-review/` and excluded from canonical scores.
- Final fixed-seed probe: 21 visible Winlogon creates, all with distinct visible SMSS parents;
  no parent GUID reused across sessions. Sysmon and Security 4688 each show 21 SMSS/21 Winlogon
  creates. eCAR shows 21/20. Sysmon5, Security4689 and eCAR each show 20 SMSS/19 Winlogon
  terminations; remaining session lifetimes are interpreted within the bounded window.
- Validation: scenario valid with existing warnings/info; all 101 config files pass. The RDP
  slow suite passed 70 tests; activity and State Manager passed 637 tests (2 deselected). Ruff,
  format, diff and behavior manifest checks pass at revision491.
- Evaluation: 96.1181 PASS, 141745 records. Fresh standalone scores: Threat52, Detection33,
  Network54, Host55; mean48.5. All verdicts Inconclusive, mean verdict confidence65.75, spread22;
  deliberation not triggered. Next candidate is persistent browser-root lifecycle ownership,
  previously corroborated in loop65/68. Full report and artifacts: `loop-71/`.

### Loop 72 — Browser root ownership verification

- The prior browser-root concern was tested against the unchanged scenario/seed42 output.
  Current Mac native Endpoint Security data has one visible Chrome main-root exec per Mac host,
  each with an in-window exit. Windows Sysmon shows no more than one concurrent Chrome root per
  observed host/user; WS-PPATEL-01's two roots are sequential. Twelve browser-instance tests pass.
- No code or scenario changes were made: the shared profile-key/reuse model was already present,
  and the reported overlap did not reproduce. Classification is `false_positive_or_unproven` for
  this output.
- Evaluation is 96.1181 PASS, 141745 records. Standalone synthetic-confidence scores are
  Threat52 / Detection24 / Network38 / Host48; mean40.50, verdict-confidence mean66, spread28.
  Verdict disagreement triggered deliberation, which retained the split and did not establish a
  synthetic-only defect. Rolling5 is43.75. Average fell eight points from loop71 with no code
  change; this is reviewer/sample variance, not a fix effect.
- Threat and Network independently flagged repeated `10.10.3.10` `.top` DNS activity and
  unanswered internal TCP probes to `10.10.2.30:8080/443`. Both allow plausible beaconing,
  monitoring, or unavailable-backend explanations. Next loop should identify the activity owner
  and determine whether visible evidence supports a family-level correction before editing.
- Artifacts: `scenarios/iteration-test/blind-test/loop-72/`.

### Loop 73 — Linux logind session identity allocation

- Fixed the confirmed elapsed-minute-derived logind ID progression in the canonical `StateManager`
  allocator. The prior output showed near-exact 8–9 IDs/minute fits on eight Linux hosts. The new
  fixed-seed output has weaker minute correlation, positive IDs, and 1–56-step visible increments;
  IDs remain tied to chronological allocations.
- The family-level shared allocator covers SSH, local interactive, and baseline session entry paths.
  Focused tests passed (5 logind/activity, 2 baseline terminal admission, 1 checkpoint restore),
  as did Ruff, formatting and the generation behavior manifest check at revision492. Validation
  passed with the established warnings. Full routine pytest was not run.
- Automated evaluation: 96.1181/100, PASS, 141745 records. Blind synthetic-confidence scores:
  Threat63 / Detection34 / Network36 / Host34, mean41.75; verdict confidence mean78.25, spread29.
  Threat chose Synthetic, Detection Real, and Network/Host Inconclusive; deliberation was triggered
  and preserved the split without revised votes. No hard contradiction was established.
- Three reviewers noted two or three macOS Unified Log records per host; collection scope is
  unknown, so this remains unproven. Network noted a narrow, partly old browser UA mix as weak
  texture. Threat's internal IDS/DNS alert cluster remains compatible with a compromised or
  misused host. Next candidate: qualify UA versions by generated traffic path and canonical software
  identity before changing the shared version/profile owner.
- Artifacts: `scenarios/iteration-test/blind-test/loop-73/`.

### Loop 74 — Windows browser User-Agent identity

- Confirmed loop73's old browser majors were internal Windows workstation User-Agents from the
  proxy catalog, while modeled binaries are Chrome 120, Edge 120 and Firefox 121. Narrowed the
  generated Windows workstation catalog to those versions. Generated-default provenance now flows
  through browser request and HTTP context so the shared planner can bind generated headers to a
  known process while retaining authored headers. Added a catalog invariant test. Behavior revision
  495.
- Loop74 generation also surfaced a rare exhausted interval in out-of-order Linux logind ID
  allocation; the bounded uniqueness fallback allows generation to continue when no integer
  remains between assigned temporal neighbors. The final output has 57 visible New sessions across
  11 Linux hosts, unique IDs, and zero chronological inversions.
- Browser probe: 360 exact Sysmon Event3-to-Zeek HTTP tuple matches, 179 browser-family requests
  matched to process FileVersion, zero major mismatches. `eforge validate-config` checked 101 files
  with no issues. Focused tests: 53 ownership/browser/session/logind tests and 4 UA-pool tests
  passed. Ruff checks, formatting, diff check and behavior manifest passed; full routine pytest not
  run.
- Evaluation: 96.3400 PASS, 135,966 records (parseability 100, plausibility 96.82, causality
  95.90, timing 90.79). Blind synthetic-confidence scores Threat34 / Detection48 / Network43 /
  Host47, mean43.00; verdict-confidence mean63.75, spread14. All reviewers chose Inconclusive, so
  deliberation was not triggered. Mean moved up 1.25 from loop73; no hard contradiction was found.
- Next candidates: verify the near-equal six-second scanner burst across four ports (Network P2)
  and the repeated high Linux forwarding queue counters (Detection P3) against their owning
  activity/collection models. Sparse macOS Unified Log coverage remains unproven without collection
  scope. Artifacts: `scenarios/iteration-test/blind-test/loop-74/`.

### Loop 75 — Scanner fan-out and Linux forwarding queues

- No generator changes. The scan concern maps to the authored WEB-EXT-01 Nmap command and the
  scanner planner's configured 6–12 second connect window. Across the five ports, Zeek core shows
  253–254 distinct targets each in 6.2 seconds, with a mixed set of incomplete/refused/reset
  states; the DMZ sensor has independent timing and similar counts. This is plausible scanner
  activity, not a confirmed defect.
- The output includes 39 rsyslog queue reports across 11 Linux hosts; 7 report more than 1,000
  pending, max 3,698. Values change across host checkpoints and do not establish an impossible
  queue transition; this remains a low-confidence distribution concern. The macOS launchd alert
  was a false positive: fork-time inherited image followed by same-process xpcproxy/application
  exec transitions, corroborated by Endpoint Security and eCAR.
- Scenario validation passed. Human/JSON eval exactly matches loop74: 96.3400 PASS, 135,966
  records. Blind initial scores Threat55 / Detection66 / Network57 / Host52 (mean57.50); verdict
  disagreement triggered deliberation. All final verdicts are Inconclusive with scores Threat46 /
  Detection44 / Network55 / Host43 (mean47.00); the only Synthetic vote was withdrawn after
  resolving the fork/exec semantics. The 10.50-point initial-to-final decrease comes from correcting
  that interpretation; against loop74's 43 mean, final loop75 is +4 with no code change.
- Next candidate: inspect the rsyslog pending/arrival state model against the full-host temporal
  series and source-route profile. Do not impose a fixed cap unless the values conflict with the
  modeled asynchronous workload or show an impossible transition. Artifacts:
  `scenarios/iteration-test/blind-test/loop-75/`.

### Loop 76 — Linux forwarding queue state

- Fresh validation, fixed-seed generation, human/JSON evaluation and four blind reviews completed.
  The generated output's queue probe covered 75 updates across 11 hosts; all pending and
  checkpoint transitions are within model bounds, with no capacity exceedance. Seven hosts report
  more than 1,000 pending and the maximum is 3,698, but the trajectories are attainable; no queue
  change was justified.
- Evaluation: 96.3400 PASS, 135,966 records. Initial synthetic-confidence scores Threat84,
  Detection72, Network18, Host45 (mean54.75); verdicts split Synthetic/Synthetic/Realistic/
  Inconclusive and score spread66 triggered deliberation. Revised mean is54.00, still split, with
  no hard contradiction or definite contract gap.
- Deliberation elevated recurring IDS/DNS background texture, high Linux PIDs, repeated generic
  commands, and collection-boundary alignment as suggestive distribution cues, all with plausible
  alternatives. Network tuple/UID evidence and endpoint process lifecycles are internally coherent.
  Next candidate: verify Linux PID scale and exact shell-history recurrence against shared owners.
  Artifacts: `scenarios/iteration-test/blind-test/loop-76/`.

### Loop 77 — Linux PID and scheduled host texture

- Fresh validation/generation/evaluation completed. The output is byte-identical to loop76 across
  all 113 data files. Evaluation remains 96.3400 PASS, 135,966 records.
- The PID probe found million-scale values on 9/11 Linux hosts, below the configured PID ceiling
  and consistent with the host-specific hidden-churn allocator. The specific repeated shell-history
  trio cited by Detection was not present in the neutral copy; no PID/history code change was made.
- Threat Hunter identified `debian-sa1` twice-hourly executions on nine hosts. Independent
  reports otherwise found source-shaped logs and strong cross-source relationships, no hard
  contradiction, and no required-companion gap. Standalone scores Threat64 / Detection22 /
  Network22 / Host36 (mean36.00); verdict disagreement and spread42 triggered deliberation. Final
  deliberative mean39.25 remains mixed, with one Synthetic and three Inconclusive positions.
- A direct probe confirmed paired `/bin/sh` and `debian-sa1` process records at a stable
  half-hour cadence and per-host phase. This merits a focused loop79 schedule-owner review; it is
  not a source-native impossibility. Loop78 examines DNS/IDS family distribution.
  Artifacts: `scenarios/iteration-test/blind-test/loop-77/`.

### Loop 78 — DNS/IDS background families

- Reused the byte-identical seed42 output after loop77's 113-file checksum comparison; scenario
  validation and the authoritative evaluation passed (96.3400, 135,966 records). No generation
  behavior changed.
- The Snort probe finds 157 alerts across the two sensors. DNS `.top`/`.bit`/`.cloud`/`.tk`/`.to`
  families are the largest group, alongside scan and STUN signatures. Network review tied scan
  spikes to endpoint-visible Nmap and found matching DNS tuples; the four reviewers found no hard
  contradiction or definite contract gap.
- Standalone scores Threat46 / Detection31 / Network22 / Host18 (mean29.25); all verdicts
  Inconclusive, no deliberation. No alert-profile change is justified. Loop79 will qualify the
  recurrent `debian-sa1` schedule against Debian package sources and the scheduler model.
  Artifacts: `scenarios/iteration-test/blind-test/loop-78/`.

### Loop 79 — Debian sysstat cadence

- Verified the repeated half-hour `debian-sa1` texture against Debian's trixie `sa1` manual and
  sysstat build default: system-stat samples are scheduled every ten minutes. Updated the typed
  schedule contract and baseline planner to emit six minute-aligned firings per hour at a stable
  per-host phase. Per-event random draws isolate the added cron tasks while preserving the shared
  RNG consumption of two legacy slots, avoiding downstream fixed-seed activity drift. Generation
  behavior revision496.
- Scenario and config validation passed (101 files); focused schedule tests: 3 passed; Ruff,
  formatting, diff check and behavior manifest pass. Two initial fixed-seed attempts hit unrelated
  RNG-sensitive RDP/profile failures; the scoped-RNG version then generated successfully.
- Final probe: 36 paired `/bin/sh` / `debian-sa1` process starts on each of ten Linux hosts,
  minute-aligned. Evaluation96.5648 PASS, 142,740 records. Blind scores Threat34 / Detection69 /
  Network24 / Host78 (mean51.25, spread54); verdict split triggered deliberation. Final
  deliberative mean51.00 retained two Inconclusive and two Synthetic positions. No hard
  contradiction; reviewer disagreement centers on whether a uniform package cron schedule is a
  synthetic tell or normal fleet configuration. Loop80 independently checks the post-fix output.
  Artifacts: `scenarios/iteration-test/blind-test/loop-79/`.

## Current state

Loops 69–85 are complete; remaining work is loops 86–88. Reuse the
same canonical six-hour scenario/seed unless an assessment-supported family fix requires otherwise.
Do not expose scenario, ground truth, eval output, or prior reports to standalone blind reviewers.
Keep a neutral data-only directory under `/private/tmp` per loop; get four independent reviewers
and deliberate only on trigger. Keep A/B scores outside `scores.json`.

Loop79 changed the repeated Debian sysstat schedule to the package-supported ten-minute cadence.
The two initial generation attempts failed on RNG-sensitive RDP/profile paths; scoped draws for
added scheduled occurrences preserved successful fixed-seed generation. Loop80 is an independent
blind checkpoint on that output, with no code change planned absent a concrete defect. Loop78 found
a compact DNS/IDS signature palette but the alerts are tuple-supported, so no change is selected.
The loop77 PID probe finds 9 of 11 Linux hosts above one million, within the
shared allocator's configured PID range and host-specific hidden-churn model; the exact
three-command history sequence cited by one reviewer was not found in the neutral copy. The loop75
scan is explicitly authored and plausible; the reported macOS launchd issue was a fork/exec
interpretation error. Do not infer a source/collection defect from macOS Unified Log sparsity
without collection scope. Do not add arbitrary jitter or PID changes without evidence.

The prior loop68 report has the outstanding candidate list. For the final loop88, run
`/Users/dabianco/.codex/skills/eforge-assess/scripts/render_loop_dashboard.py`
with `scenarios/iteration-test/blind-test --current-loop 88 --window 20`, verify the SVG, and
include it in the final response. Do not update this handoff with transient status; add each
completed loop's result and current next candidate.


### Loop 80 — post-fix independent checkpoint

- Reused the byte-identical loop79 seed42 output after the 113-file post-fix copy; evaluation remains
  96.5648 PASS, 142,740 records. No generation behavior changed.
- Standalone scores Threat78 / Detection68 / Network54 / Host48 (mean62.00). Two Synthetic and
  two Inconclusive verdicts triggered deliberation. Calibrated final scores are Threat70 / Detection62 /
  Network53 / Host48 (mean58.25), with the same verdict split. Reviewers found no hard contradiction;
  fleet-wide exact sysstat cadence remains the strongest synthetic signal, while traffic burst concerns
  were plausible and macOS collection sparsity remains unverified. No code change selected.
- Loop81 begins a fresh independent panel on the same post-fix data. Artifacts:
  `scenarios/iteration-test/blind-test/loop-80/`.


### Loop 81 — ASA and DNS cross-source checkpoint

- Reused the byte-identical loop80 post-fix output (113 files); evaluation remains 96.5648 PASS,
  142,740 records. Standalone scores Threat42 / Detection68 / Network64 / Host48 (mean55.50,
  spread26); two Synthetic and two Inconclusive verdicts triggered deliberation. The panel calibrated
  to mean67.50 and 3–1 Synthetic.
- Detection reported 2,308/2,354 proxy-facing ASA tuples with apparent reverse orientation. Independent
  source verification found this is expected ASA output: Cisco documents outbound as inside-initiated,
  and its NAT example places the outside endpoint before the inside client. EvidenceForge's ASA emitter
  deliberately projects outbound rows in responder/originator order. This is a reviewer false positive,
  not a tuple-contract defect; no code change. Probe and sources: `loop-81/asa-direction-probe.json`.
- Network's remaining synthetic signals were a high-rate TXT series and periodic `.top` DNS queries;
  Threat/Host found no hard contradiction. Keep these as plausible malicious traffic/weak texture pending
  stronger evidence. Loop82 continues independent review on unchanged data. Artifacts: `loop-81/`.


### Loop 82 — typed Linux pipeline and source semantics

- Reused byte-identical post-fix output (113 files); evaluation remains 96.5648 PASS, 142,740 records.
  Standalone scores Threat68 / Detection72 / Network62 / Host36 (mean59.50, spread36); 3 Synthetic,
  1 Inconclusive. Deliberation calibrated mean65.50.
- Detection's macOS ES claim is a false positive: Apple defines `action_type=NOTIFY` as the `action.notify`
  `es_result_t`; its `result_type` chooses auth or flags. `result_type=0, auth=0` is valid in that union.
- Network's 5,134 core/DMZ tuple offsets center at −114.245ms; configured `distributed_taps` permits
  ±250ms sensor offsets, 200–3500us route delay and shared slow wander. Treat this as weak texture, not a
  demonstrated timing defect.
- Threat's process pipeline observation remains concrete. WEB-EXT-01 has one `bash -c` process and an
  attributed flow but no pipeline child records; baseline Linux shell telemetry expands pipeline stages.
  Loop83 will inventory/repair the typed process entry path if this is confirmed at the family owner.
  Probe artifacts `loop-82/{macos-action-probe,network-clock-probe}.json`.


### Loop 83 — typed Linux pipeline stage and ownership adapter

- Evaluation: 96.2810 PASS, 148,787 records (parseability 100.00, plausibility 96.86, causality 95.03, timing 91.54). Four fresh blind scores: Threat53 / Detection76 / Network68 / Host36 (mean58.25, spread40); verdict split triggered deliberation, final mean62.50.
- Typed Linux pipeline process events now resolve external stages through the shared parser/timing planner. WEB-EXT-01 eCAR creates `/usr/bin/base64` PID2702832 and nested `/bin/bash` PID2702833 under root shell PID2702831; reverse callback FLOW is attributed to PID2702833, which terminates after the FLOW. Behavior revision497. Focused pipeline tests and Ruff/manifest checks pass.
- Probe also shows parent PID2702831 terminates at 14:20:24.165Z before child PID2702833 at 14:20:35.700Z. The flow-owner extension did not ensure the outer foreground shell waits for its pipeline. Loop83 is a partial family fix; loop84 should first resolve this shared lifecycle hold.
- Detection identified 142 short same-account/client/source-port 4769→4768 inversions across the two DCs (62/80). They are present in the rendered XML; investigate Kerberos exchange ordering/timing at its owning bundle or source timing layer in loop84 before an emitter patch. Network's full subnet scan is authored by evt-006's two Nmap commands, so it is explained by scenario context. Shared six-hour windows and narrow 4688/Sysmon offsets remain weak and unproven.
- Artifacts: `scenarios/iteration-test/blind-test/loop-83/`. Loop84 starts on the unchanged scenario/seed, carrying forward both residual lifecycle and Kerberos-order candidates.


### Loop 84 — typed Linux pipeline parent lifecycle

- Validation passed with the scenario's existing advisories. Initial generation stopped at the behavior-manifest guard; after registering revision498 and matching digest, generation completed. A first attempt to propagate the network hold during child finalization did not alter output and was replaced before acceptance with a queued-parent-close check.
- The typed storyline termination flush now consults exact `storyline-linux-pipeline:<host>:<shell-pid>:` child finalizers before emitting the parent close. The loop84 probe confirms callback FLOW PID2702833 at 14:20:21.349Z, final child close 14:20:35.700Z, shell parent close 14:20:36.690Z (990ms later). A focused test confirms unrelated non-pipeline child state does not extend the parent. Behavior revision498.
- Focused tests: 3 passed. Full `ruff check .` and `ruff format --check .` passed after formatting the added test. Behavior manifest check passes. Evaluation96.2810 PASS, 148,787 records; identical to loop83.
- Four fresh blind scores Threat67 / Detection46 / Network27 / Host39 (mean44.75, spread40), with Synthetic, Inconclusive, Real, Inconclusive verdicts. Deliberation was triggered by disagreement and spread; final deliberative mean39.50, preserving all three verdict classes. Threat's clinical DB export and rapid Domain Admin account sequence are consequential but technically possible. Detection's sparse macOS Unified Log and Host's high 4688/Sysmon pairing remain ambiguous collection-shape observations; network scan is visibly owned by Nmap and needs no change.
- The 4769→4768 concern from loop83 remains unproven at transaction level; there is no shared canonical transport identity in the reviewer sample, and loop84 did not independently establish a specific reversal as a causal pair. No Kerberos timing change selected. Artifacts: `scenarios/iteration-test/blind-test/loop-84/`.

Loop85 should use the unchanged seed and select a new family from concrete loop84 review evidence or inspect current recurrence without retargeting unproven indicators. The pipeline family probe passed; avoid reopening it absent a regression.


### Loop 85 — independent post-fix checkpoint

- Reused loop84's byte-identical output; eval remains 96.2810 PASS, 148,787 records. Four fresh scores Threat52 / Detection47 / Network66 / Host34 (mean49.75, spread32), two Inconclusive and two Synthetic. Deliberation revised all four to Inconclusive (mean50.50); this is a facilitator estimate, not a new review measurement. Five-point increase from loop84 on unchanged data reflects reviewer variance and newly surfaced weak distribution concerns, not a code regression.
- Network's 14:30–14:45 dual-sensor volume spike is largely explained: 1,268 core and 1,271 DMZ connections match source10.10.3.10, target10.10.2.0/24, and Nmap's five authored ports. eCAR identifies Nmap PIDs2705081 and2705106 at 14:39:52Z/14:40:04Z. Mac flow concentration is to the visible PROXY-01 address/port. Neither merits code changes absent other contradictions.
- Threat identified DC-01 WMI/SYSTEM activity without clear initiating identity in its sample. This remains a potential investigation/companion-contract candidate, not a synthetic finding yet. Loop86 can inspect relevant Security/Sysmon/eCAR evidence for a concrete source/effect inconsistency before selecting code.
- No code or scenario changes; panel reviewed only copied data. Artifacts: `scenarios/iteration-test/blind-test/loop-85/`.

Loop86's first candidate is a bounded DC-01 WMI source/effect trace. If it does not establish a reproducible companion or attribution contract violation, continue independent review with no change rather than patching unknown operator identity.

### Loop 86 — DC-01 WMI source/effect attribution

- Continued Loop85's candidate attribution-gap probe. Security 4688 records show the account,
  privilege and persistence commands running as SYSTEM/LUID `0x3e7` under `WmiPrvSE.exe`; the
  visible 4720/4728 effects follow those commands. Nearby WS-PPATEL/DC-01 SMB network logons
  correlate to separate tuples and do not establish a WMI initiator. The authored scenario models
  these steps as SYSTEM and does not assert a remote source, so no concrete generator contradiction
  was proven and no code/scenario change was selected.
- Fresh-panel input is byte-identical to Loop84 output, copied under a neutral label. Human/JSON
  evaluation remains 96.2810 PASS, 148,787 records. Four fresh standalone reviewers scored Threat29 / Detection19 / Network28 / Host18 (mean23.50, spread11; mean verdict confidence70.50). All verdicts were Inconclusive; deliberation was not triggered. The 26.25-point decrease from loop85's standalone mean on unchanged data is reviewer variance, not a dataset or fix effect.
- No P0–P2 defect or generator change was established. Artifacts: `scenarios/iteration-test/blind-test/loop-86/`.

### Loop 87 — DC-02 Citrix installer transfer trace

- Continued the panel's unusual-installer observation. Zeek DMZ shows a complete 124,385,593-byte
  HTTP transfer from DC-02 to the proxy and the external fetch; both file observations share the
  same SHA-1 and byte count, and the client flow completes in 7.51 seconds. Inspected DC-02 eCAR
  and Windows files do not show an exact endpoint flow/process/file companion. That absence does
  not prove installation or a collection-contract violation; the scenario does not claim execution.
  No code or scenario change was justified.
- Loop87 is a fresh blind panel on a byte-identical copy of Loop84 output; automated evaluation
  remains 96.2810 PASS (148,787 records). Standalone scores Threat34 / Detection34 / Network24 / Host26 (mean29.50, spread10; mean verdict confidence74); all verdicts are Inconclusive and deliberation was not triggered. The six-point rise versus loop86 is reviewer variance on unchanged data.
- No code/scenario change. Artifacts: `scenarios/iteration-test/blind-test/loop-87/`. Continue with the final Loop88 panel/dashboard.

### Loop 88 — eCAR ordering semantics (final loop)

- Investigated Loop87's weak signal across 23 per-host files: 38,468 records, zero timestamp
  inversions, and millisecond ties in 13 files. This is explicitly owned by the eCAR writer's
  chronological flat-file/external-sort contract (`_sort_flat_file`, `_external_sorting`, and
  `_ecar_sort_key`), so sorted output is not an unexplained source-order guarantee or defect.
- Four fresh blind reviewers all chose Synthetic: Threat69 / Detection68 / Network67 / Host64
  (mean67.00, spread5; mean verdict confidence79.5). No deliberation trigger. Input is
  byte-identical to Loop84; automated evaluation remains 96.2810 PASS, 148,787 records. The
  37.50-point rise from Loop87 is reviewer interpretation on unchanged data.
- Host's reused macOS `traceID` finding is a false positive: `UnifiedLogCallsite.trace_id` encodes
  a static tracepoint/callsite, not an occurrence ID; the same executable callsite should reuse it.
  Threat's claimed 15:06 event after 15:59 failures was also chronologically reversed in the XML.
  Neither was counted as a generation defect. Network's concentrated DB pair and DMZ scans remain
  contextual distribution findings; no direct contradiction or code change was established.
- The dashboard was generated for loops69–88 and XML-parsed. Latest standalone mean is 67.00;
  5-loop rolling mean 42.90. No scenario change. Artifacts and consolidated findings are in
  `scenarios/iteration-test/blind-test/REPORT.md` and `loop-88/`.
- Normalized the historical `host_edr_forensics` score key to canonical `host_forensics` in
  loops71–72 so the dashboard includes their available host scores; averages are unchanged.
