# Iterative assessment loop 6

## Outcome

**Selected family:** canonical macOS process identity chronology. **Owner:** the
StateManager process allocator and action-cohort builder. The change reserves one host-scoped
temporal PID-version timeline for fork births and exec image transitions, persists it through
checkpoint state, and rolls it back with action cohorts. Behavior revision 405 records the
change. The authored scenario was unchanged in this loop.

The focused identity, action-cohort and incremental-checkpoint suites passed: 264 tests. Ruff
check and format passed for the changed Python files. Full generation completed in 2m25s with
141,187 records. Quantitative evaluation passed at **96.880514**; all four pillars passed their
acceptance gates (parseability 100, plausibility 96.7070, causality 97.0009, timing 92.2677).

The full-output probe checked all 98 fork/exec target transitions on MAC-MROSS-01 and all 120
on MAC-MROSS-02. Both hosts had **zero PID-version reversals** when sorted by native event time.
The output keeps actor and target identity separate and host-scopes versions. The temporal
allocator uses 1,024-value reservation headroom to permit late event-time insertions; this leaves
large numerical gaps between many visible transitions and remains a realism risk to monitor.

## Individual expert summaries

- **Threat Hunter — Synthetic, verdict confidence 98, synthetic-confidence 87.** It found
  empty-input SHA-1/MD5/SHA-256 digests on two named Windows executables and three eCAR SSH
  attempts where failed authentication precedes the matching TCP FLOW/CONNECT. It also found
  coherent process, file, SMB and proxy pivots.
- **Detection Engineer — Inconclusive, verdict confidence 68, synthetic-confidence 32.** It
  identified three Security/eCAR process starts without matching Sysmon Event 1 rows, while
  sampled Windows, Zeek, and macOS records were source-native and correlated.
- **Network Forensics — Inconclusive, verdict confidence 64, synthetic-confidence 38.** It
  found valid flow states and linked Zeek companions, plus a weak concern about iPhone and Mac
  user-agent families sharing the DHCP-mapped MAC-MROSS-01 address.
- **Host/EDR Forensics — Synthetic, verdict confidence 78, synthetic-confidence 68.** It found
  repeated macOS shell-discovery commands across both hosts, and reported coherent ES target-token
  PID-version transitions with no decisive endpoint contradiction in its sample.

## Deliberation

Deliberation ran because the verdicts split and synthetic-confidence scores spanned 55 points.
The panel preserved the distinction between Threat Hunter's direct hash and eCAR-order findings,
Detection's three missing Sysmon process starts, Network's user-agent concern, and Host/EDR's Mac
command texture. No reviewers provided revised positions, so initial scores carried forward:
mean synthetic-confidence **56.25**, mixed/inconclusive.

## Prioritized improvements

1. **P0 — Empty-input digests on executable images (`hard_contradiction`; Threat Hunter).** The
   `curl.exe` process on WS-AJOHNSON-01 and `DeviceSyncSvc.exe` on DC-01 carry exact empty-file
   digest triplets despite executable image paths. Investigate canonical binary/local-artifact
   content sizing and identity publication, not only Sysmon rendering. High score leverage; broad
   sibling risk across Windows executable identities.
2. **P0 — SSH authentication precedes matching eCAR FLOW (`contract_gap`; Threat Hunter).** Three
   failed `svc_mgmt` SSH attempts have eCAR USER_SESSION/LOGIN timestamps 180–293 ms earlier than
   their same-tuple inbound FLOW/CONNECT observations. Trace transport open and auth-attempt timing
   through the SSH action bundle and eCAR source timing. High score leverage; shared owner should
   cover baseline and authored SSH sessions.
3. **P1 — Repeated Mac shell-discovery texture (`distribution_texture`; Host/EDR).** A compact
   command family repeats across both Macs and sessions. The loop-5 scenario adjustment reduced
   command repetition but did not remove the visible pattern. Review scenario-authored task
   selection and user/session variation before adding further commands or changing engine pools.
4. **P2 — Three unmatched Sysmon process starts (`contract_gap`; Detection Engineer).** Security
   4688 and eCAR show starts for DC-01 PID 5572 and WS-MCHEN-01 PIDs 8360 and 8580 without matching
   visible Sysmon Event 1 rows. Determine whether source observation/filtering explains each absence.
5. **P3 — iPhone user-agent share on a Mac-mapped address (`environment_or_collection_plausibility`;
   Network Forensics).** `10.10.1.41` has substantial iPhone, Safari, and Chrome user-agent traffic.
   The reviewer notes plausible emulation/shared use; verify endpoint/application ownership before
   changing the profile.

## Comparison with quantitative evaluation

Evaluation passed all hard acceptance criteria and did not flag either the Sysmon empty-hash values
or the repeated eCAR SSH ordering inversions. Its strong causality and plausibility totals therefore
do not resolve these source-specific authenticity findings. The evaluation reports 16 field-agreement
failures among 34,039 matched pairs, but this remains well above its hard gate and was not the
primary driver of the blind reviews.
