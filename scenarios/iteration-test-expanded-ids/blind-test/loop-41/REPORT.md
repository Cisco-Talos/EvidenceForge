# Loop 41 Assessment Report

Loop 41 generated 88,028 new records after correcting Windows OpenSSH client
ancestry. Automated evaluation scored 95.8299 and failed only pivot
linkability. All 61 `ssh.exe` processes were parented by a visible `cmd.exe` or
`powershell.exe` in the same active session; none were parented by browsers,
mail clients, or Explorer. The four fresh reviewers did not repeat that defect.

The initial blind panel was Inconclusive/Synthetic/Real/Synthetic at
45/68/36/67, average 54.0. Verdict disagreement and a 32-point spread triggered
deliberation; the final panel was unanimously Synthetic at 63/70/66/64, average
65.75.

## Individual Expert Summaries

The Threat Hunter was initially Inconclusive (82% verdict confidence,
synthetic-confidence 45). Operational chains and source volumes were
convincing, but denied and 407 CONNECT outcomes had narrowly clustered
457–480 ms durations and misleading tunnel accounting; endpoint time-sync
state also lacked UDP/123 evidence.

The Detection Engineer assessed Synthetic (88%, 68). The decisive evidence was
repeated source-native actor mismatch: WER and Defender files were created by
unrelated processes, 275 CBS package-state writes were spread across generic
service/installer actors, and Office/Explorer MRU writes were attached to bare
PowerShell launches.

The Network Forensics reviewer initially assessed Real (68%, 36). Connection,
DNS, TLS, and cross-sensor transport behavior looked plausible, while 53 TLS
sessions referenced 79 certificate FUIDs absent from both `x509.log` and
`files.log`, and the otherwise broad collection contained no NTP traffic.

The Host/EDR reviewer assessed Synthetic (76%, 67). It emphasized 316 Type 5
logons without visible logoffs, dense updater activity, and endpoint lifecycle
texture. It also found the corrected SSH shell ancestry plausible.

## Deliberation Findings

The panel converged unanimously on Synthetic at an average 65.75. Repeated
Windows actor-to-artifact contradictions outweighed the otherwise strong
transport and hunt-chain fidelity; proxy outcome texture, Type 5 lifecycle
imbalance, and dangling certificate references remained independent supporting
signals.

## Prioritized Improvements

- **P0 — Bind endpoint file and registry effects to their owning process
  families.** Detection found 68 of 99 Sysmon Event 11 WER/Defender artifacts
  owned by unrelated processes and 275 of 569 Event 13 rows targeting CBS
  package state through generic actors. This is repeated, high-leverage,
  source-native contradiction. Fix the baseline side-effect planner/config so
  WER, Defender, servicing, Office, Explorer, and installer artifacts are
  eligible only for compatible process families. Owning layer: endpoint
  side-effect selection; medium implementation risk.
- **P1 — Model Type 5 logon lifecycle/consumption.** Host found 316 service
  logons and no visible logoffs. This dataset-wide imbalance needs explicit
  service-session consumption and closure or a collection profile that explains
  the omission. Owning layer: Windows service action/session bundle; medium
  risk.
- **P1 — Make terminal proxy outcomes terminal.** Threat Hunter found repeated
  deny/407 CONNECT durations in a narrow band and populated tunnel fields when
  no tunnel formed. Owning layer: proxy transaction outcome plan; medium risk.
- **P2 — Keep TLS certificate references sensor-complete.** Network found 79
  certificate FUID references absent from both analyzer and file logs. Ensure
  every visible reference resolves to a visible file observation or omit the
  reference according to the sensor observation plan. Owning layer: frozen
  network observation plan; medium risk.
- **P3 — Align time-sync state with observable NTP.** Endpoint writes indicating
  successful synchronization should be paired with eligible UDP/123 activity,
  or the state artifact should be suppressed. Owning layer: NTP bundle and
  endpoint noise contract; low-to-medium risk.

## Priority Rationale

The endpoint ownership family is first because it creates explicit false
causality in high-volume source-native telemetry and dominated the current
cross-specialty consensus. The remaining targets are ordered by contradiction
strength, recurrence, specialist authority, and breadth of the owning fix.

## Comparison with Quantitative Eval

The automated evaluator verified 100% parseability, 100% causal ordering, and
high field agreement, but it does not yet test actor-native ownership for these
file/registry families or Type 5 consumption. Conversely, reviewers did not
emphasize the evaluator's only gate failure, 50% pivot linkability. Automated
score remains a regression guardrail; the fresh blind findings select the next
target.
