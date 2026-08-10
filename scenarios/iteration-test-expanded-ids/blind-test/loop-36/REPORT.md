# Loop 36 Assessment Report

## Outcome

Loop 36 regenerated all 85,173 records from the current code and supplied only
neutral copies of that output to four fresh blind reviewers. No previous-loop
finding or report was supplied to generation, evaluation, review, or target
selection.

Automated evaluation again scored 95.91 and failed only the scenario's existing
pivot-linkability gate at 31/62 edges (50/100). Canonical invariants, field
agreement, IDS integrity, causal ordering, and source schemas passed. The Loop
35 rendering target was independently absent from all four new critiques: Snort
classifications were source-native, Security 4624 v2 field order matched its
manifest, and Sysmon Event 8 carried both user fields.

The initial blind panel returned Real/Inconclusive/Synthetic/Synthetic at
32/49/67/78 (average 56.5). Mandatory deliberation revised this to
Inconclusive/Synthetic/Synthetic/Synthetic at 55/63/72/77 (average 66.8).

## Fresh Findings

- Endpoint lifecycle projections selectively continue after the declared
  six-hour primary window: correlated Security 4689, Sysmon Event 5, and eCAR
  PROCESS/TERMINATE rows appear as late as 18:49 while ordinary activity stops.
- Public-client population texture is too uniformly spread across IPv4 space,
  includes many improbable completed sessions from DoD ranges, and has only
  eight exact user agents across 67 external HTTP clients.
- Remote WMI-like execution on FILE-SRV-01 lacks visible RPC endpoint-mapper and
  dynamic DCOM transport companions.
- Secondary current-loop findings include unlock subject semantics,
  proxy-denial tunnel accounting, cloned Linux hardware texture, and absent NTP.

## Next Backlog Family

Enforce the half-open collection cutoff at final source admission for endpoint
lifecycle observations. Processes still active at the cutoff remain open in the
slice; their later Security 4689, Sysmon Event 5, and eCAR PROCESS/TERMINATE rows
must not render.
