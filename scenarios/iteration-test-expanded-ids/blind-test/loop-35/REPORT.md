# Loop 35 Assessment Report

## Outcome

This was the first clean post-architecture baseline. It used newly generated
data and four fresh blind reviewers; no finding, score, or target from loops
1-34 was supplied to generation, evaluation, review, or target selection.

Generation produced 85,173 records. Automated evaluation scored 95.91 but
failed its pivot-linkability hard gate at 31/62 edges (50/100); all canonical
cross-source invariants, 16,598 field-agreement pairs, 185 IDS assertions, and
12,888 causal-ordering pairs passed.

The initial blind panel voted Synthetic 3-1 at 64/64/28/66 (average 55.5).
Mandatory deliberation ended Synthetic 3-1 at 68/69/44/71 (average 63.0).

## Fresh Findings

- Source-native schema fidelity is the strongest categorical family: all 227
  Snort alerts render classtype slugs, all 1,049 Security 4624 v2 records use
  non-manifest field order, and all seven Sysmon Event 8 v2 records omit
  SourceUser and TargetUser.
- Host lifecycle projection leaks only termination rows after the apparent
  collection cutoff, through 18:49, across eCAR, Security, and Sysmon.
- Several attack actions lack visible canonical companions: source-side PsExec,
  WMI triggers, and service-binary delivery.
- Network telemetry was judged strongly production-like; its main reservations
  were stable DHCP cadence and absent NTP.

## Next Backlog Family

Correct source-native schema projection from versioned contracts: resolve Snort
classification descriptions, serialize Security 4624 v2 in provider-manifest
order, and render Sysmon Event 8 v2 user fields with strict fixture coverage.
