# Post-Gate Blind Realism Assessment

## Result

The four reviewers unanimously classified the loop-3 integrated dataset as synthetic. Their
synthetic-confidence scores were 72, 74, 84, and 85, for an average of 78.75 (`likely synthetic`).
This is a material reduction from the pre-repair panel average of 96.5, but not a passing gate.
Deliberation did not run because the verdict was unanimous, average verdict confidence was 88.25,
and the score spread was only 13.

The automated evaluator passed at 95.3524/100 over 48,839 records. Its 100 scores for parseability,
field agreement, causal ordering, and rate plausibility correctly reflect major strengths, while the
blind panel found source contracts and population texture that the evaluator does not yet measure.

## Verified gate work

Three P1 authentication/session defects are the bounded loop-4 gate repair:

- A session established before the output window could lazily create `/bin/login` inside the
  window, making a visible local login process incompatible with the intentionally absent opening.
- Windows 4624 discarded the session-owned winlogon PID and rendered one host-global PID for
  overlapping interactive sessions.
- All 29 Event 4648 records used `NetworkAddress`/`NetworkPort` rather than native
  `IpAddress`/`IpPort` XML names.

The fixed nine-module startup tuple is a verified sibling in the repaired module family and remains
the bounded loop-5 target. Network defects—zero-payload content alerts, NAT teardown containment,
sensor timing, identifier morphology, and visibility questions—remain in Batch 3. Fleet software,
Linux identity/daemon texture, scanner population, and SSH demand remain in Batch 4. This preserves
the completed review's dependency order rather than allowing the blind panel to become a new
backlog owner.

## Reproducibility

- Reviewed data: `/private/tmp/eforge-postbatch2-lifecycle-loop3/branch-enterprise/data`
- Neutral panel copy: `/private/tmp/case-zeta.7JbRlL`
- Pre-loop-4 probe: `/private/tmp/eforge-postbatch2-lifecycle-loop3/probe-loop4-before.json`
- Reports: `threat-hunter.md`, `detection-engineer.md`, `network-forensics.md`, and `host-edr.md`
- Machine-readable results: `scores.json` and `verified-findings.json`
