# Iterative assessment loop 10

## Outcome

Loop 10 continued the Mac process-exec timing family. The planner added a prior-execution floor and at least one millisecond of repair slack. That change was still insufficient: the fresh output retains **14** same-PID timestamp groups on MAC-MROSS-01 and **17** on MAC-MROSS-02 where fork/exec rows have different execution identities in the same eCAR millisecond. Inspection showed the guard compared exact datetimes and accepted a preferred time a few microseconds after the floor even when eCAR serialized both to the same millisecond.

The family contract and owner are unchanged. Loop 11 adds a rendered-millisecond collision predicate before accepting the preferred timestamp; it is currently being verified in a fresh bundle.

Fresh generation completed at `/private/tmp/eforge-iteration-test-macos-loop-10`; it contains **141,247 records** and passed one JSON evaluation at **96.880577** (parseability 100, plausibility 96.7070, causality 97.0011, timing 92.2677). All applicable hard criteria passed. The 120-file data-only blind copy was SHA-256 verified against its generation manifest.

The loop 10 source-timing suite passed (82 tests), including a regression that first asserted an exact predecessor floor; the family output probe demonstrates why the extra integer-millisecond assertion was needed. Ruff check/format and behavior manifest validation passed at revision 409.

## Family probes

| Mac host | Fork/exec rows | Same-PID same-ms groups |
|---|---:|---:|
| MAC-MROSS-01 | 98 | 14 |
| MAC-MROSS-02 | 118 | 17 |

The loop 10 panel's strongest additional source-native finding is that the ES payload uses the same authorization-result-shaped action structure across observed event types. Detection flagged it on all 303 Mac Endpoint Security records. Verify this against the modeled ES message version and source contract before changing the serializer.

## Independent expert panel

| Expert | Verdict | Verdict confidence | Synthetic-confidence score |
|---|---|---:|---:|
| Threat Hunter | Likely synthetic/staged | 94 | 91 |
| Detection Engineer | Likely synthetic | 78 | 76 |
| Network Forensics | Likely synthetic | 72 | 68 |
| Host/EDR Forensics | Likely synthetic | 83 | 81 |
| **Mean** | **likely synthetic** | **81.75** | **79.0** |

Verdicts agree, so deliberation did not run. The mean synthetic-confidence score moved from loop 9's 72.75 to 79.0 (+6.25). This coincides with deeper review of explicit DC-01 persistence activity, macOS ES field semantics, narrow collection timing, and concentrated network/proxy patterns; it does not indicate a runtime evaluation regression. Reviewers still reported coherent host and Zeek relationships. The expired R3 intermediate recurred again.

## Prioritized findings

1. **P0 — macOS fork/exec rows still serialize to colliding eCAR milliseconds (`contract_gap`).** The direct family probe finds 31 collision groups across two Macs. Loop 11 applies the one-millisecond predicate to serialized timestamp buckets and checks every execution predecessor.
2. **P1 — macOS ES action payload shape may not match event-type semantics (`schema_or_format`).** Detection found action type 1 with an authorization-result-shaped payload across all 303 ES records, including fork/exec/exit. Confirm Apple's declared message version and our typed ES event contract before changing shared publication.
3. **P1 — Expired R3 intermediate recurs in a completed www.reddit.com TLS session (`environment_or_collection_plausibility`).** Network repeated this certificate-validity finding. Trace the TLS issuer/chain data path and make certificate validity constraints coherent if this modeled client session is meant to succeed.
4. **P2 — Explicit DC-01 persistence/cleanup, concentrated scans, and Linux PID bands are conspicuous (`distribution_texture`).** They are possible and several source pivots are coherent. Do not rewrite scenario intent or attack sequences without a concrete shared renderer defect.
5. **P3 — Near-one-second bulk Mac process teardown appears on both hosts (`distribution_texture`).** Host and Detection both noted the compact exits before logout. Keep it queued until a source timing or observation profile demonstrates an implausible lifecycle, since quick user logout can terminate many processes.

## Loop 11 candidate

Fix and verify same-millisecond process-execution collisions in the planner, then investigate the repeated ES payload shape against the source version contract and the recurring expired certificate chain. The Mac SSH accepted-auth-after-shell finding from loop 8 also remains queued pending a fresh owner trace.

Loop 10 is **partial** for the process timing family: the planner change passed unit tests but its required family output invariant did not pass. Reports, evaluation, probes, and scores are saved in this folder.
