# Iterative assessment loop 9

## Outcome

Loop 9 investigated repeated macOS process-exec timestamps in eCAR. The first planner change gave each execution epoch its own repair scope. It was not sufficient: fresh output shows one PID 42171 exec now one millisecond after a later exec, but its first exec still shares the fork's timestamp; both Macs retain multiple same-millisecond fork/exec pairs. The underlying predecessor rule did not account for eCAR's integer-millisecond conversion when a preferred time was later than a floor by only sub-millisecond slack.

The selected family and owner were correct, but the root cause is not resolved. Loop 10 added predecessor-execution ordering and a one-millisecond repair minimum. Its fresh output still reproduces the create/exec collisions, so the family remains open for a corrected precision-aware predicate in loop 11.

The exact APP-INT-01 Linux SSH source contract remained fixed in this output: 2/2 root SSH eCAR logins have matching connection, accepted-auth, and PAM-open syslog observations. The family regression had passed in loop 8.

Fresh generation completed at `/private/tmp/eforge-iteration-test-macos-loop-9`; it contains **141,247 records** and passed one JSON evaluation at **96.880577** (parseability 100, plausibility 96.7070, causality 97.0011, timing 92.2677). All applicable hard criteria passed. The 120-file data-only blind copy was SHA-256 verified against its generation manifest.

Focused timing-scope regression passed. It checked that distinct exec epochs use distinct repair identities, but did not assert a strict serialized timestamp after the fork and therefore failed to capture the remaining defect. Loop 10 strengthened that test to assert predecessor ordering; loop 11 now includes the sub-millisecond same-bucket case found in loop 10's output.

## Family probes

- Loop 9's PID 42171 sequence on MAC-MROSS-01 has a fork and exec:1 at `1793624864584`, then exec:2 at `1793624864585`. The first exec still collides with the fork at eCAR millisecond precision.
- Across the selected bootstrap fork/exec rows, **16** PID/timestamp groups on MAC-MROSS-01 and **19** on MAC-MROSS-02 contain multiple execution identities at one eCAR millisecond.
- Both APP-INT-01 root SSH sessions retain all three expected syslog auth/open observations.

## Independent expert panel

| Expert | Verdict | Verdict confidence | Synthetic-confidence score |
|---|---|---:|---:|
| Threat Hunter | Likely synthetic | 88 | 82 |
| Detection Engineer | Synthetic-leaning | 63 | 67 |
| Network Forensics | Likely synthetic | 76 | 74 |
| Host/EDR Forensics | Leans synthetic | 65 | 68 |
| **Mean** | **likely synthetic** | **73.0** | **72.75** |

The verdicts align on synthetic-leaning evidence; no deliberation trigger was met. The mean synthetic-confidence score moved from loop 8's 74.0 to 72.75 (-1.25), a small change. Reviewers again described broad correlation and realistic source-specific structures; their main concerns were bounded collection cadence, concentrated activity, and a concrete `mstsc.exe` credential-use record targeting macOS without a matching connection. No reviewer highlighted the incomplete eCAR millisecond ordering, so the direct family probe remains decisive for that fix.

## Prioritized findings

1. **P0 — macOS eCAR fork and exec transitions still collide after integer-millisecond serialization (`contract_gap`).** The direct probe shows many PID/timestamp groups on both Macs contain different execution identities. Loop 10's predecessor repair is incomplete because it only activates when preferred time is at or before the exact floor; a microsecond-later time can still serialize to the same millisecond.
2. **P1 — Windows explicit credential use targets a Mac through `mstsc.exe` without a matching connection (`environment_or_collection_plausibility`).** Host/EDR found this single anomalous cross-platform record; inspect the owner of explicit-credential target/source selection and validate whether the target OS is modeled correctly before changing the shared credential bundle.
3. **P1 — Expired R3 intermediate and bounded, synchronized capture envelope recur (`environment_or_collection_plausibility`).** Network review again flagged the expired www.reddit.com intermediate and noted the similar capture window/application mix across Zeek sensor views. The certificate chain is the clearer fixable family; investigate its data-driven TLS issuer/validity profile.
4. **P2 — Mac SSH auth follows shell exec and compact process teardown remains a reviewer signal (`contract_gap`).** These reports were strongest in loop 8 and should remain queued while the SSH bundle's native source-observation timing is traced.
5. **P3 — The DC-01 persistence/cleanup chain and Linux PID bands look highly authored (`distribution_texture`).** The actions are possible and source-correlated. Do not change scenario intent based on narrative clarity alone; revisit only if concrete repeated output artifacts emerge.

## Loop 10 candidate

Validate each process exec against both its process-create floor and the previous execution epoch after conversion to eCAR milliseconds. Check the same-PID chain on both Macs and at least one Linux exec path; retain the partial loop 9 scope change only if the full millisecond-order probe passes.

Loop 9 is **partial** for the selected process-timing family: it identified a narrower missing precision case, but did not satisfy the family invariant. Reports, evaluation, probes, and scores are saved in this folder.
