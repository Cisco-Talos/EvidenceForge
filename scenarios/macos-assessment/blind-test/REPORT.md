# macOS mixed-fleet assessment

## Loop 1: supported sources

The frozen supported-source revision generated 11,409 records in 17 source
families. Native Endpoint Security was not selected. Four isolated reviewers
received only a neutral copy of the fresh evidence, the complete platform-aware
briefing, and their own persona. No scenario, ground truth, evaluation results,
implementation notes or other reviewers' findings were supplied.

All four reviewers returned **Synthetic**. Average standalone synthetic-confidence
was **83/100** (lower is better); average verdict confidence was **92.75/100**.
The score spread was two points. No deliberation trigger fired.

## Independent expert summaries

- **Threat hunter:** Synthetic, verdict confidence 94, synthetic-confidence 82.
  Identified Mac fork/transition inversions and unrelated SaaS/browser destinations
  attributed to Docker and kubectl commands. Praised SSH, SMB and Type 9 credential
  correlation. Shell-history discrepancies were weaker leads requiring an owner
  and timing investigation, not established impossibilities.
- **Detection engineer:** Synthetic, confidence 90, synthetic-confidence 82.
  Independently found the Mac chronology defect, `/netonly` children in Session 0,
  and Linux SSH failures normalized as local logins. Windows schema fidelity,
  process identifiers, session pairing and Zeek references were convincing.
- **Network forensics:** Synthetic, confidence 94, synthetic-confidence 84.
  Found three ServerHello histories without responder payload, full TLS 1.2 ECDHE
  histories missing key exchange, and tightly clustered OCSP durations. DNS type
  diversity, TLS visibility, SMB accounting and tuple joins were convincing.
- **Host/EDR forensics:** Synthetic, confidence 93, synthetic-confidence 84.
  Independently confirmed the Mac, Windows and Linux session defects. Repeated
  subsecond phase preservation across unrelated application launches was a weaker
  texture concern. Stable hashes, Windows session bootstrap, Linux operational
  variety and Mac execution/credential identity were strengths.

Unchanged expert reports and machine-readable scores are in `loop-1/`.

## Prioritized improvements

| Priority | Finding and status | Owner and concrete repair |
|---|---|---|
| P0 | Confirmed: five Mac process transitions precede explicit visible forks across three identities. A production-timing fixture reproduces all five. | SourceTimingPlanner must publish the final source-visible process birth after session and parent constraints, and use that frontier for execution, credential, job-control and child observations. Preserve canonical State identity and source-local missingness. |
| P1 | Confirmed rule coverage gap: eight supported PROCESS/MODIFY records fail evaluation. | Add the five bounded POSIX operations to the eCAR format contract with operation-specific identity/field checks; arbitrary MODIFY must continue to fail. This is separate from fixing actual timing. |
| P1 | Strong repeated contract gap: three `/netonly` children use terminal Session 0 while their callers occupy Session 1. | The NewCredentials/process owner must preserve caller terminal placement while allocating the distinct authentication LUID and outbound identity. Verify native Security and Sysmon projections together. |
| P1 | Strong repeated contract gap: two Linux SSH failures lose their native mechanism and source tuple in eCAR. | Authentication generation must own explicit SSH failure semantics, including self-directed SSH. Carry the same canonical facts into both source views. |
| P1 | Confirmed same-UID inconsistency: three TLS summaries report ServerHello but matching connection counters have no responder payload. | Canonical network/TLS outcome construction must coordinate handshake progress and directional payload/packet accounting. Do not patch a rendered SSL row. |
| P2 | Repeated process-attribution concern: `docker ps/images` and `kubectl get pods` own unrelated external SaaS/browser traffic. | Command-aware network intent and process ownership must require a legitimate transport/destination. Local Docker enumeration must not invent external HTTPS; Kubernetes needs a modeled API destination. Review forward generation and inverse owner selection together. |
| P2 | TLS 1.2 ECDHE full-handshake histories omit the key-exchange step. | Verify the selected source's history vocabulary against primary references, then coordinate history with cipher/resumption/capture facts in canonical protocol construction. |
| P3 | OCSP connection lifetimes occupy an unusually narrow approximately 460 ms band. | Inspect canonical OCSP/transport duration ownership and replace any fixed close floor with scoped path/client timing variation while retaining packet/protocol causality. |
| P3 | Independent application launches repeatedly retain an integer-second phase. | Inspect baseline application scheduling and command readiness. Keep periodic system activity, but add scoped subsecond variation where independent user activity owns timing. |
| P4 | Shell history appears several minutes after some process starts; foreground editor readiness also constrained initial authoring. | Investigate history admission/finish semantics and baseline foreground lifetimes before classifying these as defects. History persistence and occurrence time are different facts. |

P0 comes first because it makes a represented lifecycle impossible. P1 items
repair concrete cross-source or contract failures before texture work. P2
attribution has strong score leverage across behavior families; none of these
priorities licenses sample-specific host, PID, destination or timestamp patches.

Family-loop classification: process ordering, Linux normalization, TLS accounting/
history and CLI network ownership are `sibling_defect` findings in existing shared
families. NewCredentials terminal placement is a `new_family` contract defect.
OCSP/application timing texture are `new_family` leads; shell-history timing remains
`false_positive_or_unproven` pending an occurrence/persistence interpretation.
The bounded eCAR validator change is `source_native_single_schema`; its purpose
is contract coverage, separately from the source-timing family repair.

## Quantitative comparison

Automated score: **89.99/100**, acceptance **FAIL**. All records parse; eight eCAR
rows fail the obsolete object/action rule. Canonical invariants and declared
completeness score 100, but the source-visible fork inversions escaped those
checks. The expert panel also found session placement, normalization and TLS
accounting issues that are not represented by the aggregate score. Timing scores
61 and field agreement 697/699 independently indicate remaining quality work;
diagnostic volume/anomaly scores are not acceptance targets to game.

The two Unified Log records and absent native ES were not penalized. The reviewers
correctly treated normalized eCAR and native macOS exports as distinct contracts.
Generation/evaluation provenance, the frozen initial evaluation, and a bounded
fresh-evidence chronology probe are retained in `loop-1/`. Future fixes must be
assessed on a fresh bundle without modifying revision 01 or this baseline.
