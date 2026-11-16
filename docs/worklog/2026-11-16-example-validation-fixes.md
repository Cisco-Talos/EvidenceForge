# Example validation root-cause fixes

## Authorization and baseline

The user approved implementing the fifteen-issue root-cause plan, including realism
measurement, with acceptance defined as **correct and explain**: retain all hard gates,
clear confirmed defects, improve measurement and genuine generation problems, and explain
legitimate statistical variation rather than fitting scenarios to scores.

First integrated the prior work locally: `86d74702 feat: ship five bundled example scenarios`
on `codex/bundled-example-scenarios`, fast-forwarded `dev`, then created
`codex/example-validation-fixes` from that exact commit. Pre-integration verification:
266 targeted tests passed (8 expensive cases deselected), Ruff check/format and generation
behavior revision 521 verification passed. No push or product version bump is requested.

Preserve original authoritative datasets and raw reports at
`/private/tmp/eforge-example-review-pe1xvhof/`. Baseline outcomes and exact release hashes
are recorded in `status.json`, `REPORT.md`, and the bundled-example worklog. Alderbrook's
ground-truth score is 91.52 (<95); the other four currently pass. No source release bytes
may be edited. Reevaluate originals first; regenerate only where evidence or sealed
expectations must change. Never alter generated manifests, ground truth, or source logs.

## Approved worklist

1. Identity-scoped matching/cardinality for concurrent SMB, repeated history/web activity;
   preserve true duplicate and contradictory-record detection.
2. Boolean comparison before integer handling; frozen reference Boolean keys normalize
   identically to direct YAML and observed values, including spill evaluation.
3. Typed DNS RR answer comparison, especially TXT presentation; preserve payload case.
4. One-to-one HTTP cross-source matching, without using status as a join key.
5. OCSP FUID identity and incomplete-capture applicability in comparison and expectations.
6. Shared source/role/phase/filter admission predicates, independent of rendered evidence.
7. ASA canonical transport/tuple/firewall traversal/lifecycle expectations for reused channels.
8. IDS expectations honor independent sensor-local threshold/suppression decisions.
9. Remove hidden browser Security 4689 suppression; declared policy owns source eligibility.
10. Process-frontier proofs include exact actor-owned file/flow/child witnesses, not broad tolerances.
11. Email artifact/Message-ID/recipient pivot linkage without inventing TLS-visible actors.
12. Typed causal timing replaces prose matching and arbitrary bounds on unrelated adjacency.
13. Organic anomaly measurement uses eligible observations, excludes authored injections,
    respects platform/timezone, and reports sample/coverage diagnostics honestly.
14. Service cadence groups distinct actual tasks and deduplicates correlated observations;
    uses applicable schedules and reports insufficient observations rather than fabricated passes.
15. Distribution references declare applicability by workload/platform/collection; preserve
    justified variation and do not calibrate profiles to force these examples to pass.

## Acceptance

- Exact authored validation: zero errors/info, only the two accepted opaque-HTTPS warnings.
- All five authoritative evaluations complete, integrity verified, all existing hard gates pass,
  including 100% source correctness/schema and ground-truth agreement >=95.
- Confirmed targeted defects clear with positive and corruption/duplicate negative controls.
- Direct/frozen config, input ordering, and memory/SQLite spill paths agree.
- Extend existing slow shipping-example generation tests to evaluate acceptance too.
- Update behavior manifest for generation changes; preserve product version and old bundles.

## Execution

Implementation and acceptance completed; detailed changes and verification follow.

### Implementation and root-cause evidence

- **Identity/cardinality:** Windows SMB audit matching now uses file path and the same
  deterministic native handle identity as the renderer. Native history/web clocks qualify
  repeated operations. Absence checks exclude records independently matched by a complete,
  cardinality-valid present requirement for another occurrence; extra/contradictory rows
  remain failures. This removed the original Alderbrook bulk-copy/export false duplicates.
- **Boolean/TXT:** Compare booleans before integers, reject numeric stand-ins, and normalize
  Boolean distribution vocabularies across captured JSON and YAML. Decode only valid TXT
  length-prefixed chunks (including multi-chunk DKIM records); preserve payload case/bytes.
- **HTTP:** Method-aware, adjacent-bucket, bounded-time, one-to-one transaction joins; the
  status being tested never selects a counterpart. Indistinguishable requests are reported
  as unavailable, with explicit ambiguity counts.
- **OCSP:** Preserve canonical OCSP facts and source-local FUIDs. Explicitly incomplete file
  captures cannot support a missing OCSP analyzer assertion; complete captures still must
  match the cryptographic identity. Original Cedar/Alder errors had nonzero missing bytes.
- **Admission/SMB roles:** A pure source-admission predicate is shared by emitters,
  expectation production and independent verification. Linux SMB clients do not imply a
  Samba server. Application-layer-only SMB operations still produce endpoint file evidence;
  only redundant connection evidence is suppressed. eCAR SMB server/client routes and
  native paths/actions are qualified separately, and the renderer respects each endpoint's
  collection envelope.
- **ASA:** Physical persistent SMB roots previously omitted ASA from the closed publication
  target set even on a crossing firewall path. Added the exact existing ASA publication
  participant to that set and its bounded recovery/certification contract. Application
  operations do not demand another firewall build; physical transports retain source-local
  tuple and teardown requirements. No emitter-local fabricated replacement flow is used.
- **IDS:** Stateful threshold/suppression means candidate timestamps are not alert promises.
  Each filtered sensor/signature delegates only after exact retained emitted count and
  normalized ordered alert digest agree. Mixed filtered/unfiltered signatures are checked
  separately; the existing IDS integrity gate stays independent. Empty admitted streams
  also require the correct zero-count digest. Mutated/missing/extra alerts still fail.
- **Browser exits/frontier:** Removed the hidden browser-name Security 4689 exclusion.
  The Northstar Linux SMB READ advanced an eCAR frontier for an unrendered client DELETE;
  source timing now advances only actual per-host SMB phases. Existing independent process
  witness checks and timing bounds remain intact.
- **Email/typed timing:** Schema-v5 narrative linkage includes verified MIME Message-ID and
  recipient matches. No TLS-visible sender/user is invented. Attack-chain timing uses
  explicit parent/caller process references rather than prose or arbitrary adjacent-step
  deadlines; missing typed relationships are unmeasured.
- **Realism:** Anomaly sampling uses eligible observations, preferred process sources,
  authored-record exclusion, native Sysmon principals and per-host timezone. Cadence groups
  actual complete task identities, chooses a source per host and requires repetitions per
  task; cron's fixed schedule is allowed, extreme irregularity still fails. Windows-specific
  eCAR distribution references apply only to Windows populations. Missing reference
  populations are counted as unavailable; no profile or acceptance threshold was fitted to
  these examples. Evaluation policy is engine-owned, rather than restoring obsolete scorer
  rules through a bundle's captured generation defaults.

### Verification in progress

Intermediate evaluation reports are retained in `/private/tmp/eforge-validator-fixes-stage2/`.
Before the SMB endpoint-role correction, original Alderbrook and Kestrel and regenerated Cedar
reached 100% ground-truth agreement; Lantern also reached 100% after the mixed-signature fix.
Northstar exposed the additional physical-ASA omission and endpoint-role defect above.
Full CI-style import/generate/evaluate checks are now running for all five examples, with data
under `/private/tmp/eforge-final-examples-522/`. This fresh gate is needed because canonical
source facts, endpoint admission and lifecycle evidence changed; published scenario bytes have
not changed. Earlier development probes remain in the two `...generation-522*` directories.

The first broad run passed 912 checks, with two expected obsolete score-snapshot failures.
Reviewed snapshot differences are limited to: distribution applicability/diagnostics, anomaly
population (4/12 eligible instead of 3/17 mixed records), and typed timing/service cadence now
unmeasured where evidence is insufficient. Historical `reference-f93a25bf.json` is retained;
`reference-example-validation-fixes.json` pins the reviewed replacement report for both memory
and SQLite paths. Unrelated scores and hard failures in that deliberately poor fixture remain.
A separate SMB/certification/behavior run passed 251 tests (67 expensive cases deselected).

### Final acceptance follow-up

The routine rerun passed **924 tests** (146 expensive cases deselected). Subsequent focused
controls cover the last eCAR file-cardinality refinement, scoped parent references, frozen
scoring policy, HTTP source ownership and background-only process-source selection. All
existing corruption controls remain enabled.

The first full five-case slow command generated Alderbrook successfully and exposed 22 more
file-cardinality false positives in the newly verified server/client SMB roles. The matcher
now scopes native eCAR FILE rows to the canonical path, just as Windows SMB audit rows are
scoped; duplicate rows for the same file still fail. Reused that complete authoritative
Alderbrook dataset rather than regenerating its 24-hour workload: its final CLI evaluation
passes at **99.29396 overall / 100 ground-truth**, with no agreement findings (142,889 records).
Report: `/private/tmp/eforge-alder-final-report.json`.

The remaining four startups in that first slow command correctly rejected a stale generation
behavior digest after concurrent source edits. Refreshed the revision-522 digest and restarted
those four cases under `/private/tmp/eforge-final-other-examples-522/`; Cedar's complete
import/generate/evaluate check has passed. This was a development sequencing error, not an
installer/scenario defect. No source-surface edits are being made during the rerun.

A retained pre-endpoint-role Cedar probe was also compared under 1/256 MiB budgets. Scores,
counts and facts agree; separate Python processes exposed nondeterministic ordering of
missing-expectation diagnostics from set iteration. Sorted that iteration. Old probes with
HOST-only SMB ledgers now explicitly explain that per-endpoint decisions require regeneration;
their contract errors are retained, not waived. A fresh completed Cedar bundle is being used
for the final spill comparison and clean-contract acceptance.

## Final results

All five published scenarios were imported into unrelated workspaces and generated in full.
The final evaluator was then run against each retained authoritative bundle; no source dataset
or manifest was patched. Every evaluation exits 0, verifies bundle integrity, passes acceptance,
and has **100% ground-truth agreement with zero agreement findings**. Source schema, canonical
invariants and declared scenario completeness also score 100 for each dataset.

| Example | Records | Overall | Ground truth | Acceptance |
| --- | ---: | ---: | ---: | --- |
| Alderbrook | 142,889 | 99.29396 | 100 | PASS |
| Cedar Vale | 47,699 | 98.72385 | 100 | PASS |
| Kestrel Ridge (stable `juniper-vale-macos-dns` ID) | 100,356 | 97.46415 | 100 | PASS |
| Lantern Works | 86,518 | 99.23602 | 100 | PASS |
| Northstar | 38,390 | 99.10174 | 100 | PASS |

Final reports, stderr and exact bundle paths are in
`/private/tmp/eforge-final-example-evaluations-v3/` (`status.json` summarizes all five).
The original failing Alderbrook bundle and its 91.52 ground-truth result remain preserved
under `/private/tmp/eforge-example-review-pe1xvhof/` and in the preceding committed worklog.

Northstar's final two strict-CI findings distinguished two source documents copied to the same
local pathname within one second. Their retained local file IDs differ. Matching now uses those
per-endpoint IDs as well as operation/path, retaining duplicate and wrong-record detection.
Reevaluated the complete Northstar dataset after this evaluator-only correction; regeneration
was unnecessary. The final five-bundle audit applies exactly the strict acceptance and
zero-finding assertions added to the slow CI test. The slow generation invocations themselves
passed Cedar/Kestrel/Lantern directly and exposed the subsequently corrected Alderbrook/Northstar
matching defects; those datasets were retained and rechecked rather than regenerated again.

Remaining non-perfect distribution/burstiness/service-cadence diagnostics are legitimate
statistical variation or insufficient measurement, not softened gates. No example was tuned to
fit the references. Northstar retains the existing optional eCAR `auth_protocol`/`account_scope`
format-loader stderr warnings (also present in the original baseline); these do not produce
source-schema or record-correctness failures. Authored validation remains zero errors/info with
only the two explicitly accepted opaque-HTTPS warnings. Exact release verification and findings
are retained in `/private/tmp/eforge-final-example-validation.json`.

Final verification evidence:

- Broad routine evaluator/source-timing/renderer/ground-truth/example suite: **924 passed**,
  146 slow/soak cases deselected. Later focused final file-identity/source-corruption run:
  **103 passed**, 6 expensive cases deselected. The new repair module has **35 passing cases**.
- Separate SMB publication/certification/channel/behavior tests: **251 passed**, 67 expensive
  cases deselected; field-agreement/typed-timing/temporal/IDS regression subset: **165 passed**.
- Fresh full Cedar comparison at 1 MiB (SQLite spill) and 1 GiB (no spill): identical reports
  after removing evaluation time/resource diagnostics, including all scores, counts, samples,
  and acceptance. Both are clean 100% agreement. Reports are retained under
  `/private/tmp/eforge-example-final-spill-parity/`. Small fixtures also verify forced-spill
  equivalence and corruption controls in routine CI.
- Ruff check, Ruff format check, diff whitespace check and generation-behavior verification
  pass. Behavior revision **522**, digest
  `a3e5ba02803490c1506b6a2203e4ea2534bded4b6337a3e6e9a87f25164cdd9b`.
- Product version remains **3.0.0rc1**; published example bytes, original generated bundles,
  seeds/windows/output formats, thresholds and the intentional DNS attribution gap are unchanged.
  Generated datasets and operational reports remain outside Git. No push or release publication.


The final category audit also caught the cryptographic DKIM probe independently reading raw
chunked TXT, and trace coverage counting verified IDS suppressions as missing rows. All DNS/TXT
comparators now share one byte-preserving decoder. Trace coverage excludes only projections
proven wholly filtered by the sensor/signature digest gate; mixed-signature projections retain
checks for the unfiltered requirements, and zero observable projections are unmeasured. These
corrections were verified against the retained bundles without regeneration. All three objective
categories now score 100 on every example; the shipping CI assertion includes those categories.
The final category/control/storage subset passed **220 tests**, the crypto/IDS/trace subset
passed **84**, and the final zero-observable/trace/storage controls passed **102**. The final
five-bundle audit's strict category and agreement assertions all passed.
