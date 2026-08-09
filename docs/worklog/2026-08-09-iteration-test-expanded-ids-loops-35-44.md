# Iteration Test Expanded IDS Assessment Loops 35-44

Scenario: `/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test-expanded-ids/scenario.yaml`

These loops begin from the integrated canonical-contract architecture. Loop 35
is a fresh baseline: no findings, scores, targets, or reports from loops 1-34
were used to select its improvements. Every loop regenerates data, runs the
deterministic evaluator, and gives only a neutral copy of the current data to
four independent blind reviewers.

## Pre-baseline Architecture Blocker

Fresh generation found a source-side SSH client whose outbound transport
outlived the inbound SSH session that owned the process. Source-process
attribution now requires the owning session to remain active through the full
transport; otherwise the canonical flow is retained without unsafe PID/user
attribution. Four focused tests passed, Ruff passed, and the full suite produced
5,289 passes plus 41 skips; its only sandbox failure was the localhost-port
Splunk harness test, which passed unrestricted.

## Loop 35 Outcome

- **Generation/eval:** 85,173 records; 95.91073999984621; automated FAIL only
  on pivot linkability (50/100). Canonical invariants, source schemas, field
  agreement, IDS integrity, and causal ordering all scored 100.
- **Blind panel:** Synthetic 3-1 at 64/64/28/66, average 55.5.
- **Deliberation:** Synthetic 3-1 at 68/69/44/71, average 63.0.
- **Fresh selected family:** version-specific source-native schema projection
  for Snort fast alerts, Security 4624 v2, and Sysmon Event 8 v2.
- **Owning abstraction:** emitter format definitions and source-native render
  adapters; canonical event truth remains unchanged.
- **Invariant:** rendered field labels, order, and presence match the declared
  native provider/version contract while preserving canonical values.
- **Sibling risks:** SIEM parsing, ordered XML fixtures, Snort classification
  semantics, Event 8 identity ownership, format validation, and deterministic
  output.

## Loop 36 Outcome

- **Generation/eval:** 85,173 newly generated records; 95.91073999984621;
  automated FAIL only on pivot linkability (50/100). Canonical invariants,
  schemas, field agreement, IDS integrity, and causal ordering passed.
- **Blind panel:** Real/Inconclusive/Synthetic/Synthetic at 32/49/67/78,
  average 56.5.
- **Deliberation:** likely Synthetic 3-1 at 55/63/72/77, average 66.8.
- **Loop 35 target confirmation:** none of the four fresh reports repeated the
  Snort-classification, Security-4624-order, or Sysmon-Event-8-user defects.
- **Fresh selected family:** half-open source admission for endpoint lifecycle
  closures at the collection boundary.
- **Owning abstraction:** final source observation admission in the canonical
  dispatcher, after lifecycle expansion and source-native timing.
- **Invariant:** every discrete source record has a visible timestamp in
  `[output_start, output_end)`; in-progress objects remain open when their
  closure occurs after the window.
- **Sibling risks:** process/logon lifecycle pairing, cross-source termination
  agreement, source observation jitter, sensor interval records, and documented
  collection-profile tail semantics.

## Loop 37 Outcome

- **Generation/eval:** 85,138 newly generated records; 95.91042019060161;
  automated FAIL only on pivot linkability (50/100). Schemas, canonical
  invariants, field agreement, IDS integrity, and causal ordering passed.
- **Blind panel:** unanimous Synthetic at 76/71/72/68, average 71.75. No
  deliberation trigger: all verdict confidences were at least 84 and score spread
  was eight points.
- **Loop 36 target confirmation:** zero records at or after the 18:00 cutoff and
  no fresh reviewer repeated the endpoint termination-tail finding.
- **Rejected finding:** the reported Security 5156 direction inversion used the
  WFP message tokens backwards. Microsoft source-native semantics confirm that
  `%%14592`/`%%14610` is inbound receive/accept and
  `%%14593`/`%%14611` is outbound connect, matching current tuple placement.
- **Fresh selected family:** sensor-local file completeness before dependent
  X.509, OCSP, and PE analyzers.
- **Owning abstraction:** frozen network sensor observation plan; emitters only
  render the analyzer visibility already decided for each file and sensor.
- **Invariant:** incomplete file observations cannot yield full decoded analyzer
  rows or full-file fingerprints; complete observations retain canonical IDs.
- **Sibling risks:** SSL certificate FUID references, files.log hashes/analyzers,
  OCSP HTTP fan-out, PE analysis, multi-sensor variance, and parser ordering.

## Loop 38 Outcome

- **Generation/eval:** 85,068 newly generated records; 95.9090570499255;
  automated FAIL only on pivot linkability (50/100). Schemas, canonical
  invariants, IDS integrity, and causal ordering passed.
- **Blind panel:** unanimous Synthetic at 65/68/95/72, average 75.0. No
  deliberation trigger: all verdict confidences were at least 80 and the score
  spread was exactly 30 points.
- **Loop 37 target confirmation:** incomplete files produced zero X.509, OCSP,
  or PE analyzer intersections on either sensor. The Network reviewer also
  independently explained missing certificate analysis through incomplete file
  capture rather than reporting the prior contradiction.
- **Fresh selected family:** canonical Zeek connection-state and packet-history
  consistency.
- **Owning abstraction:** `NetworkTransactionPlan`; sensor observations and the
  Zeek emitter project its already-consistent transport truth.
- **Invariant:** RSTR terminates with lowercase responder `r`, RSTO with
  uppercase originator `R`, and S1 contains no observed reset/close marker.
- **Sibling risks:** generator history pools, sensor-specific network
  observations, emitter projection, packet-actor direction, ASA teardown
  reasons, and deterministic evaluator assertions.
