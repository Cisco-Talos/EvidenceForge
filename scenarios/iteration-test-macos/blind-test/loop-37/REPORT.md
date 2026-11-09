# Loop 37: continuous canonical HTTP request readiness

The shared network transaction planner replaces whole-millisecond modulo delays with
a scoped, right-skew microsecond first-request phase. A typed network policy, loader,
overlay merge and validate-config coverage own its finite bounds. Existing explicit
request anchors, application-channel timestamps and close-bounded admission retain
their owners; every sensor consumes the same canonical time. This removes arithmetic
quantization without emitter-specific jitter. The pre-fix35 first non-CONNECT probe
found exact millisecond transport-to-request gaps in97/142core and193/294DMZ rows.

151 focused tests pass across request policy, transport floors/terminal bounds, proxy
channels and temporal RNG rules. validate-config failed (corrected in42); Ruff/format pass. A test's
global-zero-open-channel assertion was overbroad: a diagnostic traced the extra channel
to an independent direct ocsp.sectigo.com request, while all three proxy channels had
closed proofs. The test now checks the remaining count against independently owned
HTTP views, retaining proxy-close and receipt assertions. The trace is retained under
/private/tmp/loop37-channel-diagnostic.txt. No channel ownership logic was weakened.

Selected next: P1 sudo/PAM integer-millisecond phase arithmetic (Detection35,115pairs,
shared bundle/timing config owner); P1 SMB baseline cadence (prior network panels,
shared baseline arrival planner); qualified network sequence/capture/file counters
need a separate source-observation contract. Original reviewer priority labels were
not assigned. Preserve explicitly authored Mac offsets and diagnostic command intent.

Validation/generation/eval pass96.0944,135878records,119files. First non-CONNECT request
whole-ms gaps are0/169core and0/362DMZ; before-transport0. Browser0/267mismatches;
TCP data/zero and clean/partial header deltas0. Counts/eval are essentially unchanged
from36; the direct phase probe verifies the selected improvement.

Correction recorded in42: the saved validate-config invocation failed with an extra
model argument to validate_entry; earlier claims of0errors were incorrect because
later shell commands masked the exit. The data-generation/eval results and scores
remain valid.42 repairs the validator and adds regression/CLI verification.


## Family contract

# Canonical first HTTP request phase

Classification: sibling_defect; family_level. Owner: network transaction planner and validated network timing policy. Every unanchored HTTP request uses one deterministic, scoped, continuous-microsecond phase draw after transport open, bounded by transport close. Baseline/storyline/direct/proxy network callers converge here; explicit canonical request anchors and application-channel timestamps retain their established owners. Both Zeek sensors and endpoint/proxy correlations consume the same canonical time. Whole-millisecond modulo seeds in the planner are the cause; per-emitter jitter would decorrelate evidence. Preserve close bounds, source-delay ordering, reused channels and explicit anchors. Risk: tiny transport lifetimes can still saturate at the admissible boundary; record those separately from quantization.


## Individual expert summaries

**Threat Hunter:** Inconclusive; verdict confidence 77; synthetic-confidence score 43. The supplied six-hour collection is operationally convincing across a mixed fleet, with usable pivots from endpoint execution to remote authentication, network transport, and destination file activity. I found a narrow cluster of questionable Linux process/file ownership assignments, but their interpretation depends on the normalized endpoint collector's attribution semantics; I did not establish a hard contradiction sufficient to confidently classify the whole dataset.

**Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 32. The supplied records are mostly production-like from a parser, field-value, and correlation perspective. I found no demonstrated impossible lifecycle or source-native contradiction in the checks performed; a repeated, unusual VMware DLL load into LSASS deserves investigation, but does not establish synthetic origin. The score reflects that limited concern, rather than penalizing selected coverage or unusually complete correlation.

**Network Forensics:** Inconclusive; verdict confidence 78; synthetic-confidence score 34. The network evidence is mostly production-like: transport accounting, protocol timing, certificate identity, and explicit-proxy behavior withstand the checks described below. Repeated DNS resolutions within advertised TTLs and a predominance of short TLS connections are weak indications of simplified activity modeling, but both have plausible operational explanations; I found no demonstrated network-layer hard contradiction that establishes synthetic origin.

**Host Forensics:** Synthetic; verdict confidence 90; synthetic-confidence score 68. The endpoint data has substantial realistic structure, especially Windows process identity correlation and Linux SSH/sudo lifecycles. My synthetic verdict rests primarily on demonstrable timestamp construction patterns in the macOS Endpoint Security records: numerous separate shell forks preserve exactly the same microsecond fraction, and all six visible inventory processes have exactly two seconds from fork to exit. These are strong timing/distribution fingerprints rather than impossible process-tree relationships; I did not establish a dataset-wide hard contradiction.


## Scores and comparison

Automated eval 96.0944; standalone synthetic-confidence average 44.25 (mixed/inconclusive), prior loop 50.5. Lower is more production-like. Scores are standalone reviewer measurements; physical/semantic probe outcomes independently verify the selected family.

Facilitator-modeled deliberation averages 56.25; see deliberation.md. Modeled revised positions are excluded from standalone and rolling averages and are not reconvened expert votes.
