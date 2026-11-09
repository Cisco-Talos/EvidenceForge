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
