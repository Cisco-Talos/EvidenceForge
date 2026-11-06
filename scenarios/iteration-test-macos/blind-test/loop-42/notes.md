# Loop 42: shared baseline SMB arrival planning and validator repair

Both mixed-fleet preplanning and Windows-only inline generation now consume one
scoped host/hour/seed Hawkes arrival planner. Existing scaled interval policy owns
the mean rate; a typed, validated host-activity profile owns burst shape and a generous
resource ceiling. Counts can vary or be zero, and the ceiling is not a quota. Content
selection, mount eligibility, authentication and SMB lifecycle keep their owners;
authored SMB times are preserved. Per-hour excitation resets are a stated bounded
approximation, not empirical long-term calibration.

190 focused tests pass across arrivals, baseline admission, host profiles, mounted
Mac/Windows/Linux siblings and temporal policy. A real Windows-only integration case
proves that a supplied shared opportunity reaches canonical SMB preparation/effects.
A72host-hour probe produces counts0–23with18distinct counts, three empty hours and
interarrival CV1.47; every offset is ordered inside its half-open hour. Rendered flow
histograms must be interpreted separately because they also contain authored activity,
infrastructure and persistent-channel reuse. Ruff/format pass.

The configuration CLI uncovered a regression introduced in37: an accidental extra
model argument to validate_entry. Later shell commands masked its failed exit, and
37/38notes incorrectly claimed0errors. The validator boundary is repaired, direct
network-policy regression tests cover both HTTP timing profiles, and the separately
checked CLI exits0with0errors (one pre-existing warning, one info).37/38reports now
include the correction; their generation/eval data and blind scores remain unchanged.
This is a validation-owner exact_regression fix, not a generated-data adjustment.

Residual priorities: shared application-child capture/parent ledger consistency and
Zeek sequence-versus-captured-byte projection; opaque CONNECT aggregate planning;
SSH hour-close clustering and coherent host-local health-age state. These require
owning contracts rather than seed-only or renderer patches. Fixed Mac shell/inventory
cadence is explicitly authored and preserved. Private module metadata, inode texture
and optional source coverage suspicions remain qualified. Original reviewer P0–P4
labels were not assigned for carried findings. Final prioritization uses the new panel.

The first full generation exposed a separate Linux bootstrap boundary bug. A shell
planner set an in-window floor, then moved the shell back before that floor to fit
preferred readiness. Repeated calls rejected their own pre-window replacement and
allocated again until the unchanged30-second PID lane failed. The diagnostic retains
exact arguments/process/session evidence; failed440console/snapshot are preserved.
Both session and loose-parent paths now share a feasibility check before replacement
allocation. An infeasible replacement returnsNone, preserving the existing valid
parent; later feasible calls create one in-window shell and reuse it.71Linux activity
tests and108additional allocation/lifecycle/sudo/admission tests pass (overlap with
earlier suites), including repeated server/workstation calls with unchanged State.
No PID capacity, ordering, watermark or lifecycle guard was relaxed. The accepted
retry uses revision441. This necessary bootstrap repair was added to the final loop
rather than disguising its runtime failure as a successful assessment.

Authoritative441retry passes validation/generation/eval at96.8482,129317records,
117files, with all hard acceptance criteria true and no eval flags. Final probes:
TCP data/zero and clean-to-partial header contradictions0; clean TCP DNS response
impossibilities0/8; browser version mismatches0/359; invalid CIM callers0(two valid
session-scopedcallers); sudo whole-ms gaps0/104with104distinct gaps; no HTTP request
before transport (one coincidental whole-ms gap in133core and299DMZ first requests).
All3mounted helpers in this distribution run have native exits. The41result12/12
separately verifies the completion fix; the new arrival schedule changes that volume,
so3/3must not be presented as the same denominator. Core successfulSMBflows449→432;
raw flows also include infrastructure/authored actions and persistent-channel reuse.

Final quantitative audit also corrected33/34PASS labels: overall96.0691was high but
pivot linkability151/189=79.8942missed80. The saved raw report already contained that
failure. Their canonical status is REVIEW; blind scores/data remain unchanged.
35–42pass all hard gates. No acceptance threshold or authored scenario was changed.


The final independent panel scores 38/53/32/65 (mean 47.00). Threat and Network are
inconclusive; Detection and Host lean synthetic, triggering deliberation. Detection
identified five ordinary-browser proxy GET targets containing `#/conversations`.
RFC 9110 §7.1 confirms the target URI excludes the client-side fragment:
https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1 . This remains a concrete
next-loop canonical browser/HTTP target-normalization issue; no post-review source
change was made. Host and Threat emphasize preserved authored Mac inventory/shell
timing. Network finds credible tuple/protocol accounting in its sampled checks;
its lower score does not refute the sequence-counter issue established in loop 41.
