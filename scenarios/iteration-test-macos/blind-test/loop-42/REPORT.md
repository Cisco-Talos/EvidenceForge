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


## Family contract

# Shared baseline SMB arrivals

Classification: sibling_defect; family_level. Owner: baseline arrival planner and typed host-activity policy. Both mixed-fleet preplanning and Windows inline paths request scoped host/hour/seed Hawkes opportunities instead of a fixed host interval with2%jitter. Existing scaled interval policy owns mean rate; validated branching/decay plus a generous resource ceiling own burst shape. Counts vary, empty hours are possible, and the ceiling is not a quota. Content selection, mount admission, authentication and SMB lifecycle remain their existing owners; authored event times are preserved. All endpoint/server/network consumers share the planned occurrence times. Verify count/gap diversity, bounded ordered offsets, host/hour/seed separation, replay, both adapters, mounted siblings and terminal admission. Per-hour excitation resets are an explicit bounded approximation, not empirical long-term arrival calibration.

Secondary exact_regression: the HTTP profile validator added in37 passed an extra
model argument to validate_entry. Repair this validator boundary and add direct
network-policy validation tests plus a separately checked CLI run. Correct37/38
report claims: the saved invocations failed and were masked by later successful
commands in the shell cell; generated-data validation/eval results are unaffected.

Runtime blocker discovered by regeneration: Linux visible-shell bootstrap applies an
in-window floor, then its preferred readiness gap overwrites that floor with a new
pre-window start. Repeated boundary calls reject their own replacement and allocate
more shells until a PID lane is exhausted. Fix feasibility at the shared local-shell
timing owner for both session and loose-parent paths. If no visible replacement can
be ready inside the window, decline allocation and retain the existing valid parent;
when feasible, allocate once in-window and reuse. Preserve PID lanes/watermarks and
all ancestry/lifecycle guards. Verify server/workstation, both paths, repeated calls,
pre-window parent fallback and later visible replacement. This is an incidental
new_family runtime repair required to accept the selected SMB distribution change.


## Individual expert summaries

**Threat Hunter:** Inconclusive; verdict confidence 80; synthetic-confidence score 38. The collection is mostly production-like from a threat-hunting perspective: the suspicious Windows and Linux activity supports useful, technically coherent process, account, network and file pivots. I found limited timing texture worth investigating, but no demonstrated impossible lifecycle or decisive authenticity fingerprint; the supplied data does not justify a confident synthetic verdict.

**Detection Engineer:** Synthetic; verdict confidence 76; synthetic-confidence score 53. The supplied telemetry is substantially production-like: Windows schemas, visible process/session lifecycles, network tuples, and protocol relationships withstand broad automated checks. I lean synthetic because five proxy records expose a repeated HTTP request-target error—browser fragment identifiers appear in purported network requests—but the demonstrated defect is localized, so the synthetic-confidence score remains in the mixed range.

**Network Forensics:** Inconclusive; verdict confidence 82; synthetic-confidence score 32. The network data is mostly production-like: transport states, protocol companions, explicit proxy routing, certificate identity, and packet accounting are coherent across three sensor locations. I found a mild DNS caching texture and a small number of locally unresolved HTTP file references, but neither establishes synthetic origin given the unspecified collection/filtering policy; I found no demonstrated impossible network relationship.

**Host Forensics:** Synthetic; verdict confidence 89; synthetic-confidence score 65. The host evidence has strong process, user, and lifecycle coherence across Windows, Linux, and macOS. My synthetic verdict rests primarily on repeated microsecond-exact command scheduling in the macOS Endpoint Security records and identical inventory-process lifetimes across two machines, with a smaller supporting signal from tightly repeated developer editor-launch spacing. I did not find a demonstrated impossible process lifetime or a Windows process-identity contradiction in the checks described below.


## Scores and comparison

Automated eval 96.8482; standalone synthetic-confidence average 47.00 (mixed/inconclusive), prior loop 68.5. Lower is more production-like. Scores are standalone reviewer measurements; physical/semantic probe outcomes independently verify the selected family.

Facilitator-modeled deliberation averages 59.00; see deliberation.md. Modeled revised positions are excluded from standalone and rolling averages and are not reconvened expert votes.

## Quantitative acceptance

PASS: all applicable hard acceptance criteria passed.
