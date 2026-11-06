# Ten-loop root-cause assessment: loops 33–42

Completed ten more loops of the unchanged iteration-test-macos scenario, ending at
behavior revision 441. Each accepted dataset received four fresh independent blind
reviews: 40 reports total. The set mean synthetic-confidence score is **50.825**,
versus **50.175** across loops 23–32; lower is more production-like. There is no
aggregate improvement demonstrated by these standalone panels. The final loop is
47.00, versus 68.50 in loop 41; newly surfaced issues and reviewer coverage contribute
to the variance. Objective probes independently establish the selected fixes.

Final quantitative eval is **96.8482**, with 129,317 records in 117 files, all hard
acceptance criteria passing and no flags. Loops 35–42 pass all hard criteria; loops
33–34 require REVIEW for pivot linkability 79.8942% below 80%, despite aggregate
96.0691. Their earlier PASS labels were corrected without changing raw data or blind
scores. Configuration CLI claims in 37–38 were also corrected; the validator regression
is repaired and separately verified in 42. Details are retained below and per loop.

## Changes and verification across the set

The [verified fix matrix](loops-33-42-verified-fixes.md) records owning layers and
before/after checks. Changes cover TCP history and physical capture partitioning;
shared browser identity and loaded executable release; exact RDP reconnect authority;
Linux daemon arrivals; continuous HTTP/sudo phases; credential-scoped CIM callers;
TCP DNS payload floors; canonical successful Mac mounted-helper exits; and shared
SMB arrivals across mixed-fleet and Windows-only paths. The final generation also
required a Linux bootstrap feasibility repair; its failed first attempt is preserved,
and only the accepted retry was reviewed. No ordering/PID/watermark guard was relaxed.

Final probes show zero TCP history/header contradictions, zero impossible TCP DNS
responses out of eight, zero browser identity mismatches out of 359, and zero invalid
CIM callers. All 104 sudo gaps are positive, distinct and off the millisecond lattice;
HTTP requests do not precede transport. Mac mounted-helper native exits improve from
0/12 to 12/12 in loop 41; the changed arrival distribution yields a different final
workload of 3/3. A 72 host-hour SMB probe produces counts 0–23 with three empty hours
and interarrival CV 1.47; rendered flows also include infrastructure and authored work.

Focused and native suites passed, including 70 RDP cases, 31 slow bounded SMB/native
cases, 71 Linux activity cases and the recorded family-specific suites. Suite counts
overlap and are not a unique-test total. Whole-tree Ruff check and formatting pass;
the full repository suite was not run. No version bump, commit or authored scenario
timing change was made. Unrelated dirty files were preserved.

## Final loop details

### Loop 42: shared baseline SMB arrival planning and validator repair

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


## Prioritized reported issues

Priorities/categories are synthesis judgments. Original reviewers did not assign
P0–P4 labels; the table preserves differing evidence strength.

| Priority | Issue / category | Original reviewer rating | Scope / score impact | Owning layer / fix risk | Evidence and next action |
|---|---|---|---|---|---|
| P0 | Zeek stream extent versus capture totals / hard_contradiction | Network 41: not labeled | 580 completed sensor pairs in loop 41; high | Canonical transport source-observation contract; high | Sequence-derived stream totals shrink by exactly modeled capture gaps despite visible handshake/FIN coverage. Separate stream extent from captured packet/payload and file-completeness ledgers, including application children; preserve loop 34's physical partition guarantees. |
| P1 | Client-only URL fragments in HTTP targets / hard_contradiction | Detection 42: not labeled | Five requests, two users, Chrome/Firefox; high local leverage | Canonical browser/HTTP request-target construction; medium | Five quoted proxy GET request lines include `#/conversations`; ordinary browsers exclude fragments from network targets. Separate navigation URL from HTTP target before shared evidence construction, retaining full URLs only in an appropriate client source. |
| P1 | Repeated authored Mac timing / distribution_texture | Host/Threat/Detection 41; Host/Threat 42: not labeled | Repeated fork fractions and six exact 2-second inventory lifetimes; high observed score effect | Authored scenario; benchmark changes outside this task | The pattern is visible and repeatedly drives specialist confidence. It is explicitly authored; preserve it during engine repair rather than adding jitter that contradicts canonical timing. |
| P2 | SSH hour-boundary closes / distribution_texture | Network 40: not labeled | 18/48 longer core SSH sessions close within first 90 seconds of an hour; medium | Session planner/teardown; medium | Closes cluster across five hours, suggesting an hour-fence lifecycle effect. Inspect the shared close owner against role schedules before changing distributions; this is a qualified lead. |
| P2 | HTTP child/parent capture consistency / contract_gap | Network 35–36: not labeled | Repeated qualified source-local file gaps; medium | Application identity and source observation; high | Child capture and parent transport need coherent source-local ownership; independently partial sensors need not be nested. Establish immutable transaction identity and a shared observation contract instead of changing only a seed or file emitter. |
| P3 | Host health-age resets / environment_or_collection_plausibility | Host 40: not labeled | fwupd ages 2/6/14 days within hours, same PID on three hosts; low/medium | Host-local metadata/state; medium | The ages deserve stateful review, but multiple remotes or distinct metadata can explain them. Qualify native semantics before treating this as a proven contradiction. |

Counter and proxy semantics outrank texture because they are reproducible source-native
contradictions. The request-target repair is narrower and lower risk, so it can lead
the next implementation pass while the stream/capture contract is designed.
[Zeek documentation](https://docs.zeek.org/en/v8.0.5/scripts/base/protocols/conn/main.zeek.html)
defines TCP byte totals from sequence numbers; captured IP/packet counters have a
different meaning. [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1)
excludes fragments from the target URI. Both durable defects are tracked in TODO.md.
Neither belongs in an emitter-only rewrite.

Private module inventories, inode texture, optional collection gaps and possible
4658 field extensions remain weak or unverified. No additional hard contradiction
is claimed from those observations. Complete coverage, compact narratives and absent
pre-window initiators were excluded as synthetic indicators.

## Quantitative versus blind evidence

Quantitative evaluation protects parseability, existing relationships and bounded
ordering contracts. It does not yet enforce the native stream/capture distinction,
fragment-free request targets or every timing distribution. Reviewers likewise did
not consistently detect the pivot-linkability hard failure in loops 33–34. Neither
high aggregate evaluation nor low blind confidence overrides a demonstrated failure.


# Ten-loop assessment comparison

Synthetic-confidence score,0–100; lower is more production-like. Deliberation* contains facilitator-modeled reconciliation, excluded from initial and rolling averages.

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 33 | 96.07† | 36 | 64 | 31 | 67 | 49.50 | mixed/inconclusive | 64.00 | 58.05 |
| 34 | 96.07† | 67 | 42 | 65 | 63 | 59.25 | mixed/inconclusive | 67.00 | 61.40 |
| 35 | 96.71 | 48 | 77 | 42 | 43 | 52.50 | mixed/inconclusive | 66.25 | 57.95 |
| 36 | 96.09 | 57 | 18 | 62 | 65 | 50.50 | mixed/inconclusive | 64.50 | 55.90 |
| 37 | 96.09 | 43 | 32 | 34 | 68 | 44.25 | mixed/inconclusive | 56.25 | 51.20 |
| 38 | 96.09 | 40 | 38 | 62 | 69 | 52.25 | mixed/inconclusive | 62.25 | 51.75 |
| 39 | 96.09 | 44 | 20 | 30 | 66 | 40.00 | mostly realistic | 49.50 | 47.90 |
| 40 | 96.09 | 43 | 35 | 56 | 44 | 44.50 | mixed/inconclusive | 49.50 | 46.30 |
| 41 | 96.09 | 64 | 63 | 84 | 63 | 68.50 | likely synthetic | — | 49.90 |
| 42 | 96.85 | 38 | 53 | 32 | 65 | 47.00 | mixed/inconclusive | 59.00 | 50.45 |

† Loops 33–34 failed the 80% pivot-linkability hard criterion (79.8942%), despite high overall scores. Loops 35–42 passed all hard criteria.


## Audit and artifacts

The [artifact audit](loops-33-42-artifact-audit.json) verifies all 40 score/report
pairs, arithmetic means, required deliberations, quantitative statuses and SHA-256
identity between authoritative data and neutral panel copies. The SVG dashboard was
rendered after loop 42 was finalized and parses successfully. Facilitator-modeled
revised scores are excluded from the standalone means and rolling averages.

- [Final loop](loop-42/REPORT.md)
- [Final deliberation](loop-42/deliberation.md)
- [Dashboard: loops 23–42](assessment-effectiveness-dashboard-last-20-loops.svg)
- [Worklog](../../../docs/worklog/2026-11-04-iteration-test-macos-assessment.md)
