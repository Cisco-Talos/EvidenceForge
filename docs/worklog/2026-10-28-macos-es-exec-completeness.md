# Complete modeled macOS ES exec coverage

## Accepted priority

The user accepted the contract proposed after commit `ea9c378e` and made it the highest priority:
every modeled successful exec on supported Mac profiles, within active lossless ES collection,
must have its corresponding native exec record or generation must fail with actionable missing
requirements. The question in this turn is how to achieve that outcome. No strict enforcement
or additional native coverage is implemented by this planning checkpoint.

Added the [implementation contract](../design/macos-workstation-feasibility/es-exec-completeness.md)
and prioritized it in TODO.md. The previous GUI worklog's unapproved-proposal note is superseded
by this explicit acceptance. The active profile remains macOS 27 arm64.

## Owning layers and first implementation increment

The current `MacosNativeCoverage` scope is `exact_process_cohorts_and_authored_births`.
`MacosESIngress.finalize` counts admitted source snapshots, while `GroundTruthGenerator`
supplements authored aggregate births. That cannot detect every background process bypass.
`prepared_macos_es_process_publication` can omit unbound/out-of-window paths and marks unknown
metadata with counter-only filtered observations. Those behaviors must not satisfy the accepted
complete-coverage contract.

The user challenged the complexity and lack of measurable output. The accepted sequence now
starts with small generation workloads, compares every intended successful start/exec with its
actual native record, and repairs concrete producer/metadata gaps. Add the all-path state/action
census and enforcement after useful workload slices work. Reuse atomic rollback/retry and
checkpoint owners rather than build a separate publication framework. Do not derive the final
expected set solely from records that already reached ES ingress. An all-failing strict guard
and repeated assessments are not substitutes for successful useful output.

The user further clarified that every process starting within the simulation window belongs in
scope, including background services/helpers. Fork-only children need appropriate fork evidence;
every image activation, including same-PID replacement, needs exec evidence. Collection must
cover the full window for a complete-coverage claim. Builtins/app reuse are not process starts.

## Clarification: generic starts versus native exec

The user asked what bypassing native publication means compared with Windows/Linux. It does
not mean an actual program bypassed a security sensor. The shared process service can publish
an aggregate `process_create` occurrence: the simulated process is already described as running
its target image. eCAR renders that occurrence on all three operating systems. Windows Security
4688 and Sysmon 1 also have direct renderers for Windows process-create occurrences. Linux
syslog renders explicitly modeled service/auth/application messages rather than every exec;
shell history is a separate command observation. There is no equivalent complete Linux-native
exec-audit coverage claim here.

Mac native ES uses a separate exact publication owner for authenticated fork/exec/exit phases.
Its emitter intentionally rejects ordinary process-create dispatch. Qualified producers build
the transition and its native metadata; aggregate producers do not. Thus a Mac process can be
present in canonical state/eCAR with no modeled native exec eligible for that publication path.
Another gap occurs when an explicit exec exists but required native facts remain unknown. Both
are implementation/qualification gaps to surface and close, not grounds for silently omitting
successful modeled executions. The existing Windows/Linux renderers also do not by themselves
prove a full producer-to-output census; this effort makes the Mac contract independently checked.

## Human dependency and privacy

Most census/enforcement/producer work needs no collection. The human has shared the v3 offline
classification; its reviewer copy `/private/tmp/eforge-gui-launch-kit-t9ksukqt` is now private.
Do not inspect or run it against a used private kit. Its results and scope remain in the
[GUI worklog](2026-10-28-macos-gui-launch-reference.md). Dock/Spotlight,
nonnull entitlements and broader unqualified helper/descriptor families may need narrowly
specified additional evidence. No collection, log access or native execution was authorized by
agreeing to the product contract. No private directories or logs were inspected in this turn.

## First measured ordinary-command slice

An initial invented six-command comparison found no native exec for three local commands and
native exec for two of three corresponding SSH commands. The larger independent 11-command SSH
test reproduced the missing `uname` record: the process was accepted and had an exec transition,
but its executable remained unresolved. Added `macos-uname` to the installed command catalog and
the existing modeled validation policy. Like the neighboring entries, these signing/Mach-O/
absent-entitlement facts are explicit synthetic binary choices, not inspected host inventory.
No automatic baseline application assignment or nominal exit result was added.

The local command producer's missing fact was responsibility. The modeled terminal chain now
explicitly selects the terminal app as the owner of its login/shell/command descendants, using
the existing exact lifetime reference and State validation. This is a canonical workload policy,
not a new Terminal capture or qualification of Terminal's own exec/entitlement export. The
internal fresh literal user-launch request carries this fact through the existing process owner;
its stable identity changes when responsibility changes. Omitted facts and older frozen profiles
stay unknown; an existing unknown terminal is not relabeled from its PID or ancestry. Generic
GUI/application launches retain their existing gates and ordinary exec inheritance is unchanged.

The 11-command generator test now passes for local and SSH launches, with native output both
selected and omitted. It matches exec identity, image, argv, canonical time and exact local
responsible owner. Public CLI tests independently compare authored process success and native
output/coverage for the same commands. The local and SSH versions are separate workloads:
an active SSH client occupies its local shell, so local commands cannot be asserted to run in
that shell concurrently. An initial combined fixture exposed that its reservation could move
commands beyond collection, then fail native directory lookup. The canonical reservation now
rejects such starts before allocation, preserving explicit skipped outcomes without claiming
missing execs or inventing a second terminal. The occupied-shell CLI case is retained as a
negative control. Baseline generation remains enabled in the successful CLI cases.

These tests establish the ordinary command slice only. Terminal/login/shell aggregate launches,
services, GUI birth-to-exec, helper/PTY/complex-command families and global strict enforcement
remain open. The denominator must not silently exclude these when the all-process claim is made.
The user's v3 Finder report also rules out a zero launcher audit session and shows a same-PID
responsibility token distinct from both exec snapshots; its exact field sampling remains unresolved.
No new classification loop, capture, app launch or local native-file inspection was performed.

The mixed-workload regression exposed a generic-logoff owner still comparing the registered
birth image with the process's current image. It now validates the existing lifecycle runtime
view (image and execution ordinal), preserving immutable birth ownership. A direct short
regression closes a zsh-born process after its bash exec and verifies both views remain intact.
The mixed-workload timing check now follows eCAR exec MODIFY records, since CREATE correctly
retains the inherited image. An out-of-order unit fixture now opts into the public engine's
existing chronological ES ingress instead of weakening the direct collector's ordering rule.

## Bounded follow-up for the v3 token finding

The v3 result exposed an ambiguous same-PID token that the prior whole-token labels cannot
explain. A code-only version-4 offline reviewer now compares all eight predefined fields of
both responsible tokens against the before/target tokens. It exports relationship labels and
known zero/sentinel classes only. Numeric PID-version position is classified only for the
controlled PID and makes no chronology, counter-wrap or sampling-cause claim. Original bounded
read/provenance controls are unchanged; it performs no collection, app launch, live lookup,
subprocess or writes. Invented mixed-token and malformed-word tests exercise the new comparison.
Agents must not run the reviewer on a human-used kit or inspect its results. No native GUI
generation gate is widened based on these new diagnostic capabilities.

## Verification and handoff for revision 347

The final public CLI acceptance workloads each produce **11 of 11 expected exec records**
for ordinary local and non-PTY SSH commands. The occupied-local-shell negative control records
explicit unavailable intents without allocating post-window processes. The six-hour mixed
benchmark now exports **34 native records: 21 fork, 10 exec, 3 known exit**, compared with the
previous **14: 8 fork, 4 exec, 2 known exit**. This is deterministic workload coverage, not a
fresh authenticity assessment or a complete process census.

Literal quoted interpreter inputs now retain the interpreter's own canonical/native exec.
Unquoted operators, expansions, concatenated quoting and effect-bearing plans retain their
existing gates. Supplied exact argv is used directly, including apostrophes, empty arguments
and literal metacharacters; it is not reinterpreted from its display string. Inner command trees
are not invented. Regression checks cover the source record's exact argument vector.

All **7 slow CLI contracts** pass, including fresh-process/native-only byte equality, parser
schema/constraint checks, mixed-workload timing and nonempty checkpoint verification/suspend/
resume byte equality. The focused final engine/reference selection passes **1,057 tests**
(one existing slow case deselected). After the final fixed-label refinement, all **187 GUI
reference tests** pass. Full Ruff/format, whitespace, all **99 config files** (zero findings)
and behavior revision/digest checks pass. The final behavior digest is
`b12117a15c284e0781a6d45aaa675df0378322d18d3392bc0e1450bd66177f57`.

The broader runtime-catalog selection has 18 passes and two failures in the existing pytest/pip
baseline-launch expectations. Both failures reproduce against an isolated, unmodified archive
of HEAD `07b02ba9`; no full routine-suite pass is claimed. They remain a separately recorded
baseline readiness lead, not justification to mask missing ES records or start an assessment loop.

Prepared human-only offline reviewer v4: `/private/tmp/eforge-gui-launch-kit-0q2jr2hb`.
Its isolated `-I -B --help` passes. It contains code/instructions only at handoff; agents ran
no setup, capture, report or review-existing command. The human should select original outer
kit `/private/tmp/eforge-gui-launch-kit-kzex70ik` at the hidden prompt and share only the fixed
JSON. No sudo, setup/capture, app launch or new collection is needed. Once used, this new copy
inherits the private no-inspection boundary. All previous used kits remain untouched.

## Version-4 Finder follow-up

The human's fixed v4 result now resolves the preimage responsibility token: old audit
user/session/PID/PID version, but four zero POSIX credential words. Target responsibility is
the complete target token. Revision 348 consumes that bounded observation at native preparation,
without changing actual process credentials/ownership or claiming a new lifetime. The selected
source rule is scoped to authenticated GUI exec and v11, including runtime/installed paths,
filtering, known exit and recovery. Nonzero anonymous preimage audit-session fixtures replace
the older arbitrary zero choice. No private files were inspected and no further collection is
needed for this token distinction. Detailed implementation/verification is in the GUI worklog.

## Authorized four-item implementation continuation

The user explicitly authorized completing all four remaining items as far as possible without
assistance: Finder end-to-end, other producers, independent accounting/enforcement, and finite
acceptance/recovery tests. Commit and push useful milestones; do not stop between items or start
new assessment panels. Standing private-capture/local-log restrictions remain unchanged.

The in-progress Finder producer now stages an aggregate xpcproxy birth and the authenticated
app exec in one existing canonical transaction. A shared host audit-session allocator reserves
the nonzero anonymous origin and rolls it back with the birth. Its initial image activation
remains an unresolved independent obligation, never an inferred native fork or silently
excluded denominator. Existing immediate and chronological native publication admit the app
exec without requiring a native record for that aggregate birth. Forty-five invented GUI
transition/recovery cases pass, including the new staged form; 95 adjacent tests pass.

Current work wires this into explicit `process.launch_method: finder` and a narrowly selected
baseline image policy. New catalog entries describe an explicit modeled xpcproxy image and an
invented EForgeReference app; their signing/image-security choices are model declarations, not
values copied from private captures or claims about arbitrary vendor binaries. xpcproxy
entitlements stay unknown, so its own initial exec is not qualified by this work. Generic apps
do not inherit the reference app's signing/entitlement facts. A real-engine authored/baseline
test is being run before closing this increment. No new collection or private access occurred.

The shared-engine authored and actual `execute_baseline_activity(process_code)` tests now pass with native output both selected and
filtered: the app has one v11 exec and its explicitly known exit, with no invented fork.
The new anonymous origin shares the existing host audit allocator and is protected by exact
cohort identity, namespace rollback, full State checkpoint restoration and subsequent login
allocation. Normal and deferred ingress paths retain interrupted-write recovery. The focused
State/process/Finder set passes 177 tests (one existing slow case deselected). A public CLI
Finder workload passes fresh-process/native-only byte equality with baseline enabled. The
baseline test opts the invented app into a temporary effective catalog and initializes under
that frozen scope; no random schedule or warm-up launch count is used as the baseline oracle.
The separate native/cross-OS regression selection passes 191 tests (two existing slow cases
deselected). All 99 installed config files validate with
zero findings; ordinary personas remain unassigned to the invented app.

This is bounded app-exec coverage, not closure of item 1's entire launcher chain. xpcproxy's
initial activation still lacks a qualified first-exec producer and known entitlement export.
It must be counted by the independent all-process census and rejected in complete mode. The
next independent engineering work is that census/enforcement plus migration of other feasible
process producers. No privacy boundary or unknown-field gate is relaxed to improve a count.

Revision 349 final verification: the native SSH checkpoint/suspend/resume contract passes
again after the Finder changes; all seven focused real-engine/CLI cases have passed. Whole
Ruff, formatting and whitespace checks pass. The behavior manifest is revision 349 with digest
`554e05ca8e5dbf4bb7cb0a0e491f1c054751081af8ca75b22dff52746f65fa76`.

## Revision 350: independent all-start census and complete-mode enforcement

Canonical accounting now lives at the two actual State mutation owners: every process birth
and every successful exec. It therefore includes legacy registration, terminal/session helpers,
services and other producers which never call the ES factory. Fork-only births require fork
evidence; aggregate born-image starts add an unresolved initial-exec obligation. Existing
lifetimes may add later exec obligations. Eligibility uses actual canonical times in the
half-open simulation window, independent of authored labels or source decisions.

The bounded per-host head retains counts, multiplicity-preserving SHA-256 fingerprints and
at most eight truncated aggregate examples. Cohort rollback restores it with State. State head
schema 11 persists it; schemas 6–10 migrate with no invented history. A complete run cannot
claim coverage from such a missing historical census and must start fresh. No emitter or
source hook supplies the expectation denominator.

Native finalization independently counts committed fork/exec occurrence receipts, compares
identity fingerprints with State, verifies native journal row counts, and streams the generated
synthetic export after close against full native-row fingerprints. Missing, duplicated or
changed records reject. Retry rebuilds the bounded receipt census from the existing spool;
there is no new duration-growing identity list or second process publisher.

Selecting native ES defaults `macos_process_coverage` to `complete`; the resolved request
survives runtime format narrowing. CLI/Studio's shared validator and engine preflight reject
missing output, disabled process collection, loss and collection-window gaps. Runtime unknowns
or aggregate starts fail before bundle acceptance, with host, fork/exec counts, aggregate image
examples and source qualification reasons. Explicit `partial` retains exploratory generation
and reports the same independent census honestly. The six-hour benchmark is now explicitly
partial; no scenario has been mislabeled complete to preserve a passing native subset.

A real-engine positive workload has **11 canonical forks and 11 execs, all matched to native
publication and export**, with a legitimately modeled pre-window terminal. Moving terminal
startup into the window rejects; disabling the qualified command producer also rejects.
Additional tests cover same-PID re-exec, PID reuse, half-open boundaries, source-bypassing
registration, provisional rollback/retry, full State restore, legacy history, omitted/doubled
writes and physical synthetic-export duplication. All 248 selected adjacent tests passed;
after final boundedness/policy refinements, the focused 103-test set also passes. Nine slow
CLI contracts pass, including native-only equality and nonempty suspend/resume. The denial
tests now assert the new independent census and pass. Two additional public-CLI negative
controls prove that unresolved starts and removal of the required native source reject by
default. All 13 slow contracts pass across these selections. The separate 468-test State,
checkpoint, behavior-manifest and legacy-lifecycle regression set passes. Whole Ruff/format
and whitespace checks pass. Final revision-350 digest:
`01319fb79a0d928fc3d7cd3f5ce72677a2057db309aeaa9e6319e8dbb9f8b45f`.

The concrete producer inventory and finite acceptance matrix are at
`docs/design/macos-workstation-feasibility/process-producer-inventory.md`. Unsupported initial
terminal/xpcproxy/service activations, helper/PTY and effect-bearing paths remain classified
gaps, not hidden denominator exclusions. Further native qualification may need a bounded
human-run experiment for populated entitlements and the controlled launcher's first exec.
No local native logs, human-used kit files, collectors or apps were accessed by the agent.

## Revision 351: retained shell-script producer

A new real-engine regression reproduced an explicitly retained shebang launch as an aggregate
birth with no native exec. The existing shell producer now accepts the exact script retention
alongside image retention and carries the caller's canonical script fact into the exec. It does
not infer that fact from the command string or argv. All source/native/artifact publication
still uses the existing atomic process cohort and exact retained-content proof; no extra
publisher or emitter-local inference was introduced. Effect-bearing plans retain their gate.

The four selected/filtered × explicit-script/argv-only real-engine cases pass, including exact
State/census checkpoint restoration and native script/interpreter distinction. A pre-window
terminal and one new script activation satisfy complete mode with one fork and one exec.
Existing birth/script retention, source placement and ordinary-command cases pass too. The
combined reference/script selection passes 238 tests (one existing slow case deselected).
The final script/native-census/behavior selection passes 79 tests. Whole Ruff/format,
whitespace and revision/digest verification pass. Revision-351 digest:
`22f64fb6795c3a53b303d77753e6d66142daf0fc51cb25e879abcf0fbe392e5e`.

## Prepared human-only launcher/entitlement follow-up

The new opt-in version-2 setup signs only the harmless own-process probe with the fixed
synthetic marker `org.evidenceforge.reference.synthetic: true`. A bounded transient xpcproxy
exec ring is added to the existing filter. Only an exact controlled-app exec can authorize
persistence of a matching launcher: full audit token, PID version, birth time, native file
object and code identity must agree. A preceding fork requires the launcher's full child
token/lifetime agreement. No unrelated candidate is written, no PID/path-only match is used,
and missing retained forks never establish absence. Stream/retention/watchdog bounds remain;
the additional in-memory ring is explicitly capped at 64 rows/4 MiB.

The supplementary report exports only fixed relationship/representation labels and agreement
with the known synthetic marker. Populated entitlements are masked only inside an explicitly
named diagnostic shape-isolation check, never in generation admission; the production codec's
nonnull entitlement gate is unchanged. Original app-only behavior and old manifest/provenance
serialization remain compatible. All 238 selected reference/script tests pass, including
canary non-disclosure, foreign token/file/code rejection, bounded buffers, versioned setup and
mocked signing; none executes native commands. The procedure is at
`docs/design/macos-workstation-feasibility/gui-launch-reference/LAUNCH-CHAIN.md`.

Fresh code-only kit: `/private/tmp/eforge-gui-launch-kit-apsp1wi7`. Isolated `setup --help`
passes. The agent ran only `prepare` and `--help`, never setup/capture/report/review or a
collector/app. No prior human-used kit was accessed. Once the human uses this new copy it
inherits the same no-inspection boundary. The next independent engine work is effect-bearing
process publication; unknown initial launcher/terminal/service metadata remains a human
qualification dependency, with complete mode rejecting those gaps rather than hiding them.

## Revision 352: plain file effects preserve native process execution

A real-engine regression reproduced a literal `/bin/ls` launch with a planned directory read
as an aggregate process birth. The shared shell producer now stages its fork/exec alongside
plain planned file effects in the existing exact action journal. Every file member retains
the authenticated effect graph and the executed process identity. It consumes no additional
ES process counter and does not become a trigger for sibling generation. Runtime artifact
mutation and mixed network/scanner/registry effect families retain their existing gates.

The existing State and lifecycle owners now admit a scalar activity frontier for the exact
post-exec identity inside that same cohort. Credential, descriptor and other state changes
remain excluded from this frontier contract. The process/session frontier includes the final
file occurrence, and later bookkeeping cannot move the session clock backward. Provisional
rollback, exact retry and full State checkpoint restoration preserve this ownership.

The focused process/effect/source suite passes 121 tests (two existing slow cases deselected).
All 507 selected State, checkpoint, lifecycle, artifact and manifest regressions pass. Additional
source-level checks exercise immediate and chronological publication separately; public complete
mode still requires chronological ingress and independent export receipts. The real-engine
matrix covers one/multiple file effects, native/eCAR format filtering, failure before journal
commit, lost acknowledgement after commit, and timing/capacity rejection without process birth.
All 16 immediate/ordered real-engine cases pass. The four public-CLI contracts pass as well,
including fresh-process/filter-independent native bytes, nonempty checkpoint suspend/resume,
and default rejection of unresolved starts or removal of the required native source. Whole
Ruff/format and whitespace checks pass.
No native collection or private evidence access occurred. Final revision-352 digest:
`b253f020eb75212f3590d8e74909e6c5676bf00ee7a53ff11eb9eab7dfb28cba`.

## Revision 353: retained file mutations share native execution publication

A second measured omission involved a qualified literal interpreter command creating a
retained synthetic file. Its file version published correctly, but the command remained an
aggregate birth. The same canonical shell transaction now admits authenticated file creation,
modification and removal. Existing image/script retention remains bound to the exec; a file
publication belongs to its exact effect member, time, artifact, content and metadata. The
existing registry group owns atomic file mutation and rollback. No new publisher, generated
artifact trigger or native ES file callback was introduced.

The closed family accepts only its endpoint file graph and an empty independent root effect
plan. An unrelated network/scanner graph cannot disappear behind a file-only reconciliation.
Writing the executing image remains outside this qualified family. Unsupported launches stay
in the independent all-start census and cannot satisfy complete mode.

The new real-engine cases cover create/modify/delete with native selected or filtered, native
output with eCAR filtered, exact State and artifact checkpoint restoration, artifact failure
after placement/withdrawal, journal failure before publication and lost acknowledgement after
publication. They also reject a mismatched file-publication time without process allocation and
prove that an unrelated root graph fails instead of being hidden by native qualification.
Reference kits and private evidence were not accessed. Revision-353 digest:
`bba265f00315ade770be1f45d880d7cf780be4e5fc562a2daaa25f54df8f5df7`.

All 156 selected process/artifact/source/manifest tests pass (two existing slow cases
deselected), including the 15 new retained-file cases. A separate 110-test Finder, GUI exec,
ingress, independent census and complete-collection selection passes. The shared State and
lifecycle verification remains the 507 passing tests recorded for revision 352; revision 353
does not change those implementations.
The four public-CLI slow contracts pass again after the final source change, including native
filter/fresh-process equality and nonempty checkpoint suspend/resume. Whole Ruff/format and
whitespace checks pass. No release/version change or assessment panel was performed.

## Remaining boundary after the independent implementation

Independent accounting/enforcement and the finite recovery matrix are implemented. Ordinary
qualified commands, retained scripts and plain/retained file effects have useful complete-mode
positive tests. Finder's app execution is connected through authored and baseline producers;
the first xpcproxy activation still needs native qualification. Initial terminal/login/shell
and service/helper activations, populated entitlement export, PTY helpers and additional GUI
methods remain unresolved. Explicit unknowns cause complete-mode rejection; no aggregate start
is silently removed to pass a workload. Unrelated scanner/non-file effect plans retain their
existing unsupported boundary rather than receiving a fabricated execution contract.

The next human dependency is the already prepared opt-in launcher/entitlement experiment at
`/private/tmp/eforge-gui-launch-kit-apsp1wi7`, following the tracked `LAUNCH-CHAIN.md` procedure
with agents closed. Only the fixed JSON report is requested. The agent must not run its setup,
capture, report or review or inspect the kit after handoff. Once that bounded reference is
available, implement the exact supported first-launch facts before requesting another broader
experiment. No new assessment panel is a prerequisite.

## October 30: authorized helper run and session-lock diagnostic

The human explicitly requested that the agent run the capture and obtain its fixed JSON.
This authorizes the bounded helper commands for this experiment; the prohibition on exposing
private native records or committing captures remains. The agent ran only the original kit's
fixed-output offline reporter, which returned `INTERNAL`; no cause was inferred from that
generic error and no capture files were opened directly. A fresh sandboxed setup failed with
`BUILD`; a new copy built successfully with normal compiler access. Sudo readiness reported
`REQUIRED`. Authentication and capture were therefore opened in a standalone Terminal, with
the password staying in its native prompt and the Finder launch left to the human. The chat
was interrupted after opening that command; the external Terminal was not assumed stopped.

The human's subsequent immediate `INCOMPLETE` report with all default fields identifies the
pre-collection `SESSION-LOCK` collision. Its displayed version 1 was the generic exception
template, not proof of a wrong kit. The helper now returns `SESSION_LOCKED` with the already
verified manifest version, collection mode and platform/provenance labels. It neither reads
nor removes the existing lock and starts no collector on this branch. Both versioned modes
have invented-input lock/canary/no-side-effect tests; all 204 selected reference-kit tests pass.
The procedure now explains single-session use, cancellation and fresh-kit recovery. Existing
capture directories, Terminal contents and process listings were not inspected or changed.

Replacement kit `/private/tmp/eforge-gui-launch-kit-3k5m_j_1` is built with version 2,
`SETUP_READY`, `error: NONE`. No capture, probe launch or automatic Terminal runner was started
from this replacement. Stop the earlier Terminal attempt and allow its watchdog/cleanup before
starting exactly one manual capture in the replacement. No evidence gate has been closed.

The next human report reached `COLLECTOR_READY` with v11 delivery, sequence continuity and
cleanup passing, then failed `INCOMPLETE` before `FINDER_READY`. This is the automatic control
probe, not another lock collision or a missed Finder click. Its own snapshot/completion was
not available for comparison. No private capture or Terminal output was inspected to diagnose
this. A code-derived collector-free own-process diagnostic is prepared at
`/private/tmp/eforge-gui-control-self-check.py`; it isolates session, audit-token, BSD-info and
descriptor API failure stages and returns only an allowlisted label. It reads no private
capture and opens no GUI. Automatic approval review rejected executing this new probe under
the standing compile-only restriction. Compile-only verification subsequently passed with
`COMPILED_NOT_EXECUTED`; native execution has not occurred. An explicit async permission
question is pending. Do not execute the diagnostic until that answer arrives, and do not
request another full capture without using the bounded diagnosis to narrow this failure.

## October 30: control-launch failure isolated with the approved self-check

The human explicitly approved the collector-free own-process self-check. The original API
check returned `PASS`. An isolated replica then exercised the same own-process APIs, bundle
path and run-directory validation against newly invented sidecars; it never opened a human
kit, native record or GUI and never saved observed identity/descriptor values. The ad-hoc
variant without the synthetic entitlement passed. The marker-signed variant was killed;
explicit DER generation and a fresh-inode copy of the signed executable both left that result
unchanged. This isolates the marker-signing variant
as the failing condition in this controlled experiment. The specific OS policy/component
behind the kill was not established because no local security logs were inspected. No security
setting, certificate/keychain identity or entitlement granting an Apple capability was used.
Apple's [signing guidance](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/)
requires standard XML entitlement input; its general rules do not identify this kill's cause.

Launcher collection now defaults to no added synthetic entitlement. The marker is a separate
explicit `--synthetic-entitlement` setup option requiring `--launch-chain`; the new manifest
and fixed report retain that choice. Existing manifests without the field preserve an unknown
choice and their original serialized provenance. Populated-entitlement generation admission
is unchanged and remains gated. No failed probe is substituted as successful native reference.

The investigation also found that readiness accepted a matching exec/exit even when the
process was killed. Native readiness now requires wait status zero, and subprocess checks
require successful completion too. A short non-GUI check runs before any capture files or
collector are created; failures return fixed `PROBE_*` labels. Control launch errors have
specific `CONTROL_*` labels. Finder timeout retains `FINDER_READY` and reports `FINDER_TIMEOUT`;
an empty pre-collection stream no longer claims sequence continuity. All 217 reference-kit
tests pass using invented inputs, including native-execution guards, marker opt-in/default,
legacy provenance, failed readiness, pre-collector failure cleanup and Finder timeout.

Final replacement kit: `/private/tmp/eforge-gui-launch-kit-j2f7qyi4`, already built with
`kit_version: 2`, `synthetic_entitlement: false`, `SETUP_READY` and `error: NONE`. Its actual
non-GUI `--ready` path also returned the fixed `PASS` label under the approved self-check.
No full GUI control or collector was started by the agent. Earlier kits and captures remain
untouched. Use this replacement for the next single human-run Finder capture; no setup rerun
or synthetic marker is needed. No evidence gate has yet been closed by these checks.

Whole Ruff/format and whitespace checks pass. These are private-kit code and documentation
changes, not a generation-behavior or product-version change. No native capture files are part
of the commit; the diagnostic source and its invented-layout work remain outside Git.

## October 30: successful launcher experiment and missing-prefix follow-up

The human shared a completed marker-free version-2 report from the final replacement kit.
Provenance, platform, readiness, bounded collection, cleanup and sequence continuity pass under
v11. Both app exec/exit shapes, image/identity/argv/descriptor comparisons and known zero status
pass. Finder again has a launchd parent, self responsibility and non-TTY vnode stdio. Environment
comparison remains different from main entry, consistent with the earlier reference distinction.
No raw capture, own-process snapshot or Terminal was inspected by the agent.

`launcher_retained: NONE` leaves the first xpcproxy phase unresolved. Code review found a real
filter blind spot: the candidate ring accepted xpcproxy execs only during Finder phase, so a
matching candidate observed in readiness/control was discarded. The ring now spans those
three phases while retaining the same 64-row/4-MiB bounds and exact full-token, lifetime,
file-object and code-identity persistence proof. Invented-input tests cover earlier-phase
prefixes without persisting unrelated data. This does not prove the cause of this report's
missing prefix, and no native source admission or process-census requirement was relaxed.

The version-5 offline reviewer now accepts original app-only and launcher-chain kits without
modifying them. It isolates retained app phases from any launcher prefix, preserves the chain's
missing-data labels and classifies the Finder preimage lifetime relative to control birth/exit.
It exports no times, durations, identifiers or arbitrary environment/signing data and starts no
process, collector, app or role query. It cannot recover a discarded candidate ring or establish
the collection-subscription instant. All 223 reference-kit tests pass, including v2 read-only
review, lifetime categories, provenance/canary guards and cross-phase prefix matching. Obtain
the bounded offline supplement before asking for any repeat collection. Initial launcher and
populated-entitlement gates remain open; GUI ULF and other launch methods remain uncollected.

Code-only version-5 reviewer prepared at `/private/tmp/eforge-gui-launch-kit-h5zvt6u_`.
It has not been set up or run against a real capture. Whole Ruff/format and whitespace checks
pass. The next operation needs permission for the fixed-output offline read of the existing
capture under the standing local-log rule; it requires no native execution or new collection.

## Approved version-5 offline result and finite next capture diagnostic

The human approved running the offline reviewer on the completed capture. It finished with
`error: NONE`, provenance and original collection controls passing, and no collector, app,
probe or live role query started. The agent received only fixed labels through the hidden-path
review command; no raw native record or private snapshot was returned or changed.

The Finder preimage is XPCPROXY and its birth is `AFTER_CONTROL_EXIT`. It therefore began
during the active collection, rather than being an old pre-collection process. This does not
locate that birth relative to the controller's Finder-phase switch. Control environment
differences are only the known CF text-encoding addition at main; Finder has changed common
values, as previously observed. Its native audit/session/group/descriptor/argv facts reproduce
the earlier reviewed transition, including the distinct preimage responsibility token. The
preceding launcher exec/fork remains unretained, so no first-launch source gate is closed.

Because the discarded transient ring cannot be recovered offline, the corrected collector now
also exports a fixed matching decision and a ring-eviction boolean. It distinguishes no
candidate, no execution-identity match, full-token mismatch, image mismatch and an exact match.
It exports no identifiers, values or counts and retains exactly the same raw-row ownership
proof. A malformed unretained candidate cannot discard the otherwise valid controlled app
record. Offline reports preserve these recorded labels and leave older reports unknown. All
226 reference-kit tests pass with invented inputs; no repeat collection has been started.

Corrected collector kit `/private/tmp/eforge-gui-launch-kit-_wy8qxd6` is built with version 2,
no synthetic entitlement, `SETUP_READY` and `error: NONE`. It has not run a probe, GUI control
or collector. The C probe and watchdog sources are unchanged from the working marker-free
capture. A repeat, if performed by the human, will retain earlier-phase candidates and report
fixed rejection/eviction reasons rather than another unexplained `NONE`. No setup rerun or
changes to the completed original capture are needed. Initial-xpcproxy qualification still
requires actual retained first-exec facts; no process census, collection policy or native
qualification gate was weakened to accept this report.

## October 30: token mismatch identifies the remaining collector join defect

The human shared a complete corrected-filter report with all original collection controls
passing, no ring eviction, and `candidate_selection: TOKEN_MISMATCH`. Both app cases retain
passing shapes, image/identity/argv/descriptors, completion and zero exit status; the launcher
is still unretained. The decision proves matching PID, PID version and birth but does not
establish file/code agreement, which the old loop checked only after full-token equality.
No private capture, native record, Terminal content or process listing was read by the agent.

Code/primary-source review identified the overstrict join: the full audit token includes
mutable current user/group/audit-origin fields. Apple's XNU `proc_find_audit_token` validates
PID and PID version; `proc_calc_audit_token` combines those with current credential/audit data.
The [process implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
and [credential implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_prot.c)
support separating execution ownership from snapshot agreement. They do not establish the
specific syscall, token words or transition in this human capture.

The collector now requires a unique earlier xpcproxy candidate with the same PID/version/birth,
device/inode, cdhash and signing/team identity. Both paths must be exact/untruncated and the
signing identifier must be xpcproxy's expected identifier. Missing code fields no longer compare
equal by default. Ambiguous or out-of-order candidates are rejected. Credential/audit word
agreement is reported separately using fixed PASS/FAIL fields; all raw data stays private and
the same rings/byte/time bounds apply. Old TOKEN_MISMATCH reports remain readable without
inventing lost history. The fork retention proof is unchanged. This fixes a collection join,
not native generation qualification or canonical process census policy.

All 241 reference-kit tests pass with invented inputs, including all six mutable token words,
reused/mismatched execution identity, image/code mismatch, absent identity fields, ordering and
ambiguous candidates. The rejected candidate was never written, so the existing capture cannot
provide the missing first-exec metadata offline. Corrected marker-free kit
`/private/tmp/eforge-gui-launch-kit-5h1iiz9q` is built with `SETUP_READY`, `error: NONE` and
passing platform/provenance checks. A first sandboxed compile failed with BUILD in a separate
unused copy; the fresh kit compiled successfully with normal compiler access. No probe, app,
collector or live role query was started. Use the new kit for the next human-run capture; do
not run setup again or change any completed private capture. Initial-launch qualification
remains open pending the actual retained first-exec facts.

## October 30: static xpcproxy identity correction and complete comparison report

The next human capture completed with passing collection/app controls, no candidate-ring
eviction, and `candidate_selection: IMAGE_MISMATCH`. This confirms that the corrected token
join reached image checks, not which image predicate failed. No actual capture, own-process
snapshot, Terminal content or process listing was inspected. The rejected raw candidate is
not recoverable from this kit's retained evidence.

Before asking for a repeat, a read-only inspection of the fixed Apple system binary
`/usr/libexec/xpcproxy` used codesign with captured in-memory output. Only allowlisted
comparison labels were returned: the old `com.apple.xpcproxy` expectation does not match,
and `com.apple.xpc.proxy` does. No raw signature metadata, records, personal values, collector,
probe or app execution was involved. The wrong spelling existed in both the private-kit
checker and the application catalog and was repeated in the invented fixture. It was
sufficient to reject a valid candidate pair, though this static inspection does not establish
that it was the only failed predicate in the discarded human candidate.

Both expectations are corrected. Generation revision 354 records the catalog-owned signing
identity correction; the initial-activation, populated-entitlement and completeness gates are
unchanged. The shared Finder engine test now checks the native preimage signing identifier
from the actual catalog-driven event path. Behavior digest:
`b360e6b475e4de1e333e2411809539e7229d6762889225bd0527c8e9500a3020`.

The image predicate now computes all checks independently in one typed fixed-label model,
which also controls retention and offline linkage. For a unique execution match, the capture
report records the full image comparison, eight token comparisons and source ordering even
when it rejects the raw candidate. Missing fields, bad representation and mismatched values
cannot become a permissive match; ambiguous execution-only comparisons remain inconclusive.
Offline reporting preserves the recorded comparisons and leaves older history absent. Raw
retention scope and bounds are unchanged. No native source admission follows from a diagnostic.

All 356 selected tests pass: private GUI/launcher kits, Finder engine generation/adoption,
application catalog and behavior compatibility. Invented negative cases cover the wrong
identifier, simultaneous independent predicate failures, ambiguous comparisons and private
canaries; generated native Finder evidence carries the corrected catalog identifier.
The marker-free replacement `/private/tmp/eforge-gui-launch-kit-jsdpx_t1` is built with
`SETUP_READY`, `error: NONE` and platform/provenance passing. No probe, app or collector was
started. Do not rerun setup or modify any completed capture; the next human-run experiment
uses this fresh kit and can explain all image predicates in a single fixed report.

## October 30: first launcher fork/exec retained; offline metadata approval pending

The human pasted the reviewed fixed report from the corrected kit through a chat attachment.
Only that supplied report was opened. The agent did not inspect the kit's private captures,
snapshots, Terminal or process listings. Collection/platform/provenance/readiness/bounds/sequence
and cleanup pass. The launcher has `ONE` retained exec, `MATCHED`, `RETAINED_MATCH` fork and
passing linkage. Every image comparison and source ordering passes, with no ring eviction.
Both launcher/app native shapes pass when entitlements are isolated; app exec/exit and own
image/identity/argv/descriptors retain their previous passes. No new live collection is needed
for the remaining metadata review.

The launcher initially has root POSIX credentials. All four POSIX token words differ at the
later app preimage, while audit user/session, PID and PID version remain equal. These are two
credential states in the same execution, before the separately observed app exec. This is
distinct from the already-modeled zero-word responsibility token: first-exec root credentials
are now directly classified, not inferred from responsibility. The current user-credential
aggregate cannot be relabeled as a qualified root fork/exec. Its replacement will need an
explicit authenticated credential transition without an invented extra image activation.

The first exec additionally reports object-valued entitlements, a failing current security
tuple, non-generic ARM64 subtype and an argv layout outside the old absolute-path classifier.
Those concrete classes remain unresolved rather than being treated as source absence or as
permission to accept guessed flags, entitlements, arguments or CPU subtype.

A static inspection of the fixed installed Apple xpcproxy binary returned only approved shape
labels, then a sanitized vendor template after confirming the expected signing identifier,
`com.apple.*` key names and Boolean-only values. The eight Boolean vendor entitlements are
code metadata, not native log records or personal configuration. Initial sandboxed display
attempts were inconclusive; the documented XML display with normal filesystem access succeeded.
Only the static system file was read; no app/probe, collector, security setting or signing
mutation was involved. The template is embedded only in the private reviewer's expected
reference. It has not been asserted equal to eslogger's object or admitted to generation.

Version 6 of the offline supplement now classifies all remaining first-exec facts in one pass:
named public code-signing bits/category (with an unknown-bit check), ARM64 subtype/capabilities,
argv0 and controlled-app service-label roles, standard environment relationships, fork parent/
image linkage, and exact static Boolean entitlement keys/values. It returns no arbitrary
entitlement names/values, environment strings, service labels, paths, timestamps, numeric
identities, hashes or raw flags. It starts no subprocess, app, collector, probe or live query
and changes no evidence. Existing v1/v2 provenance and capture reports remain readable.

All 272 reference-kit tests pass with invented inputs, including read-only end-to-end review
of a populated-entitlement launcher chain, private canaries, named flags/unknown bits, ARM64e
capabilities, argv roles, exact Boolean typing, environment differences and schema rejection.
Ruff/format and whitespace checks pass. Generation revision remains 354; no codec, source
qualification, State census or native producer gate was changed by this supplement.

Code-only reviewer `/private/tmp/eforge-gui-launch-kit-qpj8kw44` is prepared. No setup or native
execution was run from it. Permission was requested to run `review-existing --private-run`
against the completed `/private/tmp/eforge-gui-launch-kit-jsdpx_t1` under the standing local-log
rule. Do not read that capture until the answer arrives. Use the hidden original-outer-kit
prompt, never overwrite the old helper or run setup in the used kit.

After that bounded review: admit only the confirmed entitlement wire form and named security/
slice metadata; implement launchd fork -> root xpcproxy exec -> explicit POSIX credential
transition -> existing GUI app exec -> known exit through the exact action publication owner;
then prove the authored/baseline complete-mode census, output filtering and recovery matrix.
Other startup/service/helper families remain separate inventoried obligations. No assessment
loop is a prerequisite for this development sequence.

## Approved offline result and revision 355: reviewed executable metadata

The human approved running version 6. The prepared reviewer completed with `error: NONE`,
passing provenance and original collection controls. Only its fixed JSON reached the agent;
it performed no collection, app/probe/subprocess launch or mutation of the capture. The same
bounded review also classified the already-retained fork parent and first-exec source security
and standard environment roles. No additional private files or live queries were added.

The fork's parent is the boot parent and the child preserves its image and credentials.
Fork parent, first-exec source, xpcproxy target and app preimage share the named flags
VALID, FORCED_LV, HARD, KILL, RESTRICT, ENFORCEMENT, ENTITLEMENTS_VALIDATED, RUNTIME,
NO_UNTRUSTED_HELPERS, PLATFORM_BINARY and SIGNED. All bits are known, category is PLATFORM,
and none of those processes is an ES client. The xpcproxy exec slice is ARM64E/PTRAUTH_ABI.
Its argv0 is the basename xpcproxy, with one controlled-bundle service label and decimal-pair
suffix. That label agrees with the later app's XPC_SERVICE_NAME. Entitlements are a nonempty
direct Boolean dictionary with exact static keys and values matching the Apple binary template.
The initial environment contains only XPC_FLAGS; standard user/home/path/shell/tmp/service/CF
fields are added for the app. App XPC_FLAGS is decimal one; the initial value remains OTHER
and private. No arbitrary environment values or label suffixes were requested or recovered.

Revision 355 implements the verified flat Boolean native wire form with exact Boolean typing,
bounded nonempty keys, immutable tuple storage and a JSON-object serializer. Unknown facts,
empty dictionaries, nested containers and other value types remain distinct/rejected.
Catalog signer entries compile to sorted immutable pairs; absent and unknown checkpoint rows
retain their old encodings, while present Boolean data has an explicit tagged encoding. Both
installed and runtime artifact/head readers restore it. Native publication preserves the active
profile's entitlement policy and no longer mislabels unknown canonical facts as known presence.
The current macOS 27 profile permits the reviewed Boolean form; old frozen absent-only profiles
retain their restriction. This is not admission of arbitrary XPC/JSON entitlement types.

The catalog now owns xpcproxy's verified eight Boolean vendor entries. Validation policy selects
the named security mask for launchd/xpcproxy and the signed ARM64e subtype only for xpcproxy;
the reference app and ordinary arm64 executables retain their independent policies. Synthetic
digests are still derived once, never copied from a local binary or log. The updated binary
metadata reaches authored/baseline Finder source snapshots and survives packed-registry recovery.

Focused verification covers Boolean-object/null wire round-trips and input detachment, malformed
types, immutable canonical signatures, installed checkpoint encodings, and native fork/exec/exit
publication with omitted/explicit/Boolean entitlements under before-write and after-write retry.
The expanded run passed 468 tests with only three manifest-summary-length failures; shortening
that summary then passed all 23 behavior tests. Subsequent reference/behavior verification
passed 297 tests, including two exact-old-codec-lineage cases. Routine slow exclusion remains;
no full repository test-suite claim is made.

Offline review now explicitly accepts only the known pre-Boolean codec hash as a historical
lineage. New setup/capture still requires the current codec, and arbitrary codec drift rejects.
This prevents a compatible decoder update from invalidating the completed private capture;
future review should use a freshly prepared code-only reviewer rather than editing a used kit.

The first launcher remains an aggregate start in the production action owner. Metadata
qualification does not satisfy its independent start/exec census or authorize manufactured
native rows. The remaining implementation must represent the boot-parent fork, root launcher
exec, exact GUI-account credential/session ownership change and app exec as separate canonical
phases with authenticated publication and recovery. Existing State cohorts admit one exec per
process and keep credential changes separate; preserve those guarantees while adding the
needed ordered action graph, rather than hiding the initial activation from complete mode.

The runtime artifact/head metadata suite also passed all 28 cases, including an explicit
Boolean-entitlement restore through `LocalArtifactVersionRegistryParticipant`. Whole Ruff,
format, whitespace and behavior-surface checks pass. Revision-355 digest:
`c5f0374ab5598c9b56cb93a36c6f721eae9bd61869a0987b26600a1a9c4b70f0`.

## Revision 356: retained Finder startup implementation

The shared authored/baseline process owner replaces the user-credential aggregate birth with
an actual boot-parent fork, root xpcproxy exec, separate GUI account/session attribution change,
and app exec in the same lifetime. The root-to-user transition preserves execution ID, audit
pair and PID version. Only the app exec adopts the GUI audit origin, own process group and
self responsibility. Immutable historical snapshots and restored checkpoints retain both
credential states; legacy service-drop checkpoint widths still decode without GUI attribution.

A retained activity-owned startup coordinator publishes three exact cohorts in order. Every
cohort retains its pending capability/receipt, finishes source recovery before advancing, and
survives a rebound ephemeral process service. Pending startup rejects checkpoint sealing.
Nine extended interruption cases pass: before-commit, lost-return and source-release failure
at each phase. Each finishes with exactly one fork and two execs in the independent census.
Installed-only app admission, explicit bundle identity, empty effects, qualified image metadata,
exact live GUI authority, declared timing and readiness are checked before the first mutation.
Runtime app retention and unrelated effect graphs remain unsupported rather than bypassed.

The data policy owns a declared reference bundle ID independently of code signing. A scoped
deterministic decimal-pair service label is computed once and shared by xpcproxy argv and app
XPC_SERVICE_NAME. Initial XPC_FLAGS=0x2 is an explicit synthetic workload input, not the private
reference literal (which remains OTHER). App XPC_FLAGS=1 is the classified relationship.
Three opaque vnode standard descriptors come from explicit child spawn file actions; no
launchd descriptor table or backing path is inferred. The selected timing gap is synthetic,
not measured startup calibration. Static fixed-output inspection of /sbin/launchd confirmed
its public com.apple.xpc.launchd signing identifier and absent team; no logs were opened.
The catalog now supplies that static identity, with synthetic code digests as usual.

Native fork preparation exposed one unclassified field: launchd's parent_audit_token when
its canonical parentage is explicitly absent/PID zero. Apple public ES documentation names
the field but does not establish its no-parent representation. The source profile now has an
optional explicit wire policy, with no default. Unknown policy records the fork gap as
boot_parent_token_unknown; explicit partial output can still publish both qualified execs.
The independent complete-mode census continues to reject that missing fork. No kernel process,
parent credentials or zero token is silently invented.

Version 7 of the offline reviewer adds only fixed boot-parent token, PPID, group/session and
unattributed-origin classes to the same bounded existing records. Its 275 reference-kit tests
passed before three additional boot-label cases were added; the subsequent focused regression
passed 534 tests including those cases. The prepared code-only reviewer is at
/private/tmp/eforge-gui-launch-kit-b9gy67m0. Permission to run it against the existing completed
/private/tmp/eforge-gui-launch-kit-jsdpx_t1 was requested asynchronously. Do not inspect that
capture until the answer arrives; no new collection is required.

Invented-policy authored and baseline tests each produce fork -> exec -> exec -> known exit,
and a complete census with one fork, two execs and no aggregate starts when the GUI login
really predates the collection window. Filtered execution follows the same canonical chain.
These tests verify the implementation without claiming the pending real no-parent wire fact.
The 534-test regression covers credential/GUI changes, process snapshots, census, exact cohorts,
source profiles, mixed projections, private-kit fixed output, lifecycle runtime and owner bindings.
The wider initial run stopped on obsolete expectations for the retired aggregate Finder fallback
and zero audit-session origin, plus a test-fixture error; those were corrected. No full repository
suite or completed public native acceptance claim is made.

### Public recovery acceptance and two owning-layer fixes

The public CLI's authored Finder generation and format-filter equivalence passed. A new
three-hour checkpoint/suspend/verify/resume/control comparison then found two actual defects.
First, a later independent baseline member could advance the boot-group reservation timestamp
and falsely reject the earlier app's setpgid at exec. The qualified GUI exec now uses the same
independent-member boundary rule as birth/exit, while retaining per-process time checks and
rejecting early retirement of the final member. A focused regression covers both the allowed
lookahead and rejected early retirement; the ordinary POSIX transition suite remains strict.

Second, lifecycle checkpoint hydration still required immutable login attribution in every
current runtime view. The new reviewed credential transition requires an explicit retained
GUI-attribution frontier, separate from immutable process lifetime membership. It contains the
before/after tokens, binding time and revision, survives subsequent app exec/history compaction,
and cannot be rewritten by an ordinary runtime change. Lifecycle head schema 9 serializes this
bounded frontier; genuine schemas 5-8 remain readable and rewrite as schema 9. Legacy heads
cannot contain new GUI attribution. Corrupted/missing/foreign/time/revision and downgraded proof
cases reject without changing the restore target. No broad authentication-invariant removal
or emitter correction was used.

After these fixes, the public checkpoint test passed: it retains a live ordinal-2 app with its
GUI credential record, verifies the checkpoint read-only, resumes and starts another Finder app,
and compares every deterministic bundle byte with uninterrupted generation. Each authored PID
has exactly one root xpcproxy exec and one app exec. It remains an explicitly partial workload
because the boot-parent token and in-window GUI/terminal startup gates are still open.
No private capture, Terminal or process-list inspection occurred during this implementation.

Final focused routine verification passes 708 Mac execution/source/reference/manifest cases
(with five slow exclusions) plus 189 lifecycle/POSIX/checkpoint compatibility cases (also five
slow exclusions; overlapping cases are not an independent combined count). Whole Ruff, format
and whitespace checks pass. Revision-356 generation surface digest:
`65c4b5839cf08e8fdee59c7eb7e7ca6fc2f155a03d4f527978172c1d692c228a`.
The final public CLI/filter/checkpoint and per-phase fault tier passed all 11 cases against
that exact surface in 64.45 seconds. The v7 private review remains unrun pending the requested
permission. No native logs are included in this commit.

## Revision 357: approved v7 offline review and Finder fork qualification

The user authorized the prepared v7 reviewer against the existing completed capture. It ran
read-only and only the fixed JSON reached the agent. Error NONE, provenance PASS, original
collection controls PASS, retained chain PASS and fork parent/image/credential comparisons PASS.
The new labels are boot_parent_ppids_zero PASS, boot_parent_group_and_session_one PASS,
boot_parent_parent_token DEFAULT_UNATTRIBUTED_KERNEL and boot_parent_default_audit_origin FAIL.
Given the established sentinel audit user and valid unsigned token fields, the last FAIL means
launchd's own ASID is nonzero. This inference requests or reveals no private numeric ID. No
collector, app, probe, live role query or capture mutation occurred.

The production profile selects the reviewed parent token. Canonical State reserves a synthetic
assigned unattributed boot audit session through the existing host audit counter, rather than
using the PID-zero parent's default session. Both primitive and batch planning expose the same
bounded boot intent: Mac root launchd, fixed PID 1, parent zero, new POSIX session and explicit
unattributed credentials. It is allocation-free until commit and participates in rollback.
Boot descendants inherit that pair. GUI authentication uses the same namespace after the boot
reservation, so its session cannot collide. Audit-user sentinel membership remains unattributed
with a nonzero session; no authenticated account is invented for launchd.

The reviewed Finder chain now publishes native fork plus both execs, and known exit when
explicitly supplied. Authored and baseline complete-census tests use the active production
profile with a genuinely pre-window GUI login; their previous invented boot-policy override
was removed. A missing policy remains an explicit unavailable-fork diagnostic and complete
mode still rejects it. Existing generic/in-window GUI, terminal, service/helper and Dock/
Spotlight gaps remain separate. Public docs and inventory now distinguish this closed producer
from the remaining all-process work. No native records or private capture files are committed.

Revision-357 verification: 33 boot/Finder/audit-namespace cases passed; the broader initial
275-case source/audit/materialization run passed 274 and exposed a direct-mixin Mock compatibility
call, subsequently corrected. Its boot/profile/manifest group then passed all 61 cases. A separate
SSH/SMB/process/provisioning regression passed 65 cases (one slow exclusion); its old zero-boot-ASID
expectation now checks the assigned origin and exact receiver inheritance instead. The final
public Finder CLI/filter/checkpoint plus nine per-phase interruption cases passed all 11 in
61.57 seconds. Production-profile native output includes the fork, both execs and an explicitly
known exit; the independent complete census has one fork, two execs and no aggregate birth.
Whole Ruff, format, whitespace and behavior-surface checks pass. Revision-357 digest:
`21e248cba8e19d14a43d181f7e9b358f3bafedb53660676bb71d68c068757195`.
The private review returned only fixed labels, changed no capture files and requires no rerun
for this gate. All new test records are invented; no native records enter the repository.

## Revision 358: Apple Terminal and iTerm2 share the session path

The user requested both terminal applications in the Mac catalog and the same process logging
contract for each. `macos-iterm2` now has its own native executable, product/deployment identity
and per-session singleton policy. [Upstream iTerm2's release plist](https://github.com/gnachman/iTerm2/blob/master/plists/release-iTerm2.plist) confirms the
`iTerm2` executable and `com.googlecode.iterm2` bundle vocabulary. The catalog does not infer
a signing identity from that bundle identifier or copy Apple's validation/entitlement policy.
Both apps have the `macos_terminal` role and the same modeled login child spawn rule.

Automatic shell bootstrap selects the frozen user's eligible terminal assignment, defaulting
stably to Apple Terminal when both are eligible. An existing active shell is reused. The shared
bootstrap also accepts an explicit terminal catalog ID, rejects another app before mutation,
and cannot silently substitute another app for a live session shell. Both variants reuse the
existing audit, responsibility, PTY/device, lifecycle and descendant-command owners.

The new measured workload covers both apps with selected and filtered native output and with
pre-window versus in-window startup. In each variant the external `id` has exactly one native
exec and its responsible token points to the actual selected terminal. Pre-window startup
passes the independent complete census; in-window startup still rejects because app/login/
initial-shell activations remain aggregate. No denominator exclusion or invented app exec
was introduced. This increment does not qualify either app's own native startup or assume
that iTerm2's real helper tree is identical to Apple's.

The initial focused run exposed two older framework-module assertions that searched only live
processes after a short command's bounded termination had already been published. The test now
uses the existing retained lifecycle lookup and checks its actual close, rather than depending
on a sampled command still being live. All 120 terminal/catalog/metadata/foundation cases pass.
The next reference must establish app activation, helper/login/shell exec boundaries and native
metadata for each app; existing GUI audit probes establish inheritance but not those births.
No system logs, private captures, live apps or process listings were inspected.

Final revision-358 regression passed 204 command/audit/Finder/signature/terminal cases in
66.41 seconds. Whole Ruff, formatting and whitespace checks pass. The behavior manifest
passes with digest `c15a02a4a12e96bdd8e3244623ffc48e7bf0e42e8dab33a4ec97676bd28ecc56`.
Catalog/session milestone `ee01457a` is pushed to the existing branch.

### Two-terminal private startup kit, prepared only

`scripts/macos_terminal_startup_reference.py` prepares a separate human-run experiment for
each real terminal. The ordinary-user controller reuses the existing bounded root eslogger
guard and fixed-output ABI/shape helpers. Readiness is proved by the known compiled marker;
the human then launches the selected terminal and invokes that same marker once. A bounded
transient ring retains no unrelated candidates on disk. Only the marker-authenticated launch
chain can be saved, and only when the selected app's exact device/inode is observed in an exec.
An ancestry link and a kernel responsibility link have distinct fixed labels: responsibility
does not imply parentage. Same-PID replacements, actual forks and unmatched forks remain
separate. Raw rows are written only after successful chain proof and collector cleanup.

The fixed report includes role order, audit/credential/session relationships, public signing
flag/category labels, slice/entitlement shapes, argv classes, stdio kinds, terminal/cwd classes
and environment comparisons. It cannot export arbitrary native strings, IDs, paths, hashes,
environment values or entitlement keys. Private provenance binds normal-user account inputs,
OS version/build, code/codec hashes and both binary objects. Setup compiles/signs but launches
nothing; replay reads only the saved fixed JSON. Neither operation is run by the agent.

All 235 terminal-kit and existing GUI reference-kit invented-input cases pass, including
replaced identity/birth cases, unrelated candidates, responsibility-only linkage, ring loss,
sequence/stream limits, fixed-output failure handling, cleanup and successful selective writes.
Both C sources pass clang's warning-as-error syntax checks without execution. The isolated
prepared helper's help command succeeds. The public Finder CLI/filter/checkpoint and complete
coverage rejection tier also passes all four cases in 39.41 seconds against revision 358.

Prepared code-only copies (no setup, collector, marker, real app launch or native-record read):

- Apple Terminal: `/private/tmp/eforge-terminal-startup-kit-58skrbfu`.
- iTerm2: `/private/tmp/eforge-terminal-startup-kit-lt0qqywk`.

Each contains `private_terminal_startup.py` and `PRIVATE-RUN.md`; setup uses `--terminal apple`
or `--terminal iterm2` respectively. Control each test from the other terminal app so the test
app can be fully quit before a fresh launch. The human must run privately with agents closed.
Once used, do not inspect these directories or their native records without new permission.
This is a diagnostic kit, not new native qualification. The in-window app/login/initial-shell
gate remains open pending the human's fixed reports; no additional Finder test-app capture,
fresh GUI login or machine-wide historical log access is needed.

### Terminal kit version 2: installed binary permissions and setup failure diagnostics

The human reported an immediate capture `IO` with all controls inconclusive and confirmed
that setup had returned `ERROR / LOCATION`. Code review and invented-file reproduction found
the owning defect: `_image` reused the GUI helper's private-file reader for the installed
Terminal executable. That reader deliberately rejects files with another owner or public
permissions, which are normal for an installed app. Setup therefore never sealed its manifest;
the subsequent capture reported the missing manifest as generic `IO`. No private kit, capture,
native record, system log or process listing was inspected to diagnose this.

Version 2 has a separate descriptor-bound installed-executable reader. It accepts ordinary
system/user-owned public executables, retains regular-file/no-symlink/change checks, streams
the hash with a 256 MiB bound and no longer applies the private-record reader's 16 MiB limit.
Private code, provenance, marker/guard and record readers retain their existing strict checks.
Setup and verification share the corrected installed-file reader. No app is launched by it.

Fixed failure steps now distinguish installed app, setup manifest, build, private artifacts,
run preparation and publication stages without exposing exception text or native values.
Missing setup returns `SETUP_REQUIRED` before platform commands or collector activation;
repeated one-shot operations return `KIT_ALREADY_USED`. Failed CLI operations exit 2, so
shell success chaining cannot continue after a failed setup. The saved version-1 fixed report
shape remains readable. Native collection scope and all simulation evidence gates are unchanged.

All 248 terminal and existing GUI reference-kit tests pass. New tests reproduce the original
private-reader rejection with invented public files; cover system ownership, strict private
permissions, bounded large-file hashing, symlinks/writers/file changes, and successful mocked
setup plus manifest verification without native execution. Missing setup never starts a
command or creates a session lock; error messages remain outside the shareable JSON.

Fresh version-2 code-only copies replace the earlier instructions:

- Apple Terminal: `/private/tmp/eforge-terminal-startup-kit-jlgbqbs1`.
- iTerm2: `/private/tmp/eforge-terminal-startup-kit-vcnw5bf8`.

The old version-1 directories are untouched; do not reuse or inspect them. No setup, native
collector, real app, marker or private-file review was run by the agent. Whole Ruff, formatting,
whitespace and the unchanged revision-358 behavior-surface check pass.

## Revision 359: successful Terminal reference and bounded runtime metadata

The human supplied the version-2 fixed Terminal JSON directly. Error NONE, complete stage,
provenance/platform/readiness/cleanup/bounds/sequence PASS, no ring eviction, retained app exec
PASS via ANCESTRY, wire V11 and marker exit zero PASS. Only that attachment was read; the
private kit, native records, system logs and process listings were not inspected.

The retained exec roles are xpcproxy (launchd preimage), Apple Terminal (xpcproxy preimage),
login (Terminal preimage), zsh (login preimage) and the marker (zsh preimage). Matched forks
are reported for xpcproxy, login, zsh and marker. Same-PID replacement describes each exec's
before/after pair; it does not make this entire chain one PID. The Terminal app has no matched
fork for its xpcproxy-to-app replacement, which is consistent with the existing Finder owner.
The detailed offline reviewer will explicitly classify each retained fork's parent image.

Terminal's native shape fails while the shape excluding entitlements passes, isolating the
remaining codec mismatch to that value. Its exact value layout is not yet established.
Login's argument class is OTHER, its credential tuple differs from an all-user tuple, and
its "only standard descriptors" predicate fails. That last result can reflect extra open
descriptors or a different last-FD bound; do not infer an inventory from the single Boolean.
The app's audit/group changes and the false ES-client predicates are observations, not failed
collection controls. Marker-entitlement predicates are not vendor-app validity checks.

The active execution profile now selects the observed clean runtime flags and ARM64e/PTRAUTH
slice separately for Terminal, login and zsh: 0x26017b01, 0x26015b11 and 0x26010b01 respectively,
with signed subtype -2147483646. Existing xpcproxy policy agrees. Other utilities retain their
explicit existing policy; iTerm2 receives none of these Apple signing/runtime defaults.
No entitlement, argument, FD or credential transition is invented to enable startup. The
complete-mode in-window startup rejection remains in force. No raw records are committed.

### Offline terminal detail reviewer

The new `scripts/macos_terminal_startup_review.py` prepares a code-only, offline reader of the
existing completed version-2 capture. It verifies exact capture code/codec, setup and run
provenance, controlled marker/guard metadata, collection controls and retained chain scope.
It opens no installed app, runs no command or live role query, starts no collector/probe and
writes nothing during review. The report exports closed labels for entitlement value types,
login argv words/flags, descriptor slots and last-FD extent, per-word local/root credential
classes, parent/child fork images and transitions, and exact responsibility comparisons.
Unknown native strings stay hidden. No entitlement keys/values, usernames, paths, hashes,
PID/audit/pipe IDs or environment values can enter the fixed report.

The reviewer is not yet run against private evidence. Reading the original kit requires a
new explicit permission under the standing local-log rule. No additional Terminal collection
is proposed. The independent iTerm2 startup reference remains necessary before treating its
real helper/metadata behavior as equivalent to Apple's.

The focused regression passed 341 tests in 48.19 seconds, including 19 new offline-review
cases and the complete selected/filtered terminal command boundary. Those cases cover
same-PID exec versus separate forks, fork-parent images, credential/membership transitions,
closed argv/FD/type vocabulary, unchanged files, broken provenance/code/guard/codec/control,
extra/unlinked rows, bad marker exit and private file permissions. Native commands and
installed-app reads are explicitly forbidden in the reviewer tests. One existing zsh policy
expectation was updated to the new observed flags; legacy missing policy still stays unknown.
The public Finder CLI/filter/checkpoint and complete-mode rejection tier passed all four
cases in 40.68 seconds against revision 359. Whole Ruff, formatting, whitespace and surface
checks pass; digest `df38fab309196c7e5c1e185298f80ce8934694f386484ef53f6da1153d273b64`.

Prepared reviewer, code only: `/private/tmp/eforge-terminal-startup-kit-9_bkj8sj`.
Its `private_terminal_review.py --help` passes with isolated Python. The exact pending
permission request is to run that reader against the completed original Terminal outer kit
`/private/tmp/eforge-terminal-startup-kit-jlgbqbs1`; it has not been run. The alternate human
command is `python -I -B private_terminal_review.py review-existing --private-run`, selecting
that original outer directory at the hidden prompt. No new collection, setup, app/marker
execution, live query, capture mutation or direct record display is authorized by preparing it.

## Revision 360: approved Terminal review and bounded entitlement arrays

The user explicitly approved the exact version-1 offline reviewer above against the completed
Terminal kit. It ran once, read only its approved bounded input and returned fixed labels.
Error NONE, step COMPLETE, provenance, original collection controls and retained chain all
PASS. No collector, app, probe or live query ran, and no capture file changed. No native record,
identity, argument value, environment value or entitlement key/value was displayed or copied.
This approval does not authorize another review or a broader local-log read.

The review closes these relationship/shape questions for this Apple Terminal experiment:

- Terminal's entitlement object has exact Boolean values and arrays containing strings; no
  nested object value types were observed. The previous flat-Boolean decoder rejected it.
- Terminal forks the login child with user credentials. Before login exec the child establishes
  its own POSIX session/group and a controlling terminal. Login then has real UID user,
  effective UID zero and user groups. Its exact argv classes are basename `login`, `-pf`, user.
- Login's post-exec inventory is VNODE FDs 0, 1, 2 and PIPE FDs 4, 5, with last-FD bound 5.
  This report does not establish equality or inequality of those pipe IDs; do not invent it.
- Login forks the shell while still effective UID zero; the child drops that privilege before
  shell exec. Zsh argv0 is `-zsh`, its session/group remain login's, and only standard FDs remain.
- Login, shell and marker retain the exact Terminal responsible execution. The command child
  inherits the shell group at fork and forms its own group before exec. Xpcproxy/app startup
  audit and membership changes agree with the already-qualified GUI prefix.

The new shared entitlement type accepts only nonempty objects with exact Boolean or string-array
values. It bounds keys, array/string lengths, aggregate text and nodes, detaches mutable input,
and retains immutable canonical values. V11 renders native JSON arrays; scalar strings, numeric
coercions and nested objects/arrays remain unsupported. Unknown versus explicit absence stays
distinct. Boolean-only checkpoint encodings retain their previous bytes; a separate explicit
`boolean-string-array-v1` tag preserves arrays through installed-release and runtime restore.
The current source profile enables that capability. Old frozen absent-only and Boolean-only
profiles still enforce their original restrictions, including publication fault recovery.

Separately from the private capture, a read-only static signing check verified the installed
Terminal and login against Apple's signing anchor and their exact public identifiers. Only
vendor entitlement definitions with Apple-prefixed keys/service strings, absent-team labels
and closed file-mode/ownership classes were returned. The sandbox trust-service failure was
resolved by the same filtered check outside the sandbox; no app or native collector ran.
Terminal's catalog template contains five Boolean entitlements and the `kTCCServiceAll` string
array; login has two Boolean entitlements. Login is root-owned/root-group setuid mode 04555;
Terminal is root-owned/root-group mode 0755. This is static vendor metadata, not a retrospective
native-capture comparison. Generated hashes/UUIDs remain independently synthetic. iTerm2 gets
none of these Apple-specific facts. File-mode/credential startup effects are not enabled by
adding signer metadata.

Review version 2 preserves future review of the original capture by recognizing only the exact
revision-359 predecessor codec fingerprint in addition to the current decoder. It reports the
fixed lineage class; arbitrary fingerprints still fail. Capture code, marker/guard, provenance,
controls, permissions and scope checks are unchanged. Only invented bundles exercise this
compatibility path before the separately approved real run below.

That prepared version-2 reader also closes the two precise remaining comparisons without a
new live collection: FD 4/5 pipe identity equality and native entitlement equality against the
independent static vendor templates. Only fixed relationship/PASS/FAIL labels can leave it.
Invented inputs test both pipe relationships, missing/malformed inventories, exact Boolean
types and canary non-disclosure. The user separately approved that exact version-2 reader
against the same completed original Terminal kit. It ran once and returned error NONE, step
COMPLETE, qualified predecessor lineage, and provenance/controls/retained-chain PASS. Login's
FD 4 and 5 are SAME pipe identity. Both Terminal and login vendor-entitlement comparisons PASS.
No pipe ID, captured entitlement definition or other native value was disclosed. No collector,
app, command or live query ran, and all capture files remained unchanged. That authorization
does not extend to future modifications or other captures.

The next development task is the canonical native terminal startup chain, using the qualified
GUI prefix plus login setuid/session/TTY/pipe transitions and shell credential drop. The full
in-window terminal/login/initial-shell rejection remains in place. The specific Apple Terminal
relationship/template questions above are closed; no further Apple Terminal collection is
currently required. The separate iTerm2 startup reference is still outstanding. This increment
does not silently treat all GUI apps as qualified.

Validation: 670 focused codec/signature/restore/source/profile/GUI/terminal cases passed in
48.09 seconds. After the version-2 comparisons were added, all 27 offline-review tests plus
the four public CLI/filter/checkpoint/complete-rejection cases passed in 40.23 seconds. The
first CLI run caught an overlong behavior-manifest summary, corrected before final validation.
Whole Ruff, formatting, whitespace and behavior checks pass. Revision-360 surface digest:
`22c19638c7cb47f75b5f45bb0e79cf1e7667ebd8a07e2e510785bcc8cdff5029`.
The version-2 code-only reviewer is `/private/tmp/eforge-terminal-startup-kit-0965dwiz`;
its isolated help command passes. No native capture files are part of this change.

Entitlement milestone is committed as `626ad29f`. Pushing to the existing origin branch failed
with HTTP 403; a read-only repository-permission check reports pull true and push false for
the current CLI account. No credentials, remotes or access controls were changed. Publication
needs restored repository write access (or an explicitly selected writable remote).

## Revision 361: installed login permissions through the canonical file owner

The next independent implementation adds exact permission rules to the frozen installed-file
profile. The only shipped rule selects machine scope, product `apple-macos`, artifact `login`
and exact path `/usr/bin/login`, with verified mode 04555. Ownership still comes from the
canonical root account of that installation's host. Path spelling alone cannot select setuid
metadata for another product, a user copy or an aliased installation. The deployment registry
already rejects a path whose basename has no exact artifact; the initial negative test was
corrected to assert that earlier rejection rather than expecting provisioning to accept it.

Profiles without permission rules retain the previous generic permissions. Duplicate selectors,
noncanonical paths, artifact/path disagreements and coerced permission values fail schema
validation before allocation. The existing installed filesystem owns and projects the actual
stat; there is no emitter rewrite, runtime host filesystem lookup or new credential default.
Checkpoint reconstruction includes the exact login stat. Login setuid execution, the later
shell privilege drop and the terminal/descriptor transitions still belong to the next native
startup producer; this metadata increment does not enable aggregate startup export.

Validation passed 91 installed-file/provisioning, terminal-path and Finder-generation cases
in 34.87 seconds, including legacy policy, exact selector isolation and actual engine checkpoint
reconstruction. The four public CLI/filter/checkpoint/complete-rejection cases pass in 40.48
seconds. Whole Ruff, formatting, whitespace and behavior checks pass. Revision-361 surface:
`a9daf970835a30d72b2e7a3de021a63715715f2f31145cb603350b9dbb166fcd`.

### Push authentication resolved

The user identified `DavidJBianco` as the correct repository account. A token-free identity
and permission check confirms that gh uses that account and it has push access. Git has a
separate credential-helper chain, including Keychain; an ordinary push still selected the
other account. A command-scoped helper override successfully pushed `626ad29f` and `f01b3622`:

```sh
git -c credential.helper= -c 'credential.helper=!gh auth git-credential' -c credential.username=DavidJBianco push origin codex/macos-workstation-support
```

This resets helpers only for that command and uses the already active gh account. No tokens
were displayed, and no saved authentication settings, accounts, remotes or other projects
were modified. Until account isolation is configured separately, use the same override after
confirming that gh's active account is `DavidJBianco`; do not globally switch the other project.

## Paired iTerm2 reference before shared startup implementation

The user requested collecting the equivalent iTerm2 evidence now, then implementing both
terminals together with shared code where justified. This replaces the proposed sequence of
finishing Apple Terminal first. Existing Apple Terminal references remain sufficient; no new
Terminal capture or private-record read is proposed.

The fresh code-only kit `/private/tmp/eforge-terminal-startup-kit-u0gu76nv` bundles the unchanged
version-2 capture controller, version-3 offline detail reviewer and focused `ITERM2-RUN.md`.
The human runs setup/capture/review privately with agents closed, controlling from Apple
Terminal and launching a fresh iTerm2 ordinary login shell from Finder after readiness. Both
fixed reports are requested together. No setup, collector, probe, app or private/native record
read was run by the agent. All older used/unused kits remain untouched.

Version 3 reports equivalence groups for pipe FDs in fixed slots 0-15 without native pipe IDs.
This covers a different iTerm2 FD arrangement in the first review rather than assuming Apple's
FD 4/5 layout. Duplicate/malformed facts fail; higher pipe slots stay inconclusive. It keeps
unknown helper roles as OTHER without exporting their paths. Shared canonical fork/exec,
audit, responsibility, job-control, descriptors and recovery should be reused where evidence
agrees; app-specific helper stages and signing/launch inputs stay explicit.

iTerm2's [own session-restoration documentation](https://iterm2.com/documentation-restoration.html)
describes long-lived servers and reattachment. Preserve that feature during the test; use a
fresh shell rather than a restored job, and do not force it into Terminal's observed topology.
One marker-authenticated ancestry/responsibility chain is not proof of all sibling helpers or
all restoration modes. Unrecognized roles/metadata may require later bounded qualification,
but the equivalent startup collection can proceed now.

All 61 invented-input capture/reviewer tests pass in 0.32 seconds, including both apps' full
offline provenance/scope validation, a separate intervening helper, arbitrary pipe-slot groups,
malformed/higher-slot bounds, canary non-disclosure and unchanged files/no native commands.
Both prepared helpers' isolated help commands pass. Generation behavior remains revision 361;
no engine, active generation policy, application catalog, release version or evidence gate changed.

### iTerm2 controller prerequisite: Apple Terminal Full Disk Access

The human supplied a fixed report from the first iTerm2 attempt: version 2, Terminal identity
iterm2, platform/provenance PASS, immediate COLLECTOR at step COLLECTOR, readiness inconclusive,
cleanup FAIL, no retained app/wire/phase evidence. Code inspection confirms this is the early
collector-exit path; stderr is deliberately discarded and guard failure does not distinguish
authorization, sudo or other startup failures. Cleanup FAIL means the helper did not return
the expected zero status, not a claim that collection remains running.

The installed eslogger manual (static documentation only) and Apple's
[Endpoint Security introduction](https://developer.apple.com/videos/play/wwdc2022/110345/?time=488)
require the responsible controller app to have Full Disk Access independently of root/sudo.
The previous Terminal experiment used iTerm2 as controller; the iTerm2 experiment reverses
those apps. Asked for only the setting's status, the human confirmed that Apple Terminal is
disabled or absent in Full Disk Access. No privacy settings, TCC databases, private kit files,
native records, historical/system logs or live processes were inspected by the agent.

The instructions now state this prerequisite before setup and describe the early-failure
report accurately. The human may choose to grant Apple Terminal authorization and relaunch
it before privately collecting. No permission is changed by the agent or kit. A fresh code-only
replacement is `/private/tmp/eforge-terminal-startup-kit-wvb_cqm5`; it has the same tested
version-2 capture and version-3 offline reviewer plus corrected instructions. The failed
one-shot kit remains untouched; do not reuse or modify its setup/lock/provenance files.
No collector, probe, app or native-record read ran during diagnosis or preparation. No
generation code or evidence-admission policy changed, and no new native qualification is claimed.

## Revision 362: paired iTerm2 reference and exact flat entitlement objects

The human supplied the successful version-2 iTerm2 capture and version-3 fixed offline report.
Provenance, platform, collection readiness/cleanup, bounded delivery, continuity, retained app
and ancestry pass; the marker exits zero, with no candidate-ring eviction. Only these shared
reports were read. They establish a different fresh-start topology from Apple Terminal:
app -> helper -> login -> helper -> same-PID zsh. Login argv includes `-fpl` and the bundled
ShellLauncher invocation; login has standard descriptors only. Its effective-UID transition,
the child's later drop, GUI audit origin and exact app responsibility agree with the shared
mechanisms. Native shape failures isolate to scalar-string and empty entitlement objects.

The user separately approved version 4 of the prepared offline reader at
`/private/tmp/eforge-terminal-startup-kit-3lq60k0p` against the completed private iTerm2 kit
`/private/tmp/eforge-terminal-startup-kit-wvb_cqm5`. It ran exactly once. All original controls
and three independent vendor signing/entitlement comparisons pass. The two helpers are
iTermServer in a user Application Support copy and ShellLauncher in the app bundle. Their
public argv forms and the xpcproxy responsibility-token word classes are confirmed. No private
values were returned, no file changed and no command, app, probe, collector or live query ran.
This approval is consumed and does not authorize future readers or direct capture inspection.
No further collection is currently needed for these bounded startup paths. The full paired
comparison and actual fork/exec counts are in the adjacent terminal reference COMPARISON.md.

Independent, filtered static signature checks against the vendor anchor/team verified all
three installed bundle binaries. Main iTerm2 has signer com.googlecode.iterm2, team H7V7XYVQ7D,
and Boolean/string/string-array entitlements; iTermServer has signer iTermServer and explicit
`{}`; ShellLauncher has signer ShellLauncher and the literal application identifier H7V7XYVQ7D.
(including its trailing dot). These public vendor definitions, not captured private values,
are the comparison oracles. The sealed app version is 3.7.6; the vendor downloads page dates
that version October 15, 2026. No native hash, UUID, user identifier, path or environment value
is copied into generation. The main catalog now contains its verified signer/template;
helper installation/runtime policies remain the next startup implementation work.

Canonical entitlements now distinguish unknown, explicit null, explicit empty object and
bounded flat Boolean/string/string-array objects. Scalar and empty cases use a new exact
checkpoint tag; older Boolean/array encodings retain their bytes. Native v11 decoding and
current-profile publication accept these observed forms, while frozen older profiles retain
their previous restrictions. Aggregate size/node/string bounds reject malformed/nested/coerced
values before rendering. Retry tests cover all shapes and publication fault positions. Two
older malformed-fixture tests now use nested objects because scalar strings are qualified.
This metadata milestone does not yet enable aggregate in-window terminal startup export.

Validation: all 773 selected codec/signature/runtime/source/reviewer/GUI/terminal cases pass
in 51.87 seconds, plus all four public Finder/filter/checkpoint/complete-rejection cases in
40.29 seconds. Whole Ruff, formatting and whitespace checks pass. Revision-362 behavior
surface is `c5b3d1affa56502143632a23f11ac80a4117bb08e79beffc2635875434ef7d15`.

## October 31, revision 363: paired terminal startup prerequisites

The shared startup implementation now has the required canonical installed and credential
primitives. iTerm2's frozen release is explicitly 3.7.6 (available October 15, 2026), with
independently signed main, user-support iTermServer and bundled ShellLauncher images. Their
observed runtime flag sets and Developer ID validation category are separate from Apple's.
The support cache is explicitly pre-existing, not a fabricated in-window byte copy. No
generation code reads installed host binaries or native captures. Helper deployment uses
optional `installed_with`: a single independent app owns host prevalence/selection and user
eligibility/overrides; helpers retain their own scope/path/release/signer and helper category.
Dangling, recursive and cross-platform dependencies fail before placement. Helpers are omitted
when the owner is excluded; user exclusion removes the user cache without deleting the
machine-wide app bundle. No Apple metadata is inherited into these helpers.

Explicit post-fork `setsid` can allocate a terminal or declare no controlling terminal. Its
canonical session/device/inode/slot/counters commit and roll back together; history and
checkpoint reconstruction preserve the new session's start independently of process birth.
An explicitly selected GUI-app responsibility at fork names that exact live app rather than
silently leaving the child self-responsible. Other forks retain existing inheritance; a new
unrelated responsible lifetime is rejected.

The installed filesystem now supplies an allocation-free observation of an exact exec input
through the same release/placement/stat owner used for loaded files. The qualified login
producer consumes the exact machine-installed Apple login, root owner/group and 04555 mode;
it changes effective UID to the installed owner while preserving real credentials/audit
origin. Missing/wrong permissions or ownership reject before mutation. A separately owned
local-login child drop verifies its authenticated GUI session, exact live login parent at
fork, responsibility, job membership and inherited setuid credentials. It preserves process
and execution identity. The existing SSH API still requires the SSH session, privileged
receiver and audit binding; this does not generalize arbitrary setuid operations.

This is prerequisite implementation, not a completed fresh-terminal acceptance claim. The
public aggregate terminal/login/zsh bootstrap still rejects in-window complete collection.
Next is the shared retained native phase coordinator with exec-owned descriptor setup, then
public Terminal/iTerm2 command workloads, exact census reconciliation and recovery checks.
The approved private review remains consumed; none of this work rereads private evidence or
requires further collection. No native log or private observed value is committed.

Validation: 420 focused state/credential/TTY/checkpoint/deployment/catalog/fork cases pass
in 27.10 seconds. They include both terminal prefixes, wrong login file owner/mode/group,
SSH-versus-local admission separation, parent/child authority, provisional rollback and exact
history reconstruction. The four public Finder/filter/checkpoint/complete-rejection cases pass
in 39.70 seconds. Whole Ruff, formatting and whitespace checks pass. Revision-363 surface:
`574e5c2c0f6449b4b5a0843a2d8c72d190c7f05eaac1410a730cf44e30c501a8`.

## Revision 364: shared native Terminal/iTerm2 startup integration

The current profile now replaces the aggregate fresh-start path for both terminals with
`MacosTerminalStartup`. It inherits the already qualified launchd/xpcproxy/GUI prefix and
exact retained phase publisher; one stage machine selects each measured tail. Apple Terminal
has three actual forks and four execs. iTerm2 has four forks and six execs, including the
support server, login, ShellLauncher and same-PID replacement with zsh. Extra kernel/API
calls are not invented as native fork records. Both use the same State, lifecycle, collector,
source timing, installed release, descriptor and native publication owners. Existing shells
reuse their PID; a new window or restored job in an already running app is still an explicit
unsupported plan. Older frozen profiles without terminal policies keep their previous path.

Exec-owned file actions create the exact complete post-exec tables. Apple login has TTY
vnode standard descriptors plus FD 4/5 sharing one pipe; its shell closes the extra descriptors.
iTermServer has sockets 0/1, different pipe identities at 2/3 and vnode FD 4; iTerm login has
only standard TTY descriptors. All pipe identities/counter transitions commit and roll back
with exec. Native socket tag 2 is now supported by the canonical FD observation, alongside
vnode 1 and pipe 6; these are the [Apple native constants](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/proc_info.h).
The [public server implementation](https://github.com/gnachman/iTerm2/blob/master/sources/Tasks/iTermFileDescriptorMultiServer.c)
independently identifies its listening/connected sockets, distinct pipe roles and lock FD.
The [connection owner](https://github.com/gnachman/iTerm2/blob/master/sources/Tasks/iTermMultiServerConnection.m)
supplies the public home-support `iterm2-daemon-N.socket` naming. The bounded fresh-server
policy selects slot 1; no private native path or peer is copied or inferred. Each internal
transition has its own scoped sampled gap; timing is selected simulation policy, not a
claimed native latency measurement. Startup-specific lifetime IDs include their invocation.

Local login's drop changes only effective UID, with the same logical principal/integrity
token. Canonical State and source occurrences own that change; lifecycle activity advances
without inventing a different registry token. Missing ordinary command parents now request
the shared native terminal owner. Public CLI acceptance exposed a suspicious-command path
that previously created aggregate zsh directly under launchd. The fix materializes the
dependency before optional effects freeze their actor/time and uses the parent's current
execution readiness rather than its older fork birth. Windows/Linux timing paths retain
their previous anchors. Required prepared actors remain immutable. Deferred shell reuse can
return the exact already published ready dependency without allocating another app.

The focused all-start tests now pass complete coverage with no aggregate births: one command
plus fresh Terminal has four forks/five execs; the same iTerm2 workload has five forks/seven
execs. Pre-window startup correctly contributes only the in-window command's fork/exec.
Both apps' bounded public CLI workloads also pass complete reconciliation, including
suspicious-command noise, and their native bytes match with eCAR selected or filtered out
across distinct PYTHONHASHSEED values. No native log collection/read was performed for these
engineering checks; all generation inputs and outputs are invented fixtures.

The native startup journal stays on ActivityGenerator, and pending phases explicitly block
checkpoint capture. Routine lost-return tests preserve allocation and full census for both
apps. All 66 exhaustive per-phase interruption checks pass: failure before commit, lost commit
return and source release failure at every Apple/iTerm2 stage. A broader focused suite passes
666 checks, including canonical state, source/runtime metadata, descriptors, lifecycle,
parent readiness, checkpoint state and the behavior manifest.

Checkpoint acceptance exposed a warm-up lookahead defect in shared POSIX membership. Explicit
`setsid` now uses the same lifetime-boundary handling as exec/session transitions: another
member's later activity cannot block a child from leaving the shared group/session, and the
remaining membership preserves its later frontier. Retiring the last member before that
frontier still rejects. The targeted regression and existing POSIX/GUI/metadata cases pass.
Both public terminal checkpoint/resume tests pass, with nonempty native startup state, later
commands and byte equality against uninterrupted generation. The final 70-case slow run passes
all 66 interruption cases plus the existing Finder/filter/checkpoint and complete-mode
rejection contracts. The two paired terminal CLI/filter tests also pass. Whole Ruff, formatting,
whitespace and all 23 behavior-manifest checks pass. Revision-364 surface:
`d2a9bad7070d0a105cab1b7ecc0ac843f3863d595cf06def49d252683b297207`.

This closes the bounded fresh-terminal producer milestone, not the global all-process backlog.
No new ULF GUI-launch layout,
generic app helper tree, existing-app restoration, SSH PTY command contract or script-child
expansion is claimed by this increment. No additional private evidence is currently required.

## October 31, revision 365: whole-SSH measurement and bounded reference preparation

The user authorized the next SSH milestone after paired terminal startup. A small invented
receiver workload independently expects three forks and five image activations. All three
forks publish; no exec currently publishes. The wrapper is still an aggregate initial start,
and four subsequent helper/shell execs need exact native FD inventories. Before the metadata
changes, three of those execs first failed on unknown entitlements and one on descriptors.
Afterward all four fail precisely on unknown descriptors. No denominator was narrowed and the
whole session still rejects complete mode. One pre-auth helper's exit outcome also stays
unknown rather than becoming an assumed successful result.

A separate public synthetic Mac-client-to-Linux workload has four of five required in-window
execs and no aggregate births. Its SSH client signature needs an integer entitlement in addition
to a string array. Apple's [public SSH entitlement definition](https://github.com/apple-oss-distributions/OpenSSH/blob/main/Entitlements/ssh.entitlements)
supplies the template. A read-only static code comparison against the fixed Apple SSH binary
matched exactly, returning only the template label. Equivalent fixed comparisons matched the
public [daemon](https://github.com/apple-oss-distributions/OpenSSH/blob/main/Entitlements/sshd.entitlements),
[session worker](https://github.com/apple-oss-distributions/OpenSSH/blob/main/Entitlements/sshd-session.entitlements),
[authentication worker](https://github.com/apple-oss-distributions/OpenSSH/blob/main/Entitlements/sshd-auth.entitlements)
and [wrapper](https://github.com/apple-oss-distributions/OpenSSH/blob/main/Entitlements/sshd-keygen-wrapper.entitlements)
templates. These checks read vendor code metadata, not captures or logs, and started no SSH
connection, collector, app or probe. No observed code hash or private value was exported.

Canonical signing values now retain exact signed 64-bit integers, with a separate checkpoint
tag and exact-type equality/hash semantics: integer 1 and Boolean true cannot become the same
signature, even inside a mixed object with an identical supplied cdhash. Older tags/bytes and
old source restrictions remain intact. v11 decoding supports the type independently; the current
generation profile does not enable integer export until a native sample establishes its wire
shape. Verified static SSH/helper templates now live in the application catalog. A separate
explicit source-policy capability allows invented tests to prove admission/rejection and sink
recovery without turning on that capability in the production profile.

The broad SSH regression exposed a revision-364 parent-readiness bug: an already published
SSH shell could be selected before its session started. Early dependency selection is now
restricted to an active local interactive GUI session. SSH again requires a genuinely live
shell; the existing no-mutation negative regression and paired terminal readiness cases pass.

The new `scripts/macos_ssh_startup_reference.py` prepares a human-only, non-PTY loopback kit,
reusing existing private-file/provenance, native schema, stream pump and collector-guard code.
It keeps ambient fork/exec/exit rows only in bounded memory. A random controlled remote marker
must link through exact exec/fork identities all the way to a launchd-owned per-connection root;
fork-only intermediate children are supported. Only that root's descendants, including the
pre-auth sibling, can be retained. Reachability never starts from launchd itself. A separately
marked client exec must match the private PID control. No PID-only or path-prefix connection
join is accepted. Only proved records are saved after code/provenance revalidation and collector
cleanup. Reports contain fixed labels, including cross-stage pipe equivalence classes, parent/
responsibility/audit/credential relations, public signer templates, runtime flags and CPU slice.

The client uses the existing Remote Login service at 127.0.0.1, disables configuration hooks,
forwarding, proxies, multiplexing, agents and public-key authentication, and retains host-key
verification with a kit-local known_hosts file. The human authenticates privately in a second
terminal window and pastes one marker command. Standard descriptors remain those of that
window. The collector connection window is 140 seconds and the independent guard stops by
180 seconds or parent cancellation. No SSH/privacy/service setting changes are part of this
experiment. No private native command, collector or existing kit was run or read by the agent.
See the [complete instructions](../design/macos-workstation-feasibility/ssh-startup-reference/PRIVATE-RUN.md).

Validation: all 799 selected SSH/signature/native-contract/network-identity/catalog/deployment/
terminal tests pass (84 extended exclusions). The four selected extended identity/security/
fresh-process checks pass, as do all eight paired-terminal/Finder/default-complete public CLI
and checkpoint/resume contracts. All 883 existing private-reference checks pass. The new kit's
final 36 invented-input cases pass, including successful/failed collector cleanup, interrupted
capture, schema/argument canary redaction, fork-only intermediates, pre-auth sibling retention,
unrelated-connection exclusion, exact token/birth/image/nonce controls, integer-versus-Boolean
templates and fixed exit dispositions. Marker and guarded collector source pass strict
syntax-only C compilation; no compiled probe was executed. Whole Ruff, formatting, whitespace
and behavior-manifest checks pass. Revision-365 surface:
`536d3a4da1be86aa543b9c5c11e418ebb14ef1af063f0766cb86a2f2c9acf2a7`.

Final prepared code-only kit: `/private/tmp/eforge-ssh-startup-kit-1a39x1ww`. No setup or
collection has been run. Do not inspect this directory after human handoff, even to check
whether result files exist. The earlier preparation-only copy is superseded. The next required
human action is the documented single private non-PTY loopback run, then sharing only its fixed
JSON. Integer native export and receiver startup remain explicitly gated until that review;
the global all-process backlog is not marked complete.

## October 31: clarify the non-PTY capture's input step

The human reported that Window B appeared to hang after password entry and Ctrl+C returned
control. Source review confirms that this client intentionally opens a non-PTY login shell
without supplying a remote command: after authentication it waits for the human to paste the
printed marker command, and there may be no prompt. This behavior alone cannot establish an
SSH/authentication failure. A fixed-choice clarification asks whether the marker was pasted;
no terminal output, native record or private path is requested.

The client now explicitly prints that there may be NO PROMPT and that the human must paste the
marker and press Enter. The tracked instructions emphasize the same step. All 36 invented
reference tests and whole Ruff/format/whitespace checks pass. No generation behavior changes.
Fresh code-only replacement: `/private/tmp/eforge-ssh-startup-kit-xxjb4ftc`. Setup and collection
remain human-only; neither was run. The interrupted kit is untouched. Do not inspect either
handed-off kit or remove its locks. The replacement also remains off-limits after handoff.

## October 31: retrieve the successful SSH report without recapture

The human confirmed that the marker was pasted, then clarified that capture is working but
the report exceeds terminal scrollback. This supersedes the tentative hang interpretation;
there is no established SSH input/authentication defect to repair. They attempted collection
again and it exited immediately. Source inspection confirms the single-use `SESSION-LOCK`
rejects another capture before changing `ACTIVE-RUN`, preserving the completed run/report.

The human can run the existing `report --private-run` operation in the successful kit's
directory, redirect its validated fixed JSON to `SHAREABLE-SSH-REPORT.json` and attach that
file, or pipe it to `pbcopy`. Neither starts a collector/SSH connection or opens native records.
The tracked instructions now make report recovery explicit. No fresh capture, lock removal,
kit modification or further private access is needed. The agent inspected repository source
only and did not read any handed-off kit, private report or local log.

## October 31, revision 366: reviewed native SSH client and collision-aware transport

The human explicitly supplied the safe `SHAREABLE-SSH-REPORT.json` from the completed
non-PTY loopback kit. That one report was read; authorization did not extend to native
records, provenance, setup, controlled metadata or any other file in the handed-off kit.
Collection, lineage, cleanup, continuity and marker controls all pass, with v11 and no ring
eviction. Every retained exec has an admitted native shape. The public SSH signing template
matches its exact array/integer object. Client and four SSH helper snapshots establish Apple
validation category 1, flags `0x26015b11` and arm64e/PTRAUTH ABI. The current source profile now
admits exact integer values; frozen historical profiles retain their narrower capabilities.
Code/security facts remain distinct from graph, credentials, arguments and descriptor gates.

Complete public client-to-Linux workloads now pass through both Apple Terminal and iTerm2:
every expected in-window fork/exec publishes, with no aggregate births. The client retains
its verified literal arguments, standard TTY vnodes and typed signing object. Full and native-
only output is byte-identical across different PYTHONHASHSEED values. This reference is a
controlled re-exec in a previously established foreground group; it does not independently
qualify a new shell `setpgid` policy. Existing canonical parent/session ownership stays intact.

The longer checkpoint workload exposed an actual shared SSH transport bug: WorldPlanner
chose a random port and supplied it as an exact requirement, bypassing the bundle's automatic
collision handling. A baseline connection still held that tuple when a second authored
connection selected it. WorldPlanner now delegates automatic intent with `source_port=None`;
the SSH bundle allocates against canonical leases. An authored explicit port retains exact
semantics. The regression starts overlapping sessions with repeated caller RNG state and
requires distinct transport ports/UIDs. This owning-layer repair affects all OS variants and
the behavior manifest records SSH transport, Zeek and Syslog impact as well as native/eCAR.

The complete native client checkpoint/suspend/resume run now reproduces uninterrupted bytes,
including integer signatures and in-window starts. The shared acceptance test correlates SSH
endpoint flows with in-window Zeek closes before requiring termination: a background session
can legitimately remain open after the collection cutoff, with neither a close-time Zeek row
nor an endpoint termination in the window. At least two observed closed clients must terminate;
the test does not fabricate post-window closes or exempt process starts from the census.

The receiver is not qualified by client success. Its existing implementation lacks the
launchd fork/xpcproxy prefix and additional fork-only children shown by the report. Wrapper
argv disagrees with the old bare-path template; exact sibling order, audit adoption, job and
responsibility ownership still need classification. Known receiver FD tables and `_sshd`
authentication-helper exit zero are documented in the adjacent reference. Session helpers
report exit 255 while the marker/client exit zero; their result must not be inferred from the
command. Private shell startup descendants are not portable default catalog entries.

A separately tested read-only offline reviewer is prepared at
`/private/tmp/eforge-ssh-startup-kit-p8f430ou/private_ssh_review.py`. It verifies original code,
binary, provenance and collection controls, then classifies only exact marker ancestry and
authentication/closed fork-only siblings into fixed opaque lifetime aliases, public argv
layouts, credential/audit/job/responsibility relations and exit labels. It excludes unrelated
shell startup commands. It writes nothing and starts no subprocess, collector, app, probe or
live installed-image query. All 19 invented-fixture tests pass, including canary redaction,
read-only behavior and changed-provenance/control/code/native-linkage rejection. Explicit
permission to run it against the existing completed kit has been requested and is pending.
No new collection is needed; no private native records have been read or committed.

Final client CLI/filter/checkpoint plus receiver complete-rejection checks: all five extended
tests pass in 52.26 seconds. WorldPlanner, port retention, offline reviewer/reference and
behavior-manifest checks: all 131 pass in 3.68 seconds. The broader routine SSH family suite
passes all 440 selected tests in 41.02 seconds (220 extended exclusions). Whole Ruff,
formatting and whitespace checks pass. The three existing SSH client/receiver/authored-close
checkpoint regressions also pass in 73.90 seconds. Revision-366 surface:
`064dbf9b845add3d0a3e2a69d889cbee0acc73a7584bc69d0b2f8644e1f8dc29`.
The global all-process backlog remains open; receiver startup, PTY commands, broader app
helpers and other unsupported producer families retain their independent obligations.

## October 31, revision 367: approved SSH graph and retained receiver primitives

The human approved the prepared version-1 offline reviewer at
`/private/tmp/eforge-ssh-startup-kit-p8f430ou/private_ssh_review.py` against the completed
`/private/tmp/eforge-ssh-startup-kit-xxjb4ftc` capture. It ran exactly once. Provenance, original
controls and core lineage pass. Only fixed aliases/labels were returned; no file changed and
no collector, application, probe, subprocess or live query started. This consumes that
permission and does not authorize direct inspection, another reviewer or another capture.

The resolved bounded core has six actual forks and six successful execs before the marker
replacement. The initial launchd child executes xpcproxy, establishes a new POSIX session,
then executes basename-only wrapper, daemon and session-worker images in one lifetime.
The daemon has a short fork-only child; the session worker has an authentication child and
another short fork-only child. Those short children preserve their exact execution/image
until exit zero. The authentication child executes sshd-auth, drops to `_sshd` and exits zero.
After audit adoption the privileged worker forks a user worker; that child drops credentials,
forks the shell, and the shell establishes its session before exec. The privileged worker
remains responsible for all descendants. Both surviving session workers finally exit 255,
whereas the controlled marker exits zero. These observations are not generic exit defaults.
The complete derived graph and limits are in the adjacent SSH REFERENCE.md; no private
identifiers, paths, argument text, environment or raw records are copied into the repository.
Apple's current public launch daemon definition independently confirms the wrapper argv.

The canonical session batch now has `plan_macos_ssh_receiver_fork`. It requires its own exact
fresh pre-authentication SSH session and live launchd parent, then preserves the parent's
loaded image, credentials, POSIX membership, argv, environment and current descriptor table.
Logical SSH session ownership is explicit and separate from unchanged inherited audit origin.
The process-fork contract accepts that bounded session association only with its exact SSH
session identity; omitting that authority rejects. The fork bit and table are retained in the
original integrity-authenticated batch, so rollback restores allocators and session links
together and checkpoint recovery preserves the actual initial execution. No aggregate wrapper
can be relabeled by changing image text.

Explicit root-service child responsibility can name that exact live parent lifetime. This is
an opt-in relationship, like the existing GUI-app relationship; ordinary forks do not acquire
an inferred new controller. Unknown ownership, a non-root parent, another session or another
lifetime remains rejected. Both event and State planning apply the same structural rule.

Shared exec file actions now model the reviewed inetd, session-worker and authentication-worker
tables. The wrapper gets two socket standards and its retained stderr vnode; session exec adds
a vnode and socket at 3/4; auth exec retains standards, uses socket 3 and allocates pipe 4.
The canonical allocator, FD table and source observation share one exact exec transaction.
Unproved inherited standards, a controlling terminal or a wrong pipe policy reject. Existing
terminal layouts retain their behavior. Invented inputs verify open-object preservation,
native FD extents, pipe allocation, provisional rollback, checkpoint restoration and negative
authority cases. No generation code reads native captures or the generator host.

All 137 selected fork/responsibility/descriptor/session-batch-recovery/manifest checks pass
in 7.89 seconds. Both existing public Terminal/iTerm2 complete/filter cases pass in 15.34
seconds. Whole Ruff and formatting pass. Revision-367 surface:
`e6a1edc228ed19ce4ee9fedfa06c7680a70c03f7b689a86160f46d06ed59dfa8`.
These are integration prerequisites: the default receiver still uses its old incomplete
startup coordinator and remains gated in complete mode. Next, wire the real initial fork into
deferred network publication and replace that coordinator with the reviewed stages, then
verify whole-receiver CLI/filter/checkpoint and census acceptance. No further private review
or human collection is currently required for this bounded non-PTY integration.

## Revision 368: measured native receiver stages, not yet the production default

`MacosNativeSshReceiverStartup` reuses the original receiver's exact publication, artifact
retention, retry and pending-phase journal. A separate nineteen-stage topology starts from
the already committed launchd fork: xpcproxy exec, explicit setsid, wrapper/daemon execs,
short daemon-child fork, session exec, short-child exit, auth fork/exec/drop, short session-
child fork/exit, auth exit, audit adoption, user-worker fork/drop, shell fork/setsid/exec.
There is no exec for any of the three fork-only workers. Declared nominal exit zero applies
only to the three short startup helpers. Final worker results remain unknown for generic
session teardown; this code does not extrapolate the captured exit 255 to every close.

The transient request explicitly distinguishes the legacy and nineteen-stage shapes and
locates their audit boundaries. The existing coordinator's phase acceptance is a small
overridable method; its exact source-publication algorithm is shared unchanged. The current
production SSH factory still selects its legacy coordinator. This is intentionally not a
claim that a whole SSH receiver passes complete mode yet.

The wrapper's catalog argv is now its independently verified basename, separate from its
absolute image path. The bounded parser permits that exact wrapper case while retaining
absolute-image binding for other helpers. Historical literal-path wrapper descriptors remain
decodable for old internal fixtures. Launcher exec explicitly establishes three vnode
standards under its boot-parent root/first-exec/non-PTY contract, without asserting a complete
launchd FD table. Other helper file actions still require complete inherited standard handles.
Initial shell exec validates its exact authenticated user worker, remote audit identity,
session/transport/readiness bounds, shell argv and absent terminal before observing the
channel's already reserved pipe objects. It does not allocate another pipe set or silently
substitute streams for an arbitrary process. External command readiness remains independent
of that earlier shell-exec observation.

The invented real-engine prototype supplies the initial session/fork State batch and starts
the new coordinator directly. All six native execs, five subsequent native forks and three
short native exits are emitted. The independent State census expects six forks and six execs,
with zero aggregate births: the deliberately external initial fork still lacks its native
source-publication handoff in this isolated test. The test does not shrink that denominator
or claim whole-receiver acceptance. Six representative committed-source lost-return cuts
recover without another State version, PID, exec, native row or pipe allocation.

All 116 selected native/legacy startup, arguments, receiver planning and spawn-layout cases
pass in 19.95 seconds. The additional 92 manifest, fork, SSH-command-descriptor and POSIX
membership checks pass in 8.41 seconds. All six selected public SSH-client, Terminal/iTerm2
filtering and complete-rejection CLI cases pass in 40.66 seconds. Whole Ruff/format and
whitespace checks pass. Revision-368 surface:
`394abeb6b9d1bea6c40b6e3b5be675cf246555e7676b49cbc1a9af74539f1f17`.

Next is software integration, with no further native reads: the SSH deferred State/network
owner must publish the real initial fork through the same atomic source tail and native
occurrence ingress, then select the new coordinator/current profile. Its timing replay must
recognize nineteen stages and audit index 13. Restored receiver verification must recognize
initial launchd/four execs and a root setsid after birth; legacy wrapper/two-exec recovery
remains supported. Complete CLI/filter/checkpoint and exact six-fork/six-exec reconciliation
are required before claiming the bounded receiver milestone. Do not mark the global P0 done.

## Revision 369: complete non-PTY SSH receiver production integration

The current macOS 27 profile now selects the reviewed native non-PTY receiver graph and its
public launchd service-label prefix. Both fields are frozen, paired schema policy; older
resolved inputs default to the legacy coordinator. Normal generation selects this canonical
graph independently of output filtering. Low-level compatibility fixtures without occurrence
ingress retain their previous diagnostic behavior.

The deferred transport/session batch plans a real inherited launchd fork, not an aggregate
wrapper birth. Read-only planned relationship/installed-file observation accepts only that
integrity-authenticated one-session/one-fork batch; it gains no action-cohort commit authority
or exec/exit observation capability. The exact initial fork's frozen native occurrence joins
the same source-publication batch as transport/eCAR evidence. Its bytes count toward retained
capacity, and its exact authenticated source tail is checked before ordinary target proofs.
Committed source failures retain the original ingress/body/State plan for retry. Neither
the process-start denominator nor source-proof requirements are weakened.

The retained nineteen-stage coordinator supplies the remaining five forks, six execs, three
short known exits and separate audit/credential/job transitions. Deferred timing replay uses
the correct audit boundary and preserves strictly increasing sampled stages. Recovery checks
the initial launchd image, four same-lifetime receiver replacements and the root setsid
between xpcproxy and wrapper. Frozen legacy wrapper/two-exec/session-at-birth recovery remains
supported. The earlier compatibility fixture's hardcoded wrapper argv was updated to the
reviewed basename; production descriptor/identity validation remains strict.

Measurable acceptance is now successful: complete Mac-to-Mac workloads through both Terminal
and iTerm2 reconcile all in-window starts on both hosts, with zero aggregate births and equal
expected/published fork and exec counts. Full and native-only CLI output matches byte for byte
across different PYTHONHASHSEED values. The receiver's initial native row preserves the exact
launchd-loaded executable and lifetime. Complete receiver suspension/checkpoint/resume matches
uninterrupted bytes. Initial native-source failure before write and committed lost-return
recover without another canonical commit, PID or native row; the isolated receiver ends with
exactly six native forks and six execs. Unsupported GUI app launch still rejects actionably,
and removing the native source still rejects before accepting a complete bundle.

Validation: all 688 selected routine SSH/native fork/collection/snapshot/publication/manifest
checks pass in 64.68 seconds (196 extended exclusions). All 322 shared deferred-session,
network-contract and exact-publication checks pass in 6.75 seconds, including Linux/Windows
compatibility. The six public complete-client/receiver/filter/rejection cases pass in 48.37
seconds. The complete receiver checkpoint/resume case passes in 26.64 seconds. The additional
three initial-fork snapshot/recovery checks pass in 4.28 seconds. Whole Ruff, formatting and
whitespace checks pass. Revision-369 surface:
`68e68f530c95b248893b66f8b14e0fb8615b0043e412e77095a8cd8231fa0bef`.

No additional private access occurred after the single approved reviewer run recorded under
revision 367. Its permission is consumed. All subsequent checks use invented inputs and
synthetic outputs; no raw reference records were inspected, copied or committed.

This closes the bounded non-PTY receiver startup gap, not the global all-process P0. Generic
final worker outcomes stay unknown rather than adopting the controlled capture's exit 255.
PTY startup/commands, other GUI application/helper trees and Dock/Spotlight relationships,
existing-app new windows/restoration and launchd job activation remain separate producer
obligations. Native SSH Unified Log messages were not collected or added. No blind assessment
loop or further collection was required for this milestone.

## November 1: prepare the interactive SSH / PTY reference

The user approved the next sequence: PTY SSH first, then launchd job activation, broader GUI
apps/helpers/Dock/Spotlight and existing-app windows/execution plans. Collection must precede
qualification. Existing own-process PTY descriptor comparisons do not establish the native
receiver/helper/shell/command graph. No new live operation or private-log access is authorized
for the agent by this preparation request.

The existing SSH reference now has a code-only `prepare --pty` variant. Its owner-only
EXPERIMENT.json selects PTY once; setup freezes the mode and its digest in provenance.
Modification, removal, invalid content and symlinks reject rather than changing experiment
type silently. Old non-PTY selection remains the default. The controlled client requests
`-tt`, preserves the actual window streams and retains the existing loopback/config bypass,
no-agent/no-forward/no-proxy/no-multiplexing and isolated host-key verification restrictions.
PTY connect requires real terminal standard streams. The human pastes one harmless marker
command followed by `; exit`, deliberately creating a command child instead of replacing the
login shell. No shell configuration, service, account or privacy settings are changed.

The tracker, bounded memory-only ambient ring, exact marker/client proof and root traversal,
guard hard stop, source controls and cleanup are reused. Only the proved tree/client may
reach private disk after successful cleanup. A version-2 fixed report adds actual command
fork evidence and before/target terminal presence. Stable terminal identity is compared only
locally, excluding changing stat timestamps, and exported as closed equivalence classes.
The shared graph classifier now traces either a shell-replacing control or a genuine command
child back to launchd. Its fixed opaque lifetime/group/session/parent/responsibility and exit
labels are included in the PTY report during the human's capture analysis. This avoids a
planned second offline read merely to resolve the original helper topology. Unknown images
on proved ancestry stay OTHER; unrelated startup children are not promoted into the core.
Classification is not native generation admission. No raw identifiers, paths, argument text,
environment values, terminal devices or stat values enter the shareable schema.

PTY capture prints only a short fixed completion status; the full validated report remains
available through `report --private-run` and file redirection. Report recovery opens only
the saved fixed JSON, not native records, and never reruns collection. Existing timeout
errors now retain the TIMEOUT label instead of being collapsed to INTERNAL. Complete
human instructions are in
[PTY-PRIVATE-RUN.md](../design/macos-workstation-feasibility/ssh-startup-reference/PTY-PRIVATE-RUN.md).

All 1,087 selected private-reference tests pass in 2.72 seconds, including 34 new PTY checks
and paired setup selection. The final focused 90 SSH capture/reviewer checks pass in 0.54
seconds after completion-status hardening. Tests prohibit native operations and use invented
records or mocked setup/collector/exec calls. They cover real child versus same-PID replacement,
terminal and foreground-group relationships, source/provenance/mode tampering, dangling
symlinks, prepared-code graph loading, fixed schema redaction, cleanup after interruption and
analysis/cleanup failures, preserved stdio, compact output and report-only recovery. Whole
Ruff, formatting, whitespace and the unchanged revision-369 behavior manifest pass. No engine
generation behavior or evidence gate changed; no new C probe was introduced or executed.

Fresh code-only human handoff: `/private/tmp/eforge-ssh-pty-kit-spnfsbgm`. Setup, collection and
SSH connection have not been run. Do not inspect this directory after handoff, including for
result existence, or touch any previous handed-off kit. The human should close agents, run
the documented setup/capture/connect once and share only SHAREABLE-SSH-PTY-REPORT.json. Leave
single-use locks intact; failed attempts require a fresh kit. A further offline native read
would need separate explicit permission. Next implementation depends on that fixed report;
PTY generation remains unsupported meanwhile.

## November 1: repair PTY reference selection after the human's LIMIT report

The human supplied only SHAREABLE-SSH-PTY-REPORT.json from the handed-off PTY kit. That
specific fixed report was read once. It reports version 2, LIMIT during ANALYSIS, no ring
eviction and passing provenance/collector readiness/cleanup. The other qualification controls
are inconclusive. It does not identify which bound fired or establish usable PTY evidence.
No native records, provenance, controls, directory inventories or other private kit files
were inspected. The old kit remains untouched and single-use.

Code inspection finds that PTY retention still selected the entire connected descendant
tree before the graph classifier removed personal shell-startup children. An invented
100-child startup workload reproduces the RETAINED_ROWS failure despite an unchanged,
small controlled SSH graph. This is a demonstrated kit defect, not proof that the human's
private shell has that exact workload or that it triggered that particular bound.

Version 3 selects the exact marker ancestry and direct SSH authentication/fork-only helper
siblings before retention limits, along with the controlled client. The capture and graph
classifier now share this selector. It preserves the receiver prefix, user worker, shell,
actual controlled command fork/exec and short helper closures while excluding personal
startup child trees. Report retained_scope explicitly identifies CONTROLLED_SSH_CORE.
Unknown images on the proved spine remain OTHER. The simulator's independent process-start
census and supported generation behavior are unchanged; this reference filter cannot exempt
any modeled process from complete coverage.

Limits stay bounded and independently reject ancestry rows, retained rows, stream bytes,
core lifetime count, core event count or fixed-report capacity. The fixed limit_scope field
identifies the failing class, including in compact output. Endpoint/sequence controls already
verified before a later analysis failure remain in the saved report. Prepared classifier
exceptions cross the module boundary as fixed codes; no exception text or observed value is
exported. Failed analysis still saves no native row file, so this failed attempt cannot be
salvaged through an offline reviewer and needs a fresh human capture.

All 98 focused SSH kit/reviewer tests pass in 1.01 seconds; all 1,095 private-reference tests
pass in 2.97 seconds. The large invented startup workload now retains the same exact core
graph as the quiet control and no startup-canary records. A genuinely oversized helper graph
still rejects with CORE_LIFETIMES. Cleanup/no-native-disk behavior after LIMIT, fixed enum
redaction, module-boundary error translation and compact limit output also pass. Whole Ruff,
format/whitespace and unchanged revision-369 behavior-manifest checks pass. No native command,
collector, probe, SSH connection or further private read was run by the agent.

Fresh code-only replacement: `/private/tmp/eforge-ssh-pty-kit-2tdf9qps`. Do not inspect it after
handoff or modify/reuse the original kit. The human can repeat the same documented steps in
this fresh directory, then share only SHAREABLE-SSH-PTY-REPORT.json. PTY generation remains
gated pending a successful fixed report; no independent collection or review is authorized.

## Revision 370: reviewed PTY shell and foreground command integration

The human supplied SHAREABLE-SSH-PTY-REPORT.json from the fresh version-3 kit. Only that
fixed report was read. It establishes COMPLETE/NONE, passing provenance/collector/cleanup/
bounded/sequence/client/lineage/marker controls, no ring eviction or limit, v11 shapes for
all execs, an observed PTY and a genuine command fork. The receiver prefix matches the six-
fork/six-exec non-PTY startup. The initial zsh has its own POSIX session/group and controlling
terminal before exec, with three vnode standards. A command child inherits shell membership
at fork, then has its own group before exec while staying in the shell's session and terminal.
Root-receiver responsibility and remote audit identity persist. The marker and explicit shell
exit are zero in this test; surviving worker exits are 255. These are controlled outcomes,
not generic success defaults. The bounded reviewed facts and limits are in
[PTY-REFERENCE.md](../design/macos-workstation-feasibility/ssh-startup-reference/PTY-REFERENCE.md).
No native record, provenance, control file or other private kit path was inspected or copied.

Authored `ssh_session.pty: true` now flows through the typed handler, WorldPlanner, SSH intent
and existing exact deferred receiver owner. The Boolean is strict; omission preserves the
non-PTY path and its historical stable IDs. Explicit PTY requests require a qualified Mac
receiver, native startup policy and installed initial zsh. WorldPlanner does not reuse an
unclassified/non-PTY session for this fresh-start contract. Source Mac SSH clients retain
the explicit `-tt` argument. Other OS types keep their prior SSH behavior and reject this new
explicit Mac PTY intent. No new top-level configuration block or emitter launch path exists.

The shared nineteen-stage receiver coordinator selects terminal allocation at the shell's
setsid boundary instead of explicit terminal absence. Authenticated State file actions bind
its three vnode standards to that exact session-owned terminal; no non-PTY channel pipes are
reserved or substituted. Parent/receiver ancestry, audit origin, user credentials, shell argv,
directory, native image, terminal ownership and source timing retain their existing validation.
All earlier helper stages and short-helper results are shared unchanged.

`MacosPtyCommandStartup` reuses the existing retained Mac phase publication/recovery algorithm
for three canonical cohorts: fork, setpgid, exec. The original inherited fork image/membership
is preserved, the group transition has its own eCAR modification, and exec preserves the
new group and the shell's terminal/session/standard open objects. It uses the existing activity-
owned pending-startup map and checkpoint guard, not a new queue. Literal installed metadata,
qualified parent/session and empty effects are checked before the first fork; unsupported
effects, shell syntax, alternate/nested owners and unknown policy reject actionably. The
normal process lifecycle owner receives the completed command and supplies only already
qualified natural outcomes. No shell builtin gets an invented process.

The durable Mac SSH auth tag `macos-v3-pty` preserves the mode through close-continuation
recovery. Historical v1/v2 rows retain their previous meanings. Restored native graph checks
verify that PTY mode agrees with the actual terminal and absent channel pipes; a changed tag
cannot relabel a non-PTY shell. Generic final worker outcomes remain unknown, and no SSH
Unified Log family or generic shell-teardown success was added.

Measurable acceptance: receiver startup plus one foreground query reconciles exactly seven
forks/seven execs with zero aggregate births. Native fork inherits shell PGID, both exec
snapshots retain the command's own PGID, and SID/TTY/audit/responsibility remain shared correctly.
The same canonical behavior works with eCAR alone under explicit partial collection. All nine
public client/receiver CLI/filter/checkpoint cases pass in 139.36 seconds, including both
terminal apps and complete PTY resume byte equality. All nine before-commit/lost-return/source-
release cuts across fork/group/exec recover without duplicate starts; their finite extended
matrix passes in 11.82 seconds. All 649 selected routine SSH/Finder/world/schema/manifest checks
pass in 109.60 seconds (209 extended exclusions). The additional eCAR-only PTY check passes in
2.31 seconds. Whole Ruff/format/whitespace and behavior-manifest checks pass. Revision-370 surface:
`4691d8a7c94f40bd9f01bdb34c5c6d2cab208c8ee6c8cc9ee8d0f7365fb3d0ef`.

This closes bounded initial-zsh PTY startup and literal foreground command execution. The
global all-process P0 stays open: launchd job activation, other GUI apps/helper trees and
Dock/Spotlight, existing-app windows/restoration and additional execution plans still require
their own producers/qualification. No further collection or private-log read was needed to
implement this PTY milestone. Next in the agreed order is launchd service/job activation;
its native initial fork/exec facts need a separate controlled reference before admission.

## November 1: prepare the system launchd activation reference

The user approved proceeding from PTY to launchd job activation. The new
`scripts/macos_launchd_reference.py` prepares a separate human-only kit. No live
collector, job, native probe or private-record review was run by the agent. No old
handed-off kit was inspected, including for existence or directory contents.

The experiment registers one uniquely named **system-domain/root** job using a
temporary root-owned plist, then explicitly kickstarts and boots out that exact
service. Apple's `/usr/bin/true` is the only permitted payload; its controlled
nonce arguments do not alter its immediate zero-return behavior. The fixed C
guard accepts only run/cleanup plus a 32-character lowercase hex nonce, builds
its own plist and starts only fixed `/bin/launchctl` commands. There is no arbitrary
program/path/plist input, persistent installation, enable/disable, entire-domain
bootout or inspection of other jobs. The program's standards are `/dev/null`,
directory is root, and RunAtLoad/KeepAlive are false. Registration and activation
are separate controls. Primary Apple command/source references and the public
installed manpages support the proposal; documentation does not qualify native
fork/exec relationships.

The root guard has independent bounded command waits and cleanup after EOF,
INT/TERM/HUP/deadline. It ignores SIGPIPE so loss of Python's output reader cannot
skip removal. A failed bootout never establishes absence. Its exact-content,
root-owned scratch lease is retained on removal failure; human-only cleanup can
retry that same label without launching the payload or collecting. SIGKILL,
machine failure and native-command failure cannot guarantee cleanup. The plist
is outside startup directories and the payload is neither persistent nor kept
alive. The existing 55-second eslogger guard owns the bounded collector.

Collector readiness uses the existing harmless normal-user marker. Ambient
fork/exec/exit input remains in a bounded memory ring; exact nonce argv/environment,
public executable identity, a unique execution spine back to verified launchd
PID 1, one zero exit, sequence integrity and no eviction are required before
retention. Siblings/descendants are not walked. Both job and collector cleanup
must pass before any native row file is written. Environment changes are measured
separately from nonce authentication instead of discarding an otherwise proved
reference. Tampered code, guards, codec, installed images or setup controls reject.

The fixed report includes the entire retained graph, opaque lifetime aliases,
first-fork launchd/child security and image preservation, parent-token form,
audit origin, credentials, responsibility comparisons, PID-version transitions,
group/session, terminal/descriptors, native slice, signing/entitlement classes,
public argument layout, controlled/public environment comparisons and exit.
The shared SSH metadata analyzer now accepts explicit role/argument classifiers;
existing SSH defaults are unchanged. No SSH path labels are used in the shareable
launchd report. Unknown forms stay OTHER/INCONCLUSIVE, and gate_status remains
NOT_EVALUATED. This is not native generation admission or a claim about other
launchd domains, triggers, restart policy, GUI mechanisms or Unified Log messages.

Validation: all 1,151 final selected private-reference checks pass in 3.27 seconds,
including all 56 launchd checks (focused run: 0.50 seconds).
Invented fixtures cover direct/proxy startup, unrelated launchd children, exact
token/birth/exit linkage, duplicate records/environment, loss, eviction and bounds,
readiness, source/setup tampering, prepared-code imports, parser redaction,
single-use locks, compact capture output, report-only recovery and cleanup after
interruption/analysis/stream failures. A compiled C simulation substitutes every
OS-facing API: success, registration/activation failure, EOF cancellation, command
timeout, failed removal/lease recovery, altered leases, partial writes, non-root
and malformed input all run without host filesystem, signal, process or job APIs.
Clang syntax-only, whole Ruff/format and unchanged revision-370 manifest checks
pass. No generated/native files are added to the repository.

Fresh code-only handoff: `/private/tmp/eforge-launchd-kit-4g2591rk`. Setup and live
collection have not run. Do not inspect this directory after handoff or reuse
an older kit. Human instructions are in
[PRIVATE-RUN.md](../design/macos-workstation-feasibility/launchd-reference/PRIVATE-RUN.md).
The human closes agents, runs setup then automatic one-window capture once, and
shares only SHAREABLE-LAUNCHD-REPORT.json. Future native reads need separate
explicit permission. The next implementation step depends on that fixed report;
system launchd activation remains gated meanwhile.

## November 2: review launchd facts and qualify its installed true command

The human supplied only SHAREABLE-LAUNCHD-REPORT.json from the handed-off
`/private/tmp/eforge-launchd-kit-4g2591rk` kit. That exact fixed report was read.
It establishes COMPLETE/NONE, all collection/authentication/lineage/cleanup controls
PASS, no eviction/limit and v11 shapes. One launchd fork preserves the boot image;
the child execs xpcproxy, acquires its own group/session and execs true in the same
lifetime, then exits zero. Root credentials, the boot parent's assigned nonzero
unattributed audit origin and self responsibility persist. Native PID version
increments at each exec. Both execs have three vnode standards, no controlling
terminal, root cwd, no script and matching dyld paths. The nonzero ASID agrees
with the existing assigned boot-origin producer; no new identity allocation is
needed. es_client FAIL and audit_session_zero FAIL are false comparison predicates,
not collection failures. The bounded facts and remaining limits are recorded in
[REFERENCE.md](../design/macos-workstation-feasibility/launchd-reference/REFERENCE.md).

The human separately authorized the new version-1 offline reviewer. It ran once
against that capture, reading only bounded records/provenance/saved report and
controlled code/guard metadata; it wrote nothing and started no native commands,
jobs, probes, collectors or live queries. It verified original controls, exact
selected graph and fixed report agreement. Xpcproxy has only XPC_FLAGS=0x0; true
retains the four controls and has decimal XPC_FLAGS=1 and the exact test service
label. At least one extra target key remains outside the allowlist and stays
hidden. This permission is consumed; no further original-kit read is authorized.

The version-2 checker adds only the public OSLogRateLimit candidate and the literal
64, returning fixed labels. The name's presence was independently checked through
a fixed Boolean search of the installed public launchd executable, not a process,
environment, private kit or log read. The tested code-only reviewer is prepared at
`/private/tmp/eforge-launchd-kit-7jtlfrbd/private_launchd_review.py`. Separate
permission for that added comparison is pending. Do not open either handed-off
kit, or run that review, without the new reply. No further collection is needed.

Independent implementation adds `/usr/bin/true` to the engine-owned installed Mac
catalog with no persona/default activation, reviewed com.apple.true/null-team/
absent-entitlement facts, ARM64E pointer-auth slice and 0x26011b11 runtime flags.
The validation bit absent from this image is not borrowed from xpcproxy. Binary
hashes/UUIDs/file metadata stay synthetic and deployment-owned. Only the bare
command receives a nominal short timing profile and explicit zero completion;
arbitrary argv or other commands do not acquire a success default. YAML's true
artifact name is explicitly quoted. Generation behavior revision 371 is localized
to this command/catalog expansion, not system-job activation admission.

Measurable acceptance: the native complete-collection workload including receiver
startup plus the true command reconciles seven real forks/seven execs with zero
aggregate births. The new command contributes exactly one fork, one exec and one
known zero exit with correct flags/null entitlements. The eCAR-only explicit
partial variant also succeeds. Both checks pass in 3.27 seconds. All 230 selected
runtime/catalog/manifest/reference checks initially had 229 passes and one stale
SSH catalog assertion: it expected an absolute wrapper argv despite revision
369's reviewed basename. That assertion now tests the exact wrapper basename
while retaining absolute paths for the other receiver roles. The additional
offline tests pass all 34 cases, using invented data and forbidding commands,
installed-image inspection and live queries. They cover code/guard/codec/report/
provenance/nonce/graph tampering, symlinks, immutable files, parser redaction and
closed public candidates. The final combined catalog/private-reference regression
passes all 1,196 checks in 5.02 seconds, including the corrected catalog assertion.
Whole Ruff/format checks pass. Revision-371 surface:
`1f131085b35be3b6fc506ae24fb44b64df24315dd5a2382acfd3386103b6a2f5`.

Full launchd activation remains unqualified. After the environment check, its
canonical startup must replace the aggregate with the measured root fork,
xpcproxy exec, setsid and target exec, preserving exact service binding, retained
publication recovery and checkpoint ownership. The current persistence bundle is
created per typed stage and its process/service composite accepts a staged birth,
so simply inserting native rows or execs around that aggregate is insufficient.
Use the existing canonical phase journal and service authority, retain the loaded
definition after plist removal, and cover complete/filtered/checkpoint/fault
workloads. Unsupported user domains, triggers, privilege drops and arbitrary
helper graphs retain their gates. No native record, raw report or private
provenance is committed, and no new collection ran during this work.

## November 2: admit the bounded native root system-job producer

The human explicitly approved the version-2 offline reviewer at
`/private/tmp/eforge-launchd-kit-7jtlfrbd/private_launchd_review.py` against the
existing `/private/tmp/eforge-launchd-kit-4g2591rk` capture. It ran once and returned
PASS for the added OSLogRateLimit/64 comparison and complete environment
classification. No unknown name/value remains. Each review permission is consumed;
neither handed-off kit may be opened again without separate permission. The review
started no commands, probes, jobs, collectors or live queries and wrote no files.
No new collection ran and no raw records, report or provenance are committed.

Write-only `launch_profile: root_xpcproxy_v11` selects the bounded native root
system-job producer. The execution policy allowlists installed `/usr/bin/true`
with RunAtLoad false and explicit activation. Clean PATH/LANG/LC_ALL inputs
are frozen into the canonical modeled file before publication, then retained by
the loaded definition after file edits/removal. The producer adds the observed
public OSLogRateLimit=64, XPC_FLAGS=1 and exact XPC_SERVICE_NAME. Xpcproxy has only
XPC_FLAGS=0x0. No private nonce or observed environment is copied into generation.
Legacy definition serialization/content seeds and partial aggregate behavior are
preserved when no preset is selected.

`MacosSystemJobStartup` reuses the existing retained Mac phase journal:
launchd fork plus xpcproxy exec, separate setsid, then true exec. Each exec uses
its reviewed installed security/slice/entitlement policy. Root credentials,
assigned boot audit origin and self responsibility persist; the target has its
own group/session, root cwd and three non-TTY vnode standards. Scoped lognormal
phase timing is nominal synthetic timing, not a private-duration measurement.
Preflight rejects unqualified inputs before process allocation/census mutation.

The existing service admission token/capability binds that already published
process. The authority holds State before registry mutation, checks current
execution/group and live old-group members, then consumes the ordinary capability.
Ordinary registry commit cannot consume this request. There is no new queue or
proof registry and no replay of a birth. Failed phases or lost binding returns
retain the same startup for exact retry, block other launch-item stages and block
checkpoint capture while unfinished. Success clears the journal. Explicit
exit/unload retain the existing group owners.

Checkpoint hydration validates the native preset's post-fork setsid group time
against its current execution instead of requiring it to equal process birth;
legacy group validation stays exact. The public acceptance workload uses an
explicitly pre-window provisioning caller, whose unqualified startup is outside
the measured collection. Authored warm-up entries now execute in their indexed
warm-up pass before collection through ordinary pre-window source suppression.
Previously they were deferred until the post-collection tail, making a declared
pre-existing caller unavailable. Windows/Linux ordering tests cover this generic
scheduler correction. The outside-collection validation warning stays visible;
no census exemption or fake start was added.

Measurable acceptance: the two native job activations reconcile two forks/four
execs and zero aggregate starts, with explicit known zero exits. Public full and
native-only CLI runs under different Python hash seeds preserve native bytes.
Fresh-process checkpoint suspend/verify/resume retains an active job's loaded
definition, environment and post-fork group, then exits, reactivates after removal
and unloads with byte-identical deterministic bundle content. That recovery test
deliberately stretches the explicit lifetime across hourly checkpoints to test
ownership; it is not a true-duration realism sample. The example uses short
explicit target completion instead.

All 252 selected routine lifecycle/metadata/persistence/Finder/manifest/scheduler
checks and 391 shared State/ground-truth checks pass. The nine slow first-fork,
setsid and target-exec fault cuts pass; binding before-commit/lost-return recovery,
checkpoint transient guards, frozen environment after policy changes, unsupported
image rejection before allocation, legacy byte identity and eCAR-only filtering
also pass. Whole Ruff/format, diff and behavior-manifest checks pass. Revision 372 surface:
`e7ba17d89d83d5b3a0c06709988c8e321e11484d1acff9fb2506441a4f674ac9`.

This closes the bounded root system-job milestone, not the global P0. Other GUI
mechanisms/apps/helper trees, existing-app windows/restoration, additional job
images/domains/triggers and complex execution plans remain separate producer and
qualification work. No extra collection is needed for this preset; the next
native GUI extension needs its own controlled reference before admission.

## November 2: fixed workstation workload replaces component-led qualification

The user challenged the practical breadth and approved a fixed thirty-minute
two-Mac acceptance scenario: fresh Apple Terminal/iTerm2, ordinary commands,
non-PTY and PTY Mac-to-Mac SSH, real catalog Chrome plus renderer/GPU/network
helpers and browsing, useful background inventory jobs and baseline activity.
The new managed Schema 3 artifact is under
`scenarios/macos-workstation-acceptance/` (draft.json plus source/); its CLI-created
UUID is retained and no release is published. WORKLOAD.yaml independently records
case membership/required roles; the measurement runner uses the ordinary public
CLI. Industry/organization context reuses the invented development-lab archetype
from the existing example, with no packs or local inventory.

The unchanged full source rejects at Chrome's missing Finder bundle policy. No
reference-app substitution, target-start warmup relocation or process-family
suppression was used. Pre-collection job registration/provisioning is explicit
fixture state from the original workload; its startup is not claimed qualified.
All terminal/command/SSH/browser/helper/job target starts remain in collection.
Four warnings are retained: three setup steps outside collection and no firewall
sensor in the endpoint/SPAN lab. The initial low-intensity seed scheduled no user
timestamps. Intensity was raised to medium during workload construction to
exercise baseline, retaining seed/window/target activities. Seed 373 remains
quiet; supplementary seeds 374 and 375 are both retained, not cherry-picked.

Concrete repairs from observed failures:

- Root jobs reuse the qualified launch mechanism and existing independent
  sw_vers image metadata for OS inventory, rather than stopping at true. The
  reference observed true; this extension does not claim captured sw_vers flags.
- Mac final-pass process families admit starts through their existing natural
  lifetime owners; they no longer disappear for lacking an in-window close bound.
  Optional starts displaced after collection reject before requested-process
  materialization. Other unbounded OS/family gates remain intact.
- Mac-containing user-activity passes execute due authored owners before the
  scheduled background action, retaining future authored transitions until due.
- Baseline catalog Terminal/iTerm2 activity uses shared native startup/reuse.
  Previously it created an aggregate app before the later shell request, which
  then rejected as an unqualified existing-app window. Tests prove one native
  chain and no extra starts on ordinary reuse for both brands.
- Ground truth excludes actual pre/post-collection occurrences from expected
  visibility, preserves subsecond timestamps and marks no-matching-session
  logoffs as no-ops. Native aggregate diagnostics respect their independent
  census window. No evaluator threshold or source renderer was weakened.

The report records actual overlapping case counts: Apple Terminal 5 forks/6
execs, iTerm2 6/8, non-PTY SSH 11/12, PTY SSH 12/14 and two inventory jobs 2/4.
The combined diagnostic excluding Chrome has **29 forks/34 execs**, exact
independent fingerprints, zero aggregate starts, 12 known exits and 75 native
rows. eCAR process phase counts agree. It explicitly uses partial policy and is
not the full-workload acceptance target. Seed 375's supplemental baseline has
5 forks/7 execs with exact reconciliation; primary seed 373 and seed 374 have
zero in-window background starts and remain reported as unexercised.

The first deterministic combined evaluation failed visibility/pivot/timing due
to setup and no-op logout expectations. Correcting those truth records yields
all hard gates passed, overall **89.5282**, 100% format conformance, 100% field
agreement and 100% intent reconciliation. No blind panel or assessment loop ran.
Native-only filtering preserves nonempty byte-identical native output. The
complete combined bundle was copied to the ignored persistent local path
`runs/macos-workstation-acceptance/2026-11-02/supported-combined/`; evaluation of
the copied bundle verifies its manifest and again passes all hard gates at
89.5282. Raw generated rows are not committed.

All **329 selected routine checks pass**, with one pre-existing skip, and all
**15 selected public terminal/SSH/job CLI and recovery regressions pass**.
Whole Ruff/format/diff and behavior-manifest checks pass. Behavior revision 373
is material: baseline admission/order, native terminal selection and job target,
plus truthful collection/no-op visibility. Final surface:
`1112d76da93cf383cef734e563f7e3790a021e49d59a8a03ebb52704b0c40a72`.
Frozen primary source SHA-256:
`632fe6d932b6749049d3c8f8d1d559092c7ceb07994a1afd5d619725c769470d`.

Full acceptance remains BLOCKED: Chrome/main/helper metadata and launch plans,
primary exercised baseline, and full-workload filtering/recovery remain open.
Public Chromium signing/entitlement templates were researched as leads; they
do not establish the frozen catalog release's runtime FD/security/helper facts.
The user has been asked only whether Chrome is already installed (Yes/No), to
design a bounded fresh-profile reference. No capture, installed-app query, private
kit read or native-log read ran. Previously consumed permissions were not reused.
See REPORT.md and RESULTS.json for the reviewable outcome and exact limits.

## November 2: prepare the single Chrome workload reference

The user confirmed that Chrome is already installed. This is availability only,
not permission to inspect the app, run a collector or read prior private kits.
Workload milestone `23e3078f` is committed and pushed. Its unchanged full source
still rejects at Chrome; the previously measured diagnostic subset is unchanged.

`scripts/macos_chrome_reference.py` prepares a fresh code-only kit. Human-only
setup snapshots fixed installed code/signature metadata, compiles the unchanged
readiness marker and 55-second collector guard, and launches nothing. It verifies
Google's signing requirement for Chrome code and Apple's for xpcproxy. Human
capture requires attestations that ordinary Chrome is closed and the external
network disconnected, then uses LaunchServices `open -n -a` with a new explicit
test profile. The supplied server serves only an invented local WebGL/fetch page
from memory on 127.0.0.1. It logs no requests and serves no disk files. There is
no headless/debugging mode, sandbox bypass, installed-app modification, personal
profile read, historical-log query, process enumeration or bundle-wide quit.

The existing bounded reader/guard and image/security/entitlement comparison
helpers are reused. Ambient ES stays in a bounded in-memory ring. A matching
installed main file object/signature plus exact controlled arguments and unique
profile/URL proves the root. Exact xpcproxy/fork ancestry and controlled execution
or parent-token linkage prove descendants before private retention. Path or PID
alone cannot admit rows. Changed native path spellings are classified separately;
unrelated Chrome instances and duplicate profile overrides fail admission.
Missing forks are counted explicitly, not synthesized. The user quits only the
test browser manually; interruption, timeout, collector/launch failure and cleanup
are tested with fake processes/server/clock. Verification of installed code runs
after collectors/server stop, not inside the collector watchdog's deadline.

The outer kit's SHAREABLE-CHROME-REPORT.json exports only closed labels, public
allowlisted entitlement/switch names, fixed FD slots and sequential execution/pipe
aliases. It covers native shapes, signing/security/slice, parent/responsibility,
audit/job-control transitions, argv roles, FD inventory and pipe relationships,
environment comparisons, entitlements and known public template membership in
one report. Unknown names and all observed values stay hidden. Short stdout
avoids another scrollback problem; the human shares only the fixed detail file.
Native records/provenance/profile remain private, outside Git. A 4 MiB report
overflow explicitly returns LIMIT without pretending a truncated graph is full.

This does not qualify direct Finder/Dock/Spotlight launches, app reuse, arbitrary
helper graphs or exact catalog-release behavior when the private installed build
differs. It starts no new admission/assessment loop. The next development step is
to apply the report to Chrome's owning canonical launch/helper plans, then rerun
the fixed workload and its outstanding baseline/filter/recovery acceptance.
No live Chrome query, app/probe launch, native collector or private-log/kit read
ran during preparation; tests use invented inputs only. No production generation
surface or behavior revision changed. Detailed human instructions and public
Chromium design inputs are under `chrome-reference/PRIVATE-RUN.md`.

All 359 selected Chrome/common GUI/launcher/terminal kit tests pass, including
50 Chrome tests with invented inputs and fake lifecycle operations. Whole
Ruff/format (1,414 files), diff and generation-behavior checks pass. Revision 373
and its digest remain unchanged. Prepared fresh code-only handoff:
`/private/tmp/eforge-chrome-kit-qfs15vnt`. Once handed to the human this directory
must not be opened, listed or queried by an agent without separate permission.
The next authorized agent action is to read the human-selected fixed shareable
report, not to inspect native records or silently start this experiment.

## November 2: repair Chrome kit installed-code setup

The human reported `error: BUILD`, then clarified `Setup — INSTALLED_CODE`.
No private kit, local log or installed Chrome metadata was opened to diagnose it.
Source review found a concrete command-construction defect: the separate `-R`
argument lacked the leading `=` that codesign requires for inline text and was
therefore treated as a requirement filename. Apple's TN3127 documents the correct
form. The entitlement display also lacked an explicit XML request; TN3125 says
the default display is human-readable DER. The fresh v2 kit uses `-R '=…'` and
`--entitlements - --xml`. Signature checks remain strict and retain the same
Google/Apple constraints; no admission check is bypassed.

Chromium's public signing/parts.py identifies app bundles as signing subjects
and crashpad as a standalone executable. App checks now target the containing
bundle; the metadata's Executable field must bind the exact separately hashed
leaf. No app is modified or re-signed. Installed-code failures carry closed
item/check/reason enums, so another failure can be diagnosed without native
stderr, paths, exception text or identity values. Setup remains before any
collector, browser, server or readiness-probe execution.

The only native command executed by the agent was Apple's `csreq` parser with
two literal public requirement strings. Both parsed successfully; this read no
installed app, profile, private kit or log, and launched no test app or collector.
Regression fixtures model command exits/timeouts, missing/symlink/permission
errors, malformed metadata, invalid executable binding, bundle-vs-tool targets,
XML arguments and inline-requirement syntax. Unknown error content is canaried
and absent from every fixed JSON failure. The old handed-off kit is left intact.

All 374 selected kit regressions pass (65 Chrome-specific). Whole Ruff/format,
diff and behavior-manifest checks pass; generation revision 373 is unchanged.
Fresh code-only version-2 handoff: `/private/tmp/eforge-chrome-kit-isc7tieu`.
Do not inspect it after handoff without separate permission. Human should run
setup there first and stop on failure; no capture is needed to verify this fix.

## November 2: isolate the remaining Chrome signature-check failure

The human's v2 fixed report identifies MAIN / SIGNATURE_VERIFY / COMMAND_EXIT.
The previous malformed inline requirement is corrected, but this combined check
still cannot distinguish whole-bundle integrity, strict validation and signer
requirements. It is not evidence that Chrome's executable is modified or that
the expected Google identity differs. No native collector has started in setup.

A separate `diagnose-code --private-run` command performs six fixed, read-only
codesign queries against only the standard installed Chrome app and main leaf:
basic bundle, strict bundle, strict Google requirement on bundle/leaf, a separately
labeled leaf-code-only comparison and XML metadata. Each query has a fifteen-second
timeout. It compares file hashes before/after privately and exports only equality,
public-template comparisons, XML/flat-type labels and allowlisted tool-message
classes. Unknown text, paths, identifiers, certificate names, hashes and stderr
remain hidden. A completed diagnostic is not successful signature validation or
generation admission; all original setup admission checks remain unchanged.

The code-only comparison uses Apple's documented --ignore-resources flag only in
this explicit diagnostic. It does not change capture verification, sign or modify
code, disable Gatekeeper, request online notarization, open a browser/profile,
read a native log, build/run a probe, start a server/collector or write helper files.
Existing prepared kits are untouched. The new source reuses the same verification
and metadata argument builders as setup, so diagnosis tests the actual command
construction. Regression tests deny installed-code access by default and inject
all static metadata/tool failures, including private canaries and a bundle-resource
failure alongside a passing code-only result.

Prepared fresh code-only diagnostic: `/private/tmp/eforge-chrome-kit-4xemu5yv`.
The human has been asked whether the agent may run exactly this fixed-output
installed-code diagnostic. Permission is pending; no installed-code query or
private-kit/log read was run during its preparation. The human-only setup/capture
boundary remains intact. Do not inspect any handed-off kit without separate
permission. This adds no new collection or assessment loop and changes no
production generation surface or behavior revision.

All 389 selected kit regressions pass, including 80 Chrome-specific checks.
Whole Ruff/format/diff and behavior checks pass. Production revision 373 and
its surface digest are unchanged; there is no generated-data acceptance claim.

## November 2: approved signing diagnostic and process-reference validation scope

The human explicitly approved running the prepared `diagnose-code --private-run`
from `/private/tmp/eforge-chrome-kit-4xemu5yv` with project Python. It ran once as
the ordinary user outside the execution sandbox, without sudo. That specific
permission is consumed. No other installed-code query, kit read or diagnostic
rerun is authorized by it. No native logs or browser profiles were opened; no
browser, probe, server or collector started and the helper wrote no files.

The fixed report says ordinary bundle verification PASS, all strict comparisons
FAIL/RESOURCE_SEAL (including the code-only diagnostic), main file unchanged PASS,
and metadata/expected identifier/Google team/executable binding/XML/flat types
PASS. It does not independently prove why strict resources fail, or that the
Google requirement passes without strict mode. No raw stderr, paths, signer
values, hashes, entitlement object or diagnostic JSON is committed.

Version 3 corrects the tool's overly broad admission scope for a process reference:
app bundles require ordinary signature validation plus the unchanged explicit
Google vendor requirement. Main/helper code is still descriptor-bound and hashed
before/after, signed-bundle metadata must bind that executable, and a failed
ordinary verification or vendor requirement still refuses setup. Standalone
crashpad/xpcproxy retain strict checks and their existing Google/Apple constraints.
The ignore-resources switch remains diagnostic-only and is never used for setup.
The manifest/report declare the standard app signature policy and expressly
leave strict distribution conformance NOT_EVALUATED. No Chrome bundle, system
setting, generation admission gate or native generation profile is modified.

This is a scope correction for gathering ES process facts, not a claim of strict
distribution/Gatekeeper acceptance or a repair of the installed app. The revised
full installed-code checks have not run on this host; those remain the human-only
setup command in a fresh kit. Synthetic regressions exercise all six image kinds,
retain vendor constraints, reject verification errors and prove resource-ignore
never appears in admission commands. Old prepared kits remain untouched.

All 395 selected kit regressions pass, including 86 Chrome-specific checks.
Whole Ruff/format/diff and behavior checks pass; generation revision 373 and its
surface digest are unchanged. Prepared fresh code-only v3 handoff:
`/private/tmp/eforge-chrome-kit-yrjg1s1l`. No setup, installed-code query, probe,
browser or collector ran in that new kit. Do not inspect it after handoff without
separate permission. The next human step is setup there, then the already
documented private capture only after SETUP_READY/error NONE.

## November 2: handle framed entitlement output and verify setup before another handoff

The human's v3 setup reaches XPCPROXY / ENTITLEMENTS_DECODE / INVALID_METADATA.
By execution order, the five Chrome executables completed their code/signature/
metadata checks; xpcproxy verification and metadata extraction also completed
before plist parsing failed. This is still setup, with no collector or browser
started. No old kit, installed executable, native output or local log was read
by the agent while investigating this new report. Earlier diagnostic permission
was not reused.

The old parser accepts bare plists only. Apple's published XNU cs_blobs.h and
Security blob.h define an embedded-entitlements container: magic 0xfade7171 plus
network-order total length, including the eight-byte header. Version 4 supports
bare XML/binary plists and that exact container, validates its full extent, then
requires a dictionary. DER containers, damaged lengths, unknown prefixes, arbitrary
text prefixes and non-object values fail with fixed reason labels. It neither
scans for a later XML document nor replaces an unrecognized value with {}. The
existing signature checks, vendor requirements and file identity/change checks
are intact. Installed metadata formats are exported only as fixed names for each
declared component; no keys, values, lengths, hashes or observed paths are added.
The actual local xpcproxy encoding is still unobserved by the agent; framing is
a source-grounded hypothesis, not a finding from the user's private stdout.

Synthetic tests now exercise all six installed-code checks through the real
setup orchestration with fake native commands and a framed xpcproxy object, plus
XML/binary, truncation/extent, unsupported DER, unknown prefixes, wrong object
types and private canaries. All 410 selected kit tests pass, including 101 Chrome
checks. Whole Ruff/format/diff and behavior checks pass. Revision 373 is unchanged;
there is no production generation/profile or native-source admission change.

Fresh code-only v4: `/private/tmp/eforge-chrome-kit-x02_rnsp`. The human has been
asked to authorize only its setup: fixed platform/installed-code reads, compiling
and signing controls without executing them, and writing private setup metadata
outside Git, with only fixed JSON/format labels returned. That permission is
pending. It authorizes no browser/probe/collector launch or log/profile/old-kit
read. Do not inspect a handed-off kit or run setup without that permission.
This is intended to let the agent verify setup before another human capture
attempt; capture itself remains human-only and has not run.

## November 2: verify actual setup and separate verbose metadata from XML extraction

The human authorized **setup only; no capture**. The agent continued that setup
task within its existing platform/six-executable metadata/control-compilation
scope, using fresh isolated code copies after parser corrections. No capture,
browser/probe/collector execution, native-log/profile read or old-kit inspection
was performed. This setup authorization is distinct from the earlier one-shot
Chrome signing diagnostic; routine corrections/retries did not add resources or
authorize collection.

The v4 setup returned XPCPROXY / ENTITLEMENTS_DECODE / OUTPUT_NOT_PLIST; a v5
structural report identified OTHER_TEXT. Header and dictionary-fragment support
did not establish the local cause. Fixed-output comparisons of only the same
installed xpcproxy metadata then reproduced the problem: entitlements-only
`codesign -d --entitlements - --xml` returns parseable XML; adding --verbose=4
adds a human-readable bracketed dictionary before the XML, making the combined
stdout invalid as a plist. Verbose metadata-only display also emits that bracketed
form. The helper returned only public format/parseability labels. No native
strings, keys, values, paths, hashes, stdout/stderr or diagnostic JSON are committed.

Version 6 fixes the acquisition owner. Verbose signing metadata and XML entitlement
extraction are separate commands against the same code object, with the existing
signature check and before/after image binding retained. Verbose stdout is ignored;
only metadata stderr is parsed for identity, and only the clean dedicated XML
stdout is decoded. No scanning around diagnostic text, prefix stripping of unknown
text, or permissive fallback to {} is used. Unneeded bare-dictionary admission
from the intermediate experiment was removed; structural diagnostics remain fixed
labels. The optional code diagnostic now reports its separate seventh query
explicitly. Native generation/source profiles and behavior revision 373 are unchanged.

**Actual host setup succeeded** in `/private/tmp/eforge-chrome-kit-fdw97zzl`:
SETUP_READY, error NONE, platform/provenance PASS. Main, renderer, GPU and xpcproxy
metadata use XML_PLIST; generic helper and crashpad have EMPTY entitlement output.
Those are representation labels only. The installed build comparison is OTHER;
its version remains private and exact frozen-catalog parity is not established.
Controls were compiled/signed and hashed but never executed. Do not rerun setup
or inspect this kit after handoff. It is already built for the human's private
capture, which remains outside the current authorization.

Regression fixtures now reproduce mixed verbose DER text plus XML and require
separate queries across the full six-executable setup. They deny all native calls
and installed-code reads by default and assert that private canaries never reach
fixed output. The actual success is setup acceptance, not Chrome native process
generation or the full-workload P0 acceptance milestone.

All 416 selected kit regressions pass, including 107 Chrome checks. Whole
Ruff/format/diff and behavior checks pass. The built v6 kit is the handoff;
its code/controls must remain unchanged for capture. The human should skip setup,
close agents/ordinary Chrome, disconnect external networking and run only the
documented private capture, then share only its fixed report. No further native
command ran after successful setup, and no collection is authorized here.

## November 2: Chrome fixed report, generic GPU role and global identity versions

The human supplied only the outer kit's exact `SHAREABLE-CHROME-REPORT.json` in
`/private/tmp/eforge-chrome-kit-fdw97zzl`. The agent read that named fixed file,
validated it against the closed report schema and inspected only its labels.
No other file in that kit was listed/opened. No native row, setup/provenance,
profile or installed-code query was read/run; no collector/app/probe was started.
This permission does not authorize an offline native-record review.

The collection controls passed, all 43 retained native shapes passed, and the
fixed graph has 15 forks, 14 execs and 14 exits. Renderer/network/main evidence
is present. The reported GPU failure is a classifier defect: one retained exec
has the GPU argument label and verified generic-helper file/signature/entitlement
identity. Version 7 recognizes a generic helper's unique renderer/GPU/utility
role without substituting the dedicated GPU image or its JIT entitlements.
Duplicate/conflicting type switches stay unqualified; unknown file objects cannot
acquire a known helper role from arguments alone. Existing v6 captures remain
readable and unchanged; future capture manifests/reports default to v7.

The report also distinguishes two fork-without-exec lifetimes. One intermediary
forks the Crashpad child and exits; its fork-only lifetime is legitimate, not a
missing exec to synthesize. The other child has no retained exec or exit. Its
ending is unresolved: collection stops after the main exit and the shareable
report cannot establish whether a record was filtered out or the child survived
collection. A strict main exec transition check also fails, despite a retained
native exec; that alone does not identify the differing identity component.

Primary-source research found a second reference-kit defect: XNU kern_exec.c
allocates identity versions from the global nextpidversion counter (and ensures
that exec changes the prior version). Concurrent process activity can consume
intervening values; wraparound can occur. Exact +1 was an invalid collector and
diagnostic assumption. The Chrome kit now requires preserved PID/birth and a
changed version while retaining the existing exact before execution/image or
kernel parent-token ownership proof. It still rejects unchanged versions,
different lifetimes and unproven parents. This fixes reference acquisition; it
does not recover already discarded records or prove the unresolved child's cause.

References: Apple's
[kern_exec.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
and [kern_fork.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c).
Only the Chrome reference owner changed here, not production generation.

`scripts/macos_chrome_review.py` prepares one comprehensive offline reviewer.
It authenticates the original code hashes, controlled binaries, setup/provenance,
collection controls, native shapes, retained selection and original fixed report.
It compares each exec's PID/birth/version separately, corrects generic GPU roles,
classifies only predeclared public system/Chromium paths and role switches, checks
seatbelt/Mojo arguments against retained descriptors without exporting numbers,
compares known environment key/value templates and main/helper environment
relationships, and lists fork-only/unfinished lifetimes with opaque aliases.
A public path comparison is explicitly not independent code/signature admission.
Unknown names/values stay hidden. Review writes nothing, opens no browser profile
or installed code, and starts no commands, collectors, probes or live queries.

A trusted code-only v6 copy was prepared from the repository before the fixes;
no handed-off kit was used to construct it. The reviewer pins that original code
for exact v6 report/selection verification while its added comparisons are
separate. Fresh prepared reviewer: `/private/tmp/eforge-chrome-kit-lpxff5he`.
It has not been run on the human's capture. Separate local-log permission is
required to run it against `/private/tmp/eforge-chrome-kit-fdw97zzl`; no new
collection is needed for this review. Previously prepared intermediate reviewers
are superseded by this path.

All 499 selected Chrome/GUI/launch-chain/terminal checks pass, including 32 offline
review cases using invented records, read-only file checks, native-operation
prohibitions, private canaries and tamper rejection. An additional invented-data
smoke check exercised the standalone reviewer with the actual frozen v6 code,
confirmed exact original-report agreement, corrected the generic GPU label and
left its synthetic fixture unchanged. No private report or native record is
committed. Production behavior revision 373 is unchanged. The full fixed
workstation acceptance remains blocked on the Chrome canonical producer work;
these reference fixes do not close P0 or claim generated Chrome acceptance.

## November 2, revision 374: approved Chrome review and complete bounded workload

The human approved the prepared offline reviewer in
`/private/tmp/eforge-chrome-kit-lpxff5he` against
`/private/tmp/eforge-chrome-kit-fdw97zzl`. It ran read-only and passed provenance,
original collection controls, exact retained selection and original-report
agreement. The identical command was repeated only to compact its already
approved fixed output after the first tool output was truncated. Scope did not
expand: no new comparisons, direct native-record read by the agent, installed
code query, profile read, command/app/probe/collector launch or file write occurred.
No additional review/collection is authorized by this completed operation.

The fixed results confirm that the main transition preserved PID/birth and
changed the global identity version with a gap. All retained transitions satisfy
same-lifetime/changed-version semantics. The generic helper GPU role is confirmed;
all retained seatbelt arguments refer to a pipe in the same descriptor inventory.
Renderer, GPU and network roles have known installed security/entitlement
agreement. A storage utility is also observed. An auxiliary image remains OTHER,
another matches the public alerts layout without independent installed-code
qualification, and a generic-helper role remains unclassified. The exited
fork-only Crashpad intermediary and the separate child with no retained ending
remain as previously described. Unknown environment names/values stay hidden;
known public keys include OSLogRateLimit. No raw report, native record, captured
identifier, version, path, environment value or code hash is committed.

Production now consumes the bounded reference through canonical owners:

- Chrome main has an explicit fresh LaunchServices/Finder bundle policy. It uses
  the existing boot fork, root xpcproxy exec, GUI credential transition and main
  exec journal. A baseline adapter bug is fixed at that boundary: catalog argv
  is serialized once into its canonical shell-quoted display before the request.
- Renderer and generic helper are independently signed placements installed with
  Chrome, using the same frozen synthetic release. Vendor identifiers and public
  entitlement templates are explicit data; a child never inherits main signer
  metadata. Generic GPU/network share one actual helper image and null entitlement
  state. Reviewed runtime flags/slices are separate validation policy. The private
  installed build differs from the frozen catalog, so exact release parity is
  expressly not claimed.
- Exact renderer/generic-GPU/network invocations enter a bounded browser-helper
  policy. They inherit authenticated GUI ownership and current directory and
  publish actual fork and exec occurrences. A State-owned sandbox pipe and its
  argv slot share one allocation. Slot, timing and clean environment additions
  are explicit synthetic inputs, not exported capture values or modeled browser IPC.
- The first retry test exposed duplicate births after a committed return was
  lost. Helpers now reuse the retained Mac startup phase journal. A small base
  extension selects the final app phase; existing Finder/PTY/system-job phases
  retain their prior indexes. Pending helper startup uses the already-checkpoint-
  guarded transient owner. Both fork and exec before-commit/lost-return faults
  retain one process identity and one pipe allocation; shared source release
  recovery is covered by the existing journal gates.
- A direct request test exposed a pre-existing unexpected source_visible_by
  keyword passed to Windows CLI spacing. That branch already requires the value
  to be None; the unsupported keyword is removed at its call owner.

The fixed workload's GPU image expectation was wrong: it demanded the unobserved
JIT-capable dedicated GPU bundle. The source/catalog now select the observed
GPU-on-generic-helper variant. All three operational roles remain required,
including explicit argv checks so one generic helper cannot satisfy both GPU
and network coverage. No activity family, time, seed, intensity or completeness
policy was removed. Only the two explicitly conditional warmup cleanup logoffs
may count their typed no_matching_session no-op; that exception cannot hide
skipped process starts or other failures.

The full thirty-minute two-Mac source now generates successfully:

- Primary seed 373: **33 forks/39 execs**, all exact independent identities,
  **zero aggregate starts**, **84 ES rows**, no missing executable/argv roles or
  authored phase gaps. eCAR agrees on all fork identities and exec PID/version,
  path and argv tuples. Native-only filtering is byte-identical across both hosts.
- The primary still schedules **zero background execs**. The original positive
  background acceptance bar remains unexercised; it is not lowered or replaced.
- The previously predeclared supplemental seed 375 runs the same full source:
  **37 forks/44 execs**, **93 ES rows**, **five background execs**, exact census,
  no aggregate starts or missing authored/operational roles. It is separately
  labeled and does not replace the quiet primary seed.
- One deterministic evaluation verifies the primary authoritative bundle and
  passes all applicable hard gates at **88.9227/100**. Behavioral diversity and
  noise volume remain low. This is not a blind authenticity assessment.
- The twelve-hour native browser-helper checkpoint gate passes suspend/status/
  integrity verification/exact resume and deterministic bundle equivalence, with
  live helpers retained at its checkpoint. The exact thirty-minute workload was
  also attempted with checkpoints/test synchronization; it finished without
  exposing the requested intermediate boundary. That attempt is preserved and
  does not count as full-workload recovery acceptance. Source duration/times were
  not changed to conceal this remaining condition.

The first full-run attempt failed during warmup on the catalog quoting defect;
its output is preserved. The corrected primary is `full-2` under
`runs/macos-workstation-acceptance/2026-11-02-chrome-native-374/` (ignored), alongside
native-only, supplemental and checkpoint diagnostics. Only summaries are tracked:
`scenarios/macos-workstation-acceptance/CHROME-RESULTS.json` and the updated REPORT.
The former report is retained as INITIAL-REPORT.md; original RESULTS.json is
historical, not current capability.

Validation passes with the same four expected warnings. All **193 focused routine
checks** pass across the Chrome/canonical metadata/census/descriptor/catalog and
shared application/deployment/process owners, including the Windows spacing case.
All **10 selected extended recovery checks** pass (nine existing Finder fault
cases plus the native helper checkpoint gate). Whole Ruff, format, diff and
behavior checks pass. Revision **374** digest is
`d20e1cafe315eaca2a79bb4840ca292ce2b35f2a576453d0ef0c0d457d31c6bc`.
No feature-branch product version bump or release is made.

The global P0 milestone remains open: primary positive-baseline and exact full-
workload checkpoint conditions remain explicit, and other unqualified app/helper
paths still reject under complete coverage. Dedicated-GPU, Crashpad/alerts graph,
arbitrary helpers, app reuse/restoration, browser IPC, helper-attributed network
traffic and general app-launch Unified Log evidence are not admitted by this
bounded producer. No additional human data was requested and no assessment loop
was started. The next work should use the measured workload/coverage conditions,
not another open-ended reference or reviewer loop.


## 2026-11-02 — Combined recovery and phase-one acceptance

The user authorized finishing the combined recovery check, fixing only concrete
failures, pushing that milestone, then completing phases 1–4. The separate managed
`macos-workstation-recovery` draft preserves the two invented Macs, installed apps,
seed 373, medium baseline, source selections and complete native policy. Its three-hour
window holds both SSH continuations and live terminal/browser/helper work across the
checkpoint, then runs remote commands, closes sessions and reactivates the inventory
job. The original thirty-minute source remains unchanged.

The new extended integration gate passes public suspend/status/verify/exact resume,
retained non-PTY/PTY continuations and live terminals/helpers, equality of **all 22
deterministic bundle files**, and native-only filter byte equality. The completed
companion has **45 forks, 55 execs, 112 native rows, 16 background execs**, zero aggregate
births, exact independent identities, every authored phase and every required Chrome
argument role. One deterministic evaluation verifies 2,816 records and passes applicable
hard gates at **88.7095/100**; only two ULF rows are present. Source warnings remain the
three pre-window fixture setup steps and absent firewall sensor.

Initial test-harness attempts are preserved under ignored runs: a standalone harness
correctly rejected the pytest-only synchronization hook; the integration test initially
assumed a single suspension cursor and looked for SSH snapshots in State instead of their
retained continuation. Those expectations were repaired. No production failure or engine
change was established. The final passing run is
`runs/macos-workstation-acceptance/2026-11-02-combined-pytest-374d/`.

The acceptance matrix now explicitly separates the quiet thirty-minute primary seed 373
from positive predeclared seed 375 and this longer seed-373 recovery companion. A quiet
sample does not prove positive coverage; a companion does not replace the primary. This
closes phase 1's bounded fork/exec engineering milestone. Whole Ruff/format/diff and behavior
checks pass; production revision remains 374. No native logs were read or collected.

Remaining finite sequence:

2. Measure known/unknown native exits and repair concrete owning-layer lifecycle or
   cross-source failures. Do not assign success to unknown GUI/SSH teardown results.
3. Minimum ULF scope: existing GUI workspace entry and qualified ASP refusal, plus bounded
   SSH authentication/session and launchd job activation/completion if reference-qualified.
   Existing ES-only captures do not establish these ULF templates. Additional app catalogs,
   arbitrary GUI mechanisms and every auxiliary Chrome helper are outside this phase.
4. One combined acceptance and bounded realism review, after actual implementation; repair
   concrete blockers. Do not restart an open-ended assessment loop or declare unqualified
   ULF families accurate.


## 2026-11-02 — Lifecycle accounting, current-code acceptance and finite ULF blocker

The combined recovery milestone was committed as 748febe6 and pushed before
continuing development. Phase 1 is closed for the agreed bounded workload; this
is not universal application support or a guarantee of known results for all exits.

Revision **375** declares a nominal zero result only for the exact installed
`/usr/bin/uname -a` invocation at its untruncated natural completion. The existing
query owner remains responsible; successful exec or generic session teardown cannot
supply the result. Natural-completion, forced/truncated/held/deadline, replacement,
explicit-signal, frozen-policy and recovery checks pass (**32 routine tests**).
Measurement now separately exposes native exit row count and unknown exit
observations. Its initial exit counter incorrectly used event number 10; a regression
test now requires the typed ESExitEvent union (native exit is 15). Earlier diagnostic
JSON with zero exit counts is superseded by CURRENT-RESULTS.json, not edited in place.

Current unchanged primary: **33 forks/39 execs/85 ES rows**, **13 known native exits**,
**13 unknown exit observations**, no missing roles/authored starts/aggregate births.
The three-hour companion repeats full suspend/verify/exact resume and equality of
all **22 deterministic files** plus native filtering: **45 forks/55 execs/113 ES rows**,
**16 background execs**, **13 known exits/32 unknown exit observations**. These
observation counts are not an independent full terminal-result census. Both gate
runs pass. One evaluation per current bundle passes applicable hard gates at
**88.9170** (primary) and **88.7093** (companion, 2,817 records). A bounded current-code
review of nine execution roles, one uname exit and two ULF workspace rows found
no concrete identity/argument/writer contradiction; it does not qualify missing families.

The finite phases and stopping conditions are now recorded in
`endpoint-delivery-acceptance.md`. Phases 2–4 are **not all complete**: arbitrary GUI/SSH
teardown remains unknown; SSH authentication/session and launchd job activation/
completion ULF require bounded native references. Existing ES-only captures cannot
verify their writer/sender/callsite/message shapes. No guessed ULF template was added.
The current primary/companion contain only **two** ULF loginwindow workspace entries;
that limitation is now explicit in the current report and machine-readable summary.

A human-run launchd ULF diagnostic is prepared at
`/private/tmp/eforge-ulf-launchd-kit-jkrwd8g7`. Preparation only copied public code.
The kit's **14 routine privacy/containment tests** and the measurement's **7 tests**
pass, along with C syntax checks of the public marker and existing restricted job guard.
No compiled program, native collector, job, installed-code query or private log reader
was run. The ULF collector runs as the normal user; only the existing restricted job
guard uses sudo. Both the OS predicate and retention require the generated job label;
retention also requires launchd/PID 1. Ambient input is discarded in bounded memory,
private records stay outside Git, and unknown strings/values never enter fixed JSON.
The guard independently removes the exact job/private plist; cleanup failures remain
visible and an exact-label recovery operation starts no collector or new job.

The user was asked asynchronously to run setup/capture privately with agents closed
and share only fixed JSON. That request is pending; silence is not collection permission.
SSH ULF remains a distinct bounded reference requirement. Do not read this or any old
private kit without separate approval. Do not mark expanded ULF/final acceptance complete
because the existing code passes deterministic checks. No new assessment loop is needed.

Whole Ruff/format/diff/behavior checks pass. Revision 375 digest:
`569998740598b3b228f4bc1b06408bfe1d765efeb9e6bcfbffdca72a7f147e7f`.
No feature-branch product version bump or release is made.

## 2026-11-03 — Launchd ULF result: zero retained rows, no template qualified

The user supplied only the fixed version-1 JSON: error NONE, stage COMPLETE,
readiness/activation/job removal/private temporary-file removal/collector cleanup
all PASS, retained_rows 0. Native envelope/writer/sender/subsystem/message checks
are consequently INCONCLUSIVE or NOT_OBSERVED. This confirms the controlled job
ran and cleanup passed; it does not prove that launchd emits no ULF on macOS 27.
No private kit, native record file, local diagnostic file or its metadata was read.

Code inspection found the selection limitation: only eventMessage could carry the
generated label. Version 2 matches eventMessage OR category in both the OS predicate
and retention, still requiring the unpredictable full job label, launchd, PID 1 and
/sbin/launchd. Fixed counters expose match location without observed field values.
Readiness is now explicitly OWN_PROCESS_MARKER_ONLY; empty retention reports
NO_MATCHING_ROWS. Twenty invented-record/containment tests pass, including category-
only matches, foreign-writer exclusion, private-field suppression and no qualification
from marker-only readiness. This correction has not been run natively. The used
version-1 kit remains untouched; no new collection is requested merely to get a
positive result.

Apple Developer Technical Support points to a separate launchd diagnostic file:
https://developer.apple.com/forums/thread/791996 . This is a primary-source clue to
check the collection-source assumption, not proof of macOS 27 behavior. The new
launchd-ulf-reference/REFERENCE.md records that distinction. The launchd ULF gate
remains unpassed; no new file-log format or guessed ULF template is enabled, and
no requirement was silently removed. SSH ULF remains the next distinct reference
family. This is not a reason to restart broad collection or a blind review loop.

## 2026-11-03 — SSH ULF reference prepared; no native run

The launchd correction/result note was pushed as 6221bf51. Rather than requesting
another launchd run to force a positive, work moved to the distinct SSH ULF family.
The opt-in `prepare --unified-log` extends the existing controlled loopback workflow.
The original non-PTY/PTY workflows retain their source-code inventory and default
behavior; ULF support and its opt-in selection have separate frozen hashes so old
reference/reviewer provenance remains usable. No production generator input changed.

The new normal-user ULF reader subscribes to SSH server process names plus a
nonce-authenticated own marker. Ambient input remains in bounded memory only
(8 MiB/2,048 rows, 64 MiB total, 128 KiB line bound). Before any ULF native row can be
written, the existing ES marker/client/receiver proof must succeed. Retention uses
closed selected server execution intervals with exact PID, executable and half-open
time bounds, including each exec epoch. Launchd, client/shell processes, different
images, other connections, PID-reuse gaps and unclosed executions cannot claim a
match. Ambiguous identities/windows or capacity errors fail closed. Selected
retention is capped at 256 rows and 8 MiB serialized. Only test-bound data is saved
in the private kit, outside Git; no native records or observed identifiers are
returned to an agent.

The separate fixed summary reports envelope shape, server-role/sender/format classes,
message levels, redaction and controlled authentication/PAM message-family counts.
Unknown text, subsystem/category values, user names, addresses, ports and IDs stay
private. Redacted messages are not reinterpreted as observed authentication success.
The own-process ULF marker proves only its channel, not SSH visibility; zero retention
remains NO_MATCHING_ROWS and gate_status remains NOT_EVALUATED. This is evidence
acquisition, not permission to add guessed templates or a new syslog format.

The same normal-user setup compiles/signs the existing marker; a new --ulf-ready
path logs only a generated public nonce. No settings, server configuration, users,
Full Disk Access or persistent services are changed. Only the existing bounded
eslogger guard uses sudo. Capture is compact for ULF opt-in; `ulf-report` reads saved
fixed JSON, starts no process and makes no live query. Instructions preserve the
two-window non-PTY procedure, including pasting PRIVATE_REMOTE_COMMAND after password
entry even when the remote shell prints no prompt.

All **241 selected routine checks** pass across new privacy/binding/capacity tests,
SSH/PTY capture and failure cleanup, old reviewer compatibility, and both launchd
kits/reviewers. The marker passes C syntax checking; no compiled control was executed.
Whole Ruff/format/diff/behavior checks pass. Revision remains 375. No generation,
blind assessment or unrelated regression loop was repeated.

Code-only preparation created `/private/tmp/eforge-ssh-startup-kit-9pmp5kku`.
No setup, installed-code inspection, SSH connection, collector or private log reader
was run. The next input is the human-run fixed SSH ULF JSON, with agents closed for
collection. The used launchd kit and every older private capture remain untouched.

## 2026-11-03 — SSH ULF captured; comprehensive offline review prepared

The user supplied the fixed SSH ULF report: **38 retained rows**, readiness,
cleanup and execution binding PASS, ring_evicted false, native_shapes FAIL.
All source/message classifications remained empty. The original analyzer stops
at its first failed logEvent validation; those zeros are therefore not evidence
of absent SSH auth/session messages. No private capture, its metadata or raw
records have been opened by the agent in this turn.

Source inspection found the selector does not restrict eventType while the
analyzer assumes every retained entry is a logEvent. Non-log entries can poison
classification, as can genuine unsupported log shapes. The fixed report does not
identify the actual cause. No native codec or generation contract was relaxed.

A new offline-only reviewer diagnoses all log schema failures at once and counts
other entry kinds separately. Only known field names and coarse type/string/
integer-sentinel/object-key classes are returned. Unknown key names, validator
messages/input/context, observed values and native text never leave private
memory. It classifies the fully valid log subset with explicit subset counts and
LOG_EVENT_ROWS_ONLY scope; overall native_shapes stays FAIL if any actual log
entry fails. Non-log shapes are not silently qualified. Gate stays NOT_EVALUATED.

The reader validates frozen code/guard/marker/opt-in provenance and original
controls, re-proves the selected ES tree and all ULF PID/image/time bindings, and
checks original row counts before classifying. It executes no captured code,
starts no commands/collectors/apps/probes, queries no installed applications and
writes nothing. ES source sequence continuity comes from the original full-stream
control; it is not inferred from gaps in the deliberately filtered saved subset.
Original collection code, used private kits and production generator inputs are
unchanged.

All **261 selected routine tests** pass, including **20** new offline/provenance/
privacy tests. They cover all-field diagnostics, missing/null/numeric/unknown-field
failures, non-log separation, unknown-key suppression, tampered controls/tree/
counts, PID scope, symlinks, read-only file equality, no native/live operations and
fixed CLI exception output. A PEP-695 alias introspection issue in the first draft
was caught by these tests and corrected before preparation.

Code-only preparation created `/private/tmp/eforge-ssh-startup-kit-5vrzrmhy`, whose
entry point is `private_ssh_ulf_review.py`. The intended source is the existing
`/private/tmp/eforge-ssh-startup-kit-9pmp5kku`. No new collection is needed. The next
step requires explicit permission under the standing no-local-log-read rule;
silence is not permission. This reviewer covers the schema defects together,
rather than requesting one field at a time. No private input has yet been read.

## 2026-11-03 — Authorized SSH ULF review resolves the schema failure

The user authorized the prepared bounded offline reviewer. Its fixed output passes
provenance, original collection controls and execution binding: **38 retained rows,
17 valid ordinary logEvent rows, 21 activityCreateEvent rows, zero invalid ordinary
logs**. The production codec already accepts all 17 actual logs. The original
capture analyzer had applied its log-only schema to activity records and returned
before classifying the genuine logs. No production schema was relaxed.

Grouping the same fixed classifications establishes one accepted keyboard-interactive/
PAM authentication record: SESSION role, root writer, same main-image sender/UUID,
Info, empty subsystem/category, zero activity and parent activity. Trace, sender PC,
Mach time and thread are nonzero. Its callsite does not match the existing static
main-image profile. The other 16 messages remain unclassified; no PAM-open/close,
disconnect or session-completion template is qualified from them. Only fixed labels
were returned. Native values, unknown text/names, records and private identities
were neither displayed nor copied into Git. No collector, app, probe or live query
was started; the source capture was not changed.

The capture summary now separates ordinary-log/other/invalid/classified counts and
states LOG_EVENT_ROWS_ONLY. Activity-only input cannot pass ordinary-log shape;
invalid ordinary logs still fail the overall shape but cannot hide valid-subset
message counts. Version-1 saved summaries remain readable. Invented regression
inputs cover both defects and suppress unknown-field/text canaries.

The grouped reviewer additionally prepares public trace-header/known-format/range/
alignment/code-to-PC classifications without exporting numeric values. The public
Apple XNU layout and OpenSSH logger provide comparison candidates, not a substitute
for the private observation. A tested code-only version-3 reader is prepared at
`/private/tmp/eforge-ssh-ulf-review-e2cf_keq`, retaining the trusted old support and
expected hashes from the earlier code-only reader. It has NOT been run against the
capture. Separate permission is pending for the additional comparisons under the
standing local-log rule. No new collection is requested and no unknown source
profile is enabled merely to finish the phase.

All **267 selected routine privacy/reference checks** pass, including **24** offline
review tests and **22** ULF capture tests. Whole Ruff/format checks pass. Production
generation behavior remains revision 375; no unchanged generation or blind panel
was repeated. Expanded ULF and final acceptance remain incomplete. Launchd's
separate zero-row reference remains unqualified and unchanged.

## 2026-11-03 — PAM SSH authentication source implemented after approved review

The user explicitly approved version 3 of the same bounded offline reviewer. It
ran once against the authorized capture and returned only fixed labels. Provenance,
original controls and execution bindings PASS. The accepted authentication row has
log/Info agreement, MAIN_IMAGE PC style, PRIVATE_DATA as its only flag, static public
`%.500s`, bounded/aligned PC, absent source metadata and present backtrace. Dynamic
format is absent. This explains the earlier narrow-callsite mismatch. Native
text/identifiers/offsets/addresses/frame contents were not exposed, copied or committed.
No additional collector, app, command, probe, live query or unrelated log read occurred.

The bounded PAM-success source now shares the native receiver's existing successful-
authentication/audit-adoption occurrence. Its context freezes the actual root
sshd-session execution, SSH session, user and transport peer; its State cohort
requires the exact matching audit binding and session activity owner. eCAR retains
its process before/after roles and process-only collection requirements. ULF requires
process/authentication/session collection and renders the reference-qualified source
view. The producer supports either PTY mode for password intent. Public-key intent
cannot be misreported as PAM. No new authored event type or raw-message path exists.

The callsite has an explicit private-data flag, and the build profile supplies an
explicit synthetic main-image backtrace and offsets. These are modeled build facts,
not the private system's addresses, frame count or call stack. The profile models
observed visible Info collection; it does not claim every endpoint collector exposes
private arguments or persists Info messages. The emitter uses frozen native writer,
thread, image UUID and uptime; it neither allocates identities nor re-queries a PID.
Exact eCAR/ULF publication shares the retained startup journal, including filtered
output, post-commit source failure and lost-return recovery without duplicate auth.

The original seed-373 workload chooses password for non-PTY and public-key for PTY.
It therefore produces **three ULF records: two workspace entries and one PAM success**.
The initial four-row test expectation was corrected after inspecting the selected
canonical authentication policy; no source was changed to force another message.
A separate real-engine test verifies the same PAM source on a password-intent PTY.
SSH PAM-open/close, disconnect, public-key success and launchd ULF remain unqualified.
The sixteen other bound messages were not promoted or privately inspected further.

A broad Mac/contract run passed 4,607 tests and exposed 12 older fixture/expectation
failures. Every one reproduced on the pre-feature commit in an isolated tracked-code
snapshot. They concerned direct-test chronology/final delivery, historical terminal
profiles, fresh-app-only admission, now-supported in-window terminal starts, launchd
signing and integer entitlements. Tests now reflect those already implemented contracts;
production admission was not relaxed. A separate Chrome regression now recognizes the
two physical helper binaries serving three roles, retaining distinct role arguments
and shared generic-image identity. No blind assessment or metadata collection loop
was started. Final current-code measurement and checks follow below.

### Final revision-376 acceptance and remaining gates

The final source snapshot passes public generation and independent census checks:
primary 33 forks/39 execs, companion 45 forks/55 execs with 16 background execs,
zero aggregate births, no missing image/argument roles, no unrealized authored steps
or missing phases. Known native exits remain 13 per workload; unknown observations
remain 13/32. No unknown outcome was converted to success.

The combined public suspend/status/read-only-verify/exact-resume test passes with
all **22 deterministic files** equal to uninterrupted generation. Its native filter
now selects and compares **both ES and ULF**. Both bundles have three ULF rows, one
PAM success; the fixed seed's PTY is public-key, so a second PAM message would be
wrong. The final primary and companion authoritative evaluations pass their hard
gates at **88.9114295108** and **88.7090757677**, respectively (345/2,818 records).
Source profile, writer, peer, static-private header and modeled-frame checks pass.

Selected regression checks pass, including non-PTY/PTY password authentication,
public-key exclusion, peer mismatch rejection, eCAR process-only versus ULF auth
collection, missingness/filtering and post-commit lost-return recovery. The 12
reproduced stale regression expectations and Chrome helper-identity expectation
have been corrected without changing their production gates. The registry's
payload inventory gained the new typed context; the historical full path census
was not republished or passed off as a new architecture assessment.

Whole Ruff/format/diff/behavior checks pass. Revision 376 digest:
`95ff84e02b780af5f98a78f993b13273520c5871366b68e5feda2f1c3b23452a`.
Final synthetic bundles are `/private/tmp/eforge-macos-376-primary` and
`/private/tmp/eforge-macos-376-delivery/test_combined_macos_workstatio0/resumed`.
Only aggregate acceptance metadata is tracked; all generated/native records remain
outside Git. The scenario sources, seed, baseline and complete ES policy are unchanged.

The finite sequence is **not marked fully complete**. Remaining ULF requirements are
SSH session-open/close and launchd activation/completion; related public-key/PAM/
disconnect messages remain unqualified. Launchd's zero-row result is unchanged.
No new native collection is authorized or implicitly requested by passing these
engineering checks. Generic GUI/SSH final exit results remain explicit unknowns.
No new hidden catalog, helper-metadata or repeated blind-review phase was added.
No product release/version bump occurred.

## 2026-11-03 — Ordinary-verbosity SSH completion and plain-key authentication

The user chose to retain ordinary SSH daemon verbosity and leave VERBOSE session
messages gated. Public Apple OpenSSH source explains the distinction: accepted
methods share auth_log at Info and the same %.500s syslog callsite; session-start/
close messages are daemon VERBOSE, which an Info-enabled collector cannot itself
enable. Public PAM code does not establish a generic successful PAM-open Info row.
The reference note links each primary source. No private capture, native diagnostic
file or installed metadata was read, and no system configuration was changed.

The existing native-qualified envelope now supports a separate plain public-key
accepted message. Its method, key type and SHA256 fingerprint come from the shared
SSH owner. MacosSshAuthentication records public_source_same_logger for this
source-derived payload, separately from the locally observed PAM reference. The
producer reuses the root receiver's exact audit-adoption occurrence, peer/session
checks and retained eCAR/ULF publication journal. It does not derive an auth event
from ES rows. Missing/noncanonical key facts, certificates and historical frozen
PAM-only profiles cannot invent public-key output. No new authoring event or raw
message path was added.

A concrete shared fingerprint defect was fixed at the SSH client-identity owner:
43 independently drawn Base64 characters could have invalid final pad bits. The
owner now encodes 32 synthetic bytes canonically and supplies that same fingerprint
to all sources. Per-client/user/seed identity remains deterministic and target-
independent. No real key material is read or generated.

All **232 selected routine tests** pass: 161 native SSH/profile/projection/shared
realism checks, 51 receiver/syslog/behavior checks and 20 unchanged launchd-kit privacy
checks. Added coverage includes all three plain key types, malformed/missing keys,
source-basis separation, frozen PAM-only compatibility and public-key source lost-
return recovery without duplicate publication. The existing combined slow test
also passes: public suspension/status/read-only verification/exact resume agrees
with uninterrupted generation across **22 deterministic files**, and filtering
preserves identical ES and ULF bytes.

Final revision-377 public generation preserves scenario sources, complete ES policy,
seed 373, formats and baseline. Primary: **33 forks/39 execs**, 13 known native exits,
13 unknown observations. Recovery companion: **45/55**, 16 background execs, 13 known
exits, 32 unknown observations. Both pass the independent full-process census and
all required image/argument/authored-role checks. Each has **four ULF rows**: two
workspace entries, one PAM success and one plain-public-key success. Bounded
synthetic checks verify the root writer, same main image/UUID, peer, Info/static
format, zero activities and canonical public-key fingerprint. No new blind panel
was started. The prior revision-376 bounded review remains historical metadata.

One authoritative evaluation per final bundle verifies integrity and passes hard
gates: primary **88.9058446346** (346 records), companion **88.7088659642** (2,819).
Final synthetic roots are `/private/tmp/eforge-macos-377-primary` and
`/private/tmp/eforge-macos-377-delivery/test_combined_macos_workstatio0/resumed`.
Only aggregate measurements are tracked. Revision-377 surface digest:
`3008dfcd000f671f24256c492c8b113c62eb13ca88fa5cd28d3fed105702c7e8`.

Phase 2 is complete under its explicit bounded-outcome contract; unknown GUI/SSH
teardown is still unknown. Ordinary-verbosity accepted authentication is implemented.
**Launchd ULF is the remaining minimum-family evidence gate.** A fresh code-only
kit is prepared at `/private/tmp/eforge-ulf-launchd-kit-cpmhqa3_` with the already
code-tested category-or-message selector. Setup/capture have NOT run. The user has
been asked to run one bounded private test after closing agents. If still empty,
leave it gated; do not repeat collection for positivity, inspect the separate
launchd diagnostic file or invent templates. Final expanded ULF acceptance remains
incomplete pending that evidence. No additional metadata/assessment phase was added.
Tracked canonical skills and reference docs were updated, and ignored project-local
ChatGPT/Codex skill copies were regenerated. No product version was changed.

### Corrected launchd attempt: control failure and cleanup diagnosis

The user ran the corrected selector and supplied only its fixed version-2 report.
The own-process marker and collector cleanup PASS, but job activation, job removal
and temporary-file removal FAIL. Zero retained rows is therefore inconclusive;
it is not evidence that the tested launchd job produced no ULF. The original kit's
exact-label cleanup subsequently returned CONTROL with removal/file checks failing.
No agent read native records, queried the system job, ran sudo or started a probe.
The used kit remains unchanged and cleanup is unverified.

A concrete kit reporting defect was repaired: capture previously ignored the guard
exit and could print COMPLETE/NONE despite failed controls. Version 3 requires all
job success flags and zero exit, returns CONTROL/ERROR and CONTROL_INCOMPLETE on
failure, and retains only the guard's known literal failure labels. Unknown native
command output remains suppressed. Cleanup distinguishes a noninteractive cached-
sudo failure from guard/control failure. A cleanup-only --kit-root override validates
all original control hashes and invokes the original kit's exact-label guard; it
cannot run setup/capture/report on that root and reads no native records. The root
C guard and original kit's hash-bound code/binaries were not changed.

All **31 kit tests** pass, including activation/removal/file/unknown-status failures,
nonzero guard exit despite success-looking flags, cached-sudo rejection, unknown
output suppression and cleanup-only root routing. Whole Ruff/format/diff checks and
the revision-377 generation surface check pass. Production generation is unchanged;
the passing combined recovery/evaluations were not repeated for this diagnostic-only
fix. The SSH implementation is already pushed as d28f1f8c.

The user has been given one grouped cleanup command using the repository helper
against `/private/tmp/eforge-ulf-launchd-kit-cpmhqa3_`. It checks original controls
and cached sudo, then returns the exact guard failure classification. Its fixed
report is pending. No further collection is requested; keep the kit and do not
rerun setup/capture. The delivery gate stays open and the system cleanup status
must not be called successful until verified.

## 2026-11-03 — LOCATION_FAIL cleanup narrowed without native-log access

The user supplied the version-3 cleanup JSON: cached sudo PASS, original guard
LOCATION_FAIL, removal/files FAIL. Original control hashes passed before invocation.
Code inspection shows that this label rejects the exact root control directory or
recovery lease before removal. It includes missing-directory/lease cases and does
not itself prove resources remain. No agent inspected that directory, queried the
system job or read any native logs.

One grouped read-only check is implemented, instead of requesting individual mode,
owner or file values. It validates the original kit controls, compiles public C
code in a fresh temporary directory, and invokes only its new inspect mode. That
mode opens the exact nonce-owned directory and job.plist read-only, follows no leaf
symlinks, rejects unsafe owner/mode/type/linkage, and compares safe bytes only to the
existing generated public lease template. The original run/cleanup semantics and
used kit's binary/source/config are unchanged. The check also queries only the
exact generated system-service label, discarding stdout and classifying stderr
locally. Unknown error text, IDs, paths and service details are never returned.
Nonzero query exit is not absence: only the exact missing-service diagnostic qualifies.
ABSENCE_VERIFIED requires both directory absence and proven exact-service absence;
a matching owned lease remains distinct from cleanup success.

All 69 focused tests pass, including 38 new grouped-check tests and the 31 existing
kit tests. A compiled unprivileged harness exercises the C inspection function on
invented temporary files only, with synthetic root metadata; it never invokes the
real guard CLI, sudo, launchctl, a job or a collector. Missing/symlink/permission/
linkage/size/content cases and no-file-change assertions pass. Python tests mock all
native commands, suppress private canaries, reject incomplete/contradictory labels,
require exact service/domain absence and preserve original-kit records untouched.
C syntax checks also pass. The real grouped check has NOT been run by an agent.

The user has been given `check-cleanup --kit-root` for the same original
`/private/tmp/eforge-ulf-launchd-kit-cpmhqa3_`; its fixed JSON is pending. No additional
collection is requested and launchd ULF remains gated. Production generation remains
revision 377; passing recovery/evaluations are unchanged and are not repeated for
this diagnostic-only work. Only the test kit's control state needs human input now.

## 2026-11-03 — Test directory and exact service absence verified

The user supplied the grouped read-only check's fixed JSON: error NONE, original
controls PASS, cached sudo PASS, directory ABSENT, exact service ABSENT and
cleanup_state ABSENCE_VERIFIED. No native record files were opened, no collector
or job started, and original-kit files were unchanged. The lease comparisons are
correctly INCONCLUSIVE because the directory is absent. No agent repeated the
check, inspected the directory or queried launchd.

This closes the temporary-resource concern: no cleanup is needed. Keep the used
kit preserved. Earlier LOCATION_FAIL did not prove leftover resources. The report
does not identify why the original run's activation controls failed, and does not
qualify its zero rows as a valid native-source absence observation. No further
cleanup, capture, metadata query or assessment loop is requested.

Current reference/acceptance documents and aggregate results now distinguish the
verified resource absence from the still-open launchd ULF gate. Launchd process
starts/known exits remain covered by ES. Full-scope phase 3/4 acceptance remains
incomplete until a launchd ULF message/envelope is qualified; the family was not
silently dropped from the plan. Production code, scenario inputs, behavior
revision 377 and prior passing recovery/evaluation results are unchanged. This is
a documentation-only reconciliation; no generation or behavioral tests are rerun.

## 2026-11-03 — Collector-free activation check prepared

After asking what comes next, the user authorized continuing the finite sequence:
precise job-activation diagnostics, a private collector-free control test, then one
separate bounded ULF capture only if those controls pass. The original kit's verified
absence remains closed; no original private file or native log was opened or changed.

Version 4 has fixed stage/reason pairs for directory create/open/stat/validation,
lease path/create/write/close/validation, registration, activation, removal and file
removal. Coarse errno categories and command exit/signal/timeout/cancellation causes
are allowlisted; native strings, error numbers, paths, IDs and command output remain
suppressed. New configs explicitly select detailed-v1 guard operations. Legacy configs
retain run/cleanup, and the shared ES reference reader keeps its original literal
wire vocabulary. No used kit was updated and original root target restrictions,
content-verified recovery lease, deadlines and cancellation/watchdog rules remain.

The new one-shot self-test validates frozen controls and cached sudo, starts only
the exact guard with stdin PIPE held open through normal completion, waits for its
bounded literal output and reports all control outcomes. communicate() is deliberately
not used: its stdin close would cancel the guard. A timeout closes cancellation and
waits for the watchdog cleanup path, retaining uncertainty if it still does not exit.
Signals, partial flags, nonzero exit or unknown/duplicate output cannot pass. The
attempt marker precedes guard launch and prevents retry or later capture in that
kit. No collector, readiness marker, job query or native record read occurs.
Activation scope is explicitly LAUNCHCTL_ACKNOWLEDGEMENT, with native execution
NOT_COLLECTED and gate_status NOT_EVALUATED; this is not native ULF qualification.

All **161 related tests** pass, including **37 new activation-control tests** and the
124 existing launchd/reference/cleanup tests. A compiled C harness substitutes all
job/process/clock primitives, redirects guard paths to invented pytest files, and
supplies synthetic root metadata. It exercises creation, metadata, lease, registration,
activation, removal, timeout, cancellation, spawn, signal and clock failures without
sudo, launchctl, native jobs or real privileged paths. Legacy success bytes match;
the synthetic success path removes its own files. Python tests cover fresh setup/
hash/protocol selection without execution, pipe lifetime, deadlines, zero/nonzero/
signal recovery, one-shot rejection, privacy canaries and capture exclusion.
C syntax checks pass. Production generation remains revision 377 and its prior
exact recovery/evaluation results are unchanged; no generation or panel is repeated.

Code-only preparation created `/private/tmp/eforge-ulf-launchd-kit-st5dekg3`. No setup,
self-test, probe, job or collection has been run by an agent. The user has been given
setup followed by `self-test --private-run` as their normal user, with cached sudo
used only inside the guard. Its fixed JSON is pending; no capture command is currently
requested. Preserve failed kits. A passing test requires a distinct fresh kit before
any later native capture, and does not silently close the launchd ULF gate.
