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
