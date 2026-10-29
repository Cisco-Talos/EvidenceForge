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
