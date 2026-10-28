# Private GUI launch reference kit

## Authority and stopping boundary

The user requested continued Mac evidence development after reviewing current ESF/ULF coverage.
The assessment cycle remains closed: no new panels or unrelated finding fixes are authorized
by this continuation. This slice prepares the next private Finder reference kit, synthetic tests
and a concrete human-run procedure. Agents may prepare code and compile without execution;
they must not run setup/capture/report on a real kit, start collectors/apps, read local native
logs or open private capture directories. Raw evidence stays outside every Git tree.

## Implemented experiment

The new `scripts/macos_gui_launch_reference.py` copies itself, a small AppKit probe, a bounded
root collector guard and instructions into a new owner-only temporary directory. `prepare`
does not compile or run anything. Human-only setup compiles/ad-hoc signs one regular app and
records code, executable, Info.plist, guard and native-codec digests. The same app executable is
used for a direct control and a subsequent human-attested Finder launch; there is no browser,
web server, download, quarantine manipulation, policy override or permission change.

The app snapshots its own audit identity, birth, parent/POSIX session/group, descriptors and
byte-preserved argv/environment at main entry before opening its own output file or window.
It shows a minimal two-second window, writes only private controlled files, and has an independent
eight-second watchdog. Main-entry observations are not presented as atomic kernel-exec facts.

The collector subscribes only to fork/exec/exit, discarding unrelated rows in memory. A bounded
transient fork ring is persisted only when an exact executable file object and matching audit
PID-version/birth establish the controlled exec's preceding fork. Exit admission requires that
same owned file object and full execution identity. There are no path-prefix or PID-only matches.
Readiness uses at most eight controlled exec/exit attempts. Separate readiness/control/Finder
deadlines are 10/8/30 seconds. The root guard stops on parent-pipe EOF and has a 55-second hard
limit with process-group termination/reap. Input/line/ring/retained-row bounds are explicit.

After collector cleanup, up to four queries classify the exact parent/responsible audit tokens
into fixed system-role labels. The helper uses `proc_pidpath_audittoken`, emits no native path,
enumerates no processes and never falls back to a reused PID. Offline report does not repeat
those live queries. Exited/inaccessible/unknown roles remain unavailable or OTHER. These limited
queries are disclosed in the procedure; they are human-only, not agent inspection authorization.

Reports contain only enumerated labels. Unknown v11 shapes, incomplete observations, vector/FD
differences and sequence gaps are diagnostic findings, not silently admitted generation facts.
The report always retains `reference_review: REQUIRED` and `gate_status: NOT_EVALUATED`.
No generator, schema, codec, active source profile, product version or behavior revision changes.

## Scope after the human report

Finder-only evidence may inform a bounded canonical launch/responsibility contract after review.
Do not extrapolate this ad-hoc non-sandboxed test app to Dock/Spotlight, Apple Terminal, arbitrary
vendor signing/entitlement classes, helpers, other Mac targets, or Unified Log app messages.
No previous audit-origin, SSH descriptor, exec/exit or kernel-refusal experiment needs repeating.

Public API qualification uses Apple's [libproc declarations](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.h)
and [process-info structures](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h).
They define the API boundary; only the future private test can establish the actual GUI relationships.

## Verification and handoff

All 96 new invented-input checks pass, including fixed-output canaries, exact file/lifetime
matching, delayed fork admission, nonblocking stream persistence, source bounds, malformed input,
private file protections, code/codec provenance, mock capture cancellation, cleanup failure and
offline review. The entire adjacent private-reference selection passes **744 tests**. Its tests
block native subprocess execution unless explicitly replaced with invented mocks. Both native
sources pass `clang -fsyntax-only -Wall -Wextra -Werror` (Objective-C also uses ARC); neither was
executed. Full Ruff, formatting, whitespace and the unchanged revision-344 behavior check pass.
No broad generation/evaluation or blind assessment run is needed for this code-only kit change.

Prepared code-only copy: `/private/tmp/eforge-gui-launch-kit-kzex70ik`. Its isolated `-I -B --help`
entry point works with the existing checkout venv. At handoff it contains only sources and
instructions: no compiled app, collection, role lookup or private result. Once the human uses
it, agents must not inspect that directory or run its human commands without new explicit
authorization. The detailed procedure is `gui-launch-reference/PRIVATE-RUN.md`; setup builds
without launching, capture runs a direct control then waits for manual Finder launch, and report
reopens the latest private run without asking for a path. Only its fixed report should be shared.

## Human-reported Finder result and offline follow-up

On October 28 the human shared the fixed version-1 diagnostic only. Collection, sequence,
provenance, cleanup, native v11 shapes, app identity/image, before/after exec identity transition,
audit identity, argv, descriptor inventory, known completion/exit, parent and POSIX comparisons
pass for both launches. The Finder app's parent role is LAUNCHD, original parent equals current
parent, and responsibility is SELF. Standard streams are VNODE/no tty; main-entry access is
READ / READ_WRITE / READ_WRITE. The control has OTHER parent/responsibility and all three
standard descriptors READ_WRITE. The Finder fork check is inconclusive; the control fork passes.
Both exact environment comparisons fail. No ULF or other launch method was collected.

The [bounded relationship contract](../design/macos-workstation-feasibility/gui-launch-reference/finder-relationship-contract.md)
separates those observations from unknown backing vnodes, exec-versus-main environment state,
spawn/fork admission, other signing classes and additional launch methods. A missing retained
fork does not establish its absence or a specific collector failure. No native facts were read
by agents and no generation scope was promoted.

Added human-only `review-existing --private-run` to a new prepared copy. It asks for the original
outer kit at a hidden interactive prompt (no echo fallback), validates its unchanged code/app/
guard/plist/codec/provenance, and reads only that run's bounded controlled rows and own snapshots.
It runs no subprocess/preflight/role query, writes nothing and needs no repeat collection.
Fixed supplemental labels distinguish reordering, additions/removals and common-value changes,
including duplicate-assignment structure. Only the known technical CF text-encoding variable
gets a dedicated presence/change label, with no value output. The native control vector is
checked against the declared clean input; main-entry state is never silently substituted.
Failed original collection controls leave comparisons inconclusive. Neither report admits a
generation gate automatically.

The new checks use invented inputs only and prevent native execution. All **134 GUI reference
tests** and the full adjacent **782 private-reference tests** pass. Full Ruff, formatting,
whitespace and unchanged revision-344 behavior checks pass. Existing original kit
`/private/tmp/eforge-gui-launch-kit-kzex70ik` is now private and was not opened or modified.
New code-only reviewer: `/private/tmp/eforge-gui-launch-kit-6ak0i0c1`. Its isolated `-I -B --help`
entry point passes; no human command was run by an agent. The exact human command is provided
in the chat handoff. The next human action is this offline supplemental review, not setup/capture
or another experiment. Once used privately, this new directory inherits the same no-inspection
boundary as the original kit.

## Supplemental result and canonical relationship producer

The human shared version-1 `GUI_ENVIRONMENT_AND_FORK_DIAGNOSTIC` labels. Provenance and original
controls pass. The control's native vector exactly matches the declared clean input; only the
known CF text-encoding variable is added by main entry. Finder changes values under existing
names, with unchanged duplicate structure and unchanged CF text encoding. No private variable
names or values are necessary to distinguish these observation times, and none were requested
or read. Control has RETAINED_MATCH fork evidence; Finder has NOT_RETAINED, with no claim that
no fork happened. The original environment FAIL labels are not grounds to discard native exec.

Implemented a bounded internal `macos_launch_kind="finder"` intent through the existing canonical
process action owner. It requires a fresh literal regular-app bundle executable, exact live
launchd PID 1, the selected relationship profile and a current authenticated local Type-2 GUI
session. The producer consumes that exact audit origin and explicit no-other-responsible
lifetime, represented as self when native projection is otherwise complete. A missing/legacy
profile, unknown credentials, wrong parent, expired session or foreign audit origin rejects
before allocation. Generic user/system launches retain their previous semantics. The intent
participates in stable action identity, normal state publication and exact state checkpoint
round trip; it uses no emitter repair or host inspection.

This slice intentionally retains aggregate birth semantics and no native fork/exec phase. It
does not reconstruct environment/cwd, infer script or image-validation results, manufacture
descriptor objects, or treat non-TTY stdio as proof of controlling-terminal absence. Existing
explicit POSIX session planning is a model choice, not a calibrated Finder default. There is
no authored scenario/Studio launch-method field and no automatic Finder classification for
generic GUI, Terminal, browser or vendor/helper launches. Behavior revision 345 records the
new explicit relationship producer; no product version changes.

### Completing the reference without new collection

The first fixed report omitted several distinctions already present in the controlled native
records: the process-field image before exec, PID/session/group relationships, controlling tty,
cwd category, native FD extent, dyld path, slice/script/entitlement shape and signature agreement.
Those matter to the next canonical birth-to-exec contract; native-versus-own agreement alone
does not answer them. The version-2 offline supplement classifies them with fixed labels only.
It retains the original code/app/codec/provenance checks, reads the same bounded files, writes
nothing and starts no subprocess, app, role lookup or collector. No names, identifiers, counts,
flag/signature values, paths or vectors are exported. It does not claim an unobserved fork or
automatically close a generation gate. No original or used reviewer directory was opened by
an agent. The human should run this next offline classification, without setup/capture.

### Verification and next handoff

Focused selections pass 21 Finder intent/engine/state/legacy-profile checks, all 797
private-reference checks, 19 process-parent preflight, 24 process-state and 23 behavior-manifest
checks. The adjacent GUI-audit/metadata selection also passed (53 tests).
Full Ruff/format, whitespace, all 99 config files (zero findings) and the revision-345 digest/base
comparison pass. No full generation, assessment panel, live collection or native-file inspection
was performed. Native codec and capture/probe code remain unchanged.

Prepared version-2 code-only reviewer: `/private/tmp/eforge-gui-launch-kit-lp8zhuj8`. The isolated
`-I -B --help` check passes; agents ran no human command. The human's next command is
`review-existing --private-run` in this new copy, with the original outer kit selected at the
hidden prompt. It does not use either reviewer copy as the original capture root. The original
kit and previously used reviewer remain untouched and private. Only the resulting fixed JSON
should be shared; no repeat Finder launch or disclosure of changed environment keys is needed.
