# Finder relationship reference: macOS 27 arm64

Source: the human-shared version-1 fixed `GUI_LAUNCH_RELATIONSHIP_DIAGNOSTIC` report on
2026-10-28. No native records, process identifiers, environment values, paths or capture files
were reviewed by agents or copied into this repository. This is a successful local launch of
one ad-hoc-signed, non-sandboxed controlled AppKit app, not a Gatekeeper policy experiment.

## Established observations

The reported collection/provenance/readiness/cleanup/bounds/sequence checks pass under v11.
Both direct control and Finder have one native exec and exit, matching the controlled app's
own identity/image, audit identity, argument vector, descriptor inventory and known zero exit.
The before/after exec PID and birth agree while the execution identity transitions. Parent
and POSIX session/group agreement also pass.

| Relationship | Direct command control | Human-attested Finder |
| --- | --- | --- |
| Parent image classification | OTHER | LAUNCHD |
| Original parent versus current parent | SAME_AS_PARENT | SAME_AS_PARENT |
| Responsible identity | OTHER | SELF |
| Responsible image classification | OTHER | SELF |
| Standard descriptor kinds | VNODE / VNODE / VNODE | VNODE / VNODE / VNODE |
| Standard descriptor access at main entry | READ_WRITE / READ_WRITE / READ_WRITE | READ / READ_WRITE / READ_WRITE |
| Standard streams with a tty | NONE | NONE |
| Matching retained fork | PASS | INCONCLUSIVE |
| Exec environment versus main-entry snapshot | FAIL | FAIL |

The Finder report supports a launchd-parent/self-responsibility/no-tty-on-stdio relationship for this
experiment. It does not identify the vnode backing each stream, establish that they are all
`/dev/null`, or prove descriptor access flags were unchanged before main. The reported audit
comparison binds this app's native exec to its own snapshot; it is not a new comparison with
every process in the GUI login session.

The human subsequently shared the version-1 offline supplement. Provenance and original
collection controls pass. The direct control's native environment matches its declared clean
input, and only `__CF_USER_TEXT_ENCODING` is added by main entry. Finder has changes to values
under existing names, with unchanged duplicate structure and CF text encoding. No names or
values from that vector are needed or requested. These observations distinguish exec inputs
from later process state; they do not invalidate the native exec vector or establish the
component responsible for Finder's value changes. Fork labels remain RETAINED_MATCH for the
control and NOT_RETAINED for Finder.

The version-2 supplement identifies the Finder message's pre-exec image as XPCPROXY. Parent
PID and its audit token identify boot PID 1; parentage and POSIX credentials are preserved.
Audit origin changes across exec. The target's session ID equals its parent's PID, its group ID
equals its own PID, and membership changes across exec. Both Finder snapshots lack a controlling
tty. Only standard descriptors are present, native extent is 2, cwd is untruncated root, script
is absent, slice is generic arm64, entitlements are null and dyld path matches the target. The
target signature matches the direct control and differs from the pre-exec image/file object.
PID and birth stay the same while audit PID version changes: this is image replacement within
one lifetime, not a new app child beneath xpcproxy.

The control demonstrates why stdio and controlling tty stay separate: its non-TTY standard
vnodes coexist with a controlling tty in both process snapshots. Its audit and POSIX memberships
remain unchanged. Finder's comparison FAIL labels describe differences across exec, while
original collection/provenance controls remain PASS.

## Remaining distinctions

Do not substitute main-entry environment for the kernel exec input or attribute the difference
to a particular startup component. The reviewed supplemental classes resolve the diagnostic
ambiguity needed for this distinction; identifying private changed variables is unnecessary.

An inconclusive fork means no matching fork was retained. The bounded transient buffer and
matching rules cannot establish why. Do not invent a native fork for the Finder launch, claim
that all Finder launches lack one, or call the finding a collector drop. Any future spawn
admission must carry its own canonical birth/exec proof rather than borrowing fork authority.

No Unified Log was collected. This reference supplies no LaunchServices/runningboard message
templates and no native GUI ULF lifecycle. Dock, Spotlight, other app/signing/entitlement classes
and other OS targets remain outside it. A normal app exit also supplies no evidence about
crash, force-quit, background helper or long-running GUI lifecycle behavior.

The original fixed report's POSIX comparison checks native-versus-own agreement, not whether
the PID is a session/group leader. Its stdio tty labels do not establish controlling-terminal
absence. Version 2 of the offline reviewer classifies those already captured relationships,
the message process's image relative to the test app/launchd, cwd category, native FD extent,
script/slice/entitlement shape and signature agreement. It exposes no raw identifiers, flag
values, paths or vectors and needs no repeat collection.

Version 3 additionally classifies the launcher's audit user/session, responsibility and
individual session/group relationships. Version 2 establishes differences, not whether the
launcher's prior audit origin was default/unattributed or already associated with an account or
session. A complete launcher producer needs those classes. The checker uses the same existing
capture and exports fixed relationships only, without numeric values or new collection.

The human's version-3 result now establishes an unattributed preimage audit user with a
nonzero audit session distinct from the target's; preimage SID and PGID both identify the
parent PID. Its responsible token has the same PID as the controlled process but matches
neither full before nor full target token. That result does not establish a different process
lifetime or identify which credential/version fields differ. Version 4 compares each of the
eight predefined token fields with both snapshots, with fixed labels only; numerical version
position is reported only for the controlled PID and does not assert temporal order. This
uses the existing capture, with no new collection, live query, native values or extra keys.

The human's version-4 report resolves that ambiguity. The preimage responsibility token keeps
the before snapshot's audit user, nonzero audit session, PID and PID version; its effective and
real UID/GID words are all zero. The target responsibility token equals the complete target
audit token. Both process snapshots themselves retain the user's POSIX credentials. The
responsibility export therefore must not be modeled by changing the actual launcher to root,
inventing a third process lifetime, or substituting the target's token into the preimage. These
relationships establish neither the sampling time nor the mechanism that produced the token.
No additional collection or field classification is needed for this distinction.

## Canonical relationship implementation

Generation behavior revision 345 adds an internal explicit `macos_launch_kind="finder"` process
intent. It requires literal app-bundle argv, exact parent PID 1 and a qualified current profile.
The relationship producer resolves the live canonical launchd lifetime and authenticated local
Type-2 GUI session, consumes its exact audit credentials and sets explicit no-other-responsible
lifetime (projected as SELF when a complete native snapshot is admitted). Foreign audit origins,
missing/legacy policies, expired sessions and wrong parents fail before process allocation.

This is connected to the existing process action owner, state planning and checkpoint codec.
Generic user/system launches are unchanged. The Finder selector supplies no environment, cwd,
script, image-validation result, descriptor objects or controlling tty from these relationship
observations. The existing planner's explicit POSIX launch choice remains a modeled choice, not
a measured Finder default. This slice preserves aggregate birth semantics and does not publish
a native fork or manufacture an exec epoch. It adds no authored scenario/Studio launch-method
field and automatically classifies no installed app as Finder-launched.

Generation behavior revision 346 adds authenticated GUI exec adoption for an already live
canonical xpcproxy launcher. Its exact active local GUI session supplies audit origin; POSIX
credentials remain unchanged, the boot POSIX session is retained, a new own process group is
created and responsibility becomes explicitly self. Ordinary exec retains its existing rules.
The session authority is bound into the sealed cohort and exact projection, including indexed
group counts, prior snapshots, rollback and checkpoint history. No separate synthetic audit-bind,
setpgid or fork observation is emitted for this single exec.

The metadata producer requires explicit kernel-exec environment/cwd for this path and retains
existing binary/signing/descriptor gates. Missing launcher/exec facts yield unavailable native
coverage instead of fabricated fields. Complete invented inputs verify v11 publication, source
filtering and interrupted-write recovery. Their pre-exec values are selected fixture facts,
not recovered private values. The complete authored/baseline launcher producer remains separate;
no GUI Unified Log template or broader app/signing/entitlement class is admitted here.

Generation behavior revision 348 represents the preimage token as a separate immutable Mac
source observation, selected only while preparing the exact State-authenticated GUI exec.
It preserves the old audit pair/PID/PID version and supplies the four observed zero credential
words. The canonical process, parent and ownership facts remain intact. Target and exit records,
ordinary execs and live process snapshots retain their existing full-token mapping. Runtime and
installed-file preparation use the same observation boundary; historical profiles cannot borrow
this v11 sampling rule. Missing or unreviewed GUI token facts remain unavailable native phases.
Invented IDs with a nonzero anonymous preimage audit session verify this shape, recovery and
checkpoint restoration. The human's used v4 reviewer is private and was not opened by agents.

Apple's [spawn implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
supports audit-session port actions and process-group changes with image activation. Its
[process-group API](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/posix_spawnattr_setpgroup.3.html)
defines the new-group option. These mechanisms support the modeled transition, without proving
the exact userspace calls, flags or unretained callbacks in the private experiment.

## Implementation order after the supplemental review

1. Completed: distinguish native exec environment from later state using the human-shared
   supplemental classes, without collecting or disclosing changed variable names/values.
2. Completed: add the bounded canonical relationship intent described above.
3. Establish a birth-to-exec admission contract that does not assert an unobserved fork. Supply
   remaining descriptor backing, input-vector, image-security and terminal-outcome facts from
   explicit modeled contracts or qualified references, leaving unknown facts unadmitted.
4. Render via existing native ES ingress/publication, then verify normalized/native identity,
   ordering, lifecycle, source filtering and exact checkpoint recovery. Add a bounded authored
   and baseline acceptance case; a new blind panel is not required for every implementation slice.

The fixed report deliberately retains `reference_review: REQUIRED` and `gate_status: NOT_EVALUATED`.

## October 30 launcher-chain capture

The human's marker-free version-2 collection completed with provenance, readiness, cleanup,
bounded delivery and sequence continuity passing under v11. Control and Finder app exec/exit
shapes, image/identity/argv/descriptor comparisons and zero terminal status pass again. Finder
retains the launchd parent and self-responsibility relationship. Environment comparisons differ
from main entry, as in the earlier reference; no private variables are requested to explain
their names or values. The probe's exec entitlements are null.

No preceding launcher exec was retained. Its linkage, first-image/security/argument/environment
and fork facts therefore remain inconclusive. This does not close first-xpcproxy admission,
prove an absent first exec/fork, qualify populated entitlements or supply GUI Unified Log.
Reviewing the collector found that its launcher ring was limited to Finder phase; a matching
prefix observed earlier in the same stream would be lost. The corrected ring spans all three
bounded phases with the identical full-token, lifetime, native-file and code-identity retention
proof. Its bounds and prohibition on writing unrelated candidates remain unchanged. That code
finding is a possible explanation, not an attribution of this capture's missing prefix.

Version 5 of the offline supplement accepts an unchanged launcher-chain kit, selects the exact
retained app phases for comparison and classifies its preimage lifetime relative to the control.
It preserves missing-prefix uncertainty and cannot recover discarded candidates or establish
the precise collection-subscription boundary. No new collection is required for this supplement.

The next human-run capture completed with the same app/control passes and returned
`candidate_selection: TOKEN_MISMATCH`, with no candidate-ring eviction. This establishes that
the filter saw an xpcproxy candidate with the same PID, PID version and birth time, then
rejected it before comparing its file/code identity because one or more credential/audit
words differed. It does not establish which words differed or prove the later image check
would have passed. The rejected raw candidate was never persisted and cannot be recovered.

The collector now separates execution identity from mutable credential snapshots. It retains
only a unique earlier candidate with matching PID, PID version, birth, native file device/inode,
cdhash and signing/team identity, with both untruncated xpcproxy paths and the expected signing
identifier. Per-field token agreement is exported separately as fixed checks. This follows
Apple's PID/version process lookup and current-credential token construction; see the
[retention procedure and references](LAUNCH-CHAIN.md). No PID-only join, additional ambient
retention or production admission was introduced. Actual first-exec facts still require a
new human-run capture with the corrected filter.
