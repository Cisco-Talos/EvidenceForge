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
