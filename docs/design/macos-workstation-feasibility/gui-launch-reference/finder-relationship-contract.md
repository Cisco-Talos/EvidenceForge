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

The Finder report supports a launchd-parent/self-responsibility/no-tty relationship for this
experiment. It does not identify the vnode backing each stream, establish that they are all
`/dev/null`, or prove descriptor access flags were unchanged before main. The reported audit
comparison binds this app's native exec to its own snapshot; it is not a new comparison with
every process in the GUI login session.

## Remaining distinctions

The environment failure is an exact vector comparison across two observation times. Order,
startup mutation or another mismatch can fail it. The offline `review-existing` supplement
classifies those differences without exporting arbitrary names or values, changing evidence,
launching apps or collecting again. Until reviewed, do not substitute main-entry environment
for the kernel exec input or attribute the difference to a particular startup component.

An inconclusive fork means no matching fork was retained. The bounded transient buffer and
matching rules cannot establish why. Do not invent a native fork for the Finder launch, claim
that all Finder launches lack one, or call the finding a collector drop. Any future spawn
admission must carry its own canonical birth/exec proof rather than borrowing fork authority.

No Unified Log was collected. This reference supplies no LaunchServices/runningboard message
templates and no native GUI ULF lifecycle. Dock, Spotlight, other app/signing/entitlement classes
and other OS targets remain outside it. A normal app exit also supplies no evidence about
crash, force-quit, background helper or long-running GUI lifecycle behavior.

## Implementation order after the supplemental review

1. Resolve the environment comparison using the existing private capture's fixed supplemental
   labels; keep exec-time metadata distinct from later process state.
2. Add an explicit Finder launch intent through the canonical process action owner. Model the
   launchd parent, exact audit origin and self responsibility only in that qualified intent;
   do not change every generic user process or shell launch.
3. Establish a birth-to-exec admission contract that does not assert an unobserved fork. Supply
   remaining descriptor backing, input-vector, image-security and terminal-outcome facts from
   explicit modeled contracts or qualified references, leaving unknown facts unadmitted.
4. Render via existing native ES ingress/publication, then verify normalized/native identity,
   ordering, lifecycle, source filtering and exact checkpoint recovery. Add a bounded authored
   and baseline acceptance case; a new blind panel is not required for every implementation slice.

The current engine and generation behavior are unchanged by this reference/reviewer work.
The fixed report deliberately retains `reference_review: REQUIRED` and `gate_status: NOT_EVALUATED`.
