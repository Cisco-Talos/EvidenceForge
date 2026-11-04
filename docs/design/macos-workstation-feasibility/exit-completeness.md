# Mac process-exit completeness

The November 4 request is to repair exit completeness without new private collection
unless a specific remaining behavior needs evidence. Process-start acceptance remains
separate. No PR into dev is authorized yet.

## Reconciled starting point

An instrumented revision-381 replay preserved the authored/resolved inputs and produced
byte-identical `data/` to the accepted MacOS-test run. Instrumentation observed only
synthetic objects in the deterministic engine; it ran no commands from the scenario,
collectors, apps, probes, installed-code inspections or private-log readers.

| Canonical in-window termination family | Count | Initial state |
| --- | ---: | --- |
| Known completed outcomes | 42 | Native exits present |
| Natural bounded commands | 89 | Unspecified results or missing natural-completion handoff |
| Generic session logoff | 55 | End times exist; termination causes/results unspecified |
| SSH client close | 1 | Result unspecified |
| Exact SSH receiver/descendant close | 13 | Compound auth/process occurrences bypass native accounting |
| **Total** | **200** | **42 known, 158 unresolved in-window exits** |

The previous reported 147 unknown observations include two warmup exits outside the
collection window and omit the thirteen compound SSH closes. Thus the net eCAR/ES
count difference was eleven. This is an accounting defect, not thirteen newly discovered
process starts. Every eCAR process object joins to its exact retained synthetic identity.
The detailed inventory stays outside Git under the existing November 4 trial root.

The 89 natural commands are 55 Apple discovery/file queries, 32 Homebrew database
queries and two Homebrew HEAD requests. Twenty-three database completions are retimed
after process-owned work. Their natural-completion owner must resolve that work before
requesting an exit; later termination clamps cannot independently certify completion.

## Implementation boundary

Natural query results are explicit selected nominal simulation outcomes, qualified by
exact invocation/template, deployed image identity, natural-completion ownership and
untruncated timing. They are not inferred from successful exec or TCP establishment.
Unknown, held, truncated and unsupported invocations retain unknown outcomes. Templates
bind home to the modeled account and retain literal argv, including the find pattern.

Exact Mac SSH exits must be pure canonical process occurrences, with authenticated
session ownership retained in the identity plan and the existing exact publication/
recovery journal. Logout is separate. Native source admission must account for these
exits even while the result is unknown. Window classification precedes missing-result
classification.

The independent bounded State census counts all actual in-window terminal transitions
and the subset with known outcomes before source qualification. Native receipts reconcile
all exit observations and known output separately. Complete start collection must reject
missing exit observations or lost known outcomes. Unknown results remain visible and
`exit_complete: false`; they do not silently become successful exits. A process alive
past collection has no in-window termination obligation. Legacy census records have
unknown exit history rather than fabricated zero counts.

## Remaining shutdown-model choice

After natural command repair, the inventory identifies 69 shutdown observations:
47 GUI application/helper closes, seven shells, three login processes, eight SSH server
workers, three still-active curl commands and one SSH client. Existing code chooses
closure times without declaring how each process actually ends.

A concrete way to finish without empirical collection is an explicit ordinary-close
simulation profile: orderly GUI quits, shell logout after completed work, and a named
SSH close path with separately selected worker/client results. Interrupted work needs
an explicit cancellation/termination result rather than success. These would be declared
model choices; they must not be described as measured macOS 27 automatic-logoff behavior.

Alternatively, retain unknown shutdown results until a bounded native reference qualifies
the desired automatic teardown behavior. Existing captures may help, but require separate
permission for an offline fixed-output review. No such review or new collection is
currently authorized by this document.

The existing reviewed SSH reference explicitly reports final server-worker exit 255
while the controlled client/marker exit zero. It cannot supply a universal success or
failure default. Apple's public source also has distinct normal and error paths. AppKit
permits applications to delay/cancel termination, so a quit request alone is not a
completed exit. These are reasons to require a declared shutdown path.

Primary references: [reviewed SSH findings](ssh-startup-reference/REFERENCE.md),
[Apple sshd-session normal/error paths](https://github.com/apple-oss-distributions/OpenSSH/blob/main/openssh/sshd-session.c),
[Apple monitor result handling](https://github.com/apple-oss-distributions/OpenSSH/blob/main/openssh/monitor.c),
[AppKit termination response](https://developer.apple.com/documentation/appkit/nsapplicationdelegate/applicationshouldterminate(_:)).

## Acceptance and stopping rule

Preserve the unchanged MacOS-test workload, start census and exact eCAR/ES joins.
Require exact exit accounting, correct final execution identity, normal/signal status
agreement, no duplicate exits and no collection-cutoff exits. Exercise filtered output
and checkpoint recovery. Regenerate once and evaluate once after the independent fixes.
Classify any remaining unknowns against the fixed inventory; request only the specific
model decision or evidence needed. Do not broaden catalogs or repeat a blind panel.
