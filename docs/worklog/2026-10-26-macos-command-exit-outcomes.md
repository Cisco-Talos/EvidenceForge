# macOS command completion outcomes

## Scope and reference boundary

The user authorized the next producer milestone after SSH descriptors. The earlier human-run
private capture already passed controlled normal/signal wait-status agreement, fork/exec/exit
linkage, failed-exec controls, delivery and sequence checks. The reviewed v11 shape diagnostic
also passed the exit payload. That evidence is sufficient for the bounded result encoding;
there is no reason to repeat that collection for this implementation.

No private directory, native record, report file or local log was inspected by the agent. No
collector, probe, SSH connection or private reviewer was run. Only invented tests and their
synthetic outputs are used. No captured data belongs in Git, including ignored directories.

## Canonical producer

Revision 336 adds an optional explicit `PosixProcessExit` to the ordinary process-termination
request. It requires the exact expected live execution; a stale/replaced identity fails before
mutation. The process occurrence and authenticated State termination share that result through
the existing lifecycle/artifact/native publication journal. Normal nonzero and completed signal
results are separate from launch success, signal requests and unload intent. No new scenario
field or event family is introduced, and existing callers retain an unknown result by default.

The frozen Mac execution policy declares a small `command_completions` list. Its current exact
argv vectors are `/usr/bin/id`, `/usr/bin/sw_vers`, and `/usr/bin/sw_vers -productVersion`, with
nominal exit code zero. These are explicit synthetic workload choices, not measured failure
rates or a claim that a matching real command always succeeds. There is no basename, substring,
display-command or generic successful-exec fallback. Unknown or additional arguments do not
match; older frozen profiles omit the list and preserve unknown outcomes.

Only natural bounded completion owners request this policy: the foreground/due finalizers and
the immediate/deferred authored-command completion paths. The producer requires a first real
exec, literal argv, known script absence, the modeled account and matching exact installed
content. Runtime replacements, later execs and unknown metadata do not borrow a nominal result.
Session teardown does not request this policy; a close moved by a deadline or connection hold
does not acquire it. Native exit rows still require all other qualified process metadata.

Deferred authored completion retains process lifetime/execution IDs in its existing queue.
A reused PID cannot receive an older command's result; a later execution in the same lifetime
leaves the result unknown. Old queue entries keep their previous unknown-result behavior.
The existing engine/foreground/State checkpoint owners retain the necessary fields; there is no
new outcome registry, process forecast table or checkpoint record type. Existing terminal-result
serialization preserves known outcomes after termination.

## Related closure correction

The new real-engine finalizer test exposed an existing admission check comparing immutable
lifecycle birth image against current State image after fork/exec. Foreground close admission
now compares the birth image with the retained lifetime image and checks the current runtime
image and execution ordinal independently. It does the same for compatibility child checks.
This preserves exact owner validation without rejecting a valid shell-to-utility exec.

## Verification

Tests use invented inputs only. They cover selected/filtered native output, natural completion,
unknown/truncated/legacy results, explicit nonzero and signal results, stale execution rejection,
native write interruption before/after commit, exact retry/counter stability, State outcome
recovery, existing engine/finalizer checkpoint recovery, and literal policy validation.

The broad Mac/State/checkpoint sweep passed 3,359 checks. Its two failures were in the new
recovery test fixture, which needed the same empty DHCP state initialized by normal engine
setup; that fixture was corrected and both cases pass. The final focused command/shared-process/
manifest selection passes all 221 checks, and the two added malformed-deferred-owner cases pass.
All 26 new routine cases pass, with one additional slow fresh-process byte-equivalence case.
The selected 13 slow SSH, filtering, CLI and fresh-process contracts pass without coverage.
An overlong behavior-history summary initially prevented seven CLI checks from starting;
shortening it restored those checks without changing generation. No full release, coverage or
soak gate is claimed.

Full Ruff check and formatting pass (1,342 files); revision 336's behavior digest and whitespace
checks pass. Canonical Mac skill references were regenerated into the ignored project install.

## Remaining boundary

This completes the bounded ordinary exit producer, not universal process outcome knowledge.
Unlisted invocations, SSH helper teardown and other unspecified closes remain unknown. GUI
responsible-process relationships, PTY command generation and helper FD inventories are still
separate coverage limits. Native Gatekeeper denial remains a distinct human-evidence gate;
neither nominal completion policy nor a completed signal result establishes a Gatekeeper denial.
