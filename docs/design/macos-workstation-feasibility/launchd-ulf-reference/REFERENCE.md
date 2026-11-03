# Launchd ULF: controlled test, no qualifying rows

On 2026-11-03 the user supplied a fixed version-1 diagnostic report. The collector's
own-process marker, job activation, job removal, temporary-file removal and collector
cleanup all passed. The capture retained **zero** launchd rows. Native shapes,
writer/sender/subsystem and messages are therefore unobserved, not failed native
contracts. No private capture file was opened by the agent.

This establishes that the controlled job ran and cleanup succeeded. It does not
establish that launchd never writes to ULF, that every launchd row was observable,
or that the proposed spawn/completion message templates exist on this build.
The normal-user readiness marker establishes its own channel only.

The source review found a concrete selection limitation: version 1 matched the
generated label in `eventMessage` only. A structured `category` containing the label
could not pass either its OS predicate or its retention check. Version 2 checks
those same two fields at both boundaries, still requiring the launchd process and
nonce in the OS predicate and PID 1 plus `/sbin/launchd` at retention. Fixed counters
describe the match location; no observed category or message is exported. Invented
record tests cover each match location, unrelated input and foreign writers.

Separately, [Apple Developer Technical Support's daemon debugging guidance](https://developer.apple.com/forums/thread/791996)
points to `/var/log/com.apple.xpc.launchd/launchd.log` for deeper launchd diagnostics.
That is a distinct file source. It supports checking the collection-source assumption,
not asserting that this macOS 27 system has particular messages or no ULF output.
No local diagnostic file, its metadata, or a broader native stream was inspected.

The launchd ULF generation gate remains unpassed. No template is enabled from this
report, and no new native file source is silently added to the product scope.
There is no recommendation to repeat collection merely to obtain a positive result.
SSH ULF remains a separate planned family; launchd ES coverage is already implemented.
