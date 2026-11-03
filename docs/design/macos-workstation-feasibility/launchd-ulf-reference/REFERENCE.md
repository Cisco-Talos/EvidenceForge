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

## Corrected-selector attempt: job controls did not pass

The user supplied the version-2 category-or-message report from
`/private/tmp/eforge-ulf-launchd-kit-cpmhqa3_`. The own-process marker and collector
cleanup pass, but activation, job removal and temporary-file removal FAIL. Zero
rows in this attempt cannot establish launchd source visibility: the controlled
job's execution was not established. The original exact-label cleanup command also
returned CONTROL with removal/file checks failing. Preserve the kit; cleanup is
unverified. No agent opened this kit's records or queried its system job.

This exposed a concrete diagnostic reporting defect: capture reported COMPLETE/NONE
without requiring successful job controls or a zero guard exit. Version 3 reports
CONTROL/ERROR and CONTROL_INCOMPLETE for these cases, retains only the compiled
guard's public literal failure labels, and checks the guard's exit. Unknown command
output remains suppressed. A read-only cached-sudo preflight and grouped cleanup
labels distinguish credential, control and guard failures without revealing native
command output. The corrected cleanup entry point can validate the original kit's
control hashes and invoke its original guard via an explicit cleanup-only root
override. It cannot reuse capture or start a new job, and reads no native records.

The user has been asked to run that cleanup diagnostic only. No further collection
is requested, and the used kit and its hash-bound files are unchanged. The ordinary
verbosity SSH auth source is implemented separately; this launchd attempt does not
invalidate its process or authentication acceptance.
