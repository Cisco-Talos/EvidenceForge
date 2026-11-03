# Launchd ULF: controlled test, no qualifying rows

**Current cleanup status:** the human-run grouped check verified both the test
directory and exact system service ABSENT on 2026-11-03. No cleanup is needed.
Launchd ULF remains unqualified; verified absence does not establish job activation
or native log visibility in the failed attempt.

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
Ordinary-verbosity SSH accepted-authentication ULF is implemented separately;
launchd ES coverage is already implemented.

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
output remains suppressed. A noninteractive cached-sudo check and grouped cleanup
labels distinguish credential, control and guard failures without revealing native
command output. The corrected cleanup entry point can validate the original kit's
control hashes and invoke its original guard via an explicit cleanup-only root
override. It cannot reuse capture or start a new job, and reads no native records.

The user has been asked to run that cleanup diagnostic only. No further collection
is requested, and the used kit and its hash-bound files are unchanged. The ordinary
verbosity SSH auth source is implemented separately; this launchd attempt does not
invalidate its process or authentication acceptance.

The version-3 cleanup report subsequently established cached sudo PASS and
LOCATION_FAIL from the original guard. That guard returns this label before job
removal when the exact root-owned directory cannot be opened/validated or its
exact-content recovery lease cannot be validated. The label does not establish
that resources remain; absence is one of its possible causes. Cleanup remains
unverified, rather than being called successful or treated as proof of leftovers.

A grouped read-only `check-cleanup` is now prepared. It validates the original
kit's code/marker/guard hashes without opening records, compiles current public
guard code into a separate temporary directory and invokes its inspection-only
entry point with the original generated nonce. The C classifier opens only that
exact directory and `job.plist`, refuses unsafe ownership/mode/type/linkage and
compares safe lease bytes to the guard's existing public template. It returns
fixed existence/metadata/content-match labels, never values or bytes. This does
not execute the old capture helper or change any hash-bound file in the used kit.

The same check queries only `launchctl print system/<generated-label>` with stdout
discarded. Nonzero exit alone cannot prove absence. Only the exact generated-label
system-domain missing-service diagnostic qualifies ABSENT; unknown stderr remains
hidden and yields INCONCLUSIVE. Apple's
[daemon troubleshooting guidance](https://developer.apple.com/documentation/network/troubleshooting-packet-traces)
documents that missing-service diagnostic; the check also admits its known
`Bad request.` prefix without generalizing failures to absence.
ABSENCE_VERIFIED requires both missing control directory and explicit service
absence. A safe matching lease is reported separately from completed cleanup.
The check starts no jobs/collectors, removes no test resources, and deletes only
its own fresh temporary compilation directory. The user has been given one
grouped command; no agent has run it on the original kit.

## Grouped result: absence verified

The user supplied the complete fixed check report with error NONE, controls PASS,
cached sudo PASS, directory ABSENT, exact service ABSENT and
cleanup_state ABSENCE_VERIFIED. Lease checks appropriately remain INCONCLUSIVE:
there is no directory to inspect, rather than a failed or mismatched lease.
No job or collector started, original-kit files were unchanged, and native record
files were not opened. No agent repeated the check or inspected local native data.

This closes the temporary-resource concern. Nothing needs removal and the used
kit remains preserved. It does not identify why the earlier run failed to create
or validate its controls, and does not convert that run's zero rows into a valid
launchd ULF absence observation. No further capture or cleanup is requested.
The missing product evidence is still a qualified launchd ULF message/envelope
from an activated controlled job; current launchd process evidence remains in ES.

## Next finite step: collector-free activation controls

After asking what comes next, the user authorized continuing the collector-free
activation check before another ULF capture. Version 4 has an explicit detailed
guard protocol and a one-shot self-test. The root guard identifies filesystem,
lease, registration, activation, removal and file-removal failures with fixed
stage/reason pairs. Syscall errno values and command output never leave the private
process. The original run/cleanup protocol and used kit files remain unchanged.

The self-test starts only the exact controlled job guard, keeps its cancellation
pipe open during normal completion, and starts no collector, readiness marker or
job query. It requires zero guard exit and every success flag; timeouts, signals,
unknown/duplicate output or partial success cannot pass. Failed cases remain
preserved. It records an attempt before starting the guard and refuses reuse or
capture in the same kit. Fresh setup hashes and declares the detailed protocol;
old configurations stay legacy and cannot run this new test by accident.

A passing report establishes launchctl control acknowledgements and completed
cleanup, not native ES/ULF execution evidence. Only after this report can the user
run one separate fresh bounded ULF capture. No capture is enabled automatically,
and absence of qualifying records still leaves launchd ULF gated. Code-only
preparation and synthetic tests do not close the native evidence gate.

## Collector-free controls passed; one fresh ULF capture pending

The user supplied the fixed activation-control report with error NONE, stage COMPLETE,
original controls and cached sudo PASS, all directory/lease/registration/activation/
job-removal/file-removal fields PASS, guard_exit ZERO, no control_failures and result
PASS. Collectors were NOT_STARTED and native record files NOT_OPENED. This establishes
the stated LAUNCHCTL_ACKNOWLEDGEMENT scope and completed cleanup. It does not explain
the earlier attempt's failure or establish native execution/ULF messages.

A separate fresh code-only kit has been prepared for the one planned bounded ULF
capture with the already-tested category-or-message selector and detailed controls.
The self-test kit is not reused. Setup and collection remain human-run; no agent has
started them or read private files. If the capture passes its controls but yields no
qualifying records, leave launchd ULF gated and stop collecting. No separate diagnostic
file source or broader metadata/assessment investigation is added to compensate.
