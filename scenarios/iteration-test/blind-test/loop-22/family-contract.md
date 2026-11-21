# Natural Windows lifetimes must not inherit observer clock headroom

Selected hypothesis: sibling_defect / adapter_to_family_model. The existing shared
SourceTimingPlanner already projects process start/end in each host clock and
contains same-source create/dependent/terminate evidence. Canonical process close
adapters must not compare an elapsed runtime in canonical time to a conservative
future source-observation bound. The latter is admission headroom, not physical
work performed by the process. Preserve all real canonical activity, transport,
child and session-deadline constraints; do not shrink durations in an emitter or
add random short-lived rows.

Qualification: direct actual-generator user and system requests ask to close at
500ms after birth. Complete-profile source headroom950ms moves the real closes to
1.169411/1.128095s; enterprise_standard headroom2.8124s moves them to2.975902/
2.899328s. The existing profile uses a maximum positive1800ms host-clock offset,
up-to950ms create latency and drift headroom. Borrowing that bound stretches
physical duration even though host-clock offset should cancel within a lifetime.
The source planner then correctly preserves that artificially lengthened canonical
lifetime. Raw probe details retain all finalized source times. Separate ordinary
helper probes already produce1.21–1.73s natural runtimes, proving no universal
three-second lifetime-policy floor. Do NOT change operation lifetime policy or
source clock ranges to make this finding disappear.

Owning boundary: process execution/system close adapters into shared canonical
lifecycle and SourceTimingPlanner. Inventory: ProcessTerminationService.terminate
(user/storyline/baseline/command-derived foreground); generate_system_process_
termination (service/background/baseline); generic session teardown uses a separate
actual-visible-source close schedule and must be assessed separately, without
claiming a universal whole-session redesign. Linux sudo clamp is already a no-op
for Linux. Legacy emitter timestamp containment operates in source time and must
remain intact. SourceTimePlanner._runtime_process_termination_time owns native
clock conversion, latency and lifecycle containment; it is the shared family model
these adapters should use rather than independently moving canonical close time.

Consumers: State process close, lifecycle registry, foreground parent release,
auth/session teardown, source observation cohorts, Sysmon1/5, Security4688/4689,
eCAR CREATE/TERMINATE, file/network/process dependents and checkpoint recovery.
No new cache, source gap, record census, jitter pool or resource limit. Do not
randomize around the three-second edge. Same-source native ordering remains a
hard source contract; source-specific minima should not be conflated with all
Windows processes. Keep authored scenario, seed and review instructions fixed.

Before code: add actual public generator tests for user/system close requests
under complete and enterprise_standard profiles; they must fail before adapters
change. Verify real activity and transport holds still win, and inspect post-run
native matched lifetime distributions on all Windows hosts. Implement only after
loop21 successful generation and postprocessing have exited; source557 is reserved
for the unchanged21 retry. This is not a declaration that any code has been applied.

## Corroborated console sibling admission repair

325virtual family cases passed; a broader98case nativeconsumer/source-agreement
run had96PASS2FAIL. Both failures reproduce without any Windows prototype changes
on frozen558: proxy-denial tests add a Linux server without idle getties. Newly
created console getty uses400–1800ms lead, less than conservative source-create
clock/latency headroom. System service correctly rejects readiness before login.
This is a sibling defect in21's new-getty adapter, not Windows close regression.

Own preparation timing in console adapter and interval occupancy in existing pure
console planner. For a new getty, reserve native creation headroom plus modeled
idle lead before login, using SourceTimingPlanner's existing bound. Check it before
creating State; preserve hard readiness guards. Extend derived terminal admission
to the whole reserved getty birth-to-login interval, including retained closed
lifetimes; do not backdate a new getty into an occupied terminal. Existing idle
getty, frozen absent console policy, GDM, SSH, and root/human identity roles stay
unchanged. No retry guessing, quota increase, new State/cache or source timestamp
patch. Add400ms-lead reproduction and retained-overlap sibling, then rerun actual
proxy controls/native tests. Keep558 source frozen until21postEXIT0.
