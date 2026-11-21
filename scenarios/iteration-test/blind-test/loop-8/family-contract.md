# POSIX hidden PID churn: capacity clipping versus workload distribution 

New family, distribution_texture: panel6 Threat measured67/350 sysstat-job PID
increments exactly940, identical minimum across10Linuxhosts; nativeCRON agrees.
Root: StateManager shared prefix samples low workload counts then max-clips all
counts below94=2*47reorder-lane slots. Quiet hourly regimes collapse onto94/min.
The capacity guard is logical allocation safety and must not become a large atom
in visible cross-host PID deltas.

Owner: StateManager shared hidden-churn schedule, consumed by live and preview
POSIX allocators. Invariant: minute counts retain bounded nonuniform host/hour
workload variation in every regime, while each30s lane has required safe capacity;
preview/live, deterministic seed/scope, chronological order, out-of-order admission,
collision reservations, watermark expiry, PID ring wrap/reuse and checkpoint
continuations remain equivalent. Linux and macOS share this helper: both require
coverage. No emitter PID rewrite, per-cron special case, hostname exception or
arbitrary change to a reviewer-visible increment.

Candidate: model a minimum background allocation component plus bounded variable
host/hour workload churn, sampling from admissible support rather than sampling
below capacity then clipping. The current lane capacity floor remains an explicit
allocator-model limitation; do not claim empirical kernel workload calibration.
Inspect shape/rate changes and both quiet/busy regimes before choosing bounds.
An alternative full separation of logical reservation capacity from physical PID
space is architectural and not automatically in scope of one bounded iteration.

Entry paths: StateManager live create_process; materialization batch preview and
prepared activation/recovery; Linux shell/cron/services/SSH, baseline/storyline/
causal process families, macOS qualified fork/exec/native preflight and policy
refusal allocation. Consumers: canonical process identities, native Syslog/eCAR/
MacEndpointSecurity, children/threads/session membership, reservations/checkpoints,
all process/file/network correlation. Raw supplied identities unchanged.

Sibling matrix: representative host seeds, whole week/minute and ten-minute gap
samples, quiet/weekend/night versus busy, every lane capacity, no point mass at
capacity, cross-host diversity, same-time bursts, half-minute boundaries, reverse
request order, wrap, fixed/active reservations, saved replay, exact planned/live
materialization and full qualified Mac fork/exec census. Root rendered job-delta
probe must assess all repeated command families, not only sysstat. Priority and
implementation follows actual panel6 deliberation and scoped prototypes.

Selection: all four actual panel6 deliberators reproduced the shared PID floor;
prioritize this over RDP timing. This is a family_level candidate; prototype only
while generation7 runs. Preserve explicit capacity invariant and qualify residual
model limits rather than presenting a full physical kernel allocator redesign.

Implementation: shared prefix samples the mean of two bounded integer counts on
admissible capacity support, with existing host/hour regimes and rare bursts.
No raw continuous temporal RNG API or inventory ceiling was added/relaxed. Quiet
regimes retain variation rather than censoring all low draws to94. Actual primary
443 checks, global RNG policy3, normal checkpoint2 and native Mac checkpoint1
passed. Before-repair distribution test failed while safety/purity checks passed.
Sixteen-host weekly prototype mean rises4.97%; retained lane-capacity lower support
is a model limitation, not empirical kernel calibration. Full separation of
physical PID churn from logical reservation capacity remains outside this fix.
