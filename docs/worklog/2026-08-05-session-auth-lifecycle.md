# Session and Authentication Lifecycle Realism Worklog

## Status

Implementation completed on 2026-08-05 after the user approved proceeding from the canonical
contract foundation into the first output-changing realism slice. The feature changes generated
records and clears the targeted rendered-invariant findings; generated datasets remain untracked.

Branch: `codex/session-auth-lifecycle`

Stacked on: `codex/canonical-contract-foundation` at `0b0ad32c`

## Targeted validated findings

- `REAL-001`: connection-owner processes can cross session boundaries or outlive their owner.
- `REAL-002`: one Windows LogonID can change from a null to non-null LogonGuid.
- `REAL-003`: distinct same-timestamp failed authentication attempts can share an eCAR object ID.
- `REAL-004`: Linux server local-session ancestry reverses `/bin/login` and `systemd --user`.
- `REAL-006`: an RDP source endpoint FLOW can render after target authentication.
- Foundation shadow debt: machine-account start/closure occurrences bypass registered session
  identity; some successful logon/SSH paths also need exact trace verification.

## Slice invariants

1. A published session identity, including LogonGuid nullability, never changes.
2. A user process can be reused only within its exact owning LogonID and valid session interval.
3. SSH client processes are one-shot per transport unless explicit multiplexing is modeled.
4. Every failed authentication attempt has a stable, distinct action-relative occurrence ID.
5. Linux server console ancestry is system manager -> login -> shell; a per-user system manager is
   not the parent of `/bin/login`. Desktop terminal ancestry remains session appropriate.
6. Every successful RDP target authentication observation follows both admitted endpoint FLOW
   observations for its exact transport.
7. Machine-account type-3 start/logoff evidence resolves one registered session identity and then
   closes it through the normal state transition.

## Validation strategy

- Add focused unit tests at each owning layer and entry-path sibling tests for SSH, proxy,
  browser, and mail-client process reuse.
- Re-run the integrated review topology and the expanded rendered-invariant probe.
- Compare before/after output and account for every changed source family; byte identity is not an
  acceptance criterion for this output-changing slice.
- Run Ruff, the complete non-slow suite, and targeted slow tests relevant to lifecycle behavior.

## Implemented ownership changes

- `StateManager` now finalizes a session's null/non-null LogonGuid policy at allocation, retains
  that identity after closure, rejects replacement, and allocates deterministic peer ordinals for
  otherwise identical semantic attempts.
- Connection-owner reuse requires the exact active LogonID. SSH, SCP, and SFTP client processes
  are one-shot per transport until explicit multiplexing is modeled.
- Failed authentication attempts receive action-relative occurrence keys, so identical retries at
  one timestamp remain distinct without depending on unrelated generation order.
- Linux server console sessions now use system manager -> `/bin/login` -> shell ancestry. Desktop
  terminal sessions retain their per-user system-manager ancestry.
- Source timing anchors remote authentication after the later admitted source or target eCAR FLOW,
  preventing source-visible RDP/SSH transport from appearing after target authentication.
- Baseline logoff plans are published to canonical session state before activity fan-out, so every
  consumer rejects reuse after the planned closure rather than relying on a local deadline map.
- Anonymous and machine-account Type 3 logons now use registered, state-backed start/closure
  lifecycles with one identity object. Sysmon projects the canonical session LogonGuid, including
  ended sessions, and no longer invents emitter-owned shared truth.
- The SSH contract treats a modeled source host as optional because inbound traffic from an
  unmodeled external client is a supported partial-observation path.

## Empirical before/after evidence

Scenario: the review branch-office enterprise topology, using the same scenario, observation
profile, and seed as the frozen review output.

- Frozen output: `/private/tmp/eforge-realism-review/branch-enterprise`
- Final output: `/private/tmp/eforge-session-auth-v3/branch-enterprise`
- Final probe: `/private/tmp/eforge-session-auth-v3/probe-branch-enterprise.json`
- The frozen probe reported 46 findings (44 errors and 2 warnings). Fourteen findings belonged to
  the six targeted checks: failed-attempt identity (1), Linux login parentage (1), process after
  logout (3), RDP transport-before-authentication (2), overlapping SSH actor transports (5), and
  mutable Sysmon LogonGuid (2).
- The final probe reports zero findings for all six targeted checks. It reports 32 unrelated
  findings (30 errors and 2 warnings): Windows 4648 native fields, Zeek AAAA success distribution,
  Zeek file intervals, and Zeek OCSP duration distribution. Its nonzero exit is therefore expected
  and preserved as input to later remediation slices.
- Two independent post-change runs at
  `/private/tmp/eforge-session-auth-v2/branch-enterprise` and
  `/private/tmp/eforge-session-auth-v3/branch-enterprise` are fully byte-identical (`diff -qr`
  exit 0), confirming that the changed output remains deterministic.
- The integrated shadow-contract pass initially exposed one external-client SSH occurrence as
  missing a source-host context. The reviewed contract now records that context as optional, with
  an exact registry regression test. No generated records were weakened or fabricated to satisfy
  the contract.
- Generation retained the scenario's pre-existing undeclared-domain warning for
  `portal.northstarclaims.net`; this slice does not change that scenario input.

The post-change package is intentionally not expected to be byte-identical to the frozen output:
one-shot SSH processes, corrected ancestry, immutable session identity, and changed source timing
all alter rendered evidence. Some later record IDs and RNG-dependent values can consequently move
even when the direct fix owns only one event family; the rendered invariant probe is the acceptance
boundary for this slice.

## Validation results

- Focused tests cover immutable LogonGuid policy, ended-session lookup, scoped semantic ordinals,
  same-timestamp failed attempts, exact-session and one-shot process ownership, Linux server
  ancestry, published baseline closures, state-backed anonymous/machine logons, external SSH
  sources, and later-endpoint RDP timing.
- The first complete non-slow run reached 5,106 passed and 41 skipped, with one stale
  `test_world_model` assertion that still required a server's system manager to share the user
  session lifecycle. The assertion was corrected to distinguish the boot lifecycle from the
  `/bin/login` and shell lifecycle; the affected world-model and generator tests both pass.
- `uv run ruff check .`: passed.
- `uv run ruff format --check .`: passed; 452 files already formatted.
- `git diff --check`: passed.
- `uv run pytest --no-cov -q`: 5,107 passed and 41 skipped in 215.89 seconds.
- `uv run pytest --no-cov --include-slow -q tests/integration/test_parallel_generation.py`:
  5 passed in 3.36 seconds, covering threaded temporal consistency, cross-log identity,
  corruption checks, storyline generation, and performance.

## Post-fix blind gate (2026-08-07)

Four fresh reviewers assessed a neutral copy of the final integrated output without the scenario,
ground truth, code, prior reports, or each other's conclusions. The exact reports and verified
dispositions are under
[`docs/design/realism-review/post-batch-2-blind/`](../design/realism-review/post-batch-2-blind/summary.md).

| Specialty | Verdict | Verdict confidence | Synthetic-confidence score |
|---|---|---:|---:|
| Threat Hunter | Synthetic | 99 | 98 |
| Detection Engineer | Synthetic | 97 | 95 |
| Network Forensics | Synthetic | 96 | 94 |
| Host/EDR | Synthetic | 99 | 99 |

The average verdict confidence was 97.75, the average synthetic-confidence score was 96.5, and
the score spread was 5. Deliberation was not triggered because the verdicts were unanimous, the
average verdict confidence exceeded 60, and the score spread was below 30.

All six targeted rendered-invariant checks remain at zero, and those original contradictions did
not recur in the panel. The panel nevertheless failed the broader family gate by identifying
independently reproducible sibling defects:

- host-local Linux process creation uses interleaved/backward PID allocation;
- SSH target syslog can precede the same PID's eCAR process creation;
- mandatory Windows startup modules can first load minutes or hours after process creation, while
  narrow third-party modules are assigned to incompatible processes;
- Windows channel record IDs can jump by hundreds or thousands inside milliseconds.

The panel also validated later-batch defects in Kerberos transport ordering and cache behavior,
HTTP `HEAD` bodies, DNS cache TTL state, TCP state/history derivation, sensor-clock stability,
DHCP lease state, OCSP object stability, Linux daemon/hardware state, and Snort classification
projection. Weak TEST-NET RDP and unobserved `kubectl` signals were rejected or left unproven.

The original pre-fix panel averaged 91.75 synthetic confidence (88, 96, 86, 97). The post-fix
panel averaged 96.5 (98, 95, 94, 99), but this is not evidence that the implemented fixes reduced
realism: the panels were independent and evaluated a broadly changed output. The supported
conclusion is narrower: the intended defects are gone, while previously unprioritized sibling
and downstream contradictions are now decisive. Batch 3 remains gated until the four lifecycle
and source-sequence families above are remediated and reassessed.

## Gate-repair loop 1 contract: Linux process identity and observation

Classification: `sibling_defect`; intended fix classification: `family_level`.

- **Owning abstractions:** `StateManager` owns the one host-local Linux PID namespace and process
  lifecycle; the SSH action bundle plus `SourceTimingPlanner` own the ordering between a responder
  process observation and same-PID SSH syslog.
- **Family invariant:** absent an explicitly modeled PID-space wrap, Linux process-create PIDs are
  strictly increasing by host-native process start time, including durable and syslog-only
  processes. Every same-PID SSH connection/auth message must render after the destination eCAR
  process create when that create is observed.
- **Entry paths:** engine process-tree seeding and fixed registration; baseline user/system/cron
  processes; activity and storyline process bundles; SSH/SCP/SFTP responder and client helpers;
  file-transfer helpers; and transient `sudo`, PAM, sshd, and daemon syslog PID allocation.
- **Consumers:** canonical process/session identity, eCAR PROCESS/FLOW/USER_SESSION rows, Linux
  syslog PID fields, process parent/child and termination evidence, ground-truth identity
  references, lifecycle probes, and PID allocator/source-timing tests.
- **Layer rationale:** PID ordering is shared host truth and therefore belongs in `StateManager`,
  not an eCAR rewrite. SSH cross-source ordering belongs in the bundle/source-timing boundary,
  because delaying one syslog template or emitter would leave sibling SSH paths inconsistent.
- **Sibling coverage:** the repair must cover canonical and transient allocations, out-of-order
  generator traversal, parent/child bursts, baseline and typed SSH sessions, and repeat-run
  determinism. PID wrap/reuse beyond the current long-duration window remains a separately tested
  boundary. Windows module scheduling and EventRecordID throughput are intentionally deferred to
  the next gate-repair loop.

### Gate-repair loop 1 implementation and static validation

- Replaced overlapping ten-second Linux PID bands with one host-specific monotonic churn function
  shared by canonical and transient allocations. The temporal allocation index remains the owner
  of lower and upper bounds when generator traversal is out of chronological order.
- Removed the elapsed-seconds collision heuristic from PID acceptance. The new sub-one-per-second
  host rate already avoids a one-PID-per-second fingerprint, while the heuristic rejected natural
  candidates and forced bounded fallbacks that produced the observed reversals.
- Added one shared Linux process-observation floor and applied it to successful SSH sessions,
  generic port-22 pre-auth failures, and typed failed-SSH logons. Each path shifts the entire
  source-local syslog sequence together, preserving its internal timing texture.
- The first integrated regeneration showed that allocator order alone was insufficient: eCAR
  process-create latency and generic per-request lifecycle grouping could still reorder explicit
  same-shell pipeline stages. eCAR process-create latency now changes slowly and coherently per
  host, and an explicit process concurrency group takes precedence over each stage's compatibility
  action lifecycle for observation decisions.
- A later safety regeneration exposed two process terminations 51–101 ms after their eCAR logout
  when the newly coherent process delay exceeded the independent session delay. Non-authoritative
  logoff planning now budgets the active profile's worst same-source delay difference after the
  latest planned eCAR process termination. The general probe returns that previously repaired
  lifecycle check to zero.
- The standalone reproduction produced 188 adjacent PID reversals before the repair and zero with
  the new allocator regression. Focused state and SSH tests cover shuffled dense allocation,
  success, generic failure, typed failure, dense eCAR source timing, and pipeline observation-group
  precedence.
- `uv run ruff check .`: passed.
- `uv run ruff format --check .`: passed; 452 files already formatted.
- `uv run pytest --no-cov -q`: 5,112 passed and 41 skipped in 226.71 seconds.

### Gate-repair loop 1 rendered evidence

- Integrated output:
  `/private/tmp/eforge-postbatch2-lifecycle-loop1/branch-enterprise`.
- Repeat output:
  `/private/tmp/eforge-postbatch2-lifecycle-loop1/branch-enterprise-repeat`.
- `diff -qr` returned zero: the two identical-input outputs are byte-identical.
- Across 152 PROXY and 135 WEB Linux eCAR process creates, both adjacent PID reversals and creates
  below the prior visible maximum are zero.
- Across 13 PROXY and 26 WEB responder PIDs visible in both eCAR and SSH syslog, syslog-before-create
  occurrences are zero. First syslog messages follow eCAR creation by 20–266 ms.
- The general realism probe reports 28 remaining unrelated findings: 27 errors and one warning in
  Windows 4648 field naming, Zeek file intervals, and OCSP duration distribution. All six original
  Batch-2 checks and both gate-repair-loop checks are zero.
- Human-readable and JSON `eforge eval` both pass at 95.52/100 over 50,793 records. Parseability is
  100, plausibility 97.82, causality 88.36, timing 94.90, and all 7,556 evaluated causal pairs are
  correctly ordered. The evaluator's 40/100 pivot-linkability flag and its existing indicator and
  cross-source samples remain inputs to later review batches.
- The post-loop blind gate remains pending; the Windows module and EventRecordID gate repairs are
  intentionally next so the panel evaluates the complete failed-gate batch rather than another
  knowingly blocked intermediate dataset.

## Gate-repair loop 2 contract: Windows module lifecycle and ownership

Classification: `sibling_defect`; intended fix classification: `family_level`.

- **Owning abstractions:** the process-execution action bundle owns initialization-time module
  activity; the unified DLL profile catalog owns executable compatibility and load phase; the
  baseline engine may schedule only catalog-declared runtime loads. `ImageLoadContext` carries the
  selected phase/order as canonical occurrence truth, while Sysmon and eCAR remain projections.
- **Family invariant:** a visible Windows loader-chain module is observed during process
  initialization, after the matching process-create row and before later process-owned activity.
  A configured non-OS module may load only in an executable declared as one of its owners. One
  module path is emitted at most once for one process instance.
- **Entry paths:** process creation currently constructs a probabilistic `image_load` directly;
  hourly baseline generation combines process profiles with the global `edr_pools.dll_pool` via a
  permissive hardcoded matcher; RSAT sessions call `generate_image_load()` for explicit MMC
  snap-ins. No authored storyline event exposes module loads. The legacy `module_load` name is an
  emitter-only compatibility consumer and remains outside canonical production.
- **Consumers:** canonical identity/lifecycle planning, eCAR `MODULE/LOAD`, Sysmon Event 7 and its
  filter/PE metadata projection, process last-activity and termination containment, rendered
  invariant probes, and DLL-profile tests.
- **Layer rationale:** module phase and product ownership are process facts, so an emitter filter or
  timestamp rewrite cannot repair them. The global generic pool is duplicate truth and must not
  supplement a process profile. Explicit MMC snap-in loads remain an intentional adapter because
  their owning tool definition supplies the process/module relationship directly.
- **Sibling coverage:** common loader modules, application-catalog modules, inline service modules,
  process-specific lazy/runtime modules, unknown executables, short-lived processes, duplicate
  suppression, non-default observation, eCAR-only/Sysmon-only format selection, and exact repeat
  determinism. EventRecordID throughput remains the final, separate gate-repair loop.

### Gate-repair loop 2 validation strategy

- Add phase-aware loader tests and process-bundle tests proving startup placement, canonical phase
  projection, duplicate suppression, and exclusion of common or incompatible modules from hourly
  sampling.
- Extend the read-only rendered probe with startup-module chronology and configured module-owner
  checks, then regenerate the integrated review topology and compare the exact pre-fix recurrence.
- Run Ruff, the complete non-slow suite, human/JSON evaluation, and identical-input repeat output
  before committing the loop.

### Gate-repair loop 2 implementation and rendered evidence

- Added explicit `startup`/`runtime` phase and load-order ownership to the canonical image-load
  context. The process bundle emits catalog-declared startup modules immediately after process
  creation, while hourly baseline sampling is restricted to catalog-declared runtime modules.
- Removed the baseline generator's independent global DLL-pool merge and permissive executable
  matcher. The DLL profile catalog now owns configured non-OS module compatibility, while Windows
  system modules and explicit tool-owned adapters remain legal across their intended paths.
- eCAR and Sysmon now project phase-aware source timing from `SourceTimingPlanner`; neither emitter
  invents module chronology. Startup modules remain strictly ordered after the source-visible
  process create, including independent source latency.
- Before the repair, the integrated output contained 112 of 118 foundational loader modules more
  than five seconds after the matching process create, plus 144 configured module/executable owner
  violations. The repaired output contains zero in both categories; 375 foundational observations
  follow process creation by 1--9 ms.
- The expanded general probe decreased from 42 findings to 29. Both new module checks are zero for
  eCAR and Sysmon; remaining findings belong to later scheduled families (Windows 4648 field
  naming, Zeek file intervals, DNS AAAA distribution, and OCSP duration distribution).
- Focused DLL, activity, baseline, and source-timing suites pass (265, 297, and 236 passed across
  the recorded invocations; one baseline/config test was skipped). `uv run ruff check .` and
  `uv run ruff format --check .` pass. The complete non-slow suite passes with 5,122 passed and
  41 skipped in 222.17 seconds.
- Integrated output:
  `/private/tmp/eforge-postbatch2-lifecycle-loop2/branch-enterprise`; identical-input repeat:
  `/private/tmp/eforge-postbatch2-lifecycle-loop2/branch-enterprise-repeat`. `diff -qr` returned
  zero, proving byte-identical repeatability.
- Human-readable and JSON `eforge eval` both pass at 95.30/100 over 48,839 records. Parseability is
  100, plausibility 95.63, causality 89.44, timing 95.17, cross-source field agreement is 100, and
  all 7,331 evaluated causal pairs are correctly ordered. The existing 40/100 pivot-linkability
  flag is retained for its scheduled evaluator/remediation batch.

## Gate-repair loop 3 contract: Windows channel sequence realism

Classification: `sibling_defect`; intended fix classification: `family_level`.

- **Owning abstraction:** `WindowsRecordIdSequence` is the sole owner of source-native record
  numbers, with one stateful sequence per rendered host/channel. Windows Security and Sysmon
  emitters own final chronological assignment after their source timestamps are normalized;
  XML, Splunk, and SOF-ELK® projections consume the same assigned value.
- **Family invariant:** within one host/channel epoch, every record ID increases with rendered
  time. Gaps represent omitted records from that same channel, so their count must arise from and
  be bounded by elapsed time and host/channel throughput. Security Event 1102 starts a new
  Security-channel epoch at record 1; no Sysmon event resets that sequence.
- **Entry paths:** canonical Windows Security and Sysmon events, raw compatibility events, direct
  emitter tests, spool/non-spool Security flushes, Sysmon final flush, and the three Windows output
  target projections all converge on the two emitter flush loops. The engine and activity
  generator retain unused private counters that never reach output and are duplicate legacy truth.
- **Consumers:** Windows XML and Snare renderers, timestamp-precision derivation, external parsers,
  evaluator parsing, chronological-order tests, rendered probes, and investigators who use record
  gaps to infer missing/filtered channel activity.
- **Layer rationale:** record IDs are explicitly permitted source-local derivation under the
  approved projection contract. Canonical events must not own them, but independent per-event
  heavy-tailed gap sampling is also invalid because it fabricates thousands of same-channel
  writes without elapsed time. Remove the dead upstream counters and keep one final source owner.
- **Sibling coverage:** Security versus Sysmon, domain-controller/server/workstation rate bands,
  subsecond bursts, long quiet intervals, same-time normalization, log clears, malformed raw event
  IDs, direct/XML/Splunk/SOF-ELK rendering, spool mode, deterministic repeats, and 30-day cost.
- **Reference basis:** Microsoft defines EventRecordID as the record number assigned when an event
  is logged and documents sequential numbering. No universal host throughput is specified, so
  the model uses conservative per-host/channel background rates and an explicit peak-rate safety
  bound rather than presenting a fitted production distribution.

### Gate-repair loop 3 validation strategy

- Replace independent heavy-tailed gaps with elapsed-time Poisson counts bounded by a conservative
  host/channel peak. Unit tests must prove short-interval bounds, elapsed-time scaling, independent
  channel epochs, log-clear behavior, deterministic output, and efficient long-duration sampling.
- Extend the rendered probe to flag high-confidence millisecond-scale record-ID rate
  contradictions, then measure exact recurrence against the frozen loop-2 output and the repair.
- Update the source-reference ledger and Evidence Formats limitation, run focused emitter/parser
  tests, Ruff, the complete non-slow suite, human/JSON evaluation, and identical-input repeat output
  before the post-gate blind panel.

### Gate-repair loop 3 implementation and rendered evidence

- Replaced independent heavy-tailed per-row gaps with elapsed-time Poisson counts. Large expected
  counts use a constant-cost normal approximation for long-duration generation, and every draw is
  capped by a conservative host/channel peak rate.
- Canonical `HostContext.system_type` now selects the domain-controller/server/workstation rate
  class. Hostname inference remains only as a raw/direct-emitter compatibility fallback. Host type
  travels as non-rendered emitter metadata and is thread-local during projection.
- Removed the engine and activity generator's unused private record counters plus the emitters'
  duplicate numeric mirrors. `WindowsRecordIdSequence` is now the only value owner; Security and
  Sysmon retain independent stateful per-host channel epochs.
- Extended the general probe with chronological epoch, Security-clear reset, and conservative
  throughput checks. On the frozen loop-2 output it found 171 high-confidence rate contradictions
  aggregated across 13 of 14 Windows channel files. The repaired output has zero. The worst
  inferred hidden-record rate fell from 1,784,568.369 records/second to 49.461 records/second.
- The repair preserves non-contiguous texture: for example, the DC Security stream has 11,688
  omitted records across 4,994 visible rows and a maximum gap of 3,324 over a correspondingly long
  interval; workstation channels retain smaller host-specific gaps instead of becoming contiguous.
- Added the direct Microsoft EventRecordID and sequential-record references to the source ledger
  and replaced the obsolete probabilistic-gap limitation in `EVIDENCE_FORMATS.md` with the actual
  elapsed-time contract.
- Focused sequence/emitter/threading tests pass with 138 passed. `eforge validate-config` passes
  all 87 files with zero findings. Repository-wide Ruff check and format check pass.
- The first complete suite run exposed only the repository's first-reference trademark guard for
  the new worklog text (5,118 passed, 41 skipped, one failure); the worklog now uses `SOF-ELK` at
  first mention. The final complete non-slow suite passes with 5,121 passed and 41 skipped in
  225.82 seconds. Targeted slow parallel-generation validation passes with 5 passed.
- Integrated output:
  `/private/tmp/eforge-postbatch2-lifecycle-loop3/branch-enterprise`; identical-input repeat:
  `/private/tmp/eforge-postbatch2-lifecycle-loop3/branch-enterprise-repeat`. `diff -qr` returned
  zero, proving byte-identical repeatability. The general probe returns the same 29 later-batch
  findings as loop 2 and no Windows record-ID, Linux PID/SSH, or Windows module findings.
- The final probe also makes the first two gate families directly reproducible. Against the frozen
  pre-repair output it detects 47 Linux PID reversals across both Linux hosts and 57 same-PID SSH
  syslog-before-eCAR-create inversions; both checks are zero against the repaired output. The same
  pre-repair run non-vacuously detects the module and record-ID families as well.
- Human-readable and JSON `eforge eval` both pass at 95.3524/100 over 48,839 records. Parseability,
  cross-source field agreement, causal ordering, and rate plausibility are 100. The retained
  40/100 pivot-linkability flag remains scheduled beyond this gate rather than reopening the
  repaired family.

## Post-gate blind panel and gate disposition

- Four fresh reviewers inspected only the neutral data copy at `/private/tmp/case-zeta.7JbRlL`.
  Their synthetic-confidence scores were Threat Hunter 72, Detection Engineer 74, Network
  Forensics 84, and Host/EDR 85 (average 78.75; spread 13). All four verdicts were synthetic with
  average verdict confidence 88.25, so the established deliberation thresholds were not met.
- This is a material improvement from the pre-repair average of 96.5, but the gate does not yet
  pass. Static and rendered verification accepted three same-scope root-cause families: local
  session bootstrap materialized an in-window `/bin/login` for a pre-window session, Windows 4624
  projected a host-global winlogon PID instead of the canonical per-session PID, and all 29
  Windows 4648 rows used display labels rather than native `IpAddress`/`IpPort` XML field names.
- The repeated nine-module startup sequence is a sibling of the repaired module family and is the
  next bounded gate loop. Network findings (IDS payload prerequisites, NAT lifetime containment,
  Zeek identifier morphology, transport visibility, and sensor timing) remain in their existing
  Batch-3/network slices. Fleet software, daemon/scanner texture, Linux system-session identity,
  and SSH concurrency remain in Batch 4. The panel therefore refines evidence and ordering without
  replacing the authoritative remediation roadmap.

## Gate-repair loop 4 contract: authentication session projection

Classification: `sibling_defect`; intended fix classification: `family_level`.

- **Owning abstractions:** session state owns the canonical start and Windows terminal-session
  winlogon identity; the logon action bundle owns the 4624 caller reference and local-session
  bootstrap; the Windows Security format definition owns native 4648 field names. Emitters may
  project those facts but may not replace a session PID with a host-global process identity.
- **Family invariants:** an in-window `/bin/login` creation requires a matching in-window local
  session opening; a session that began before collection keeps its login parent before the
  collection boundary. Concurrent Windows interactive sessions use distinct winlogon PIDs in 4624,
  while unlocks reuse their owning session's PID. Event 4648 renders `IpAddress` and `IpPort`, the
  provider-manifest names, while `Network Address` and `Port` remain display labels only.
- **Entry paths:** generic/baseline local logon, lazy Linux shell materialization, Windows local and
  compatibility interactive logons, Type-7 unlock reuse, RDP-owned sessions that reach the generic
  renderer, explicit-credential action bundles, direct emitter tests, and XML/Snare/SOF-ELK
  projections.
- **Consumers:** StateManager session/process relationships, eCAR session and process lifecycles,
  Linux syslog/logind projection, Windows Security 4624/4648, evaluators/parsers, and rendered
  invariant probes.
- **Layer rationale:** shifting or inventing rows in eCAR/syslog would leave the canonical session
  boundary wrong; the pre-window bootstrap must be repaired where the process is planned. The 4624
  caller must use the session-owned PID supplied in `AuthContext`. The 4648 spelling is purely a
  source-native schema correction and belongs in the format definition plus Windows projection.
- **Sibling coverage:** pre-window and in-window Linux local sessions, workstation and server local
  shells, overlapping Windows Type-2 sessions, Type-7 reuse, interactive compatibility paths,
  blank and populated 4648 endpoints, enterprise observation, and identical-input determinism.

### Gate-repair loop 4 validation strategy

- Add unit tests proving pre-window login parents remain pre-window, overlapping Windows sessions
  carry distinct canonical caller PIDs, unlocks reuse their session owner, and 4648 uses only the
  provider-native XML names.
- Extend the rendered probe with in-window local-login/session-open and concurrent-winlogon-owner
  checks; retain the existing 4648 schema check as the source-format proof.
- Run focused tests, config validation, Ruff, the complete non-slow suite, regenerate the integrated
  enterprise output, compare exact pre/post recurrence, run human/JSON evaluation, and prove an
  identical-input repeat before committing.

### Gate-repair loop 4 regression sibling: bounded Linux PID insertion

- The first repaired integrated output cleared the local-session, winlogon-owner, and 4648 checks,
  but the retained Linux chronology probe found one new reversal on `WEB-BO-01`: PID 2050145 at
  15:26:05 was followed by PID 2050035 at 15:30:03. A generation trace proved that baseline
  scheduled tasks, storyline SSH, and proxy service-process owners reached the shared allocator in
  non-chronological order.
- The allocator's existing future-bounded repair chose candidates anywhere in an available numeric
  interval. It placed a 15:12 SSH responder immediately below the already allocated 15:30
  responder, leaving no numeric slot when the 15:26 proxy process was generated later. This is an
  allocator-level sibling of loop 1, not an SSH projection defect.
- Preserve the existing time-derived PID model and shared namespace, but choose bounded
  out-of-order insertions from the interval's middle region so later insertions retain capacity on
  both sides. Add the exact four-way traversal order as a state-manager regression test and require
  the regenerated output to return the Linux chronology check to zero.

### Gate-repair loop 4 implementation and rendered evidence

- Windows interactive logon planning now resolves a session-owned `winlogon.exe` PID before the
  canonical logon event and carries it in `AuthContext`; the 4624 projection prefers that canonical
  caller. Later shell setup reuses the same process rather than creating a second session owner.
- Lazy Linux local-shell bootstrap keeps the user-manager or terminal parent at the original
  pre-window logon time when the owning session predates collection. The probe now rejects an
  in-window `/bin/login` without a matching visible local session opening.
- Event 4648 now renders the provider-native `IpAddress` and `IpPort` XML names in the format
  schema, direct emitter output, and transformed targets. The source-reference ledger records the
  reviewed subset as aligned rather than retaining the repaired defect.
- The Linux PID allocator now selects future-bounded out-of-order allocations from the middle
  region of the available interval. The exact integrated traversal that previously exhausted the
  15:12/15:26/15:30/15:31/15:32 interval is covered by a state-manager regression test.
- Focused activity, world-model, emitter, dispatcher, format, and state tests pass with 678 tests.
  Configuration validation passes all 87 files, and repository-wide Ruff check and format check
  pass.
- Repaired integrated output:
  `/private/tmp/eforge-postbatch2-lifecycle-loop4b/branch-enterprise`; identical-input repeat:
  `/private/tmp/eforge-postbatch2-lifecycle-loop4b/branch-enterprise-repeat`. `diff -qr` returned
  zero. The probe reports zero local-session-opening, winlogon-owner, 4648-field, Linux-PID, and
  SSH chronology findings. Its 28 retained findings are all pre-scheduled network families: 26
  Zeek file intervals, one AAAA distribution warning, and one OCSP-duration warning.
- Human-readable evaluation passes at 96/100 over 50,142 records. Parseability, cross-source field
  agreement, causal ordering, temporal integrity, and rate plausibility are 100. The 40/100
  pivot-linkability flag remains scheduled outside this bounded gate repair.
- The complete non-slow suite produced 5,123 passes and 41 skips in 225.41 seconds with one
  sandbox-only failure: the Splunk runtime unit test could not bind an ephemeral loopback port.
  Rerunning that exact test with loopback permission passed, yielding 5,124 effective passes and
  no code failures.
