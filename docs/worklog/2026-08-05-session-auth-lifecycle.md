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
