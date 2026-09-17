# Iteration-Test Assessment — Loops 77–86

## Scope

- Branch: `dev`.
- Requested loops: 77 through 86, using `scenarios/iteration-test/scenario.yaml`.
- Every loop preserves standalone four-reviewer blind scoring and automated evaluation.
- Prior loop artifacts remain under `scenarios/iteration-test/blind-test/v2-loop-N/`.

## Loop 77 Family Contract

### Persistent host-derived Linux background telemetry

- **Classification:** `family_level`; Loop 76 multi-reviewer `distribution_texture` and
  `contract_gap` findings in Linux background telemetry.
- **Owning abstraction:** the baseline Linux schedule planner owns recurring execution slots;
  data-driven extra-syslog configuration plus deterministic per-host baseline state own hardware
  and resolver-health vocabulary before syslog rendering.
- **Invariant:** hardware-level irqbalance/NUMA tuples remain coherent within one host while
  differing across unrelated hosts; configured half-hour cron executions are not silently thinned;
  cron source timestamps retain deterministic sub-millisecond entropy; and resolver degradation
  episodes have coherent degrade/recover order with host-specific counts rather than a fixed fleet
  quota.
- **Entry paths:** baseline 30-minute cron schedules, Debian sysstat shell/workload lifecycles,
  extra syslog selection, irqbalance and NUMA message rendering, and systemd-resolved health
  messages on every eligible Linux role.
- **Consumers:** RFC5424 syslog, eCAR process creation/termination for cron work, persistent daemon
  PID state, checkpoint replay, deterministic evaluation, and blind host/threat-hunter review.
- **Layer rationale:** schedule presence, hardware identity, and resolver episodes are modeled host
  state. Fixing rendered strings after selection would leave missing eCAR executions and sibling
  messages inconsistent.
- **Sibling risks:** preserve distro/role filtering, exact host resolver binding, deterministic
  regeneration, checkpoint continuity, stable daemon PIDs, non-cron systemd timer skip/jitter
  semantics, and collection-window admission.

