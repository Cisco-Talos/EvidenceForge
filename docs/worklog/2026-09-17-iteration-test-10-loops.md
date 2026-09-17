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

## Loop 77 Result

- Commit: `81cdf1e4` (`fix: bind Linux background activity to host state`).
- Verification: 11,643 passed, 48 skipped, 2,026 deselected; Ruff check/format and all 92 config
  files passed validation.
- Automated evaluation: 97.0715 / PASS across 131,365 records.
- Initial blind mean: 51.75, down 22.25 points from loop 76; deliberated mean 60.50.
- Target probes passed for per-host IRQ identity, complete sub-millisecond cron cadence, and
  coherent host-variable resolver episodes.
- Highest-confidence surviving families: TCP DNS transport state/accounting, complete
  `runas /netonly` effects, file dependency ordering, Sysmon pointer rendering, and host-role
  software inventory.

## Loop 78 Family Contract

### TCP DNS transport semantics and native Sysmon pointer rendering

- **Classification:** two bounded `hard_contradiction` / `schema_or_format_defect` families from
  the loop-77 detection review and deliberation.
- **Owning abstractions:** the canonical network transaction planner owns protocol-specific
  connection state, history, and packet accounting; the Sysmon renderer owns Windows-native
  pointer presentation.
- **Invariants:** a successful TCP DNS transaction carries TCP handshake/data/close history and
  enough packets for that history, never UDP-style `Dd` with one packet per direction; Sysmon
  Event 8 `StartAddress` renders as `0x` plus 16 uppercase hexadecimal digits.
- **Entry paths:** explicit and inferred/fallback TCP DNS responses, including SERVFAIL synthesis;
  every CreateRemoteThread event with or without a populated remote-thread context.
- **Consumers:** canonical network state, Zeek `conn.log` and `dns.log`, packet/IP-byte accounting,
  source timing, Sysmon XML, eCAR remote-thread projection, validation, and blind review.
- **Layer rationale:** TCP semantics must be corrected before source observation and rendering so
  all consumers share one defensible ledger. Pointer padding is source-native presentation and
  therefore belongs in the Sysmon renderer without changing the canonical integer.
- **Sibling risks:** preserve UDP DNS `Dd` semantics, capture-loss accounting, failed TCP states,
  DNS RTT/close bounds, eCAR lowercase pointer format, and zero/default Event 8 behavior.

## Loop 78 Result

- Commit: `3992a09e` (`fix: preserve TCP DNS and Sysmon native semantics`).
- Verification: 11,643 passed, 48 skipped, 2,027 deselected; Ruff check/format and all 92 config
  files passed validation.
- Automated evaluation: 96.7550 / PASS across 122,555 records.
- Initial blind mean: 37.50, down 14.25 points from loop 77; deliberated mean 39.00.
- Target probes passed for 13 TCP DNS flows and 11 Sysmon Event 8 records. The probe's initial
  four-packet threshold was corrected to the source-native three-packet minimum for combined TCP
  flags before the result was finalized.
- Highest-confidence surviving families: ICMP directional history, Windows local-path command-line
  escaping, duplicate endpoint publication, partial TLS analysis, and persistent Exchange service
  instance ownership.

## Loop 79 Family Contract

### ICMP directional observation and Windows system-process command paths

- **Classification:** two loop-78 multi-reviewer `schema_or_format` / `source_native_single_schema`
  defects with exact rendered censuses.
- **Owning abstractions:** the canonical network transaction planner owns ICMP request/reply
  direction before sensor observation; the data-driven Windows system-process catalog owns native
  command templates before Security, Sysmon, and eCAR projection.
- **Invariants:** ICMP with origin packets renders origin-direction history and adds responder
  direction when response packets exist; local drive-qualified Windows command paths contain one
  separator per component, while UNC prefixes and intentional shell escaping remain unchanged.
- **Entry paths:** baseline and storyline ICMP, scanner/probe ICMP, direct canonical connections,
  every Zeek sensor observation, and Exchange EdgeTransport/Imap4 background service starts.
- **Consumers:** canonical traffic/state, sensor observation snapshots, Zeek `conn.log`, Security
  4688, Sysmon Event 1, eCAR PROCESS/FLOW, config validation, and blind probes.
- **Layer rationale:** observation replaces emitter-local history from canonical facts, so fixing
  the renderer would be overwritten; the Exchange defect is literal catalog data propagated
  consistently by all endpoint renderers.
- **Sibling risks:** preserve TCP/UDP Zeek history, unanswered ICMP duration omission, packet/IP-byte
  accounting, sensor-local loss rules, legitimate UNC double prefixes, and non-Exchange templates.
