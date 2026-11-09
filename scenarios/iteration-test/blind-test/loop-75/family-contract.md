# Loop 75 family contract — scanner cadence and syslog queue state

- **Target families:** Nmap command probe scheduling and baseline rsyslog queue health.
- **Owning abstractions:** `NmapCommandProbePlanner` / `_execute_nmap_command_probe_bundle` own
  scanner expansion and relative timing; `_render_rsyslog_health_message` owns host-local forwarding
  queue state consumed by the syslog emitter.
- **Invariants to check:** the Nmap flow count, ports, tuples, outcomes and timing should follow the
  authored process command and configured connect window. Queue counters should evolve coherently
  as host-local state; high pending counts alone are not evidence if an unobserved/pre-window
  backlog or asynchronous forwarding plausibly explains them.
- **Entry paths and consumers:** typed storyline `process` events that run nmap route into the
  canonical Nmap probe bundle and feed Zeek, firewall, IDS and endpoint flow evidence. Baseline
  rsyslog health messages are selected by `extra_syslog_messages.yaml`, advance per-host state, and
  render through syslog; the same source's visible line count is only a partial observation of
  messages routed through an asynchronous queue.
- **Layer rationale:** scan cadence is owned by the scanner action bundle, not by Zeek emitters.
  Queue values are owned by the baseline queue-state model, not by generic syslog rendering.
- **Sibling risks:** don't turn authored suspicious activity into an artifact merely because it is
  compact. Check distribution across all four ports and both network views. For queues, compare
  message deltas, checkpoints, visible line volume, host roles and time spacing across every Linux
  host before changing the shared state model.
- **Initial classification:** `false_positive_or_unproven` for the scan's near-equal counts: the
  scenario explicitly authors `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24`, and the planner's
  configured connect window is 6–12 seconds. Queue backlog is a weak, repeatable `distribution_texture`
  hypothesis, not yet a contradiction: the implementation models asynchronous queue activity, so
  log lines do not bound all enqueued or processed messages.
- **Work for this loop:** inspect the full fixed-seed output and compare current counts/state
  behavior with the loop74 panel observations. Make no generator change unless the rendered data
  demonstrates an impossible queue transition or an implausible scan scheduling contract.
