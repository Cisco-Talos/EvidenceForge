# Loop 76 family contract — rsyslog forwarding queue state

- **Owning abstraction:** baseline `_render_rsyslog_health_message`, which owns durable per-host
  pending/checkpoint/worker state for the rsyslog queue reports. `extra_syslog_messages.yaml`
  selects the report family and per-host event budget; the canonical syslog route supplies the
  forward target.
- **Invariant:** pending count is host-local and persists across checkpoint/queue messages. Each
  report advances it by sampled arrivals minus processed messages, bounded to 0–4096; checkpoint
  counters advance with processing. The initial state may include pre-visible warm-up activity.
  A partial syslog export does not directly bound asynchronous queue depth.
- **Entry paths:** baseline Linux extra-syslog selection, including warm-up and visible hourly
  generation, calls `_render_rsyslog_health_message` only when the host has a canonical syslog
  route. No storyline/raw queue event is in scope for this candidate.
- **Consumers:** source-native Linux `syslog.log` rows for `rsyslogd`; evaluators and reviewers
  compare these with each host's visible syslog volume, host role, route and timestamps.
- **Layer rationale:** pending/checkpoint values are generated shared host state before rendering.
  An emitter change would hide rather than fix a bad queue trajectory; a global counter cap would
  erase valid host differences.
- **Sibling risks:** inspect all 11 Linux hosts, warm-up-to-window boundary, both `main Q` and
  `omfwd` messages, checkpoint progression, queue-name/worker stability, and per-host deltas.
  Preserve asynchronous backlog semantics and host roles.
- **Probe plan:** derive ordered pending/checkpoint rows from the loop76 output; verify observed
  pending deltas are attainable under the documented sample bounds, checkpoint movement is
  monotonic, values remain within capacity, and high values do not require more messages than the
  modeled warm-up/visible update path permits. Compare against syslog counts only as context.
- **Initial classification:** `distribution_texture` / `false_positive_or_unproven`; the loop75
  panel found high counts on seven hosts but no impossible transition. No source-level defect is
  claimed before this probe.
