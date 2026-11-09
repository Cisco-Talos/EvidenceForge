# Loop 79 family contract — Debian sysstat schedule

- **Owning abstraction:** typed `SystemdScheduleEntry` descriptors in `activity/systemd_schedules.yaml`
  define deployed service cadence; `BaselineMixin._generate_scheduled_tasks` materializes those
  schedules into canonical process and syslog events.
- **Invariant:** modeled periodic work must match the package/service cadence and remain temporally
  ordered. Cron occurrences are minute-aligned; every occurrence owns its wrapper/child process
  lifecycle and should not be randomized as if it were an unstructured user action.
- **Entry paths:** Debian `debian-sa1` enters the shared scheduled-task planner; other daily,
  weekly, and 30-minute cron/systemd entries share the scheduler and must retain their current
  semantics.
- **Consumers:** eCAR process create/terminate, Linux syslog/CRON messages, PID allocation, and
  downstream evaluation consume the canonical occurrence.
- **Sibling risks:** adding a supported cadence can affect every profile using that frequency;
  changing `30min` behavior globally could alter unrelated timers. Keep the correction scoped to
  the Debian sysstat entry and add direct scheduler coverage for ten-minute cadence plus regression
  coverage for existing 30-minute and timer-skip behavior.
- **Why this layer owns the truth:** the nine-host repetition comes from a typed service schedule,
  not an emitter text template; update the data contract and shared planner only where the cadence
  feature requires it.
- **Evidence:** loop77 showed paired `debian-sa1` events every 1,800 seconds on nine Debian hosts.
  Debian package sources describe periodic collection at ten-minute intervals. The repair should
  model six runs per hour at minute-aligned ten-minute slots with deterministic per-host phase and
  preserve the exact wrapper/child lifecycle.
