# Loop 77 family contract — Linux PID and shell-history texture

- **Owning abstractions:** `StateManager`'s time-aware Linux PID allocator owns process identity; the shell-history/activity profile and its data-driven command pools own routine command vocabulary.
- **Invariant:** Linux PIDs must reflect plausible per-host boot age and hidden process churn while remaining chronologically valid; repeated shell commands should arise from shared routine workflows without making unrelated users/roles look templated.
- **Entry paths:** baseline and storyline Linux process creation share `StateManager`; shell history can come from baseline user activity and modeled command execution.
- **Consumers:** eCAR, syslog/audit, bash history, process lifecycle records, and downstream correlations render or reference these canonical identities and commands.
- **Sibling risks:** changing the allocator may affect every Linux process source and deterministic chronology; changing generic command pools may affect all Linux user profiles and attack-adjacent commands.
- **Why this layer owns the truth:** the reviewer concern spans hosts and sources, so PID realism belongs in shared identity allocation and command recurrence belongs in activity/workflow configuration, not renderer patches.
- **Loop question:** determine whether million-scale PID values and repeated `pwd`/`ls -ltr`/`history | tail -15` sequences are plausible under existing host-runtime/workload assumptions, or whether a broad shared-owner adjustment is justified. Do not change behavior on one reviewer sample alone.

## Added probe after blind review — scheduled Linux statistics

- **Owner:** `activity/systemd_schedules.yaml` config plus `_generate_scheduled_tasks` in baseline.
- **Invariant:** periodic cron work may be regular by design, but the modeled job and fleet-wide
  timing should match a plausible installed schedule and should not create accidental duplicate
  lifecycle records.
- **Finding:** independent Threat review reports half-hourly `debian-sa1` starts on nine Linux
  hosts. This schedule is a stronger, repeated cross-host candidate for loop79. The present loop's
  follow-up probe confirms paired wrapper/child processes every 30 minutes with stable per-host
  phase offsets; no source-native contradiction is established by cadence alone.
- **Sibling risks:** changes to generic cron timing affect all scheduled host activity; any fix
  must retain source-native cron behavior and process create/termination semantics.
