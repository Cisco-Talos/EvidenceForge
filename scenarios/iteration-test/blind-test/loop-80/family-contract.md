# Loop 80 family contract — post-cadence-fix blind checkpoint

- **Owning abstraction:** the Debian sysstat deployment schedule and shared baseline scheduler were
  updated in loop79; the current objective is to review the entire regenerated dataset after that
  family fix.
- **Invariant:** service cadence should be package-consistent and minute-aligned, with per-host
  phase; endpoint process and CRON/syslog evidence must remain causally coherent, and unrelated
  baseline activity must remain stable enough for the original scenario intent.
- **Entry paths/consumers:** Debian schedule config feeds baseline occurrence planning and then
  canonical process/syslog records, PID allocation, eCAR, and evaluation.
- **Sibling risks:** the scheduler supports other daily, weekly, and 30-minute tasks; this checkpoint
  verifies output quality and whether any new hard/contract defects emerged after the cadence update.
- **Loop question:** independent whole-dataset review on the post-fix output; no additional code
  change is assumed absent concrete evidence. Compare scores with loop79 as separate standalone
  panels, not as a formal A/B experiment.
