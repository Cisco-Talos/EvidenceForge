# Linux foreground task and think-time distribution

Classification: sibling_defect / family_level. Owner: the shared
`baseline.foreground_think` timing relationship, consumed by the canonical Linux
foreground-process owner after process termination.

Invariant: terminal command starts remain ordered after the prior command's actual
completion and modeled shell wakeup, while the user's next-task decision pause can
range from a short follow-up to a multi-minute review. The configured pause must not
be a narrow fixed window that can reinforce a schedule across unrelated commands.

Entry paths: baseline Linux user activity routed through bash history and inferred
foreground processes; typed storyline shell commands that use the same process
foreground owner are sibling paths. Source-specific history, eCAR process telemetry,
and shell availability state consume the resulting canonical times.

The activity profile owns this relationship because the observed concern is the
human decision interval after real process completion. Shell-history formatting and
eCAR rendering only expose those times. Broader profile bounds should preserve the
existing minimum and the foreground process lifetime owner; no timestamps are
rewritten downstream.

Sibling risk: a broader decision-pause window affects Linux foreground command
spacing anywhere this shared profile is used. It does not change macOS/Windows timing,
authored event anchors, process lifetimes, or source-observation delay. Verify unrelated
Linux shell commands remain ordered and correlate to their process starts.
