# Loop 5 family contract — macOS routine terminal activity

- **Classification:** `scenario_intent` (authored routine behavior, not an engine defect).
- **Owner:** the `mac-1-terminal-task-*` and `mac-2-terminal-task-*` storyline entries in
  `scenarios/iteration-test-macos/scenario.yaml`.
- **Invariant:** ordinary Mac workstation activity should show Maya's inventory checks near
  session startup without replaying the same ordered system-survey checklist across seven
  entries on both machines. Later entries should reflect varied, shorter system-task groups while keeping
  the existing logon, SSH, app, launch-job, and attack narrative intact.
- **Entry paths:** typed process events in both terminal-task families; the activity, process
  command line, and explicit offsets are authored together.
- **Consumers:** canonical process/session state, macOS Endpoint Security, eCAR, zsh history,
  and blind review.
- **Why this layer owns the truth:** independent reviewers confirmed the process telemetry
  faithfully mirrors the repeated authored checklist. Generator changes would mask the authored
  intent and break the correlation between history, process starts, and endpoint evidence.
- **Change:** retain initial inventory tasks, then vary and shorten later task command groups
  using only the existing Mac process executables and argument profiles. Keep the same time slots
  and host/session boundaries.
- **Sibling risk:** `diagnostic-scenario.yaml` remains the separately labeled partial-coverage
  diagnostic copy and is not the assessed scenario. Verify the main scenario and generated
  Mac process/history evidence after validation and generation.

## Failed first generation and correction

The first loop 5 draft used `/opt/homebrew/bin/git`, `/bin/launchctl`, and `/usr/bin/plutil`.
Complete-coverage generation rejected the resulting Mac processes because the selected native
execution profile lacks qualified executable metadata for those invocations. The failed bundle
and its `.eforge-generation/` controller are preserved at
`/private/tmp/eforge-iteration-test-macos-loop-5`. The scenario was revised to use varied subsets
of commands already covered by the Mac execution profile; no coverage gate or metadata requirement
was weakened. The next attempt uses a fresh output directory.
