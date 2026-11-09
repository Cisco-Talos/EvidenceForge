# Loop 15 family contract — persona-specific Linux shell histories

## Owning layer

`bash_commands.py::_get_role_pool` and the YAML command/workflow pools in
`config/activity/bash_commands.yaml` own Linux interactive-history task selection. In the current
environment, executive, accountant, and sales personas have no pools and fall back to the generic
sysadmin vocabulary. The common pool and shared workflows also supply the same host-inspection
language to otherwise distinct users.

## Invariant

On Linux workstations, user shell-history commands should reflect the modeled persona and desktop
context, not a generic sysadmin checklist. On servers, the command pool must remain compatible with
the host role and services; adding a workstation persona must not route that persona's desktop
commands onto server sessions. Preserve event/process/session correlation and deterministic
per-user selection.

## Entry paths and consumers

Baseline SSH and assigned-user shell activity call `pick_bash_session_commands`, which resolves the
persona pool and selects coherent workflows before producing canonical `bash_command` events and
correlated process/network activity. The `bash_history` emitter consumes those canonical events.
Storyline-authored commands and Mac `zsh_history` generation are separate paths and remain outside
this loop's fix.

## Sibling risks

Verify at least one Linux workstation persona and one Linux server session. Check both ordinary
command selection and multi-command workflow selection. Confirm recognized IT personas keep their
current server-oriented pools, and validate all YAML pools and workflow references with
`eforge validate-config`.

## Why this layer owns the truth

The report points to command-vocabulary repetition across users and hosts. The picker currently
falls back to `sysadmin` for unsupported persona names, and the YAML file owns the role-specific
command/workflow vocabulary. Adding persona-appropriate pools and mapping only on workstation-like
hosts corrects selection before canonical events are created; emitter changes would not change the
commands themselves or their correlations.
