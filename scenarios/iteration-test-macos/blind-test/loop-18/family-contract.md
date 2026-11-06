# Loop 18 family contract: canonical PowerShell file-effect admission

## Owning abstraction

`select_file_side_effect()` is the shared process-execution file-effect selector used by action preflight. Baseline ambient churn separately uses `select_ambient_file_churn_effect()`. The loop-17 guard was added only to the baseline selector; fresh output showed process preflight independently emits the same temp-file class. The command-to-file semantic admission belongs in the shared side-effect selector and must be reused by the baseline path.

## Required invariant

PowerShell may receive a generic temp-file side effect only when its command line indicates file output or mutation. A PowerShell network diagnostic or read-only inspection command must not acquire a temp write solely because the process profile has a `shell_temp` entry. Explicit command-derived destinations remain eligible through the existing semantic effect path.

## Entry paths and consumers

Inventory: baseline `_emit_ecar_file_churn` and process-execution preflight both select ambient file effects. Storyline and baseline process starts enter preflight; canonical file events are consumed by eCAR and Windows Sysmon. Tests cover both selectors with a read-only diagnostic and a file-producing PowerShell command. The rendered probe counts all PowerShell `AppData\\Local\\Temp` writes across every Windows host and checks the PID/command tuple.

## Layer rationale and sibling risks

The shared selector owns process-purpose-to-artifact admission; renderer-side filtering would orphan correlated source evidence. This family rule is bounded to generic PowerShell temporary artifacts. It does not infer every PowerShell runtime temp file and does not suppress explicit destination effects or non-PowerShell file profiles.
