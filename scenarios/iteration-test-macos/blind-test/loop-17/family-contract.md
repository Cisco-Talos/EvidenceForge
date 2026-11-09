# Loop 17 family contract: PowerShell ambient file effects

## Root cause and owning layer

`_emit_ecar_file_churn` creates canonical `file_create`/`modify` occurrences through `select_ambient_file_churn_effect`, which chooses a running process and a compatible path independently. The EDR pool permits PowerShell to own generic temporary files, but command semantics are not considered. The shared ambient effect selector owns the process-to-file semantic relationship; emitter changes would only hide the already-created occurrence.

## Required invariant

Ambient shell temporary-file churn may be attributed to a shell process only when the command line indicates a file-producing or file-mutating operation. Preserve normal process attribution for applications with explicit artifact ownership and preserve command-derived file effects handled by canonical command semantics.

## Entry paths and consumers

Entry paths include hourly baseline ambient file churn and typed storyline process commands whose host participates in baseline churn. Canonical file events feed eCAR and Windows Sysmon, with correlated PID, process command line, actor, path, and timestamp. Probe all Windows PowerShell temp writes across the two modeled workstation/server hosts, including both baseline diagnostic and explicit authored commands.

## Sibling risks

The semantic gate applies only to generic ambient temp-file churn. It does not model every PowerShell internal temp-file behavior or change explicit command output artifacts. Non-shell ambient pools and Linux/macOS paths remain unchanged. This is a family-level constraint on synthetic ambient effects, with potential for a later broader process-purpose model if further evidence requires it.
