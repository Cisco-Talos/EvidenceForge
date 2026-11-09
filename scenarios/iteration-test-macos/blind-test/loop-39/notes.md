# Loop 39: valid credential-bearing CIM caller intent

ExplicitCredentialUseActionBundle now builds PowerShell/pwsh remote inventory with
Get-Credential, New-CimSession -Credential, Get-CimInstance -CimSession and finally
Remove-CimSession. It escapes principal/host literals and invents no password. Both
generated executable adapters share this builder; supplied callers, runas/MMC paths
and caller PID/subject/session ownership remain intact. Renderer or exit-status
patches would hide the invalid action rather than repair its intent.

30 focused tests pass, covering both executables, escaping and existing credential/
runas/Type9 integration. Ruff/format pass. The38probe finds one invalid Get-CimInstance
-Credential caller. Microsoft primary docs confirm the unsupported parameter:
https://github.com/MicrosoftDocs/PowerShell-Docs/blob/main/reference/docs-conceptual/learn/ps101/07-working-with-wmi.md
and credential-bearing New-CimSession semantics:
https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/new-cimsession?view=powershell-5.1 .
This verifies deterministic intent/schema, not live native Windows command execution.

Next: P1 mounted Mac helper terminal outcome (Host36,qualifiedcontractgap,SMB->canonical
process completion owner); P2 SMB baseline cadence; P1 source-local application-child
capture consistency (Network35/36,qualifiedgap). Original priority labels not assigned.
Authored Mac cadence is preserved.

Generation/eval passed96.0944,135877records,119files. CIMprobe now0unsupported
parameters with1session-scoped caller, versus1invalidcaller in38.
