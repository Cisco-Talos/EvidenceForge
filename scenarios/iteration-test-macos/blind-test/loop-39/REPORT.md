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


## Family contract

# PowerShell explicit-credential caller semantics

Classification: sibling_defect; family_level. Owner: ExplicitCredentialUseActionBundle's caller-intent adapter. Generated PowerShell and pwsh callers must express a valid credential-bearing remote inventory action: credential acquisition, New-CimSession with credentials, Get-CimInstance using that session, and finally session disposal. Never attach unsupported -Credential directly to Get-CimInstance. Escape single-quoted PowerShell literals for host/principal. Baseline/explicit-credential callers and both PowerShell executables share this builder; existing user-provided process callers are preserved. Security4648/process/eCAR consumers render the same generated command and caller identity. The bundle owns behavior intent, so changing a renderer or exit status would mask the error. Preserve runas/MMC adapters and subject/caller/session alignment. Risk: this models a successful credential prompt without inventing a password; it is not a live command execution or native Windows acceptance test.


## Individual expert summaries

**Threat Hunter:** Inconclusive; verdict confidence 82; synthetic-confidence score 44. The collection supports technically credible hunting across Windows, Linux, macOS, network sensors, SMB and an inspecting proxy. I found recurring execution-duration and background-file-access texture that raises suspicion, but did not establish a hard attack-lifecycle contradiction; the observed remote sessions, credential boundaries and transfer chains generally survive cross-source checking. The score reflects mixed evidence with limited synthetic tells, not certainty about the collection's origin.

**Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 20. The supplied telemetry is highly production-like at the schema and correlation layers. Parsing and lifecycle checks found no demonstrated impossible process ordering, identity contradiction, or malformed source structure in the cases examined; the small number of unresolved HTTP file references is compatible with filtered collection. These results support the low synthetic-confidence score, but well-constructed synthetic telemetry could also pass these checks, so they do not establish production provenance.

**Network Forensics:** Real; verdict confidence 64; synthetic-confidence score 30. The network telemetry is mostly production-like: flow accounting, protocol timing, certificate relationships, and proxy routing withstand several checks that commonly expose generated data. My lean toward real is modest, because convincing synthetic telemetry could also satisfy these checks; the clearest reservation is an unusual concentration of iPhone user agents on an address identified as a Mac.

**Host Forensics:** Synthetic; verdict confidence 82; synthetic-confidence score 66. The endpoint evidence is substantially coherent: process identity, visible termination boundaries, Windows process-creation companions, and the macOS fork/exec distinction generally hold up. My synthetic verdict rests on repeated, measurable timing and metadata patterns, especially destination-specific PowerShell-to-SSH delays that recur exactly to the millisecond, rather than on missing sources or a neatly reconstructable incident.


## Scores and comparison

Automated eval 96.0944; standalone synthetic-confidence average 40.00 (mostly realistic), prior loop 52.25. Lower is more production-like. Scores are standalone reviewer measurements; physical/semantic probe outcomes independently verify the selected family.

Facilitator-modeled deliberation averages 49.50; see deliberation.md. Modeled revised positions are excluded from standalone and rolling averages and are not reconvened expert votes.
