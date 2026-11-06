# Assessment Loop 18 — PowerShell file-effect admission

## Result

Loop 18 fixed the shared process-to-file admission rule after loop 17 exposed a second entry path. Both process-execution preflight (`select_file_side_effect`) and baseline ambient churn now require command evidence before a PowerShell process receives a generic temporary-file effect. The `Export-Csv` path remains eligible. This family-level change is at the shared EDR effect selector, where process purpose is matched to file artifacts.

The 83 focused EDR-pool tests pass. Config validation has zero errors (the existing Chrome Helper warning and derived-pool informational note remain). Ruff, format check and behavior validation pass at revision 417. Fresh generation produced 132,196 records and passed one evaluation at 96.349141/100. The 117-file blind copy is byte-identical. A bundle-wide eCAR probe found zero PowerShell writes to `AppData\\Local\\Temp\\tmp*.tmp` across all Windows hosts.

## Blind review

Initial synthetic-confidence scores were Threat 46, Detection 56, Network 64 and Host/EDR 69 (mean 58.75; verdict-confidence mean 79). The verdict split triggered deliberation; modeled revised synthetic-confidence mean is 60.5 and verdict-confidence mean is 74.5. The panel confirms strong cross-source process, SSH, Zeek UID and protocol relationships while retaining texture concerns about Mac shell history, cross-host trace IDs and DMZ Zeek field omissions.

## Next candidate

Host/EDR found a MAC-MROSS-01 receiver shell exec at 16:02:17.723Z before the corresponding `Accepted publickey` Unified Log event at 16:02:18.539Z and eCAR login at 16:02:19.207Z. Loop 19 will trace this through the canonical SSH bundle and startup timing plan; any change must preserve transport-before-auth ordering and be verified across both SSH entry paths.

See `family-contract.md`, `root-cause-probe.md`, `automated-eval.json`, four blind reports and `deliberation.md`.
