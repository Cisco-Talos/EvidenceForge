# Host/EDR Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 68

## Executive Summary

The dataset has strong host/EDR correlation and many realistic Windows/Linux artifacts, but several endpoint-level patterns look generated rather than naturally collected. The strongest synthetic indicators are improbable process lifetimes clustered near the observation-window end, inconsistent eCAR enrichment for the same process/actor, over-templated bash histories, and a few source-native field oddities that are hard to explain as normal telemetry.

## Evidence For Synthetic

- `WS-SMARTINEZ-01.meridianhcs.local/ecar.json`: `MpCmdRun.exe -SignatureUpdate` PID `6996` starts at `2024-03-18T12:10:10.276Z` and terminates at `2024-03-18T16:43:40.454Z`, a 4.5-hour Defender signature update process. Similar long-lived short-task utilities appear across hosts and often terminate near the dataset end.
- `DC-01.meridianhcs.local/ecar.json`: short-lived maintenance-style processes have multi-hour lifetimes, including `TiWorker.exe -Embedding` PID `4612` from `13:48:47.507Z` to `17:59:25.444Z`, `dllhost.exe /Processid:{3EB3C877-...}` PID `4224` from `13:46:53.099Z` to `17:54:07.591Z`, and `conhost.exe 0x4` PID `4424` from `13:49:30.665Z` to `17:50:35.969Z`.
- `FILE-SRV-01.meridianhcs.local/ecar.json`: `wsqmcons.exe` PID `4988` runs from `12:42:03.974Z` to `16:55:36.269Z`; `WmiPrvSE.exe -secured -Embedding` PID `5172` runs from `13:45:51.223Z` to `17:56:48.401Z`. These look like lifecycle completion was synthesized rather than observed.
- `WS-AJOHNSON-01.meridianhcs.local/ecar.json`: the same process identity, PID `4500` / actorID `d6838af7-c652-464d-ba11-0f21214f4414`, alternates between flows with `principal:"NETWORK SERVICE"` and flows with no principal. Example: lines around timestamps `1710780493616`, `1710780493749`, `1710780493750`, and `1710780493770` show adjacent proxy connections by the same process with inconsistent principal enrichment.
- `DB-PROD-01.meridianhcs.local/bash_history/omar.haddad.bash_history` and `WS-OHADDAD-01.meridianhcs.local/bash_history/omar.haddad.bash_history`: the command mix is repetitive and templated: many `mysqldump --single-transaction --routines <db> > /tmp/<name>_backup.sql`, `mysql -u root -p -e ...`, and `psql -c ...` commands. On `WS-OHADDAD-01`, database-admin commands lack remote host parameters, implying local DB operations on a workstation.
- Multiple bash histories include typo-like one-word commands at convenient intervals: `xat`, `whih`, `juornalctl`, `catt`, `sss`, `unmae`, `lk`. Real users mistype, but the distribution reads deliberately sprinkled.
- `zeek-dmz/x509.json`: the repeated `CN=R3, O=Let's Encrypt, C=US` intermediate has `certificate.not_valid_after: 1921143722` while being presented as R3. That validity profile is not consistent with the common Let's Encrypt R3 intermediate and looks template-derived.

## Evidence For Real

- `DC-01.meridianhcs.local/windows_event_sysmon.xml` shows a plausible PsExec service chain: `PSEXESVC.exe` PID `6056` created by `services.exe` at `2024-03-18T15:59:47.201Z`, then `cmd.exe /c whoami && hostname` PID `6064` as a child at `15:59:48.621Z`.
- The later destructive activity is well-correlated: `DC-01.meridianhcs.local/ecar.json` has PowerShell PID `6504` at `17:42:08.170Z`, proxy flow to `10.10.3.20:8080` at `17:42:09.761Z`, and `wevtutil cl Security` PID `6512` at `17:42:10.039Z`.
- `zeek-core/conn.json` line `4399` and `zeek-dmz/conn.json` line `6354` both show the corresponding DC-to-proxy connection: `10.10.2.10:54825 -> 10.10.3.20:8080`, `service:http`, duration about `4.229s`.
- `DC-01.meridianhcs.local/windows_event_security.xml` records `wevtutil cl Security` immediately before Security log clear event `1102` at `2024-03-18T17:42:12.0190916Z`; `EventRecordID` resets to `2`, then continues at `3`, which is realistic after a Security log clear.
- `WS-MCHEN-01.meridianhcs.local/windows_event_security.xml` has a clean type-3 session lifecycle: `4624` for `marcus.chen` from `::ffff:10.10.2.10` at `14:19:14.3365601Z`, `TargetLogonId 0x6d49830`, followed by `4634` for the same logon ID at `14:19:28.2964257Z`.
- Windows event formats are mostly source-native: Security uses decimal `EventRecordID`, hex process/logon IDs, IPv4-mapped remote addresses, and Sysmon includes plausible `ProcessGuid`, `Hashes`, `ParentProcessGuid`, and `CallTrace` fields.

## Detailed Analysis

### Windows Process Tree and Attack Chain

The DC attack sequence is internally coherent. PsExec-style service installation and execution are visible in Sysmon and eCAR. `PSEXESVC.exe` PID `6056` is created by `services.exe`, then launches `cmd.exe`, `sc.exe create DeviceSyncSvc`, `schtasks.exe /Create`, encoded PowerShell, `wevtutil cl Security`, and later `net user svc_mhsync /delete /domain`. That is a plausible intrusion chain and the parent/child lineage is strong.

The issue is not the attack chain itself; it is the surrounding endpoint lifecycle. Many background utilities that should normally be short-lived or independently scheduled have very long durations and terminate late in the window. The pattern is especially visible in Defender, TiWorker, conhost, wsqmcons, dllhost, SearchProtocolHost, and WmiPrvSE records. That suggests lifecycle completion was generated to close processes rather than observed naturally.

### Logon Session Lifecycle

Security logon handling is one of the more realistic parts of the dataset. Type 3 network logons often have paired 4634 events with matching logon IDs, and DC Kerberos volume is plausible for a domain controller. Failed interactive logons use believable status/substatus pairs such as `0xc000006d` / `0xc000006a`.

The eCAR session layer is weaker. Several hosts show logout events with sparse context or session type mismatches. For example, `DB-PROD-01.meridianhcs.local/ecar.json` records `priya.patel` remote login from `10.10.4.10` at `13:21:27.023Z`, then a `LOGOUT priya.patel` with `session_type:"local"` at `13:23:31.805Z`. Without session IDs this is not impossible, but it reduces authenticity.

### eCAR Process and FLOW Consistency

The best eCAR-to-network correlation is very good. The DC PowerShell PID `6504` flow to the proxy appears in eCAR, Zeek core, and Zeek DMZ with the same tuple and near-identical timing. Windows host eCAR also lines up with Sysmon process IDs in key places.

However, eCAR enrichment is uneven. The same long-running `svchost.exe` PID `4500` on `WS-AJOHNSON-01` repeatedly generates proxy and SMB flows, but principal attribution alternates between missing and `NETWORK SERVICE` even when actorID and PID are stable. That feels like optional-field generation inconsistency more than normal EDR behavior.

### Linux Syslog and Bash History

The bash histories include realistic admin activity: `journalctl`, `systemctl`, `ss`, `tail`, `mysqldump`, `kubectl`, `certbot`, and filesystem inspection. Timestamped bash history format is plausible.

The behavioral mix is too patterned. DB-related histories repeat the same families of commands with variable database names and output filenames. Workstation-local database commands on `WS-OHADDAD-01` lack `-h` or explicit remote targets. The typos look intentionally injected rather than naturally distributed.

### Environmental Consistency

The environment is broadly coherent: `DC-01`, `FILE-SRV-01`, `PROXY-01`, `WEB-EXT-01`, `APP-INT-01`, and `DB-PROD-01` roles align with observed traffic. Internal DNS responses map hostnames to expected RFC1918 addresses, and proxy-mediated HTTP/HTTPS traffic is consistent across host and Zeek records.

The main environmental weakness is that some endpoint background behavior appears generated from reusable pools. The same command shapes, Windows process lifetimes, and repeated maintenance artifacts appear across hosts in a way that is statistically tidy.

## Realism Score by Category

- **Field format accuracy:** 8/10 - Windows, Sysmon, eCAR, and Zeek fields are mostly source-native, with a few suspicious certificate and enrichment artifacts.
- **Temporal patterns:** 5/10 - attack timing is coherent, but long-lived short-task processes and clustered late-window terminations look synthetic.
- **Cross-source correlation:** 9/10 - key process, flow, Security, Sysmon, and Zeek records align strongly.
- **Behavioral realism:** 6/10 - user/admin actions are plausible individually but repetitive and templated in aggregate.
- **Environmental consistency:** 7/10 - host roles, IPs, and services mostly agree, though workstation/server command placement is sometimes questionable.

## Recommendations

- Model process lifetimes by executable family; avoid multi-hour lifetimes for update, telemetry, conhost, and short maintenance utilities unless there is a specific reason.
- Add stable session IDs to eCAR user session records and ensure logout `session_type` matches the originating login.
- Keep principal enrichment stable for the same process identity unless the source has a clear reason to omit it.
- Reduce bash-history templating by varying command intent, errors, pauses, working-directory behavior, and host-appropriate tooling.
- Validate source-native certificate chains and validity windows rather than reusing generic issuer templates.
