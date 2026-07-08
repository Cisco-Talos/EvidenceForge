# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 66
**Synthetic-Confidence Score:** 36

## Executive Summary

The host and EDR telemetry is largely production-like: process trees, logon/session lifecycles, RDP, SSH/SCP, Sysmon/Security, syslog, bash history, and eCAR records line up with believable timing and source-native fields. I did not find a hard contradiction such as logoff-before-logon, process termination before creation, impossible PID/logon reuse, or impossible cross-source ordering. The remaining synthetic concerns are weak distribution/collection-texture signals rather than decisive defects.

## Evidence For Synthetic

- **[weak_signal]** Endpoint collection is unusually tidy and consistently instrumented across Windows hosts. For example, eCAR on WS-AJOHNSON has 503 `FLOW/CONNECT`, 174 `MODULE/LOAD`, 96 `PROCESS/CREATE`, and 70 `PROCESS/TERMINATE`; WS-MCHEN has 470, 254, 104, and 60 in the same broad shape.
- **[distribution_texture]** Linux syslog/admin activity repeats a compact command family across hosts: `journalctl`, `systemctl status`, `find /tmp`, `tail /var/log`, `ss`, `iostat`, and regular `sysstat` CRON rows. Individually normal, but the repeated texture feels curated.
- **[environment_or_collection_plausibility]** Windows endpoint logs include post-window lifecycle tails, e.g. DC Security/Sysmon continue to `2024-03-18T20:09:37Z`, while eCAR files stop near `17:59`. This is explainable by different collectors, but the family-level cutoff asymmetry is a mild collection-profile smell.
- **[weak_signal]** Some custom/internal process metadata is placeholder-like, such as Sysmon `service-healthcheck.exe` rows with `FileVersion`, `Product`, `Company`, and `OriginalFileName` set to `-`. Plausible for unsigned internal tools, but repeated across hosts.

## Evidence For Real

- RDP source and destination telemetry lines up tightly: WS-AJOHNSON creates `mstsc.exe /v:FILE-SRV-01`, opens `10.10.1.35:62752 -> 10.10.2.20:3389`, and FILE-SRV records a matching Type 10 logon from `WS-AJOHNSON-01`.
- SSH/SCP evidence is strong: DB-PROD root bash history, eCAR process/file/flow records, APP-INT syslog, and APP-INT eCAR all agree on `/tmp/rpt_0318.sql.gz` moving over SSH from `10.10.4.10:46080` to `10.10.2.30:22`.
- DC log clearing behavior is source-native: `cmd.exe /c wevtutil cl Security`, child `wevtutil.exe`, Security Event ID `1102`, Sysmon process create/terminate, and eCAR process create/terminate all occur in believable order.
- Windows lifecycle checks were clean: visible Security `4634` logoffs had prior visible `4624` logons when applicable, and Sysmon Event ID `5` process terminations did not precede visible Event ID `1` creates for the same `ProcessGuid`.
- Linux evidence includes realistic session details: `sshd` connection, accepted auth, PAM open, `systemd-logind` new session, close, and removed session records with reasonable timing.

## Detailed Analysis

The best RDP example is WS-AJOHNSON to FILE-SRV. At `2024-03-18T12:31:17.458Z`, WS-AJOHNSON eCAR records `PROCESS/CREATE` for `C:\Windows\System32\mstsc.exe`, `command_line="mstsc.exe /v:FILE-SRV-01"`, `pid=5536`, `principal=aisha.johnson`, `logon_id=0x24de089`. Security Event `4688` follows at `12:31:17.7872212Z` with the same command and parent `C:\Windows\explorer.exe`. Security Event `5156` at `12:31:20.5164291Z` shows `Application=\device\harddiskvolume1\windows\system32\mstsc.exe`, `SourceAddress=10.10.1.35`, `SourcePort=62752`, `DestAddress=10.10.2.20`, `DestPort=3389`. FILE-SRV then records Security `4624` at `12:31:21.8859888Z`, `LogonType=10`, `TargetUserName=aisha.johnson`, `IpAddress=::ffff:10.10.1.35`, `IpPort=62752`, `WorkstationName=WS-AJOHNSON-01`.

The strongest Linux/EDR sequence is DB-PROD to APP-INT. DB-PROD root bash history has `#1710782497` followed by `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`, then `gzip -9 /tmp/rpt_0318.sql`, then `#1710783044` and `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. DB-PROD eCAR records `mysqldump` process create at `17:21:39.095Z`, file create `/tmp/rpt_0318.sql` at `17:21:42.091Z`, gzip creating `/tmp/rpt_0318.sql.gz` at `17:29:09.573Z`, and `scp` flow `10.10.4.10:46080 -> 10.10.2.30:22` at `17:30:48.179Z`. APP-INT syslog independently shows `Connection from 10.10.4.10 port 46080`, `Accepted publickey for root`, session opened, then closed; APP-INT eCAR shows inbound `FLOW/CONNECT`, `USER_SESSION/LOGIN`, file create `/tmp/.cache/rpt_0318.sql.gz`, and logout.

The DC event-clear sequence is also credible. DC Security logs `4688` for `C:\Windows\System32\cmd.exe /c wevtutil cl Security` at `17:41:50.6635452Z`, child `wevtutil cl Security` at `17:41:51.3685452Z`, Security `1102` at `17:41:51.6978749Z`, and `4689` termination for `wevtutil.exe` at `17:41:56.3323943Z`. Sysmon records the same process chain with Event ID `1` for `cmd.exe` and `wevtutil.exe`, then Event ID `5` for `wevtutil.exe`; eCAR records matching process create and terminate records for PID `6504`.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected score |
|---|---|---:|---|
| weak_signal | eCAR / endpoint | Multi-host | Object/action mixes are consistently tidy across hosts, suggesting curated collection texture. |
| distribution_texture | Linux syslog / bash history | Multi-host | Admin noise repeats a compact command pool and regular CRON/sysstat cadence. |
| environment_or_collection_plausibility | Endpoint collection | Family-level | Windows tails extend past the primary window while eCAR stops near `17:59`; explainable but mildly uneven. |

## Realism Score by Category

- **Field format accuracy:** 86 — Windows XML, Sysmon fields, SIDs, logon IDs, IPv4-mapped addresses, syslog RFC5424, and eCAR fields are mostly source-native.
- **Temporal patterns:** 82 — Ordering is believable; no hard lifecycle inversion found.
- **Cross-source correlation:** 88 — RDP, SSH/SCP, DC process activity, file, auth, and eCAR records correlate well.
- **Behavioral realism:** 78 — User/admin activity and process trees are plausible, though some command texture repeats.
- **Environmental consistency:** 80 — Host roles and IPs are coherent; collection-tail asymmetry is the main caveat.

## Recommendations

If synthetic, increase host-specific variation in endpoint collection behavior, especially eCAR tail handling versus Windows Security/Sysmon tails. Broaden Linux administrative noise with more host-role-specific commands and less repeated maintenance texture. Add varied internal binary metadata for recurring custom tools like `service-healthcheck.exe`, or intentionally document them as unsigned/internal in visible telemetry.
