# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 79
**Synthetic-Confidence Score:** 56

## Executive Summary

The dataset is operationally convincing: host roles, hunt pivots, proxy behavior, endpoint/network timing, and the visible compromise lifecycle are unusually coherent without hard contradictions. Its strongest synthetic tell is the interactive SSH fabric—106 logins in six hours, with named users sustaining up to seven concurrent sessions—plus several short-lived commands that remain open indefinitely.

## Evidence For Synthetic

- `[distribution_texture]` Linux telemetry contains 106 successful SSH logins in six hours: 42 by `marcus.chen`, 41 by `aisha.johnson`, and 16 by `lina.nguyen`. Peak concurrency is seven sessions each for Marcus and Aisha and five for Lina. At 13:52:09, Aisha simultaneously holds seven sessions across DB-PROD-01, MAIL-CLIN-01, MAIL-EDGE-01, and WEB-EXT-01, including duplicate sessions to three hosts; examples are `DB-PROD-01.../ecar.json:214,239`, `MAIL-CLIN-01.../ecar.json:185`, `MAIL-EDGE-01.../ecar.json:159,219`, and `WEB-EXT-01.../ecar.json:968,1115`.
- `[environment_or_collection_plausibility]` This SSH volume is concentrated in three human identities rather than automation accounts. The distribution—Aisha 41, Marcus 42, Lina 16 sessions, with 61 of 100 paired sessions lasting more than 20 minutes—creates a persistent multi-terminal administration pattern across public web, mail-edge, database, proxy, and application roles.
- `[contract_gap]` A process lifecycle join by eCAR `objectID` found three non-following `tail` commands on PROXY-01—`tail -20`, `tail -50 /var/log/auth.log`, and `tail -200`—created at 15:37:52, 15:54:51, and 15:55:00 without `-f` and without a terminate record through 17:59:55 (`PROXY-01.../ecar.json:1720,1928,1933`). `du -h /tmp/rpt_0318.sql` similarly starts at 17:17:52 and never terminates (`DB-PROD-01.../ecar.json:631`). These are visibly one-shot commands, not merely pre-window state.
- `[contract_gap]` DC-01 registers and runs `C:\Windows\System32\DeviceSyncSvc.exe`, but the eCAR file contains zero `FILE` events for that path despite 12 service/process/module references. Service creation appears at `DC-01.../ecar.json:4173` and execution at line 4367. This is not impossible—the binary may predate the window—but it is conspicuous beside the explicit PSEXESVC drop at line 3886.
- `[weak_signal]` Some remote execution parentage is source-native but operationally odd. On FILE-SRV-01, `net view` launches under `WmiPrvSE.exe`, while the immediately following `Compress-Archive` launches under `svchost.exe -k netsvcs`, both as `svc_mhsync` in logon `0xf885947` (`windows_event_security.xml`, 17:01:10.654 and 17:01:13.118; `ecar.json:1476,1494`). Token impersonation can explain this, so it is not a contradiction.

## Evidence For Real

- The source mix is substantial and role-aware: 25,321 eCAR records, 20,566 Zeek records, 13,799 Security events, 4,148 Sysmon events, 12,376 firewall lines, 4,322 syslog lines, 2,191 proxy rows, 952 web rows, and 189 IDS alerts across Windows and Linux endpoints, servers, DMZ sensors, and perimeter controls.
- The initial web compromise is temporally credible. WEB-EXT-01 records Apache spawning a base64-decoding shell at 13:19:44.843 (`WEB-EXT-01.../ecar.json:957`), endpoint flow telemetry at 13:19:46.670 (`:958`), and Zeek sees the 10.10.3.10:34169 → 45.33.32.30:8443 connection starting at 13:19:45.268 for 24.232 seconds (`zeek-dmz/conn.json:1433`). Endpoint observation remains inside the network-visible interval.
- Windows privilege and persistence activity has credible native sequencing: PSEXESVC drop/service/start at 16:00:07–16:00:09; account creation and Domain Admin membership at 16:14:33–16:14:40; service/task installation at 16:20:17–16:20:31; and service start at 16:29:10. Security, Sysmon, and eCAR retain consistent PIDs and parentage.
- Collection staging and exfiltration are huntable rather than implied. FILE-SRV-01 creates `cache_7f3a.zip` at 17:01:13; WS-AJOHNSON-01 starts its SMB copy at 17:17:04, records the destination file at 17:24:55, and Chrome reads it at 17:24:57. Proxy rows 1857–1858 then show Aisha uploading 314,782,707 bytes at 17:25:30.
- Database collection is similarly complete: DB-PROD-01 runs `mysqldump` at 17:17:07, creates `/tmp/rpt_0318.sql`, compresses it at 17:30:59, reads it with `scp` at 17:32:46, opens TCP/22 at 17:32:47, and APP-INT-01 records receiver-side creation at 17:32:51 (`DB-PROD-01.../ecar.json:624-625,694-695,706-708`; `APP-INT-01.../ecar.json:667`).
- C2-like proxy traffic is irregular rather than clockwork. Fourteen proxy egress connections to 45.33.32.30 from 16:29:55 through 17:59:55 have successive gaps ranging from 4.865 to 789.676 seconds. Proxy policy also denies direct IP-literal CONNECT attempts while allowing the named host, visible at `proxy_access.log:1539,1707,1992` versus lines 1519–1520 and later check-ins.
- Cleanup semantics are source-native: `wevtutil cl Security` appears at 17:42:03, Security Event 1102 follows at 17:42:03.663, and subsequent Security `EventRecordID` values restart from 1. The temporary domain account is deleted at 17:50:29–17:50:38.
- Network texture includes failed scans, resets, missed bytes, variable TLS resumption/certificate visibility, and uneven source-family volumes. These imperfections argue against an overly idealized collection.

## Detailed Analysis

### Huntability and attack lifecycle

The visible sequence supports reliable pivots from an exposed web process to outbound C2, remote administration, identity persistence, collection, and cleanup. Process GUID/object identity, PID, user, session, file, and network tuples survive across endpoint and source-native records.

The highest-value sequence is:

1. Apache → encoded shell on WEB-EXT-01 at 13:19:44.843.
2. Direct reverse connection to 45.33.32.30:8443 at 13:19:45–13:20:09.
3. PSEXESVC installation and SYSTEM execution on DC-01 at 16:00.
4. `svc_mhsync` creation and Domain Admin membership at 16:14.
5. DeviceSync service/task persistence at 16:20 and proxy check-ins beginning 16:29.
6. `svc_mhsync` network logon from 10.10.1.35 to FILE-SRV-01 at 17:01:08, followed by archive creation.
7. Endpoint staging and a 314.8 MB browser upload at 17:25.
8. Database dump, gzip, and SCP staging at 17:17–17:32.
9. Bash-history clearing, Security-log clearing, and account deletion at 17:41–17:50.

This is strong operational telemetry. I found no dependent event whose visible initiator occurs later, and I did not count completeness or narrative compactness against authenticity.

### Signal-to-noise and source-family mix

The compromise is embedded within far larger baseline volumes: thousands of DC authentication/firewall events, 11,784 Zeek connections across two sensors, proxy browsing, server health processes, scanner traffic, DNS-policy alerts, ordinary SSH administration, and workstation activity.

The mix is structurally plausible by role. DC-01 is authentication-heavy; WEB-EXT-01 and PROXY-01 are dominated by inbound and relay flows; workstations are predominantly outbound; DB-PROD-01 receives database traffic; FILE-SRV-01 receives SMB activity. Public addresses do not cross over between inbound-scanner and outbound-service roles in the two Zeek connection datasets.

### Session and process lifecycle

Of 106 SSH logins, 100 have matching logout records. That is good lifecycle coverage, and the six unpaired sessions are compatible with the window ending. The defect is behavioral distribution: three named humans repeatedly maintain five to seven simultaneous sessions, often multiple sessions to the same host, for a cumulative 106 logins in only six hours.

Most process lifecycles are also coherent. The exceptions are visibly terminating utilities with no terminate record: three plain `tail` invocations and one `du`. Because their creation occurs well inside the window and their commands do not request continuous execution, bounded-window extraction does not explain them.

### Host-role plausibility

The host-role model is generally convincing. The main concern is the breadth of interactive access: workstation identities directly administer DB, mail-edge, public web, proxy, and application servers, including repeated parallel sessions. A real organization can operate this way, but the repeated distribution across several users resembles generated “remote administration texture” more than role-governed access.

### Quantitative probes

- eCAR records: 25,321.
- Zeek records: 20,566.
- Successful SSH logins: 106; paired logout: 100.
- SSH users: Marcus 42, Aisha 41, Lina 16, root 4, Priya 3.
- Peak concurrent SSH sessions: Marcus 7, Aisha 7, Lina 5.
- Paired SSH duration: median 1,359.326 seconds; 61/100 exceed 20 minutes.
- Non-terminating plain one-shot commands found: three `tail`, one `du`.
- Proxy egress to 45.33.32.30: 14 connections; successive gaps 4.865–789.676 seconds.
- DeviceSync binary references in DC eCAR: 12; corresponding `FILE` records: 0.
- Public IPs observed in both inbound-originator and outbound-destination roles across Zeek: 0 of 585.

## Synthetic Indicator Summary

| Priority | Category | Affected source family | Scope | Effect on score |
|---|---|---|---|---|
| P1 | `distribution_texture` | Linux eCAR/syslog/SSH | Dataset-wide across six servers | The 106-login, 5–7-concurrent-session fabric is the strongest generator-like operational pattern. |
| P2 | `contract_gap` | Linux eCAR process lifecycle | Repeated on PROXY-01; isolated on DB-PROD-01 | Plain `tail` and `du` commands remain alive despite inherently finite execution. |
| P2 | `contract_gap` | Windows eCAR/Sysmon file and service lifecycle | One persistence family on DC-01 | A newly registered and executed binary has no visible file evidence under a profile that records related drops. |
| P3 | `weak_signal` | Windows process parentage | One remote execution sequence | Adjacent remote commands switch from WMI to service-host parentage without visible orchestration. |

## Realism Score by Category

- **Field format accuracy:** 9 — Source-native fields, identities, paths, event IDs, proxy semantics, and network tuples are highly credible.
- **Temporal patterns:** 7 — Attack and cross-source ordering are strong; SSH concurrency and orphaned one-shot processes reduce realism.
- **Cross-source correlation:** 9 — Pivots remain consistent without visible impossible ordering.
- **Behavioral realism:** 6 — The attack lifecycle is plausible, but the interactive administration distribution is difficult to accept as ordinary.
- **Environmental consistency:** 7 — Host roles and source volumes fit; direct multi-server access by a small set of users is overrepresented.

## Recommendations

If this were synthetic, the highest-value improvements would be:

1. **P1: Make interactive SSH state role- and session-aware.** Reduce new-session frequency, reuse existing sessions, cap per-human concurrency, and favor bastions, named admin identities, sudo, and automation accounts. Preserve occasional parallel sessions, but avoid multiple long-lived sessions to the same server from the same workstation.

2. **P2: Enforce executable-aware process lifecycles.** Plain `tail`, `du`, `file`, `stat`, and similar one-shot utilities should terminate promptly. Reserve long-lived `tail` state for `-f`/`-F`, pipes blocked on input, or explicit detached execution.

3. **P2: Complete service-binary provenance.** When a service is newly registered and executed inside the visible window, provide a plausible preexisting-state explanation or render the download/copy/file-create evidence that placed the binary. Apply this consistently across Security, Sysmon, and eCAR.

4. **P3: Clarify remote-command ownership.** Keep WMI, service-control, task-scheduler, and impersonated service-host entry paths distinct enough that adjacent commands have explainable parentage and token ownership.
