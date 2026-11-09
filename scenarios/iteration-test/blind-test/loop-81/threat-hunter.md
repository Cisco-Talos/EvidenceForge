# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 66  
**Synthetic-Confidence Score:** 42

## Executive Summary

The dataset looks like a plausible mixed healthcare enterprise collection covering roughly six hours on 2026-11-02, with Windows, Linux, macOS, eCAR, proxy, firewall, IDS, and three Zeek vantage points. Several high-risk sequences pivot cleanly across endpoint and network sources, including an approximately 18.8 MB upload from WS-AJOHNSON-01 and a database dump copied from DB-PROD-01 to APP-INT-01. I found one low-weight distribution concern in repeated perimeter probing, but no hard contradiction that resolves whether the data is production or generated telemetry.

## Evidence For Synthetic

- [weak_signal] `zeek-dmz/conn.json` records 173 connections from the same public source (`185.220.163.140`) to `10.10.3.10` between 13:00:05 and 18:57:00 UTC. Most target a fixed short set of database/search ports (1433: 54, 3306: 42, 5432: 38, 6379: 20, 9200: 10) and are `S0` with no payload. This is consistent with a real scanner, but the long-lived concentration on one target and fixed service set is a modest distribution-texture concern.
- [weak_signal] The visible activity and telemetry are dense and pivot-friendly across many source families. That can result from a well-instrumented environment; without a source-native mismatch or an implausible collection contract, the alignment itself is not evidence of synthesis.

## Evidence For Real

- `WS-AJOHNSON-01.meridianhcs.local/ecar.json` records Aisha Johnson's `curl.exe` at 18:24:58.049 UTC posting `C:\ProgramData\Microsoft\cache_7f3a.zip` to `/upload/telemetry/7f3a2b19`. At 18:25:00.864, the same PID reads the archive; at 18:25:01.163, its FLOW connects from `10.10.1.35:59155` to proxy `10.10.3.20:8080`. `PROXY-01.meridianhcs.local/proxy_access.log` lines 3943–3944 show the matching `curl/8.4.0` tunnel and POST from Aisha's workstation, reporting about 18.8 MB client data. `zeek-dmz/conn.json` has the matching tuple, successful `SF` state, and 18,810,608 origin bytes. The small byte-count differences are compatible with different layer accounting.
- A second coherent transfer is visible at 18:15–18:18 UTC: `DB-PROD-01.meridianhcs.local/ecar.json` records root running `mysqldump` for `ehr patients insurance_claims`, gzipping `/tmp/rpt_0318.sql`, then using `scp` to `10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. The SSH FLOW, Zeek internal connection, and `APP-INT-01.meridianhcs.local/ecar.json` target-side file creation at 18:16:08 agree on direction and timing. This is suspicious activity, but its source, destination, and lifecycle are technically coherent.
- The external probes have independent corroboration rather than being isolated endpoint assertions. For example, `zeek-dmz/conn.json` shows `185.220.163.140:41515` to `10.10.3.10:6379` at 13:00:05 as `S0`; `fw-perimeter/cisco_asa.log` lines 7 and 10 show the inbound connection and its 30-second zero-byte SYN timeout. `snort-perimeter/snort_alert.log` also records ICMP probes from that source to the same DMZ host.
- Background activity is varied across roles: Linux syslogs include sudo/PAM, cron/sysstat, and service maintenance; Windows endpoint logs include process and filtering events; the proxy includes a mixed set of user and service traffic. Linux sysstat's near-ten-minute cadence is consistent with a scheduled job and is not, by itself, a synthetic indicator.

## Detailed Analysis

### Scope and window

The directory contains Windows Security/Sysmon and eCAR records, Linux syslog and shell histories, macOS Unified Log/Endpoint Security and eCAR, proxy and web access logs, Cisco ASA and Snort logs, and Zeek `conn`, `dns`, `http`, `ssl`, `files`, and related records. Most timestamped sources span 2026-11-02 13:00–18:59 UTC. I evaluated lifecycles within that visible interval; a missing process/session start before collection or close after collection is not a synthetic indicator by itself.

### Perimeter activity and pivots

The principal unsolicited activity is the scan of the DMZ web host. The 173 observed Zeek connections from `185.220.163.140` are mostly single-SYN attempts to database/search services with `S0` state and zero application bytes. The ASA records matching inbound attempts and 30-second `SYN Timeout` teardowns; Snort alerts show ICMP echo probes from the same source. These are plausible hostile internet probes, not successful database sessions, and their cross-source agreement supports a real collection path. The concentration on a single scanner and service set is the only weak texture cue I retained.

### Endpoint-to-network exfiltration pivot

At 18:24:58 UTC on WS-AJOHNSON-01, Aisha's `curl.exe` uses multipart upload for a ZIP archive stored under `C:\ProgramData\Microsoft`. The eCAR file-read event and process command line identify the same path and upload endpoint. The workstation-to-proxy tuple, proxy POST, and Zeek byte volume agree within expected differences in accounting layers. The proxy reports a successful HTTP 200 response. The evidence is concerning operationally, but it contains no impossible visible ordering or broken ownership correlation.

### Linux-to-Linux transfer

At 18:15 UTC on DB-PROD-01, root creates a database dump and compressed archive, then starts `scp` to APP-INT-01. The source eCAR, SSH transport, and target file event form a plausible causal chain. A transfer of patient-related data to an application host is high risk and merits investigation, but does not indicate synthetic origin by itself.

### Endpoint and background realism

The Linux syslogs show source-native syslog-style records, sudo sessions, cron/sysstat, and service activity. Shell histories contain role-appropriate administrative and engineering commands, though shell history is not a complete record of execution. Windows Security counts are dominated on the domain controllers by Event 5156 filtering events and include authentication and process events; workstations show lower event volume. The macOS Endpoint Security exports carry version 11 records with audit tokens, PID versions, signing identities, and event payloads. I did not find a demonstrated source-native contradiction in the representative records examined.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `weak_signal` | Zeek DMZ / ASA / Snort | 173 inbound attempts from one source to one DMZ host over about six hours; mostly a fixed set of database/search ports and SYN-only failures | Slight upward adjustment. A real internet scanner could produce this pattern, and the sensor/firewall/IDS evidence corroborates it. |

## Realism Score by Category

- **Field format accuracy:** 8 — Representative eCAR, Zeek, proxy, ASA, and endpoint records use plausible source-native fields and values.
- **Temporal patterns:** 8 — Event times are varied; the scan cadence is irregular, and the visible transfers have credible sequencing.
- **Cross-source correlation:** 9 — The tested Windows upload and Linux SSH transfer correlate across endpoint, network, proxy/firewall, and target evidence.
- **Behavioral realism:** 7 — Activity mixes ordinary system/user behavior with high-risk actions that are technically workable; the targeted scan remains a modestly concentrated pattern.
- **Environmental consistency:** 7 — Host roles and services generally fit the observed traffic, though the single-source concentration at the DMZ web server is unusual.

## Recommendations

- If this were synthetic, vary the perimeter scanner's source/target rotation or service mix only if the intended collection model calls for broader internet background traffic; the current repeated probes remain plausible as one external scan.
- If this were synthetic, retain the upload and database-transfer evidence across endpoint, proxy/network, and destination sources. Their current timing and tuple/file joins are coherent and improve huntability without relying on completeness as an authenticity clue.
