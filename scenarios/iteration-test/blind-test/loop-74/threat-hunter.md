# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive

**Verdict Confidence:** 68

**Synthetic-Confidence Score:** 34

## Executive Summary

The strongest activity is a plausible pivot from the externally exposed WEB-EXT-01 host (10.10.3.10) into APP-INT-01 (10.10.2.30) over SSH as root. The same source/destination tuple and source port recur in endpoint flow records, firewall state, Zeek, the IDS alert, and APP-INT-01 authentication/session logs. The connection remains open for roughly 3 hours 42 minutes, with target-side session closure near the network teardown. A nearby failed SSH attempt from the same source to another internal server strengthens the scan-and-pivot interpretation.

I found no clear impossible ordering or role contradiction. Linux authentication, Windows process/security telemetry, network sensors, firewall, proxy, and web records provide useful pivots, with substantial ordinary service and user activity around the suspicious events. The visible evidence supports a realistic incident reconstruction, but coherent correlated records can also be generated; it cannot establish provenance. Synthetic-confidence is therefore low-to-moderate, with an inconclusive verdict.

## Evidence For Synthetic

- **[weak_signal]** The EDR-like `ecar.json` records use a uniform normalized `object`/`action` schema across Windows, Linux, and macOS, while the native endpoint records differ by platform. This is a plausible normalized collector design, but the uniformity means the normalized layer alone is weak evidence of independently collected production telemetry. For example, WEB-EXT-01's SSH flow at 15:14:37 has no PID or principal, while neighboring flows on the same host do carry `systemd-resolve` or `www-data` process attribution (`WEB-EXT-01/ecar.json`, records 2612–2615). This is an attribution gap, not a contradiction.
- **[weak_signal]** On the exposed WEB-EXT-01 host, the root SSH pivot is well represented in network and target-authentication evidence, but the source-side EDR flow has no process identity and the visible shell histories do not independently account for the initiating command. This limits the source-process pivot; it does not disprove the connection, which is corroborated elsewhere.
- No `hard_contradiction` or `contract_gap` was established from the visible records. I do not treat source coverage gaps, selected Sysmon event absence, or cross-source agreement by itself as evidence of synthesis.

## Evidence For Real

- At 15:14:36–15:14:37, the firewall builds inbound TCP connection 1685305 for 10.10.3.10:54214 → 10.10.2.30:22; Snort flags that tuple as a potential SSH scan (`fw-perimeter/cisco_asa.log`, record 9625; `snort-perimeter/snort_alert.log`, record 41). WEB-EXT-01 and APP-INT-01 EDR flow records show the same tuple and direction (`WEB-EXT-01/ecar.json`, record 2614; `APP-INT-01/ecar.json`, record 216).
- APP-INT-01 then records `Accepted password for root` from 10.10.3.10:54214 and opens a root session at 15:14:50 (`APP-INT-01/syslog.log`, lines 120–121). Its EDR login record carries the same source tuple and session ID (`APP-INT-01/ecar.json`, record 217). This sequence is temporally credible: transport starts before authentication.
- Zeek observes the same SSH tuple as a successful `SF` connection with substantial two-way traffic and a duration of about 13,342 seconds (`zeek-core/conn.json`, matching UID `CjjgjHcv3CppdD3pTN0`). The firewall records teardown for connection 1685305 after about 3:42, and APP-INT-01 records closure of that root session at 18:57 (`fw-perimeter/cisco_asa.log`, record 21944; `APP-INT-01/syslog.log`, line 236; `APP-INT-01/ecar.json`, record 749). The close times are close enough for source-specific timing and collection delay.
- At 15:14:42, WEB-EXT-01 also attempts SSH to 10.10.3.20:22 with a failed outcome (`WEB-EXT-01/ecar.json`, record 2615), shortly after the successful path to APP-INT-01. That supports an operator probing multiple internal targets, rather than an isolated unexplained flow.
- The surrounding records include ordinary Linux services and commands (for example, `snapd`, `irqbalance`, `systemd`, cron/sysstat, and maintenance commands in `LOG-MON-01/bash_history/marcus.chen.bash_history`) alongside incoming web traffic and failed external probes on WEB-EXT-01. The activity has meaningful background volume rather than only attack-shaped rows.
- Windows activity also has a plausible pivot chain: WS-MCHEN-01 records PowerShell launching `ssh.exe` to internal Linux hosts and a `runas.exe /netonly` invocation that checks `\\DC-01\ADMIN$` (`WS-MCHEN-01/windows_event_sysmon.xml`, records around the 13:08, 15:49, and 16:14–16:15 events; `WS-MCHEN-01/windows_event_security.xml`, 4648 at 15:49:36). Security events show network logons from that workstation, and DC/file-server telemetry supplies broader network and SMB context. I did not establish that those records prove this specific share check succeeded. This is actionable pivot material, though the 4648 event's `IpAddress` is `-`, so that event alone does not prove the remote destination.

## Detailed Analysis

### Lifecycle coherence

The clearest lifecycle is the WEB-EXT-01 → APP-INT-01 SSH session. Transport open precedes SSH authentication and session open. Zeek records a completed bidirectional SSH connection (`SF`), while the target syslog and EDR each record the root session close. The firewall's teardown occurs within seconds of the target close. The duration and byte counts are compatible with a long interactive session, not a short failed handshake. The pre-authentication failed SSH attempt from the same source to another internal server fits reconnaissance or access testing.

Other Linux SSH records generally show the expected sequence of connection, accepted or failed authentication, PAM session open, and session close. I found no basis for treating a session extending toward the end of the visible window as orphaned: the inspected APP-INT-01 root session does close within the observed window.

### Pivot feasibility and tradecraft

The most defensible hunt path is the externally exposed WEB-EXT-01 address 10.10.3.10, then source port 54214, then APP-INT-01 root session ID 360 / EDR session ID `764684d0-aab2-4b63-b15a-ba51708123b1`. The IDS scan alert, firewall connection ID, Zeek UID, host authentication, and EDR flow/session records give independent pivots by tuple, time, and identity. Investigate the source host's process accounting and shell/audit logs around 15:14, then review activity under the APP-INT-01 root session. The visible EDR flow lacks source PID/principal, so process attribution is the primary remaining gap.

A separate Windows path starts at WS-MCHEN-01: PowerShell launches SSH clients, and `runas.exe /netonly` is followed by an explicit-credential event and a command touching the DC administrative share. This is suspicious, but it is not intrinsically malicious: the actual share access and privilege outcome should be confirmed in target-side records. The records provide feasible host/user/time pivots and do not rely on narrative completeness.

### Signal-to-noise and source volume

The collection is broad: endpoint EDR-like records, Windows Security and Sysmon on Windows endpoints, Linux syslog and EDR, Zeek on core/DMZ/database segments, firewall, Snort, proxy, and web access logs. Volumes are nontrivial: for example, the two DCs have thousands of Zeek-like endpoint flows and thousands of Sysmon network events across the visible work period; the proxy and WEB-EXT-01 also have thousands of flows and several hundred access records. This gives useful background, though high event volume on DCs should be compared with a site's real baseline before calling it normal.

The records retain enough ordinary service, user, and external web noise to make the malicious-looking sequence separable but not isolated. No domain reputation or real-domain resolution inference is made. A common normalized EDR schema and a missing process identity on one important source flow modestly reduce confidence in independent collection, but they do not outweigh the coherent native and network evidence.

## Synthetic Indicator Summary

| Category | Observation | Weight |
|---|---|---|
| weak_signal | Uniform normalized `ecar.json` schema spans platforms; one key WEB-EXT-01 SSH flow has no PID/principal despite neighboring process-attributed flows. | Low |
| hard_contradiction | None established. | None |
| contract_gap | None established; source-process attribution is incomplete but not a demonstrated required companion. | None |
| distribution_texture | No decisive repeated or implausible event cadence established from the inspected evidence. | None |
| schema_or_format | No malformed source-native record established. | None |
| environment_or_collection_plausibility | The breadth of endpoint and network collection is plausible for a monitored environment; the dataset alone does not verify deployment provenance. | Low/neutral |

## Realism Score by Category

- Field format: 8/10
- Temporal patterns: 8/10
- Cross-source correlation: 9/10
- Behavioral realism: 7/10
- Environmental consistency: 7/10

## Recommendations

- Prioritize WEB-EXT-01 (10.10.3.10) and APP-INT-01 (10.10.2.30). Review WEB-EXT-01 process/audit records around 15:14 UTC and determine which process opened source port 54214; validate the reason for root SSH from a web-facing host.
- Recover commands and file activity from APP-INT-01 root session 360 between 15:14 and 18:57 UTC. Check authentication configuration, SSH keys/password policy, and any resulting connections or writes under the same session.
- Search for the neighboring failed SSH attempt to 10.10.3.20:22 and the `svc_mgmt` failed-password attempts across Linux servers around 16:09 UTC. Group by source IP, username, and target to distinguish a coordinated test or spray from routine failures.
- Correlate the WS-MCHEN-01 explicit-credential and `ADMIN$` activity with target-side DC/file-server share-access records and the user’s approved administrative role. The source event alone does not establish successful access.
- Preserve the Zeek UID, firewall connection ID, Snort alert, source tuple, target session ID, and timestamps as case pivots. The current evidence is sufficient to investigate the activity but not to authenticate whether the records were collected from a production environment.
