# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 79
**Synthetic-Confidence Score:** 47

## Executive Summary

The sampled intrusion and administrative activity supports practical hunting across endpoint, authentication, network, and file evidence, with generally coherent process and session lifecycles. One reproducible Linux session-identity discrepancy and a weaker Windows authentication-to-transport pivot gap raise authenticity concerns, but this bounded review did not establish a source-native impossibility or a broad generator fingerprint.

## Evidence For Synthetic

- [contract_gap] The root SCP receiver session on APP-INT-01 has two session numbers for the same visible activity. `APP-INT-01.meridianhcs.local/syslog.log:214–218` shows sshd PID 2983988 accepting root from `10.10.4.10:45342` at `2026-11-02T18:15:59.228037Z`, followed by logind creating and removing session **378852**. `APP-INT-01.meridianhcs.local/ecar.json:678` reports root LOGIN from that exact tuple at `18:16:00.809Z` with `session_id="378837"`; line 682 logs out that same normalized identity with 378837. A reproducible nearest-time/user comparison of Linux logind `New session` messages with eCAR LOGIN records within five seconds found **70 matching IDs and this one mismatch**. Different normalization namespaces are possible, but that explanation would need to account for the otherwise consistent mapping. This is the principal scored concern.
- [weak_signal] DC-01's successful Kerberos Type 3 login for aisha.johnson at `17:00:05.728357Z` reports source `::ffff:10.10.1.35:62105` (`DC-01.meridianhcs.local/windows_event_security.xml:172995,173013–173027`; normalized at `ecar.json:3362`). The nearby visible service-install transports instead use source ports **58809** to TCP/445 and **58810** to TCP/135 (`zeek-core/conn.json:8001–8002`), beginning at `17:00:09.964448Z` and `17:00:10.259485Z`. Searching the available source endpoint and core connection rows did not locate a contemporaneous DC-01 connection with port 62105; the observed 62105 connection belongs to an earlier Kerberos exchange with DC-02 (`zeek-core/conn.json:6102`, epoch `1793634845.773640`, or `15:54:05.774Z`). This weakens a direct pivot, but does **not** prove that the Type 3 event belongs to the subsequent service installation or that collection includes every connection. It contributes little to the score.

## Evidence For Real

- Linux lateral movement works as an investigation pivot. APP-INT-01 eCAR line 665 creates `ssh root@DB-PROD-01.meridianhcs.local` at `18:14:35.165Z`; line 669 associates it with `10.10.2.30:41321 -> 10.10.4.10:22`. Core Zeek line 10506 records that exact tuple at epoch `1793643292.064499`, an `SF` SSH interval lasting 978.117752 seconds. DB-PROD-01 syslog lines 194–197 show the connection, password acceptance, PAM opening, and logind session 279042; eCAR line 589 agrees on principal, tuple, and session ID.
- The subsequent database staging chain has meaningful artifacts rather than command names alone. DB-PROD-01 eCAR lines 591–603 show mysqldump PID 1088989, `/tmp/rpt_0318.sql` creation, gzip PID 1089075 and its output, then SCP PID 1089129 reading the gzip artifact. APP-INT-01 line 679 receives `/tmp/.cache/rpt_0318.sql.gz` after SSH authentication. The sender's gzip CREATE and SCP READ use the same artifact identity.
- The Windows remote-service trail contains operationally useful source-native relationships: DC-01 eCAR lines 3365–3375 show a dropped `C:\Windows\PSEXESVC.exe`, service creation, a services.exe-owned PSEXESVC process, then its SYSTEM cmd.exe child. Native Sysmon references include lines 108965, 108994, and 109055–109056. This is a feasible service execution pattern; its compactness is not a synthetic indicator.
- Baseline and security noise coexist: 35,313 normalized endpoint records across 23 hosts; 21,463 connection rows across three network-sensor directories; scheduled sysstat commands on APP-INT-01, PHP session cleanup on WEB-EXT-01, failed administrative SSH attempts, domain authentication, proxy access, mail, and scanner-like traffic. Volume is not proof of authenticity, but the sampled source mix does not make suspicious commands the only visible activity.
- The Mac-to-Mac SSH pivots preserve endpoint and native-log details. MAC-MROSS-01 eCAR lines 83–84 identify the SSH client and tuple `10.10.1.41:61230 -> 10.10.1.42:22`; MAC-MROSS-02 eCAR lines 102–108 show inbound transport preceding LOGIN. Its Unified Log line 2 records `Accepted keyboard-interactive/pam` for the same account and tuple at `14:24:50.491082Z`. Reverse-direction SSH similarly has public-key acceptance in MAC-MROSS-01 Unified Log line 3.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The apparent collection is roughly six hours on 2026-11-02, from 13:00 through 19:00 UTC, with workstation, domain-controller, application, database, file, web, mail, proxy, and monitoring hosts in the 10.10.1/2/3/4 address space. Sources include Windows Security and Sysmon XML, normalized eCAR, Linux syslog and histories, Mac Endpoint Security and Unified Log exports and histories, three Zeek sensor views, ASA, proxy/web access, and IDS alerts.

This was a representative review: file/row inventory, selected endpoint chains, two SSH directions between Macs, Linux database staging, Windows credential-access and remote-service pivots, and an identity-based process-lifecycle check. I did not parse every source-native event or validate every protocol field. Filesystem modification times, domain resolvability, deliberately absent Sysmon types, and the apparent completeness of the intrusion were excluded from scoring.

### Session ownership and transport

The database root SSH session is an especially useful positive control for the APP-INT receiver discrepancy. DB-PROD-01 native logind opens session 279042 at `18:15:03.989827Z` and removes it at `18:31:13.377848Z` (syslog lines 197 and 213). Normalized LOGIN/LOGOUT lines 589 and 632 use 279042. The receiver's normalized 378837 versus native 378852 therefore looks like a local correlation defect rather than a demonstrated universal namespace distinction. It does not invalidate the existence of the transfer: its tuple, principal, PID, path, and broad timing still permit a pivot.

The Windows Type 3 source-port discrepancy receives substantially less weight. A successful network logon is evidence of authentication, but it does not by itself establish the precise later operation that consumed the token. A missing exact tuple can arise from filtering, a prior connection, or a separate authentication mechanism. I would retain the event as an investigative lead, without presenting it as confirmed authentication for the immediately following PSEXESVC installation.

### Process, artifact, and privilege boundaries

The Linux mysqldump/gzip/SCP sequence preserves root ownership and distinct processes under the same remote shell, followed by receiver-side file evidence. At the Windows workstation, `WS-AJOHNSON-01.meridianhcs.local/ecar.json:702–714` records `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`, process-access observations including LSASS, then termination. Those observations support an attempted credential-access hunt; they do not independently prove that usable credentials were returned.

A bounded mechanical check over the eCAR files found no dependent actor event more than two seconds after that actor's visible PROCESS TERMINATE, matching by process object UUID. This is a limited but useful lifecycle check: it does not test all target-process relationships or native-source scheduling, and it treats missing pre-window creation as neutral.

On MAC-MROSS-01, Unified Log line 2 says policy “would not allow” MeetingAssist at `15:41:46.250414Z`. I found no matching successful MeetingAssist process execution in the sampled normalized records. I do not infer execution, child activity, or compromise from that policy message, nor do I use the thin Unified Log export as an authenticity defect. The supplied ES version and message internals were not independently verified against platform documentation, so unfamiliar native details were not scored as errors.

### Signal and noise

The WEB-EXT-01 nmap activity is conspicuous because its observed scan produces many flows: PID 2705134 has 249 ICMP FLOW records between its visible CREATE/TERMINATE, while PID 2705135 has 1,263 FLOW records for its five-port TCP scan. Their process identities and flow timing are consistent within the bounded check. Scans are expected to be bursty, and their visibility is not itself a synthetic distribution artifact. Likewise, a coherent succession of credential access, remote administration, and data staging is not evidence about origin without a concrete technical defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Linux syslog and normalized eCAR | One root SCP receiver session on APP-INT-01; 70 comparable session mappings agree | Material concern: same tuple/PID/user/time receives inconsistent session identity; could still be a normalization error in real telemetry. |
| weak_signal | Windows Security, endpoint eCAR, Zeek | One selected Type 3 logon preceding PSEXESVC installation | Small effect: exact source-port pivot is unsupported in available rows; collection and event attribution uncertainty prevent a stronger claim. |

## Realism Score by Category

- **Field format accuracy:** 9 — Examined native XML and text fields are credible; no proven impossible native field value found.
- **Temporal patterns:** 8 — Sampled scans, SSH transport/authentication, and process/file progression are coherent; no general timing conclusion from six hours.
- **Cross-source correlation:** 7 — Many useful tuple and artifact pivots, with one reproducible session-ID discrepancy and one uncertain Windows port association.
- **Behavioral realism:** 8 — Sampled tool, privilege, process-parent, and file-staging relationships support feasible activity.
- **Environmental consistency:** 8 — Mixed-host duties and observed source mix are plausible; sampling cannot establish organization-wide coverage or normal volume.

## Recommendations

- If this were synthetic, make the APP-INT-01 root receiver's eCAR session ID follow the same logind identity used in its native open/close messages. Preserve any separate audit-session namespace explicitly rather than silently substituting a different number.
- If this were synthetic, review the DC-01 Type 3 event's source-port ownership. If it represents the service-install authentication, retain the actual corresponding transport tuple; if it is independent, preserve enough collection or normalization context to prevent an unsupported association with the later SMB/RPC pair.
