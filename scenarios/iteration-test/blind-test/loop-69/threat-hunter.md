# Threat Hunter — Authenticity Assessment
## Verdict
**Assessment:** Inconclusive
**Verdict Confidence:** 68/100
**Synthetic-Confidence Score:** 51/100

## Executive Summary
The dataset has credible multi-source operational behavior: host identities, process lifecycles, authentication, network tuples, and selected endpoint/network observations often agree down to seconds or ports. A weak collection-texture concern is the very sparse macOS Unified Log compared with the much richer Endpoint Security and eCAR records on those same Macs; without collection metadata, this is not enough to call a contradiction. Overall, the visible evidence supports a mixed/inconclusive assessment rather than a confident origin claim.

## Evidence For Synthetic
- **environment_or_collection_plausibility — weak:** Each Mac has only two or three records in `macos_unified_log.ndjson` for a roughly six-hour window, while its `macos_endpoint_security.ndjson` has 137 records on MAC-MROSS-01 and 182 on MAC-MROSS-02. The Unified Log does include real-looking loginwindow and sshd messages, so sparse export could be intentional; no missing required event is established.
- **distribution_texture — weak:** The Windows endpoint exports are strongly dominated by connection telemetry: for example, DC-01 has 4,436 Security 5156 records and 3,879 Sysmon Event ID 3 records in the window. That is possible for a busy domain controller and consistent with the high network volume, but the heavy concentration warrants checking against actual filtering and event-volume baselines before treating it as production collection.

## Evidence For Real
- **Cross-source network agreement:** On 2026-11-02, MAC-MROSS-01 eCAR records an outbound SSH connection from `10.10.1.41:50608` to `10.10.1.42:22` at 14:24:46.062Z. MAC-MROSS-02 records the matching inbound tuple at 14:24:44.555Z, then a successful `maya.ross` SSH login from that same address and source port at 14:24:52.310Z. Its Unified Log says `Accepted keyboard-interactive/pam for maya.ross from 10.10.1.41 port 50608` at 14:24:51.313456Z. This is coherent transport-before-auth evidence across three source families.
- **Windows process and authentication semantics:** WS-AJOHNSON-01 Security Event 4688 at 13:21:33.159Z records `ssh.exe aisha.johnson@FILE-LNX-01...` under Aisha’s interactive logon ID. Later, Event 4625 records three local interactive failures for that account at 13:42:19–13:42:33Z, with bad-password substatus `0xc000006a`; these are plausible failed attempts rather than invalid source/target combinations.
- **Lifecycle behavior:** Across the eCAR host files, process CREATE/TERMINATE pairs were not found in reversed timestamp order. Most processes have paired starts and ends; remaining unpaired records are limited and can occur at the visible window boundaries or with source-specific event coverage.
- **Role and protocol fit:** The dataset presents Windows workstations and domain controllers, Linux application/database/file/mail/proxy hosts, and two macOS user endpoints. Observed SMB, Kerberos/LDAP, DNS, HTTP(S)-through-proxy, SSH, SMTP, and MySQL traffic generally fit those apparent roles. For example, `zeek-core/conn.json` shows a workstation accessing FILE-SRV-01 over SMB, while `zeek-core/smb_mapping.json` and `smb_files.json` describe the associated share/file activity.
- **Network protocol corroboration:** At 18:25:19.568Z, WS-AJOHNSON-01 Security Event 4688 records `curl.exe` posting an archive through proxy `10.10.3.20:8080`. eCAR records the same host’s outbound flow to that proxy at 18:25:23.301Z, and `zeek-dmz/http.json` records a CONNECT to `api.westbridge-services.net` from `10.10.1.35:53676` at 18:25:23.322Z. The seconds-level ordering and tuple are consistent with an HTTPS request observed by a proxy rather than exposing its encrypted body in the HTTP CONNECT log.
- **Source-native formatting:** Windows event files use the Windows Event XML structure and Sysmon event IDs; Linux syslog lines use RFC 5424-like PRI/version/timestamp/host/app fields; Zeek logs contain familiar typed fields and shared UIDs; macOS Endpoint Security records include audit tokens and monotonic mach time. No broad schema or timestamp-format break was apparent in the reviewed records.

## Detailed Analysis
The visible window spans approximately 13:00–19:00Z on 2026-11-02. Per-host eCAR records, Security/Sysmon XML, Linux syslog, and Zeek connection records occupy that same interval. Unix shell-history epoch timestamps also fall within it. The matching SSH pivot between the two Mac endpoints is especially useful: source-side process/flow evidence, destination-side flow/session evidence, and the sshd Unified Log all converge on one tuple and one actor, with the transport preceding authentication.

The enterprise network shape is internally plausible from the logs: workstations appear in `10.10.1.0/24`, server and directory services in `10.10.2.0/24`, the web/proxy segment in `10.10.3.0/24`, and the database in `10.10.4.0/24`. This is inferred from repeated source/destination addresses and service behavior, not from external context. DC-01 and DC-02 receive DNS/Kerberos/LDAP traffic; Windows clients generate corresponding DNS/Kerberos activity; FILE-SRV-01 has SMB traffic and file-access records; DB-PROD-01 receives MySQL traffic; and PROXY-01 is a common HTTP CONNECT destination. Repeated cross-source flows are not by themselves suspicious given the overlapping Zeek sensors and endpoint views.

The main threat-hunting chain visible on WS-AJOHNSON-01 is technically plausible and well cross-referenced. Security Event 4688 records archive collection from `FILE-SRV-01\ClinicalExports` at 18:01:05.316Z, later stages the resulting `cache_7f3a.zip`, and records a curl upload command at 18:25:19.568Z. The endpoint flow and Zeek proxy CONNECT appear seconds later with the matching source tuple and domain. These records show command intent and network transport; the CONNECT record alone does not prove the encrypted upload body or remote acceptance. The chain therefore supports suspicious behavior, while not serving as evidence of synthetic origin.

Windows source volumes are substantial but not obviously impossible for the apparent fleet. DC-01 has 6,775 Security events and 4,487 Sysmon events; DC-02 has 5,847 and 3,613 respectively. Their largest families are Security 5156 filtering events and Kerberos 4768/4769 records, and Sysmon network events, which fit the roles and traffic volume. User workstations have several hundred Security/Sysmon events each, mostly filtering, process creation/termination, DNS, and network events. Linux hosts have hundreds of syslog lines and eCAR activity, while edge sensors have thousands of Zeek flows and HTTP/TLS records. The sparse macOS Unified Log is the only notable coverage-shape concern; endpoint events otherwise show ordinary interactive process launches and session transitions.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score reason |
|---|---|---|---|
| environment_or_collection_plausibility | macOS Unified Log vs Endpoint Security/eCAR | Two Macs; 2–3 Unified Log rows versus 137–182 Endpoint Security rows per host | Weak concern (2/10): sparse selection may reflect filtering; no definite required companion is absent. |
| distribution_texture | Windows Security/Sysmon | Especially DC-01/DC-02, over six hours | Weak concern (3/10): event concentration is high but role-compatible and corroborated by network volume. |
| hard_contradiction | All reviewed families | None established | 0/10: no impossible in-window identity ordering or tuple mismatch found in the reviewed pivots. |
| contract_gap | Cross-source lifecycle | None established in reviewed pivots | 0/10: SSH and HTTPS-proxy examples have plausible companion ordering and matching identities. |

## Realism Score by Category
- **Field format accuracy — 8/10:** Windows XML, RFC-style syslog, Zeek JSON, eCAR JSON, macOS Unified Log, and Endpoint Security retain recognizable source-native structure.
- **Temporal patterns — 8/10:** The reviewed SSH and proxy pivots order correctly at sub-minute resolution; paired process lifecycles do not reverse in time.
- **Cross-source correlation — 9/10:** Matching SSH tuple/session and endpoint-to-proxy-to-Zeek upload tuple provide strong coherent correlation.
- **Behavioral realism — 7/10:** Background service activity, user sessions, failures, lateral administration, and suspicious staging/upload coexist; archive upload intent is visible, though the encrypted body is not verifiable from CONNECT metadata.
- **Environmental consistency — 7/10:** Host roles and subnets mostly fit observed services; macOS Unified Log sparsity leaves collection scope uncertain.

## Recommendations
- If this were synthetic, make the macOS Unified Log collection scope explicit in its emitted records or include a broader selection of routine entries; two or three events beside hundreds of Endpoint Security/eCAR records are difficult to distinguish from an accidentally thin export.
- If this were synthetic, compare DC Security 5156 and Sysmon Event ID 3 counts against a realistic collection baseline for the stated six-hour interval, and vary the family mix only where the modeled filtering and workload justify it.
