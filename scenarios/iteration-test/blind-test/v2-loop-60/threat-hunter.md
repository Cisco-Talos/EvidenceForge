# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive — synthetic-leaning  
**Verdict Confidence:** 80/100  
**Synthetic-Confidence Score:** 56/100

## Executive Summary

The six-hour corpus is operationally convincing: host roles, background volume, scan response patterns, protocol behavior, and several multi-source attack pivots resemble usable enterprise telemetry. However, repeated source-local SSH lifecycle gaps and selectively missing process attribution on important lateral-movement connections suggest construction or observation logic that is not fully production-like. These defects support a synthetic-leaning assessment, but none is sufficiently impossible to rule out real telemetry loss.

## Evidence For Synthetic

- **Repeated SSH lifecycle contract gaps**
  - Thirty SSH daemon PID groups contain both PAM session-open and session-close records.
  - Fourteen are close-only. Seven of those fourteen have endpoint-confirmed process creation and session activity within the capture window, so start-boundary censoring cannot explain them.
  - Examples include:
    - `WEB-EXT-01`, PID `1489241`: endpoint creation at `14:00:06`, root shell and activity, but syslog only records the close at `14:35:11`.
    - `APP-INT-01`, PID `1935711`: endpoint creation at `17:16:05`, inbound file creation, and termination, but syslog only records the close at `17:16:37`.
  - This means approximately 19% of SSH sessions known to have started and ended in-window—7 of 37—retain the close while losing the PAM open.

- **Selective loss of source attribution on a pivotal lateral connection**
  - `WEB-EXT-01` records 253 outbound TCP/22 endpoint flows to 252 destinations.
  - Of these, 251 have PID and principal attribution.
  - The only two unattributed flows are a failed connection to `10.10.3.20` and the successful lateral SSH connection to `APP-INT-01` at `10.10.2.30`.
  - The target side is richly represented—`sshd`, authentication, shell, Zeek, and firewall evidence—while the source lacks the expected `ssh` process relationship.

- **Under-specified causality for repeated WMI-parented administration**
  - On `DC-01`, the same long-lived `WmiPrvSE.exe` PID parents at least five distinct command groups between `16:14:49` and `17:50:24`, including:
    - Creation of `svc_dirsync`.
    - Addition to Domain Admins.
    - Service and scheduled-task persistence.
    - Security-log clearing.
    - Account deletion.
  - For the apparent source pair `WS-AJOHNSON-01 → DC-01`, network evidence from `15:59` through `17:50` contains one brief TCP/135 exchange, two SMB connections, and no dynamic high-port RPC connection. A local WMI caller or an unobserved source remains possible, but neither is established.

## Evidence For Real

- **Plausible scan texture**
  - The discovery sweep covers 254 addresses rather than an artificially restricted modeled-host list.
  - The ICMP view contains 508 dual-sensor records: 490 unanswered attempts and only 18 successful observations representing nine responding hosts.
  - The five-port TCP scan produces 2,538 dual-sensor records with 2,474 `S0`, 36 `REJ`, 12 `RSTO`, two `RSTR`, and 14 `SF` results.
  - That sparse response distribution resembles a real partially populated subnet.

- **Strong source-native correlation**
  - The `APP-INT-01 → DB-PROD-01` SSH session is independently visible in source and target endpoint telemetry, target syslog, and two Zeek sensors.
  - The subsequent SCP transfer is approximately 1.7 MB in both endpoint/file evidence and network byte counts.
  - The staged archive is then sent through SMB to `FILE-LNX-01`, where source-side read, target-side write, Samba authentication, Zeek SMB traffic, and the exact destination path align.

- **Credible timing relationships**
  - Network sensors generally observe connection establishment before target authentication and shell readiness.
  - Source and target endpoint timestamps differ slightly rather than being mechanically identical.
  - Long sessions have internally compatible close times. For example, the `WEB-EXT-01 → APP-INT-01` SSH flow lasts approximately 3 hours 41 minutes 55 seconds in both Zeek and firewall telemetry.

- **Realistic background variance**
  - Activity is bursty rather than uniformly distributed. Per-minute coefficients of variation are approximately:
    - Endpoint/eCAR: `0.96`
    - Zeek: `1.79`
    - Firewall: `2.21`
  - Peaks are attributable to the subnet scans rather than unexplained global synchronization.
  - Process commands, HTTP statuses, TLS versions, DNS result types, Snort signatures, and user activity all show meaningful variation.

- **Role-consistent source volumes**
  - Domain controllers dominate Windows authentication traffic.
  - The proxy and external web server carry elevated network volumes.
  - Samba evidence concentrates on the Linux file server.
  - Kerberos, LDAP, SMB, SQL, SMTP, SSH, RDP, DNS, DHCP, HTTP, and TLS appear in environmentally plausible proportions.

- **Coherent Windows evidence**
  - PsExec-style activity on `DC-01` aligns across file creation, service creation, process execution, Security event `4697`, SMB, and DCE/RPC.
  - Account lifecycle events use appropriate IDs (`4720`, `4724`, `4738`, `4728`, and `4726`).
  - Security-log clearing is represented by `wevtutil`, event `1102`, and an EventRecordID reset.

## Detailed Analysis

### Operational hunt reconstruction

The first strong path begins on `WS-DRAMIREZ-01`, where `cmd.exe` launches `ssh.exe root@WEB-EXT-01.meridianhcs.local`. Source endpoint flow, target `sshd`, target login, target shell, syslog authentication, and dual-sensor Zeek records establish the session.

On `WEB-EXT-01`, root performs network and credential-oriented discovery:

- Network interface, hosts, and resolver inspection.
- Search for credential-related files under `/opt/ehr`.
- An ICMP `/24` sweep.
- A five-port TCP scan covering SSH, HTTP, HTTPS, SMB, and MySQL.

A separate root session then reads web configuration and SSH key material. From the web server, SSH reaches `APP-INT-01`, followed later by an application-to-database SSH session. The database activity creates and compresses a SQL export, transfers it back to the application server through SCP, and copies it to a clinical-research SMB path. This chain provides practical pivots across process, session, flow, file, Zeek, firewall, and Samba data.

The Windows path contains domain discovery, PsExec-style remote service execution, privileged account creation, group membership modification, service and task persistence, execution of the persisted binary, security-log clearing, and account cleanup. The endpoint and Windows Security records are technically coherent, although the initiating context for later WMI-parented commands is weak.

### Hunt friction and signal-to-noise

The suspicious activity is embedded in substantial background traffic rather than dominating the corpus:

- 32,991 endpoint/eCAR entries.
- 33,250 Zeek entries.
- 18,232 Windows Security events.
- 11,542 Sysmon events.
- 19,376 firewall records.
- 3,869 syslog records.
- 2,524 proxy and 710 web-access records.
- 185 Snort alerts.
- 212 timestamped shell-history commands.

The background contains ordinary interactive sessions, scheduled processes, authentication noise, proxy errors, TLS resumption, DNS failures, administrative SSH, SMB, database traffic, and IDS false-positive candidates. A hunter could not simply isolate the malicious chain by selecting every rare protocol or privileged login.

### Principal realism concern

The SSH omission pattern is more consequential than ordinary thin coverage. It is not merely the absence of an optional source: the same syslog source preserves a lifecycle termination for sessions whose in-window creation, login, shell, and activity are independently established. Real collection loss can produce this, but repeated retention of the close half across seven fully in-window sessions indicates an observation or generation contract that merits attention.

The source attribution issue is narrower but similarly important. Process attribution is available for almost every TCP/22 flow generated by the large web-server scan, yet it disappears on the subsequent deliberate SSH pivot. For hunting realism, the evidentiary difficulty should arise from believable collection limits—not from losing the most relevant relationship while preserving nearly every repetitive scan relationship.

## Synthetic Indicator Summary

| Category | Source | Quantified scope | Impact |
|---|---|---:|---|
| SSH lifecycle contract gap | Linux syslog versus endpoint telemetry | 7 fully in-window sessions have close-only PAM evidence; 30 are complete | High |
| Selective process-attribution gap | `WEB-EXT-01` endpoint flows | 2 of 253 outbound TCP/22 flows are unattributed; one is the successful lateral pivot | Medium-high |
| Remote-execution causality ambiguity | `DC-01` endpoint and network telemetry | At least 5 WMI-parented command groups; only one brief TCP/135 exchange and no dynamic RPC flow for the apparent source pair | Medium |
| Boundary-censored sessions | Linux syslog | 7 additional close-only sessions occur near capture start; 8 open-only groups may extend past capture end | No synthetic impact; expected limitation |

## Realism Score by Category

- Field format accuracy: 9/10
- Temporal patterns: 8/10
- Cross-source correlation: 8/10
- Behavioral realism: 8/10
- Environmental consistency: 9/10

## Recommendations

If synthetic:

1. Make SSH source-observation decisions lifecycle-coherent. A retained PAM close should normally retain its corresponding accepted/open/session-created records unless an explicit collector-loss model independently explains partial delivery.

2. Preserve process ownership on deliberate SSH pivots when the source endpoint is instrumented. If attribution gaps are intentional, distribute them across comparable benign and suspicious sessions rather than concentrating them on pivotal connections.

3. Give WMI-parented remote execution an explicit causal origin:
   - For remote WMI, include endpoint-mapper negotiation, dynamic RPC transport, authentication context, and source caller evidence.
   - For local WMI, represent the local consumer or initiating process that requested each operation.

4. Retain the current subnet-scan response sparsity, source-specific timestamp offsets, role-based traffic volumes, and transfer-byte agreement. These are among the corpus’s strongest realism features.

5. Avoid solving the observed gaps by making every source complete. Model believable, source-specific loss, but apply it consistently to lifecycle groups and independently of whether an event belongs to the main hunt path.

## Limitations

- The assessment covers only the supplied six-hour data directory.
- No scenario, manifest, ground truth, prior assessment, source code, or neighboring directory was examined.
- Filesystem metadata, sanitized domains, completeness by itself, and narrative compactness were not treated as authenticity indicators.
- There is no packet payload, collector-health telemetry, prior host baseline, or documentation of source-specific retention. Consequently, some lifecycle gaps could reflect genuine packet or log loss.
- The WMI causality finding is suggestive rather than contradictory because local invocation or an unobserved initiating source cannot be excluded.

