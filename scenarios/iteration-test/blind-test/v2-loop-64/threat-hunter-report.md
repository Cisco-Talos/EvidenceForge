# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 49

## Executive Summary

This is a highly huntable, internally coherent six-hour collection whose endpoint, network, proxy, file-transfer, and directory-service evidence generally behaves like telemetry from shared underlying activity. Two concrete patterns keep me from calling it real: highly constrained source-to-source timestamp ordering across nearly every matched event, and repeated Windows creator/token provenance that does not reconcile cleanly when user-context attack processes are spawned by built-in service processes.

## Evidence For Synthetic

- `[distribution_texture]` Across 985 process creations that could be matched by host, PID, and command line in Security 4688, Sysmon Event 1, and eCAR, Sysmon always preceded Security. The Security-minus-Sysmon delay never changed sign and stayed between about 35 and 650 ms; host medians were tightly grouped from 113 to 156 ms across DC-01, DC-02, FILE-SRV-01, MAIL-FIN-01, and six workstations. A consistent provider order can occur, but universal ordering plus nearly identical bounded delay distributions on every host looks more like a common timing model than independent lived-in endpoints.
- `[distribution_texture]` Independent Zeek views also fall into narrow, invariant timing bands. For 4,269 one-to-one shared five-tuples, `zeek-dmz/conn.json` was always 110.287-118.742 ms earlier than `zeek-core/conn.json`; 89 core/database matches put `zeek-db` always 55.218-74.143 ms after core, and 327 DMZ/database matches put it always 168.428-188.001 ms after DMZ. Stable sensor clock skew is a plausible real explanation, so this is not a contradiction, but the three bands are sufficiently clean to contribute to the score.
- `[contract_gap]` Windows process-token provenance is inconsistent on several attack-path process launches. On WS-AJOHNSON-01 at `2024-03-18 17:00:41.944Z`, Sysmon Event 1 records PowerShell PID 7072 as `MERIDIANHCS\aisha.johnson` while its parent PID 4500 is `svchost.exe -k netsvcs` running as `NT AUTHORITY\NETWORK SERVICE`; the corresponding Security 4688 at `17:00:42.1677929Z` places Aisha in the Subject fields, leaves the Target Subject as `-`, and still names `svchost.exe` as parent. eCAR at `17:00:42.277Z` repeats the split as child principal Aisha and `source_principal=NETWORK SERVICE`. A service can create a process with another token, but 4688 should preserve the creator/target-token distinction instead of presenting the child identity as the creator with no Target Subject.
- `[contract_gap]` The same token-lineage shape recurs during exfiltration. WS-AJOHNSON-01 Sysmon Event 1 at `17:24:54.679Z` shows curl PID 7128 as Aisha with parent `services.exe`/SYSTEM; Security 4688 at `17:24:54.9253647Z` again makes Aisha the Subject, leaves Target Subject blank, and names `services.exe` as parent; eCAR at `17:24:54.862Z` records principal Aisha but `source_principal=SYSTEM`. This is a repeated semantic gap rather than a one-off malformed record.
- `[distribution_texture]` Service-logon evidence is unusually dense and repeatedly reuses the same built-in-account logon IDs. DC-01 contains 54 Type 5 4624 events for SYSTEM/`0x3e7`, 43 for LOCAL SERVICE/`0x3e5`, and 37 for NETWORK SERVICE/`0x3e4`; DC-02 has 45, 49, and 44 respectively during the same six hours. FILE-SRV-01 and MAIL-FIN-01 show the same pattern at lower volume. Reuse of these well-known sessions is normal, but repeatedly emitting new Type 5 logons for the same persistent LUID without corresponding session ends resembles a generated “service activity implies logon” rule and inflates authentication texture.

## Evidence For Real

- The visible collection has believable scope and source mix rather than an attack-only excerpt: 21 eCAR files with 34,056 records, 34,694 Zeek records across core/DMZ/database views, 30,467 Windows Security/Sysmon events, 20,059 ASA records, 2,855 proxy records, 3,780 Linux syslog records, 726 web-access records, and 140 IDS alerts. Domain controllers and infrastructure systems are appropriately noisier than user endpoints.
- The discovery sequence is operationally sound. WEB-EXT-01 launches `nmap -sn 10.10.2.0/24` at `13:39:58.463Z`, produces 250 ICMP-oriented flow observations, terminates at `13:40:11.437Z`, then launches `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` at `13:40:12.920Z`, produces 1,255 distinct connection attempts, and terminates at `13:40:34.440Z`. No dependent eCAR record is visibly before either process creation or after its termination.
- Remote execution on DC-01 has appropriate intermediate artifacts: `C:\Windows\PSEXESVC.exe` is created at `16:00:25.514Z`, the PSEXESVC service is installed at `16:00:25.781Z`, the service process starts at `16:00:27.996Z`, and its SYSTEM child runs `cmd.exe /c whoami && hostname` at `16:00:29.142Z`. Directory-account creation, Domain Admins membership, service and scheduled-task persistence, beaconing, log clearing, and account deletion are represented by plausible Security, Sysmon, and eCAR records rather than a single narrative-only source.
- The data-staging path is particularly convincing. DB-PROD-01 runs `mysqldump` at `17:15:27.139Z`, creates `/tmp/rpt_0318.sql`, compresses it, and starts SCP at `17:16:14.420Z`; APP-INT-01 records receiver-side creation at `17:16:38.332Z`. APP-INT-01 then starts `smbclient` at `17:19:06.333Z` to 10.10.2.21:445, while Zeek SMB records `Integration\DB-Staging\rpt_0318.sql.gz` being written and FILE-LNX-01 eCAR records the receiver-side write at `17:19:15.276Z` as `svc_mhsync` using NTLMSSP.
- DNS-channel behavior has useful entropy rather than metronomic timing. `zeek-core/dns.json` contains 199 TXT queries from 10.10.2.30 to `*.ns1.westbridge-services.cloud` between `16:44:40.090850Z` and `16:59:36.433546Z`; median inter-query spacing is about 2.16 seconds, with gaps from 0.045 to 50.046 seconds and response outcomes of 180 NOERROR, 12 NXDOMAIN, five SERVFAIL, and two REFUSED.
- Proxy-mediated exfiltration correlates unusually well at the byte and tuple level. WS-AJOHNSON-01 eCAR creates curl PID 7128 at `17:24:54.862Z` and records source port 54221 to proxy 10.10.3.20:8080 at `17:24:59.154Z`. `zeek-dmz/conn.json` sees that tuple at `17:24:58.874786Z` with 18,783,616 origin bytes and a 15.973-second SF connection; the proxy logs a CONNECT and POST to `/upload/telemetry/7f3a2b19` at `17:24:59Z`, tunnel ID `PT-a146a3096e4ccd47`, with 18,783,154 tunneled client bytes. Proxy-origin DNS and TLS evidence then shows the separate 10.10.3.20-to-origin leg.
- The Security-log clear behaves source-natively. DC-01 records the `wevtutil cl Security` process at `17:41:40`, then Event 1102 at `17:41:44.7309750Z` with EventRecordID reset to 1; later records continue after the reset. That is substantially more credible than merely inserting an Event 1102 into an uninterrupted record-number sequence.
- Baseline details include realistic friction: failed sudo attempts, DHCP renewals, package-manager and systemd chatter, WPAD/ISATAP lookup failures, varied DNS return codes, browser/update/monitoring traffic, short and long process lifetimes, and even an isolated `lmsod` typo in a Linux administrator's bash history. These are log-visible environmental details, not an inference from storyline complexity.

## Detailed Analysis

### Orientation and source volume

The collection spans approximately `2024-03-18 12:00:01Z` through `17:59:58Z`. It exposes user workstations in 10.10.1.0/24, infrastructure in 10.10.2.0/24, DMZ systems and a proxy in 10.10.3.0/24, and a database at 10.10.4.10. The family distribution is plausible for a selectively collected environment: domain-controller Security and Sysmon volumes dominate Windows telemetry, proxy and firewall records dominate perimeter activity, and Linux hosts contribute both eCAR and syslog/bash-history evidence.

Volume is not attack-centered. DC-01 has 6,455 Security events and 4,213 Sysmon events; DC-02 has 5,993 and 3,666. By contrast, workstation Security files contain roughly 500-900 events each. Zeek connection states are varied: core has 8,994 SF, 1,913 S0, 150 RSTO, 74 RSTR, 30 REJ, and smaller OTH/S1/S2/S3 populations; DMZ has 5,629 SF and 2,706 S0 plus reset/reject tails. The mix fits ordinary infrastructure traffic plus the visible scan.

### Hunt path and operational coherence

The first high-confidence malicious pivot is root-owned Nmap from WEB-EXT-01 at 13:39. The scan's target set, ports, source identity, process lifetime, and flow fan-out agree. Later DC-01 evidence supports PsExec remote execution, WMI-backed commands that create `svc_dirsync`, membership change, `DeviceSyncSvc`, and an hourly scheduled task. The service starts at `16:30:17.464Z`; proxy logs then show repeated Go client check-ins from DC-01 to `api.westbridge-services.net` at jittered intervals, followed by an encoded PowerShell manifest retrieval at 17:41.

The staging and exfiltration tracks are feasible end to end. The database dump moves by SCP to APP-INT-01 and then by SMB to FILE-LNX-01 with receiver-side file evidence. On WS-AJOHNSON-01, a Type 9 session at `17:00:31.942Z` clones local logon `0x2778c06` to `0x27c9469` with outbound credentials for `marcus.chen`; PowerShell creates VaultCache directories, Explorer PID 6624 opens SMB connections to 10.10.2.20 and 10.10.2.21, and staged files appear before compression. Curl's endpoint tuple, the proxy client leg, the proxy-origin DNS lookup, and the TLS origin leg are separable and temporally coherent.

I found no visible eCAR dependent event whose `actorID` precedes its process creation or follows its process termination. Across Zeek, all 8,571 DMZ, 11,230 core, and 432 database `conn.json` records were checked against UID-bearing protocol companions: no DNS, HTTP, SSL, SMB, or SMTP record lacked its local sensor's connection UID, preceded that connection, or fell after a recorded close. Those checks materially reduce concern about fabricated pivots or impossible within-window ordering.

### Authenticity concerns

The strongest concern is not that sources correlate completely; it is the texture of their timing. Every one of 985 matched process triplets puts Sysmon before Security, with similar subsecond delay bounds on all ten Windows hosts. Likewise, thousands of shared network tuples preserve three narrow, directionally invariant inter-sensor offsets. Real provider order and fixed sensor clock skew can explain each pattern, so I do not treat either as a hard contradiction. Taken together, however, they are unusually controlled for ten endpoints and three network observation points.

The creator/token mismatch is more concrete. Both the 17:00 PowerShell staging process and the 17:24 curl exfiltration process run locally as Aisha while their visible parents run as NETWORK SERVICE or SYSTEM. That transition is technically possible through token-based process creation, but Security 4688 encodes Aisha as the creating Subject and leaves the alternate Target Subject empty, even though Sysmon and eCAR identify a differently owned parent/creator. The same shape on separate actions suggests a shared modeling gap around impersonation or alternate-token launches.

Finally, the Type 5 authentication distribution is overactive. Hundreds of new 4624 records reuse the three built-in service LUIDs on infrastructure hosts. Persistent `0x3e4`, `0x3e5`, and `0x3e7` identities are normal and explain the absence of corresponding logoffs, but repeatedly announcing them as new service logons across six hours is less typical than reusing the already established sessions for routine process and network activity. This affected the score as a repeated source-family texture, not as an isolated missing-logoff complaint.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Sysmon and Windows Security | Dataset-wide across 985 matched process creates on ten hosts | Universal Sysmon-before-Security ordering and tightly shared delay ranges look centrally modeled; high impact, though provider order is a plausible alternative. |
| `distribution_texture` | Zeek core/DMZ/database | Dataset-wide across thousands of shared tuples | Three narrow, invariant sensor-offset bands resemble fixed observation profiles; medium impact because stable clock skew is also realistic. |
| `contract_gap` | Security 4688, Sysmon, eCAR | Repeated on user-token attack processes | Parent/creator account and child token are not represented consistently; high impact on attribution and lateral-movement pivots. |
| `distribution_texture` | Windows Security 4624 | Repeated across four infrastructure servers and several workstations | Built-in service LUIDs receive many repeated Type 5 “new logon” events without distinct sessions; medium impact on authentication realism. |

## Realism Score by Category

- **Field format accuracy:** 8 — Native shapes, identifiers, EventRecordID reset behavior, Zeek fields, proxy transactions, and command lines are generally strong; Windows 4688 token provenance is the main defect.
- **Temporal patterns:** 6 — Individual action timing is coherent and appropriately jittered, but cross-source ordering falls into unusually universal, narrow bands.
- **Cross-source correlation:** 9 — Host, Zeek, SMB, proxy, DNS, TLS, and firewall pivots are operationally usable with no visible dependency-before-initiator failures found.
- **Behavioral realism:** 8 — Discovery, persistence, staging, exfiltration, cleanup, user activity, and infrastructure noise are technically plausible and varied.
- **Environmental consistency:** 8 — Source volume tracks host roles and includes credible background failures and service traffic; repeated built-in service logons slightly weaken the model.

## Recommendations

- If this were synthetic, introduce independent per-host provider timing and queue effects so Security 4688 and Sysmon Event 1 do not preserve one universal order and nearly identical delay distribution across every endpoint. Preserve causal constraints, but allow realistic batching, occasional provider reversal, and host-specific latency regimes.
- Model Windows alternate-token creation explicitly. When a SYSTEM/NETWORK SERVICE parent creates an Aisha-token process, Security 4688 should retain the actual creator in Subject and place the child token in Target Subject, or the process should have a parent that belongs to Aisha's session. Apply the same ownership truth to Sysmon and eCAR.
- Revisit Type 5 generation for built-in service identities. Reuse persistent `0x3e4`/`0x3e5`/`0x3e7` sessions without emitting a new 4624 for every service-like activity, and emit a distinct service logon only when the underlying account/session semantics require it.
- Keep the strong action-bundle behavior visible here: process lifetimes bracket dependent events, protocol records remain inside their Zeek connection intervals, SMB transfers include receiver-side file evidence, and explicit proxy traffic is split into client-proxy and proxy-origin legs with byte accounting.
