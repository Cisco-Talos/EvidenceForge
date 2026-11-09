# Threat Hunter Blind Authenticity Review — Loop 10

## Verdict

Likely synthetic or deliberately staged exercise telemetry. The malicious behaviors are individually plausible and mostly lifecycle-coherent, but the bundle stacks unusually explicit, high-confidence behaviors with a wide scatter of unrelated IDS red herrings. The dataset reads as a designed hunting exercise more than a routine production capture.

## Verdict Confidence (0–100)

94

## Synthetic-Confidence Score (0–100, lower is more production-like)

91

## Executive Summary

The strongest investigation thread is a clinical database export: an accepted root SSH session to `DB-PROD-01` is followed by a dump of the `ehr` patient and insurance tables, gzip compression, SCP to `APP-INT-01` into `/tmp/.cache`, and a subsequent write of the same named archive into the ClinicalResearch integration staging share. Linux auth/syslog, endpoint eCAR, Zeek SMB, and the file server audit provide useful pivots. The combination is suspicious and sufficiently coherent to hunt.

A separate high-confidence persistence and command-retrieval thread appears on `DC-01`: WMI provider activity launches `sc.exe` to create a LocalSystem service and an hourly scheduled task, the new executable runs, and an encoded PowerShell command later fetches a manifest from `api.westbridge-services.net`. Network logs show repeated proxy-to-domain TLS sessions, while the application host generates many pseudo-random TXT lookups under `ns1.westbridge-services.cloud`.

These are valuable hunt signals, but they are unusually overt and sit among many low-context alerts for suspicious TLDs, P2P, ICMP probes, and generic policy detections. Several scenario artifacts are named to make intent easy to recognize (patient/claims dump, `.cache` staging, `DeviceSyncSvc`, and a specific vendor-ticket upload). Taken together, the density and explicitness suggest curated synthetic content. The evidence supports investigating the activity represented in the logs; it does not establish that these events occurred in a real environment.

## Evidence For Synthetic

- `DB-PROD-01` root history explicitly lists `mysqldump --single-transaction ehr patients insurance_claims`, gzip, and SCP of `rpt_0318.sql.gz` to root on `APP-INT-01`. eCAR mirrors the same command chain and file path. The direct naming of patient and insurance tables makes the data-theft intent unusually legible.
- `APP-INT-01` receives the file as `sshd: root@notty` at `/tmp/.cache/rpt_0318.sql.gz`; minutes later `FILE-LNX-01` records `svc_mhsync` writing that same filename into `ClinicalResearch/Integration/DB-Staging`. This is a neat, multi-source staging story with a hidden cache path and a named staging directory.
- On `DC-01`, WMI provider (`WmiPrvSE.exe`) activity creates `DeviceSyncSvc` as LocalSystem and schedules it hourly under a maintenance-looking task path. The executable then runs. A later encoded PowerShell command invokes `DownloadString` for an external manifest URL. This persistence-plus-download sequence is direct and textbook-like.
- Zeek DNS contains many TXT requests from `10.10.2.30` to long, high-entropy labels under `ns1.westbridge-services.cloud`; Zeek SSL repeatedly records `api.westbridge-services.net` to `45.33.32.30` through the DMZ proxy. The two similarly named domains and the encoded manifest fetch make a strong, tidy command-and-control thread.
- Snort carries a broad spread of unrelated suspicious-TLD, P2P, ICMP scan, HTTP policy, and possible-malware alerts across several hosts. Many alerts lack a clear endpoint or user pivot in the reviewed evidence, reducing signal-to-noise and making the background look intentionally seeded with red herrings.
- A second explicit outbound transfer appears on `WS-LNGUYEN-01`: Lina archives two EHR connector logs and submits the archive over HTTP through the proxy to a named external support ticket. It may be authorized support work, but the plain-HTTP destination and explicit medical-system context make it another conspicuous data-movement case.

## Evidence For Real

- Core event ordering is generally plausible. The DB SSH acceptance precedes dump and compression; the archive is read by SCP; the destination SSH session creates it; and a later SMB operation writes it to a share. Process parents, users, paths, ports, and times offer practical pivots.
- The clinical archive transfer has independent host-side and network-side support, including Linux `smbd_audit`, Zeek SMB file events, eCAR file writes, and a successful TCP/445 connection. This is stronger than an isolated suspicious command line.
- The `DC-01` persistence events appear in both endpoint eCAR and Windows Sysmon/security records, and the later service execution follows the service/task setup. The encoded command also has a corresponding outbound flow to the DMZ proxy and matching external TLS SNI observations.
- Maya Ross’s Mac activity includes ordinary interactive application use and shell commands as well as SSH hops. The Linux fleets show routine service management, package/system checks, developer work, database queries, and ordinary SMB access. These provide some background texture beyond the attack sequence.
- Logs use source-appropriate shapes (Windows XML, Linux syslog and histories, Zeek JSON, proxy/ASA/Snort text, and macOS endpoint records), and the data supports useful pivots across users, hosts, files, and network tuples.

## Detailed Analysis

### 1. Clinical database export and staging

At 18:14 UTC on 2026-11-02, `DB-PROD-01` syslog records an accepted password login for root from `10.10.2.30` (`APP-INT-01`). The root history then records inspection of the `ehr` database and a dump of `patients` and `insurance_claims` to `/tmp/rpt_0318.sql`, followed by gzip and SCP to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. eCAR records the corresponding file creation, compression, SCP process, connection from `10.10.4.10` to `10.10.2.30:22`, and file read.

`APP-INT-01` syslog records a root public-key SSH acceptance from `10.10.4.10` at 18:15 UTC. Its eCAR records the archive arriving under `/tmp/.cache`. At 18:18 UTC, the same filename appears in `FILE-LNX-01` audit and Zeek SMB records as a write into `ClinicalResearch/Integration/DB-Staging`, sourced from `10.10.2.30` and attributed to `svc_mhsync`. This is a strong hunt pivot: confirm whether root SSH from the DB to the application host and that service-account write are approved, then determine who owned the session and who consumed the staged file.

The chain is coherent, but intent is almost fully spelled out by the database/table names, output filename, hidden cache directory, and share path. That level of explicitness is a synthetic-leaning clue. The available records do not show a visible user attribution for the root transfer session at APP or prove subsequent access to the staged archive; treat those as collection gaps rather than contradictions.

### 2. Domain-controller persistence and command retrieval

On `DC-01`, eCAR and Sysmon/security logs show WMI provider activity starting `cmd.exe`, which creates `DeviceSyncSvc` as a LocalSystem service and creates an hourly `\Microsoft\Windows\Maintenance\DeviceSync` task pointing to the same executable. The service executable runs under `services.exe`. At 18:41 UTC, `SYSTEM` runs `powershell.exe -NoProfile -EncodedCommand` whose payload is a `WebClient.DownloadString` call to `https://api.westbridge-services.net/v2/manifest`. eCAR records a flow from the DC to the proxy at `10.10.3.20:8080`; the DMZ Zeek data subsequently shows the proxy resolving and connecting to `45.33.32.30` with the same SNI.

This is high-priority behavior in a domain controller role. Validate the WMI source/initiator and service binary provenance, collect the scheduled task and service configuration, and investigate the external host and returned manifest. The logs provide strong behavioral evidence, but the reviewed telemetry does not identify the binary’s origin or the initiating account in a way that establishes the full access path.

### 3. Application-host DNS activity and alert noise

Zeek core records a high rate of TXT queries from `10.10.2.30` with long, pseudo-random labels beneath `ns1.westbridge-services.cloud`; responses are short opaque strings or absent. Zeek DMZ records repeated TLS sessions from the proxy to `api.westbridge-services.net`. These are strong indicators to pivot on. Because the endpoint-to-proxy relationship for the TXT activity and the proxy-to-external TLS activity are separate observations, verify the exact timing and proxy request metadata before asserting that every record belongs to one process.

Snort also emits many generic potentially-bad-TLD, P2P, ICMP, and policy alerts across different internal hosts. They add plausible background activity but do not all resolve to a concrete user/process narrative in the visible logs. That breadth makes prioritization harder and gives the dataset a seeded-red-herring feel.

### 4. External support upload

At 16:32 UTC, Lina’s shell history and endpoint eCAR show creation of `/tmp/mhs-support-48217.tar.gz` from two EHR connector log files and a curl multipart upload through the corporate proxy to `support.valeworks-health.net`, ticket `MHS-48217`. Proxy access and Zeek HTTP show a successful 200 response and about 1.57 MB of request data. This may be a legitimate support workflow, but the destination’s authorization and the logs’ contents are not established by the bundle. Verify the vendor and ticket independently and inspect the specific archived files before treating this as benign or as a second exfiltration event.

## Synthetic Indicator Summary

| Category | Indicators |
|---|---|
| Behavior and intent | Highly explicit database/table dump, hidden-path staging, persistence, and encoded remote retrieval make the story unusually easy to classify. |
| Network distribution | Repeated C2-like DNS/TLS and many unrelated suspicious IDS events appear across hosts; alerts often lack a strong endpoint/process pivot. |
| Artifact naming | `rpt_0318`, `ClinicalResearch/Integration/DB-Staging`, `DeviceSyncSvc`, and ticket `MHS-48217` provide unusually convenient narrative labels. |
| Cross-source construction | Timelines and shared filenames align well across endpoint, syslog, SMB, Zeek, and proxy records. This is useful to hunt, though the deliberately clean joins contribute to the staged feel. |
| Collection realism | Routine activity exists across multiple operating systems and sources, but the reviewed high-risk trails are disproportionately explicit and neatly corroborated. |

## Realism Score by Category

Scores are 1–10, where 10 is most production-like.

| Category | Score | Assessment |
|---|---:|---|
| Lifecycle coherence | 8 | Login, process, transfer, persistence, and service-start sequences mostly have sensible ordering. |
| Cross-source pivots | 8 | Host, filename, account, network tuple, and domain pivots are useful and often corroborated. |
| Tradecraft plausibility | 5 | Techniques are plausible, but both primary malicious chains expose intent unusually plainly. |
| Signal-to-noise | 3 | Many broad IDS red herrings compete with the actionable persistence and data-movement signals. |
| Environment and collection realism | 5 | Multiple host roles and source types are represented; authorization/provenance context is thin for the most consequential events. |
| Overall production likeness | 4 | Strong training value, with a curated, deliberately legible exercise feel. |

## Recommendations

- Prioritize validation of the DB root login, the `rpt_0318.sql.gz` archive, root SSH to `APP-INT-01`, and the subsequent `svc_mhsync` write. Establish the business owner and intended workflow for each step.
- Investigate the `DC-01` WMI-initiated service/task creation and the encoded PowerShell fetch. Preserve the task, service, executable, WMI activity, initiating credentials, proxy records, DNS answers, and TLS certificate metadata.
- Pivot the `westbridge-services` TXT queries and TLS sessions by time, query volume, proxy session, and initiating endpoint process. Confirm whether they share a controller and whether any commands or content returned.
- Confirm whether the support ticket and vendor domain are approved; inspect the two uploaded log files for patient or credential data.
- For a more production-like exercise, reduce the number of disconnected generic IDS alerts and make filenames, service names, and transfer paths less self-descriptive while retaining enough evidence to support the same investigative pivots.
