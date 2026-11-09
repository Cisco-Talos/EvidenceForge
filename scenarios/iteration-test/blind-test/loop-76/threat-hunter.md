# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 91  
**Synthetic-Confidence Score:** 84

## Executive Summary

This six-hour slice reads as a carefully correlated synthetic enterprise dataset with credible operational behavior. A threat hunter can follow multiple useful pivots: a support-log archive upload from a developer workstation, a privileged database export transferred to an application server and then into a file share, remote administration, SMB access, directory services, web traffic, and routine host activity. Endpoint, Zeek, proxy, IDS, and file-service observations agree on several of those actions, which makes the individual workflows persuasive.

The synthetic-origin judgment rests on the repeated texture of the background and alert data, not on story coherence or unusually complete telemetry. DNS/IDS suspicious-domain activity recurs from a narrow set of internal addresses with generated-looking names and a small, repeated TLD/signature palette. Many ordinary records also have tidy, catalog-like content. These are distribution clues rather than impossible events. I found no decisive hard contradiction in the inspected slice.

## Evidence For Synthetic

- **Category: distribution_texture.** Zeek core DNS shows a high number of repeat lookups to common destinations (for example, `pypi.org` appears 41 times; `api.snapcraft.io` 20 times; `ocsp.sectigo.com` 20 times), alongside suspicious names with compact generated labels. At 13:00:19Z, `10.10.3.20` queries `cdn-check-vrkx2npi.top` and receives NXDOMAIN; the core and perimeter Snort streams flag the same source tuple as a `.top` query. This combination of a templated-looking label, recurring alert families, and repeated source pattern has a synthetic-noise feel. It is not proof by itself: real malware and blocked lookups can look similar.
- **Category: distribution_texture.** Across the six-hour interval, the two IDS files contain repeated families of `.top`, `.bit`, `.tk`, `.to`, and `.cloud` DNS alerts, plus repeated external scan/ICMP alerts. Many are ordinary false positives or internet background noise in isolation. Their recurring, bounded vocabulary and concentration around a few internal addresses feel deliberately assembled to provide huntable red herrings.
- **Category: environment_or_collection_plausibility.** The slice has broad and unusually orderly coverage across endpoint Ecar, Windows Security/Sysmon, Linux syslog, macOS endpoint streams, several Zeek views, proxy, firewall, and Snort. That is plausible for a lab or curated collection, but the near-uniform six-hour host window and broad set of synchronized sources look more like an assembled exercise dataset than an incidental enterprise export. I treat this as a weak provenance clue, not a telemetry defect; a planned collection window can produce the same shape.
- **Category: weak_signal.** Some histories contain sequences of routine inventory, troubleshooting, and editing commands across unrelated systems, with clean timestamps and low friction. Those activities are plausible and often corroborated, so the behavior itself is not a contradiction. The broad coverage of conveniently useful background actions contributes only a small amount to the synthetic reading.
- **Hard contradictions / contract gaps:** None established from the visible records. I did not count missing events at the edges of the six-hour window, sparse source coverage on individual hosts, selected Sysmon event absence, or incomplete cross-source matches as synthetic evidence.

## Evidence For Real

- **A coherent support upload is corroborated across sources.** `WS-LNGUYEN-01` history shows Lina Nguyen creating `/tmp/mhs-support-48217.tar.gz` from two EHR connector logs and posting it with `curl` to `support.valeworks-health.net`. Endpoint Ecar records the tar process and archive creation around 17:05:37Z, then the curl process, archive read, and connection through `10.10.3.20:8080` around 17:05:54–17:06:05Z. Zeek HTTP records a POST with the same case path and archive name, `curl/7.81.0`, a 1,573,258-byte request body, and HTTP 200; proxy access independently records the POST as forwarded with a 200 response. The sequence is operationally plausible for authorized support or data staging, but the amount and contents warrant review.
- **A sensitive database export has a strong local-to-network trace.** On `DB-PROD-01`, root logs in from `APP-INT-01`, runs `mysqldump --single-transaction ehr patients insurance_claims`, compresses the output, then uses SCP to `APP-INT-01:/tmp/.cache/rpt_0318.sql.gz`. Ecar shows the process/file steps and source tuple `10.10.4.10:54381 -> 10.10.2.30:22`; the receiving app host records an sshd-owned file creation. Later Zeek SMB and Linux Ecar on `FILE-LNX-01` show the same named archive written into `ClinicalResearch/Integration/DB-Staging` from `10.10.2.30`, with a successful `smbd_audit` open/write/close sequence. The exact progression across host, network, and server evidence is unusually strong for threat hunting. It is also a serious potential data-handling incident, whether benign or not.
- **Remote administration has credible Windows evidence.** `DC-01` records a type-3 session from `WS-AJOHNSON-01`, a `PSEXESVC.exe` file and service creation, the service process, and a short `cmd.exe /c whoami && hostname` child. That fits a real PsExec/remote administration sequence. Nearby normal endpoint and directory activity provides context, and the process/service ordering is plausible.
- **The dataset contains useful benign context and realistic ambiguity.** Linux histories show routine service diagnostics, package checks, and application work; Windows endpoint streams contain normal service, Office/browser, registry, and module activity; and network records include successful and failed sessions. No single alert is treated as a verdict, and the support and database transfer activity both have plausible operational explanations.
- **Source-native details generally fit their sources.** Linux paths and SSH/Samba records, Windows executable paths and service events, macOS endpoint streams, Zeek connection states and file observations, proxy request fields, and syslog audit lines use recognizable source-specific structures. The suspicious support upload carries a matching filename, URI, user agent, status, and byte counts in the relevant network evidence.

## Detailed Analysis

### Operational lifecycle and pivots

The support upload forms a practical investigation chain: user history → tar process → archive creation → curl process and file read → endpoint flow through the explicit proxy → proxy access record → Zeek HTTP POST and captured file. The request succeeds, so this is not merely an attempted transfer. The URL is unencrypted HTTP in the visible proxy-facing record, and the archive is about 1.5 MB. A hunter should establish whether case `MHS-48217` and `support.valeworks-health.net` are approved, whether those two log files contain secrets or regulated data, and whether the observed request came from a sanctioned workflow.

The database export chain is similarly actionable. Root’s shell history, process and file telemetry, outbound SSH tuple, receiving sshd file creation, later SMB transfer, Zeek SMB file record, and Samba audit all point to the same `rpt_0318.sql.gz`. This suggests staging or movement of a database dump rather than an isolated command-line artifact. The destination path under `/tmp/.cache` and subsequent placement in `ClinicalResearch/Integration/DB-Staging` merit an authorization and access review. The telemetry shows transfer evidence, not the dump’s contents or whether access was malicious.

The PsExec sequence on `DC-01` is a distinct, strong pivot from the workstation source to a domain controller. The supplied evidence reaches a service process and an identity/hostname command, but does not establish what was done after that command. The lack of later actions inside this window is not treated as a failure because collection ends at a fixed boundary.

### Signal, noise, and collection

The apparent collection includes endpoint process/session/file/flow evidence, Windows security and Sysmon on selected Windows hosts, Linux/macOS host records, Zeek at core, DMZ, and database vantage points, plus proxy, firewall, and IDS data. Host-level telemetry is uneven by host and platform, but no missing source is needed to make the visible pivots. The presence of both successful, failed, and partial network connections adds reasonable noise. A threat hunter can use IPs, process IDs, filenames, SMB paths, SSH tuples, and request IDs/URIs for pivots.

The main synthetic cue is the repeated alert/noise texture. Suspicious DNS queries recur from addresses including `10.10.3.20` and `10.10.3.10`, with short label patterns and repeated TLD families. The broad IDS stream also repeats recognizable scan, ping, STUN, and P2P signatures. Such events can occur in real networks; the concern is the consistent presentation as a compact catalog of familiar red-herring types rather than any one event being impossible.

### Contradictions and limitations

I did not identify a clear impossible ordering or a source-native format defect strong enough to classify as a hard contradiction. I also did not infer from the anonymized/sanitized domains or from the absence of a particular Sysmon event class. Where endpoint and network records agree, that agreement raises realism of the individual trace, but it is not independent proof of a real-world origin because a synthetic generator can intentionally correlate those sources.

## Synthetic Indicator Summary

| Category | Indicator | Weight |
|---|---|---|
| distribution_texture | Repeated IDS DNS alert families and generated-looking short-label domains from recurring internal sources | Moderate |
| distribution_texture | Wide catalog of familiar scan, ping, STUN, P2P, and suspicious-TLD background alerts | Moderate |
| environment_or_collection_plausibility | Highly orderly six-hour slice with broad, synchronized multi-source coverage | Weak |
| weak_signal | Conveniently rich routine command and host context across many systems | Weak |
| hard_contradiction | None established | None |
| contract_gap | None established | None |
| schema_or_format | None established | None |

## Realism Score by Category

| Category | Score (1–10) | Rationale |
|---|---:|---|
| Field format accuracy | 8 | Source-native fields and common event/log structures look credible; no decisive formatting defect found. |
| Temporal patterns | 8 | Process/file/network sequences generally order plausibly, including the support upload and database movement. |
| Cross-source correlation | 9 | Several valuable chains align across endpoint, proxy, Zeek, and Samba/SMB records. |
| Behavioral realism | 7 | Routine administrator/developer behavior and suspicious transfer tradecraft are plausible, though background alert texture feels curated. |
| Environmental consistency | 7 | Host roles, users, network zones, and destinations mostly make sense; the broad, orderly coverage and recurring red-herring palette lower confidence. |

## Recommendations

- Triage the support upload: verify case `MHS-48217`, recipient ownership, and whether the archived connector logs contain credentials, patient data, or tokens. Preserve proxy and Zeek HTTP/file evidence.
- Investigate the database dump path end to end. Confirm the root SSH session, business approval, dump contents, destination access controls, and why the compressed file moved from the application host into the clinical research staging share.
- Validate the PsExec activity from `WS-AJOHNSON-01` against approved administration records, then inspect activity immediately before and after the visible service and command events if that telemetry is available.
- Prioritize DNS/IDS clusters by joining each alert to the Zeek DNS query, endpoint process or proxy record, and subsequent destination connection. Treat TLD or signature hits as leads rather than findings.
- For an authenticity benchmark, retain these strong correlated pivots but vary the frequency and composition of background alert families and routine workstation activity. Preserve plausible benign explanations for the two data transfers so a hunter must validate authorization rather than infer intent from a planted indicator.
