# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 72  
**Synthetic-Confidence Score:** 56

## Executive Summary

This corpus is substantially more source-native and internally consistent than most synthetic log sets: the Windows/Sysmon schemas are generally accurate, the Zeek JSON is parseable and referentially coherent, and process identity survives cleanly across Security, Sysmon, and eCAR. I nevertheless assess it as synthetic because the domain-controller Security logs use down-level event versions for service and scheduled-task creation despite clear Server 2022 build evidence, and one workstation records a screen lock and unlock only 0.635 milliseconds apart.

## Evidence For Synthetic

- **[schema_or_format] [P1] Security 4697/4698 versions conflict with the visible OS generation.** `DC-01.meridianhcs.local/windows_event_sysmon.xml`, EventRecordID 3288934 at `2024-03-18T12:08:18.1712690Z`, identifies Microsoft `TiWorker.exe` version `10.0.20348.2322`; `DC-02...`, EventRecordID 1368553 at `12:05:51.7758327Z`, likewise identifies `WmiPrvSE.exe` version `10.0.20348.1`. Those are Server 2022-class builds. Nevertheless, all three service-install records are Security Event 4697 version 0 and omit the version-1 `ClientProcessStartKey` field: DC-01 EventRecordIDs 28256384 (`16:00:23.2359892Z`) and 28257338 (`16:20:27.1022181Z`), plus DC-02 EventRecordID 25384535 (`16:25:08.6940946Z`). DC-01's scheduled-task creation, Event 4698/EventRecordID 28257345 at `16:20:37.4690670Z`, is also version 0 with only `TaskName` and `TaskContent`, omitting the process/RPC fields carried by the version-1 schema on this OS generation. This is a concrete source-version fingerprint and can cause version-aware SIEM mappings to lose fields.
- **[hard_contradiction] [P1] One lock/unlock lifecycle is physically implausible.** In `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml`, Event 4800/EventRecordID 131199 at `2024-03-18T17:48:17.3933800Z` locks session 2 for LogonID `0x263743b`; the immediately following Event 4801/EventRecordID 131200 unlocks the same session at `17:48:17.3940149Z`. The elapsed time is approximately 0.000635 seconds, which is not a plausible human unlock interval. Other lock intervals in the corpus span minutes, making this pair a localized but strong timing tell rather than a global clock-format issue.
- **[contract_gap] [P2] RDP disconnect records systematically discard the client hostname.** All five Security Event 4779 records set `ClientName` to `-` even when the same LogonID's Event 4624 type 10 identifies a workstation and the 4779 retains a concrete client IP/port. Examples are DC-01 EventRecordID 813 at `17:59:42.8386948Z` (`LogonID=0x55df795`, `ClientAddress=10.10.1.31`, while the matching 4624 names `WS-MCHEN-01`) and WS-AJOHNSON-01 EventRecordID 130677 at `15:29:10.1689668Z` (`LogonID=0x2701ac7`, `ClientAddress=10.10.1.99`, while the matching 4624 names `LT-MRIVERA-02`). A blank client name is individually possible, but 5/5 suppression across several target systems weakens RDP detection enrichment in a repeated, template-like way.

## Evidence For Real

- Windows event metadata is unusually careful. Across 18,473 parsed Security events, the common records have appropriate field sets and system metadata: 4624 version 2, 4688 version 2, 5156 version 1, and correct task/keyword combinations. The sole Event 1102 is correctly rendered under the `Microsoft-Windows-Eventlog` provider with `UserData/LogFileCleared`, a reset `EventRecordID` of 1, and populated subject identity; it is not a flattened Security-Auditing event.
- The 4,816 Sysmon records use event-specific schemas and versions consistently: Events 1/3/22 are version 5, Events 5/7/10 are version 3, and Events 8/11/13 are version 2. Sampled values were type-appropriate, including hexadecimal access masks, semicolon-delimited DNS answers, process GUIDs, full hash sets, and source/target identities.
- All 926 Security 4688 records having visible Sysmon Event 1 counterparts matched on PID, image, command line, and LogonID. Sysmon preceded Security by a varied 35-650 ms, with no value mismatches; the timing was not a fixed-offset duplicate.
- Host-scoped hash identity is stable. Across 324 observed host/image pairs with Sysmon hashes, no image changed its SHA1/MD5/SHA256/IMPHASH tuple on the same host, while different Windows builds legitimately produced different hashes and file versions across hosts.
- Visible process causality held. No Sysmon termination preceded the matching visible create, no visible child referenced a parent created later, and every visible parent match agreed on PID and image. The equivalent eCAR checks found no actor or target process identity created after its dependent event and no disagreement between `actorID` and `source_process_uuid`.
- Zeek structure and references were robust. I parsed 32,626 JSON records across `zeek-core`, `zeek-db`, and `zeek-dmz` with zero JSON failures. All 12,226 protocol/file UID references resolved to a local `conn.json` UID, and no protocol record preceded its connection record. Field shapes sampled from conn, DNS, HTTP, TLS, X.509, SMB, SMTP, DHCP, OCSP, files, and PE logs were recognizably Zeek-native.
- The auxiliary sources are operationally usable. ASA priorities match message severities, 6,961 TCP/UDP connection builds have unique IDs and correctly ordered teardowns, NAT messages bracket translated flows, Snort fast-alert lines have conventional GID:SID:revision/classification syntax, and RFC 5424 syslog records carry plausible facility/severity values and process IDs.

## Detailed Analysis

### Corpus orientation and sampling

The visible window is approximately six hours on 18 March 2024. The corpus contains Security and Sysmon XML on ten Windows systems, eCAR JSON on 21 endpoints, three Zeek sensor families, Cisco ASA, two Snort alert streams, proxy access logs, Linux syslog, web access logs, and timestamped bash histories. I parsed the complete Windows/Sysmon/eCAR/Zeek families for counts and structural checks, then manually inspected representative records for every Windows Security and Sysmon event type present, every eCAR object/action pair, and each Zeek protocol family.

### Windows Security schema and event semantics

The dominant event families are 5156 (11,579), 4769 (2,094), 4688 (930), 4624 (872), 4768 (800), 4689 (773), 4634 (447), and 4672 (430), plus lower-volume account, share, service, task, lock, and RDP events. Their ordinary field names and value encodings are strong. For example, DC-01 EventRecordID 28245268 is a type-5 4624 with hexadecimal process/logon IDs, `Advapi`/`Negotiate`, service-account SID values, and the correct version-2 extension fields. DC-01 EventRecordID 28245569 is a version-2 4688 with hexadecimal PIDs, mandatory label, token-elevation token, target identity fields, command line, and parent image.

The important exception is schema versioning. Both domain controllers visibly run build 20348-era Microsoft binaries, but their 4697 records remain version 0. The DC-01 4698 record is likewise the old two-field version. These XML records are otherwise presented as native event payloads, so the mismatch is difficult to explain as normal ECS normalization or selective field extraction.

Logon fields were otherwise coherent. Type 3 records split plausibly between Kerberos and NTLM; remote addresses use IPv4-mapped IPv6 where Windows commonly does; type 2/7/10 records carry appropriate local or remote address semantics; and no visible 4634 occurred before a matching visible 4624 for the same LogonID. The 4800/4801 pair on WS-AJOHNSON-01 is the sole impossible visible lifecycle ordering/timing observation.

### Sysmon and process detection utility

Sysmon examples preserved event-specific casing differences such as `ProcessGuid` on Event 1 and `SourceProcessGUID`/`TargetProcessGUID` on Event 10. System `TimeCreated` and payload `UtcTime` differed by no more than 83 ms across all 4,816 records, which is plausible ingestion/rendering precision rather than equality copied mechanically. Event 1 records include complete parent context and four common hash algorithms; Event 3 has native boolean and address/port fields; Event 22 includes A, PTR, and SRV-style result strings plus realistic status codes (`0`, `9002`, `9003`).

Cross-source process detections would work well. There were 926 exact Security 4688-to-Sysmon 1 matches within two seconds, with no image, command-line, or LogonID disagreements. ProcessGUIDs never mapped to multiple PIDs on the same host. Visible parent-child and termination checks found no inversions. This is high-quality correlation; per the study rules, its completeness was treated as a strength rather than a synthetic indicator.

### eCAR structure and identity

All 32,914 eCAR lines parsed as JSON. The main actions were `FLOW/CONNECT` (23,866), `MODULE/LOAD` (2,266), `PROCESS/CREATE` (1,929), `PROCESS/TERMINATE` (1,787), `USER_SESSION/LOGIN` (1,046), `PROCESS/OPEN` (733), and `USER_SESSION/LOGOUT` (595), with lower-volume registry, file, thread, and service actions. Typed properties were consistent with their action families, and process-owned records aligned `actorID`, `source_process_uuid`, PID, image, and principal. Opaque `objectID` forms varied by object family, which is acceptable for eCAR correlation and did not create collisions or visible causality inversions in the tested relationships.

### Zeek and perimeter formats

The Zeek records use standard dotted field names (`id.orig_h`, `certificate.subject`), proper UID/FUID forms, expected arrays for certificates and files, and protocol-specific fields. Across the three sensors, zero referenced UIDs were missing from the corresponding connection stream and zero DNS/HTTP/TLS/SMB/SMTP/file records preceded their referenced connection. Representative DNS request/response byte counts, TCP/UDP connection histories, HTTP CONNECT rows, TLS cipher/version strings, X.509 validity fields, SMB paths, and DHCP transaction arrays were internally usable by SIEM parsers.

ASA message IDs, priorities, connection IDs, and lifecycle text also held up under parsing. All 6,961 observed TCP/UDP teardown records followed their corresponding build record; no connection ID was duplicated. Proxy and Snort formats were conventional enough for line-oriented ingestion. I found no P0 parser-breaking defect, invalid address, malformed SID/GUID, or visible cross-source identity contradiction.

## Synthetic Indicator Summary

| Priority | Category | Affected source family | Scope | Effect on score |
|---|---|---|---|---|
| P0 | — | — | None substantiated | No parser-breaking or dataset-wide hard contradiction found. |
| P1 | `schema_or_format` | Windows Security 4697/4698 | Four records on two Server 2022-class DCs | Strong source-native version fingerprint; version-aware rules lose expected fields. |
| P1 | `hard_contradiction` | Windows Security 4800/4801 | One adjacent pair on WS-AJOHNSON-01 | A 0.635 ms human lock/unlock interval is physically implausible, though localized. |
| P2 | `contract_gap` | Windows Security 4779/4624 | All five RDP disconnects | Repeated loss of client hostname despite correlated source identity reduces detection enrichment and looks templated. |
| P3 | — | — | None substantiated | Several weak candidates (complete correlation, sparse optional families, blank Sysmon rule names) were excluded under the study rules or were normal deployment choices. |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Nearly all event-specific structures and encodings are native-quality; the 4697/4698 version mismatch is the material exception.
- **Temporal patterns:** 8/10 — Precision, ordering, and cross-source latency are credible except for one sub-millisecond lock/unlock pair.
- **Cross-source correlation:** 9/10 — Process, logon, eCAR identity, Zeek UID, and ASA lifecycle checks were highly coherent without visible inversions.
- **Behavioral realism:** 8/10 — Process trees, authentication mixes, network services, and Linux operational noise are varied and detection-usable.
- **Environmental consistency:** 8/10 — Host roles and source mix are plausible, but Server 2022 build evidence conflicts with down-level Security event versions.

## Recommendations

- If this were synthetic, emit Security 4697 and 4698 according to the modeled Windows build. On build 20348 systems, use the version-1 payloads and populate the added client-process/RPC fields from the same canonical process context used by Sysmon and eCAR; add version-aware tests so older modeled Windows releases can still emit version 0 legitimately.
- Enforce a realistic minimum dwell between Event 4800 and Event 4801 for the same session. A lock followed by unlock should represent human interaction time, with a broad non-uniform distribution; preserve bounded-window cases where only one side is visible.
- Populate Event 4779 `ClientName` from the established RDP session identity when the corresponding type-10 logon already has a client workstation. Preserve `-` only for explicit unresolved-name cases, and vary that outcome according to collection/network conditions rather than applying it to every disconnect.
