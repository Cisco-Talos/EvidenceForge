# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 28

## Executive Summary

The supplied records are mostly convincing inputs for a detection stack: their formats parse, important native fields have the right types and semantics, and the visible process, session, and network relationships withstand several broad consistency checks. I found one low-confidence Windows event-version concern, but no demonstrated impossible same-identity lifecycle or decisive generator fingerprint; the data alone does not justify a confident origin attribution.

## Evidence For Synthetic

- [weak_signal] All 110 Security 5140 records declare `System/Version=0`, including `DC-01.meridianhcs.local/windows_event_security.xml:20297`, RecordID `28246379`, at `2026-11-02T13:23:14.3752710Z`, while carrying `AccessMask` and `AccessList`; Microsoft's published example of that field shape declares version 1. This merits checking against the exact provider manifest for the collected Windows build. It is **not a demonstrated schema defect**: Microsoft's same page lists version 0 in its prose, so the documentation is internally ambiguous. This small, qualified concern is the only positive origin indicator I retained. [Microsoft 5140 reference](https://learn.microsoft.com/fr-fr/windows/security/threat-protection/auditing/event-5140?view=azuresmps-3.7.0).

## Evidence For Real

- Windows event semantics are differentiated rather than flattened: Security 4688 uses hexadecimal process IDs while Sysmon 1 uses decimal IDs; 1102 uses the Eventlog provider and a namespaced `UserData/LogFileCleared` payload; failed authentication uses failure Keywords. These are useful details for actual parser and rule behavior.
- The visible Sysmon process graphs pass a same-GUID lifecycle check across all ten Windows hosts: no checked dependent or parent-reference event occurs before a visible creation or after a visible termination. This is affirmative consistency evidence, not proof of origin.
- All checked DNS, HTTP, SSL, SMB file, and SMB mapping references resolve to the corresponding sensor's connection UID with identical endpoint tuples, and their timestamps fall inside that connection's visible interval, allowing 1 ms before and 10 ms after for precision differences.
- TLS 1.2 full and resumed handshakes differ appropriately. All 389 `CsiI` histories have `resumed=true` and no `cert_chain_fuids`; full-handshake examples carry certificate evidence. The dataset also contains failed handshakes, not just successful connections.
- Native macOS records distinguish fork, exec, and exit; the exec actor retains its previous image while `event.exec.target` identifies the replacement image and PID version. For example, MAC-MROSS-01 lines 1–7 follow launchd → xpcproxy → Terminal → login → zsh without confusing exec with a new PID.
- Certificate identity is stable: 211 distinct X.509 fingerprints have no conflicting checked certificate fields across all three sensors. Within each Mac, repeated `(st_dev, st_ino)` executable references retain the same checked path, cdhash, size, and modification time.

## Detailed Analysis

### Actual input provenance and limitations

I read the complete neutral briefing at `/private/tmp/log-study-xgpo00ey/detection-prompt.md`. My dataset access was confined to `/private/tmp/log-study-xgpo00ey/data`; I enumerated its 117 files, parsed all its JSON/NDJSON and Windows XML, and sampled the supplied plaintext source families. I did not inspect repository files, TODOs, scenarios, generated manifests, prior assessments, other reviewers, or neighboring directory inventories. Inherited generic operating/project instructions existed in the environment; they were not used as origin evidence. Logged commands were treated only as text and never executed.

Primary-source consultation used actual `learn.microsoft.com`, `developer.apple.com`, and `docs.zeek.org` search filters, plus direct upstream `raw.githubusercontent.com/zeek/zeek/...` URLs. An attempted direct Microsoft repository README URL did not return content. No task-project public pages were accessed. The Apple exec-target page returned a JavaScript-only notice, so that page did not substantiate a detailed version-11 schema claim.

Representative input SHA256 values, computed from the bytes actually reviewed:

| Input, relative to data directory | SHA256 |
|---|---|
| `DC-01.meridianhcs.local/windows_event_security.xml` | `d8c897d7eed291bc9d88cb30be10a64364eff054e37b3492005faabffbf2dd31` |
| `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` | `89d58ecd7bb0cfe26b195193aaacc453ebf7d67916420c2cd590b92a6ba1c182` |
| `zeek-core/conn.json` | `d44aa60d22b8a46bb15984b4d69593b351c845fc6060455cb17e7dec421eb270` |

This is a text-export review, not EVTX validation, packet replay, binary-signature verification, or ingestion into a named SIEM. I did not have an exact Windows provider manifest, a collector configuration, an asserted stock eslogger export schema, or PCAP. I therefore separate syntactic/relationship checks from an assertion that every source was genuinely produced by its named native implementation. Sanitized destinations, similar filesystem timestamps, missing selected Sysmon types, and absent out-of-window initiators/closures were not scored.

### Parsing and coverage

The input contains 19,030 Security XML events, 11,785 Sysmon XML events, 35,805 eCAR records, 22,148 Zeek connection records, 4,313 DNS, 4,610 HTTP, 3,142 SSL, 2,385 file, and 1,318 X.509 records. There are 283 native macOS ES-shaped records and six Unified Log-shaped records. Every JSON/NDJSON line parsed successfully, and all 20 XML files parsed successfully.

The eCAR object/action distribution includes FLOW/CONNECT 27,152; PROCESS/CREATE 2,043; PROCESS/TERMINATE 1,904; MODULE/LOAD 1,798; USER_SESSION/LOGIN 955; and USER_SESSION/LOGOUT 488. These counts describe coverage; unequal creation/termination or login/logout totals in a slice are not evidence of a defect. The native Mac exports are deliberately distinguishable from eCAR FLOW rows: network observations were not treated as native ES notifications.

### Twenty concrete record checks

Paths below are relative to the supplied data directory. XML lines identify the start of the event; RecordID is an additional stable locator. Findings describe the inspected record, not a blanket certification of every event version.

| # | File and locator | Checked fields and result |
|---|---|---|
| 1 | `DC-01.meridianhcs.local/windows_event_security.xml:3`, RecordID 28245268 | 5156 v1, Level 0, Task 12810, Opcode 0, success Keywords; decimal `ProcessID=2420`, device-form application, UDP protocol 17 and port 53. Matches the documented example shape. |
| 2 | Same file `:208`, RecordID 28245287 | 4689 uses hex `ProcessId=0xcd4`, exit `Status=0x0`, full Windows path and SYSTEM subject. |
| 3 | Same file `:448`, RecordID 28245307 | 4769 has machine-account target `DC-02$`, service account `DC-01$`, domain-form SID, hex ticket options/encryption, IPv4-mapped source address. |
| 4 | Same file `:645`, RecordID 28245320 | 4688 v2 has hex child/creator IDs, `ParentProcessName`, null target SID for unchanged subject, and System integrity SID `S-1-16-16384`. |
| 5 | Same file `:1656`, RecordID 28245415 | 4624 v2 service LogonType 5, NETWORK SERVICE SID `S-1-5-20`, well-known logon ID `0x3e4`, services.exe caller, and no remote IP. No domain-ticket prerequisite was imposed. |
| 6 | Same file `:1711`, RecordID 28245416 | 4672 references the same NETWORK SERVICE identity/logon ID, about 10 ms after the 4624. |
| 7 | Same file `:2317`, RecordID 28245452 | 4768 has `krbtgt`, its domain RID 502 SID, machine target, preauthentication type 2, hex encryption/status values, and empty certificate fields. |
| 8 | Same file `:3090`, RecordID 28245477 | 4776 uses `PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, `Workstation`, and status; it does not invent a network-address field in that native event. |
| 9 | Same file `:6492`, RecordID 28245660 | 4634 has Target* identity fields, hex logon ID, and LogonType 3. |
| 10 | Same file `:20297`, RecordID 28246379 | 5140 has File object, mapped client IP, NETLOGON UNC share and NT local path, access mask 0x1; the version qualification is the weak signal above. |
| 11 | Same file `:61701`, RecordID 28248908 | 4771 has failure Keywords `0x8010000000000000`, status 0x18, type 2 preauthentication, krbtgt, and the client source endpoint. |
| 12 | Same file `:183744`, RecordID 28256455 | 4697 v0 has Task 12289, `PSEXESVC`, service type 0x10, start type 3, and `LocalSystem`. These are correctly typed service-install fields. |
| 13 | Same file `:270290`, RecordID 1 | 1102 at 18:42:11.6676456Z changes provider to Microsoft-Windows-Eventlog, Level to 4, Task to 104, Keywords to `0x4020000000000000`, and uses correctly namespaced UserData. Its RecordID reset is compatible with log clear. |
| 14 | `FILE-SRV-01.meridianhcs.local/windows_event_security.xml:146`, RecordID 271776 | 4656 v1 includes HandleId, AccessReason, ResourceAttributes, and full local file path; System process ID is 0x4. |
| 15 | Same file `:199`, RecordID 271777 | 4663 reuses handle `0x1b169349`, subject logon ID `0xf62b74b`, and object path; write access mask 0x2 corresponds to `%%4417`. |
| 16 | Same file `:240`, RecordID 271778 | 4658 closes that same handle after the visible access. Its time is 13:00:09.7044242Z, after the 13:00:06.1459007Z 4663. |
| 17 | `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml:6637`, RecordID 130232 | 4800 v0 uses Target* fields and SessionId 3; the matching 4801 at line 9775 preserves logon/session identity. |
| 18 | `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:2` | NOTIFY-shaped exec has actor PID 42152/version 10/launchd and target same PID/version 11/xpcproxy; it is not misread as a second fork. |
| 19 | `zeek-core/conn.json:1` and `dns.json:1` | UID `Cuq507OFNo7MpYfALL` and tuple agree; DNS RTT 0.028925 equals the UDP connection duration, numeric ports/IDs, boolean flags, array answers/TTLs parse correctly. |
| 20 | `zeek-core/ssl.json:4` and `conn.json:209` | UID `C81hggBFlA8cLO6LWI` is resumed TLS1.2, history CsiI, no fresh certificate-chain IDs, with SSL detection about 0.383 s after transport start and inside the 2.062069 s connection. |

The field expectations above were cross-checked with primary references for [4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624), [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688), [5156](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156), [4697](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697), [1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102), [4656](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4656), and [4800](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4800). No source-specific native defect follows merely from a value differing from an illustrative vendor example.

### Temporal and correlation checks

For all 11,785 Sysmon records, I indexed visible Event 1 and Event 5 by ProcessGuid and tested ProcessGuid, ParentProcessGuid, SourceProcessGUID/Guid, and TargetProcessGUID/Guid references against available creation/exit boundaries using SystemTime. There were no violations. This checks visible same-GUID relationships; it does not demand creation records for pre-window processes or prove the truth of every parent image.

Across Security logs, I indexed 4624/4634 by host-local TargetLogonId. For 4688, 4648, 5140, 5145, and 4697, checked ordinary SubjectLogonId references did not precede a visible login or follow the last visible logout. Well-known SYSTEM/LOCAL SERVICE/NETWORK SERVICE identifiers were excluded from that simplified boundary check because their semantics need separate treatment. This is a bounded check, not a complete Kerberos or credential-use proof.

The per-sensor connection inventories have 12,314 core, 433 database, and 9,401 DMZ rows, with zero duplicate UIDs inside each inventory. DNS/HTTP/SSL/SMB companions have no missing connection UID, tuple mismatch, or tested out-of-interval timestamps. UIDs were scoped to sensors, rather than incorrectly required to be identical across independent sensors. Zeek's documented connection schema supports the observed JSON types and UDP connection modeling. [Zeek conn reference](https://docs.zeek.org/en/current/reference/logs/conn.html).

The TLS histories and resumption/certificate relationships are internally appropriate. `CsiI` occurs 75 times on core, five on database, and 309 on DMZ, always with resumption true and no fresh certificate-chain FUIDs. TLS1.3 `Cs` is not a missing-certificate defect: encrypted handshake messages constrain passive visibility. These interpretations follow the native history and resumption logic in [Zeek's SSL script](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/ssl/main.zeek).

All checked hashes in Zeek MD5/SHA1/SHA256/fingerprint/OCSP issuer-hash fields have the expected hexadecimal lengths. For a repeated X.509 fingerprint, the serial, subject, issuer, validity interval, key algorithm/length, and DNS SAN fields are stable. That does not cryptographically validate a certificate without its DER bytes.

### macOS and plaintext interpretation

Both Mac ES-shaped exports declare message version 11. Their event types are 9, 11, and 15 with exec/fork/exit payloads, and notification-shaped actions; no authorization denial is inferred from them. Their per-event-type sequence counters increment continuously and their global counters increase, consistent with the documented purpose of [Apple's sequence numbers](https://developer.apple.com/documentation/endpointsecurity/es_message_t/seq_num?language=objc). A counter beginning at zero can reflect client collection startup and is neutral.

The two files have no visible use of an exact `(pid, pidversion)` actor identity after its exit. Exec target identities and subsequent actor identities progress coherently in sampled terminal and SSH process chains. Nanosecond-format ES times and Unified Log's offset-bearing timestamps were treated as different export representations. The kernel policy message in MAC-MROSS-01 Unified Log line 2 says a policy “would not allow” process 62503; I did not promote that text alone to proof that execution was denied or that effects occurred. Without declared OS build and exporter implementation, this review cannot certify every version-11 field or stock eslogger layout.

Plaintext samples have recognizable RFC5424 syslog envelopes, zsh extended history, ASA message IDs/priority prefixes, Snort fast-alert formatting, and a proxy access format with explicit custom fields. APP-INT-01 syslog line 1 is a sysstat CRON command, while line 3 is a PAM session close; the close near the left boundary is neutral. Proxy CONNECT and inspected HTTPS request rows were not mistaken for unencrypted Internet TLS payload in the sensor. I did not independently validate every plaintext message template or every IDS signature ID against a vendor ruleset.

### Scoring rationale

The score of 28 means mostly realistic with minor or explainable artifacts. It is not a 28% posterior probability of synthetic origin. The weak 5140 version discrepancy carries little weight because the primary documentation itself is ambiguous; broad positive consistency and schema findings keep the score low. Confidence 80 attaches to the **Inconclusive** verdict: production telemetry with a collector/export quirk and carefully constructed synthetic telemetry remain viable explanations.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| weak_signal | Windows Security 5140 | 110 events on DC-01, DC-02, and FILE-SRV-01 | Version 0 versus published version-1 example for the observed field shape; exact-manifest validation remains necessary. Small influence only; not counted as a hard contradiction. |

No hard_contradiction, contract_gap, demonstrated schema_or_format defect, or defensible dataset-wide distribution defect was established by the performed checks.

## Realism Score by Category

- **Field format accuracy:** 9 — Successful parsing and source-specific field shapes; minor event-version uncertainty and no binary/native-export certification.
- **Temporal patterns:** 9 — Checked visible process/session boundaries and network companion intervals are coherent; limited window prevents long-term cadence claims.
- **Cross-source correlation:** 9 — Connection tuples/UIDs, handles, and sampled session/process identities align; no packet-level or full authentication-mechanism reconstruction was performed.
- **Behavioral realism:** 8 — Role-appropriate service, user, browser, monitoring, and administrative observations; this review emphasizes detection semantics over exhaustive behavioral distributions.
- **Environmental consistency:** 9 — Platform-specific schemas are kept separate and repeated certificate/executable identities are stable; exact collection configurations remain unknown.

## Recommendations

- If this were synthetic, verify Security 5140 System.Version against the exact target Windows provider manifest, then use its matching version/field contract consistently. The visible version discrepancy is small but directly relevant to version-aware parsers.
- If this were synthetic, preserve the demonstrated distinctions between 1102 UserData and Security EventData, hexadecimal and decimal PID fields, TLS resumption and fresh certificate evidence, and Mac exec actor/target identities. These concrete properties are what allow detection rules and joins to behave plausibly.
- For a firmer assessment of this supplied export, obtain the collector/export schema and exact OS/provider versions. This recommendation addresses the unresolved 5140 and ES-version validation qualifications; it is not a claim that absent collection documentation makes the data synthetic.
