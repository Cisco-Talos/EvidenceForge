# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 20

## Executive Summary

The supplied telemetry is highly production-like at the schema and correlation layers. Parsing and lifecycle checks found no demonstrated impossible process ordering, identity contradiction, or malformed source structure in the cases examined; the small number of unresolved HTTP file references is compatible with filtered collection. These results support the low synthetic-confidence score, but well-constructed synthetic telemetry could also pass these checks, so they do not establish production provenance.

## Evidence For Synthetic

- No high-impact synthetic indicator was demonstrated. I did not find evidence sufficient to classify an issue as `hard_contradiction`, `schema_or_format`, or a confirmed `contract_gap`.
- [weak_signal] Six HTTP response file references do not resolve to a `files.json` row in the same sensor export: `zeek-core/http.json` lines 735, 1022, 1279, 1407, 1522, and `zeek-dmz/http.json` line 2344. For example, core line 735 names `resp_fuids=["FI8tEIuyvv9cTRXGEcH"]`; its connection is present at `zeek-core/conn.json` line 5271, but its file row is absent. This is an investigational lead, not proof of a generation defect: export filtering or source-row loss could explain it. I did **not** increase the synthetic-confidence score for this absence alone.

## Evidence For Real

- Windows records preserve important event-specific distinctions. `DC-01.meridianhcs.local/windows_event_security.xml` line 268424 uses the Microsoft-Windows-Eventlog provider and namespaced `UserData/LogFileCleared` for 1102, with EventRecordID reset to 1. Ordinary auditing events use `EventData` and the Security-Auditing provider.
- The selected Windows event schemas distinguish decimal WFP process IDs, hexadecimal Security process IDs, resource-message tokens, domain SIDs, native device paths, IPv4-mapped Kerberos addresses, and Sysmon GUID identities. These are the details that commonly break real detection pipelines.
- Across all 10 Windows Sysmon exports, 876 process-create records have internally stable executable hashes for the same host, image path, and file version. Checking source, target, parent, and ordinary process GUID references found no reference more than 100 ms before a visible create, and none more than one second after a visible termination. Image identities were also consistent for GUIDs with visible creates.
- The 22,030 Zeek connection rows have broad transport-state coverage. Protocol rows with a scalar `uid` resolve to the corresponding local connection and match its visible endpoint tuple. Protocol timestamps fall inside their connection interval within a 100 ms comparison tolerance. These are consistency checks, not an assertion that complete matching itself proves authenticity.
- Network protocols exhibit useful source-specific detail: DNS includes A, AAAA, PTR, TXT, SRV, NS, and MX queries; HTTP includes proxy authentication failures, redirects, conditional responses, partial responses, and upstream failures; TLS includes 1.2/1.3, resumption, and failed/incomplete handshakes.
- Native macOS rows distinguish fork, exec, and exit and retain audit-token PID versions. The normalized EDR export separately has network and file objects. I did not mistake normalized FLOW records for native Endpoint Security network notifications.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. It contains Windows XML, Linux RFC5424-style syslog and histories, normalized eCAR JSON, native-style macOS Endpoint Security/Unified Log NDJSON, three Zeek sensor exports, proxy/web access logs, ASA logs, and IDS alerts. The network window is approximately 2026-11-02 13:00–19:00 UTC.

I parsed every Windows XML export and all records in the Zeek families used below. Automated checks covered process/session identity relationships, selected temporal invariants, JSON field references, and network byte-budget relationships. I also inspected individual source records, including more than 20 distinct Windows event types. The checks establish bounded consistency, not exhaustive verification against every provider build or schema revision.

### Windows event shapes: selected native-schema checks

Line numbers below identify the beginning of an XML Event. `DC Security` and `DC Sysmon` mean the respective XML files under `DC-01.meridianhcs.local/`; `File Security` means `FILE-SRV-01.meridianhcs.local/windows_event_security.xml`.

| File / line | Event | Field-level observation |
|---|---:|---|
| DC Security:3 | 4624 v2 | Service logon: SYSTEM, type 5, `Advapi`, `Negotiate`, local source `-`, TargetLogonId `0x3e7`; extended v2 fields are present. |
| DC Security:58 | 4672 | SubjectLogonId `0x3e7` agrees with preceding SYSTEM logon; privilege names are native Se* names. |
| DC Security:101 | 5156 v1 | Decimal `ProcessID=2420`, native device application path, UDP protocol 17, direction token `%%14592`, DNS tuple `10.10.1.21:34462 -> 10.10.2.10:53`. |
| DC Security:388 | 4768 v0 | `TargetUserName=LT-MRIVERA-02$`, krbtgt service, AES type `0x12`, PreAuthType 2, source `::ffff:10.10.1.99`. |
| DC Security:430 | 4769 v0 | Same requesting machine/client port; service account `DC-01$`; TGS follows the TGT record by approximately 3 ms. |
| DC Security:469 | 4688 v2 | Hexadecimal NewProcessId `0xe1c`, parent ProcessId `0x924`, SYSTEM subject, WmiPrvSE path, MandatoryLabel system SID. |
| DC Security:635 | 4689 | ProcessId `0xd80`, explorer image, exit status `0x0`; distinct process-termination shape. |
| DC Security:2956 | 4648 | SYSTEM caller, Veeam process, alternate `svc_backup` credentials, target server `PROXY-01`, separate subject/target GUID fields. |
| DC Security:4359 | 4634 | Machine-account network logoff, type 3, with TargetLogonId. |
| DC Security:4433 | 4776 | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation, target user, and status, rather than inappropriate Kerberos fields. |
| DC Security:51391 | 5140 | SYSVOL share, `\\*\SYSVOL`, local NT path, remote IP/port, access mask and resource token. |
| DC Security:74453 | 4771 | Failure status `0x12`, PreAuthType 2, audit-failure keywords `0x8010000000000000`. |
| DC Security:143437 | 4779 | AccountName/AccountDomain/LogonID and RDP session/client fields, instead of generic 4624 field names. |
| DC Security:182203 | 4697 | PSEXESVC install with ServiceType `0x10`, demand start `3`, LocalSystem account. |
| DC Security:197734 | 4698 | Embedded task XML is escaped inside TaskContent; service-account principal, command, and trigger are represented separately. |
| DC Security:268424 | 1102 | Correctly distinct provider and UserData shape; clear at `18:42:26.0007020Z`, EventRecordID 1. |
| File Security:7808 | 5145 | RelativeTargetName, share and local path, access mask `0x120089`, and access-token list. |
| File Security:7853 | 4656 v1 | File handle `0x6e8fb701`, System PID `0x4`, transaction/resource attributes, request mask. |
| File Security:7902 | 4663 v1 | Same handle/path/session as preceding request, with actual access mask `0x1`. |
| File Security:7943 | 4658 | Same handle closed after access, at `13:59:21.7096218Z`. |
| DC Sysmon:3 | 10 v3 | SourceProcessGUID/TargetProcessGUID, thread ID, GrantedAccess `0x1410`, and pipe-delimited CallTrace. |
| DC Sysmon:38 | 3 v5 | Inbound DNS view uses `Initiated=false`, decimal PID, protocol and source/destination fields. |
| DC Sysmon:318 | 1 v5 | ProcessGuid, ParentProcessGuid, image metadata, user/session, hashes, and command lines are present. |
| DC Sysmon:483 | 5 v3 | Process termination has process identity and user without inappropriate create-only metadata. |

Additionally, `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml:2539` has a 4625 wrong-password failure (`0xc000006d` / `0xc000006a`) with local type 2 semantics. Its lock/unlock records at lines 25954 and 27297 preserve LogonId `0x2488b53` and SessionId 2.

### Process and session integrity

The Windows process tests used GUID identity, not PID alone; PID reuse is normal. They compared Sysmon UtcTime, not only XML TimeCreated, and accepted small timing tolerances. All 876 observed creates passed the checked image/hash consistency conditions. References to pre-window processes were neutral.

For Security sessions, I compared visible 4624 and 4634 records by host/TargetLogonId and compared Sysmon create users with visible matching logon principals. No contradictory principal or visible logoff-before-logon pair was found. I did not penalize sessions without in-window logoff or processes without in-window creation/termination.

Across eCAR files, checking actorID against visible PROCESS/TERMINATE objectID records found no actor usage more than one second after the corresponding process termination. This is particularly useful for FILE and FLOW ownership checks; it is not a claim that every normalized record has a native-source companion.

### Zeek schema and correlations

The sensor counts are core 12,279 connections, DMZ 9,287, and DB 464. Scalar-UID records in DNS/HTTP/TLS/SMTP/SMB resolve locally and retain matching tuples. DNS address answers did not show A/AAAA address-family contradictions. No `S0` TCP connection had responder packets in the supplied connection records.

For concrete anchors, `zeek-core/conn.json:2` and `dns.json:1` share UID `CYTxdaWg8hQSZFUhNr`, client `10.10.1.21:34462`, resolver `10.10.2.10:53`, and the SRV query. `dns.json:1` includes two SRV-formatted answers and two TTLs. This is compatible with the WFP/Sysmon DNS tuple cited above.

`zeek-core/smb_files.json:1` and `smb_mapping.json:1` share UID `CGGIhzcd1Hc4Y0cAlD`, the Linux file server, and ClinicalResearch share. `files.json:1` associates that UID with an XLSX transfer, matching sender/receiver hosts and five-megabyte-scale file bytes. All checked file `seen_bytes` values fit within the corresponding directional connection payload budget, and IP byte counts were never smaller than application bytes.

HTTP status distributions include core counts of 33 each for 403 and 407, 14 for 503, six for 504, and five for 206, alongside ordinary successful requests. The presence of those outcomes is not proof of real data; their field shapes and protocol contexts are plausible. In `zeek-db/http.json:1`, a successful CONNECT has zero response body and `Connection Established`, which is appropriate for the HTTP control exchange.

All checked DHCP `uids`, file `conn_uids`, and TLS certificate-chain references resolve in their local sensor exports. Six HTTP response-FUID references do not resolve; these are explicitly separated from the successful reference checks. Their timestamps are within the collection window, but a bounded export can still filter individual files rows. For example, DMZ HTTP line 2344 is a JPEG response in transaction depth 3; the same UID has files rows 1462 and 1463 for earlier HTML and WebP transactions. This is a small evidence gap with an ordinary collection explanation, not an impossible relationship.

### Linux and macOS interpretation

The Linux rows use a consistent RFC5424 envelope, while preserving source-specific payloads. `DB-PROD-01.meridianhcs.local/syslog.log:46` is an sshd connection record; line 91 is a logind session message. `FILE-LNX-01.meridianhcs.local/syslog.log:246` has a PAM sshd session-open message; line 442 has a Samba full-audit-style close payload. Different applications are not forced into a single generic message format.

The macOS native files contain 329 Endpoint Security rows: MAC-MROSS-01 has 50 fork / 57 exec / 42 exit; MAC-MROSS-02 has 58 / 70 / 52. In MAC-MROSS-01 native rows 1–2, launchd forks PID 42171 with pidversion 10, then that PID executes xpcproxy with target pidversion 11 while retaining process start time. This separates process lifetime from exec image identity. No checked native actor `(pid,pidversion)` recurred after its visible exit.

The native messages declare version 11. I did not independently verify every field against that exact SDK release, so I do not promote unfamiliar fields to schema defects. The sparse Unified Log exports and the absence of other native notification types are neutral collection choices. In particular, the MAC-MROSS-01 Unified Log security-policy message at line 2 says “would not allow”; I did not interpret it as proof that an observed exec was actually denied.

## Synthetic Indicator Summary

| Category | Source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek HTTP / files | Six unresolved response FUID references across core/DMZ | No independent penalty: filtering/loss is plausible and no contradictory collection guarantee is visible. |
| Confirmed high-impact indicators | All examined sources | None established by the performed checks | Keeps the score in the production-like 0–20 band; does not establish real provenance. |

## Realism Score by Category

- **Field format accuracy:** 9 — Broad Windows/native network schema detail is credible; exact version-11 ES conformance remains unverified.
- **Temporal patterns:** 9 — Checked process lifetimes and protocol intervals are coherent, with source precision differences preserved.
- **Cross-source correlation:** 9 — Identity and tuple checks pass; six file-reference gaps remain explainable.
- **Behavioral realism:** 8 — Diverse application, protocol, authentication, and transport outcomes; this bounded sample cannot establish a long-term production baseline.
- **Environmental consistency:** 9 — Host/platform-specific source roles are credible in the inspected records; no demonstrated OS/path contradiction.

## Recommendations

- If this were synthetic, preserve the event-specific provider/schema distinctions and the demonstrated process/session/transport identity handling.
- Investigate the six cited response-FUID gaps. If files rows were intended to be retained, supply the missing rows; if filtered, retain the filtering assumption with the collection description. The observed data alone does not justify declaring the rows erroneous.
- No other corrective change is supported by a demonstrated defect in this examination. Additional source families or more conspicuous failure activity would not, by themselves, improve authenticity.
