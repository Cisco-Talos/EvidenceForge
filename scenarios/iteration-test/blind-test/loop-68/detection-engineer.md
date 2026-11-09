# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 34

## Executive Summary

The supplied telemetry is mostly production-like and should support ordinary SIEM parsing and correlation. I found a repeated Linux diagnostic-message texture and an unusual macOS command lifetime, but neither establishes artificial origin; the tested process, session, network and certificate relationships showed no demonstrated hard contradiction.

## Evidence For Synthetic

- [distribution_texture] Linux IRQ diagnostics have a conspicuously narrow vocabulary across unrelated roles. `DB-PROD-01.meridianhcs.local/syslog.log` contains 64 irqbalance records among 207 total records, consisting of four exact messages; these include line 5 at `13:04:39.914892Z` (“Skipping IRQ 16: banned by affinity mask 00000002 (ahci)”) and line 7 at `13:05:09.572716Z` (“IRQ 16 affinity hint keeps vector on CPU 0 (ahci)”). The same four message shapes recur with host-specific substitutions on WEB-EXT-01 (120 records) and LOG-MON-01 (79 records). This could reflect a small template pool, although fleet configuration or verbose daemon logging could also explain it. I assign this limited weight and do not claim the messages are impossible for an unverified daemon build.
- [weak_signal] `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` lines 87–88 give `/usr/bin/id`, PID 64589, a successful execution lifetime of approximately 84.84 seconds: exec at `16:04:23.202602000Z`, exit at `16:05:48.039899000Z`. Other visible `id` invocations complete in fractions of a second. This is worth investigating as a possible generic activity-duration assignment, but directory-service delays, scheduling or suspension can produce this behavior on a real host. It is not an impossible lifecycle.

## Evidence For Real

- Windows records preserve source-specific conventions rather than flattening every ID into one schema. For example, DC-02 Security record 25377547 has hexadecimal `NewProcessId=0x1abc`, while Sysmon record 1368580 has decimal `ProcessId=6844` for the same WmiPrvSE process. Security uses its auditing provider, Level 0 and task-specific metadata; Sysmon uses its Operational channel, Level 4 and source-specific event versions.
- A visible NTLM network session has a coherent local lifecycle. DC-02 Security records 25377568, 25377569 and 25377570 show 4624, SYSVOL share access and 4634 with the same `0xcb5d4ec` LogonID and lina.nguyen SID, in that order, between `13:05:20.4885981Z` and `13:05:26.9432037Z`.
- Within each Zeek sensor, all tested UID-bearing DNS, HTTP, TLS, SMTP and SMB records reference an existing conn row with matching endpoint tuples. Certificate and executable analysis IDs also resolve to files rows, with matching SHA-1 fingerprints for X.509 records.
- Network behavior includes failures and capture imperfections with compatible fields: S0, REJ, RSTO, RSTR and partial connections; content gaps; retransmissions; and different service mixes by sensor. These are positive realism details, not evidence that perfect matching would itself be suspicious.
- macOS records distinguish fork, exec and exit. On MAC-MROSS-02, ES lines 1–3 preserve PID 18966 while changing the executable from launchd to xpcproxy to iTerm2 and advancing PID versions 10, 11 and 12. Later exits refer to the resulting execution identity. This is appreciably more faithful than treating exec as a new PID.

## Detailed Analysis

### Scope and provenance

I read the supplied briefing and files only under the supplied `data` directory, using system Python from the neutral study directory. I additionally consulted official/upstream vendor and protocol references. I did not inspect project files, authored scenarios, prior assessments or other reviewers' reports. Generic inherited operating instructions were not used as origin evidence.

I parsed 73,568 JSON/NDJSON records from 54 files and 31,469 Windows events from the XML files. The XML total comprises 19,283 Security and 12,186 Sysmon events. I also examined Linux syslog, shell history, proxy/web access, ASA and Snort samples. XML line citations below identify the opening Event line; record IDs provide a second stable locator. Paths are relative to `data`.

### Windows schema and field spot checks

The following table records concrete checks across more than twenty event shapes. The first thirteen examples are from `DC-02.meridianhcs.local/windows_event_security.xml`; the following nine are from that host's `windows_event_sysmon.xml`.

| Event | Opening line / record ID | Check and result |
|---|---|---|
| 5156 | 3 / 25377457 | Version 1; Task 12810; decimal ProcessID; NT device application path; protocol 17; inbound direction and receive/accept layer metadata are compatible. |
| 4769 | 126 / 25377462 | Service account `DC-02$`, service SID, ticket options, encryption type and IPv4-mapped IPv6 client address have expected representations. |
| 4689 | 452 / 25377489 | Hexadecimal ProcessId, executable path and exit Status are present. |
| 4768 | 1184 / 25377527 | `krbtgt`, SID ending 502, PreAuthType 2 and AES encryption type 0x12 are compatible. Empty certificate fields are not erroneous for password-based preauthentication. |
| 4624 | 1306 / 25377532 | Version 2 includes linked-logon, outbound-account, virtual-account and elevated-token fields. Type 5 SYSTEM logon has no fabricated remote IP. |
| 4672 | 1361 / 25377533 | PrivilegeList uses Windows privilege identifiers and refers to the SYSTEM logon. |
| 4688 | 1567 / 25377547 | Version 2 includes creator and target fields, parent image and mandatory label; PID 0x1abc converts to 6844. |
| 5140 | 2034 / 25377569 | ShareName uses the `\\*\SYSVOL` form; the subject LogonID matches the preceding NTLM network logon. |
| 4634 | 2073 / 25377570 | Target SID, user, LogonID and Type 3 agree with the visible session. |
| 4776 | 12248 / 25378035 | Authentication package name, TargetUserName, Workstation and Status are correctly differentiated from 4624 field names. |
| 4779 | 13237 / 25378084 | AccountName, AccountDomain, LogonID, SessionName and ClientAddress use the session-disconnect shape. |
| 4771 | 119790 / 25382429 | Failure audit keyword, Status 0x18 and PreAuthType 2 are consistent with failed password preauthentication. |
| 4697 | 174179 / 25384713 | ServiceName, ServiceFileName, ServiceType 0x10, demand start 3 and LocalSystem account are compatible. |
| Sysmon 3 | 3 / 1368530 | Version 5; UDP DNS tuple; Initiated false on the receiving DC; ProcessGuid and decimal ProcessId are present. |
| Sysmon 10 | 123 / 1368535 | Version 3; source/target process identity, GrantedAccess and CallTrace are present; this event uses the source-native `SourceProcessGUID` capitalization. |
| Sysmon 22 | 158 / 1368537 | QueryName, QueryStatus and semicolon-delimited SRV results are represented separately from connection fields. |
| Sysmon 5 | 424 / 1368547 | Version 3; ProcessGuid, PID, image and user identify the terminated process. |
| Sysmon 1 | 1193 / 1368580 | Version 5; parent identity, command line, current directory, integrity, hashes and logon fields are populated consistently. |
| Sysmon 7 | 1318 / 1368585 | ImageLoaded is distinct from the actor image; signed-status and DLL metadata are present. |
| Sysmon 8 | 6110 / 1368740 | Version 2; source/target process identities and remote thread start fields use the expected event shape. |
| Sysmon 13 | 31585 / 1369654 | SetValue, registry TargetObject and DWORD Details are compatible. |
| Sysmon 11 | 55007 / 1370523 | TargetFilename and CreationUtcTime describe the file rather than introducing a second process identity. |

The 5156 example agrees with Microsoft's published XML example in metadata and field structure. I did not flag its decimal ProcessID as a defect: Microsoft's example also uses decimal despite prose discussing hexadecimal. [Microsoft 5156 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156).

These are representative checks, not a certification of every possible Windows release's provider manifest. No absent Sysmon event family was counted against authenticity.

### Process and session correlation

I checked all visible Sysmon process references against same-host ProcessGuid creation and termination rows, including parent references and source/target process references. No tested reference precedes its visible creation or follows its visible termination; parent GUIDs that resolve to visible creations also agree on PID and image.

I separately checked normalized eCAR PROCESS identities and actorID references against visible process starts and exits. Those checks found no same-identity lifecycle inversion. The eCAR export has numeric millisecond timestamps and distinct event IDs, object IDs and actor IDs; string-valued properties such as ports should be converted during normalization rather than mistaken for native Windows XML field types.

Session checks used the earliest visible 4624 for each non-well-known LogonID. This matters because unlock logons can reuse the existing session identity: simply joining to the last 4624 would incorrectly manufacture “process before logon” findings. No tested Security reference remained earlier than its first visible logon or later than its visible 4634 after applying that distinction. Missing starts before the slice and closures after it remain neutral.

### Zeek protocol records

The three sensors contain 21,805 conn rows, with no duplicate UID within a sensor. Protocol-row tuples match their associated connections, and checked protocol timestamps fall within their associated connection intervals, allowing a small boundary tolerance. Files-to-X.509/OCSP/PE references resolved without errors. For TLS 1.2 connections exposing certificates, RSA versus ECDSA authentication in the cipher agrees with the leaf certificate key type.

For example, `zeek-db/ssl.json` line 1 references `CAno5Y6yLIc05OrSzK` and certificate FUID `FOPb7Uuatgk3N1ulbk`; `zeek-db/files.json` line 2 carries that FUID, and `zeek-db/x509.json` line 1 has its matching SHA-1 fingerprint `8087310b139f1969a3ab19f455cd6df5886e6c07`.

A simplistic packet-byte check initially identifies some TCP rows whose sequence-derived payload exceeds captured packet payload capacity. These are not scored: every such row in this check has nonzero missed_bytes. Zeek explicitly distinguishes sequence-derived payload counts from observed IP bytes and records content gaps. [Zeek conn field semantics](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

HTTP CONNECT dominates the HTTP data, with 3,879 of 4,501 rows. The visible proxy path provides an ordinary explanation, and the presence of 403, 407 and gateway errors adds credible operational variation. HTTP/1.1 on these control exchanges is not evidence that HTTP/2-capable client applications are modeled incorrectly.

### macOS and Linux interpretation

The 303 macOS ES rows declare message version 11 and contain fork/exec/exit event numbers 11/9/15. Both hosts maintain contiguous global sequence numbers and separate contiguous per-event-type sequence numbers. Across the examined process snapshots, a given PID/PID-version pair retains the same executable and start time; device/inode identities do not collide across different visible executable identities. Native ES rows are not expected to contain network FLOW fields merely because the separate eCAR export contains them.

The five Unified Log rows use timestamp/timezone, boot UUID, writer/sender and message fields distinct from ES. MAC-MROSS-01 Unified Log line 2 says a policy “would not allow” MeetingAssist at `15:42:20.850119+0000`; I found no matching successful MeetingAssist exec in the ES file. I do not turn that wording into an unsupported claim about an authorization result, execution or downstream file effects.

Linux syslog uses parseable RFC 5424-style envelopes. Sudo command, PAM open and PAM close rows preserve the same sudo PID in sampled transactions; SSH and logind records provide session-specific details. The IRQ message concentration remains the main distribution concern, but normal cron periodicity and common fleet maintenance commands are not independent synthetic indicators.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux syslog / irqbalance | Four-message vocabulary repeated on DB-PROD-01, WEB-EXT-01 and LOG-MON-01; 64, 120 and 79 rows respectively | Modest upward weight; consistent with templated background noise, but also explainable by daemon logging configuration. |
| weak_signal | macOS ES process lifetime | MAC-MROSS-01 lines 87–88, one `/usr/bin/id` execution lasting about 84.84 seconds | Small upward weight; unusual relative to other visible id invocations, without an impossible ordering or proven failure. |

No demonstrated hard_contradiction, contract_gap or schema_or_format defect was established by the checks performed. The two observations are insufficient to decide origin confidently.

## Realism Score by Category

- **Field format accuracy:** 9 — Diverse sampled Windows, Zeek, ES and text-source shapes retain appropriate types and source-specific fields.
- **Temporal patterns:** 8 — Tested identity lifecycles are coherent; one unexpectedly long trivial command merits explanation.
- **Cross-source correlation:** 9 — Visible process, session, connection and file-analysis identities resolve consistently in the checks performed.
- **Behavioral realism:** 8 — Credible proxy errors, failed connections, capture gaps and administrative activity; some diagnostic vocabulary is narrow.
- **Environmental consistency:** 8 — Source and role differences are plausible; IRQ logging concentration leaves a collection-configuration question.

## Recommendations

- If this were synthetic, diversify Linux background diagnostics through actual daemon state and configuration, particularly the four repeating irqbalance message shapes, while retaining legitimate repetition where a real daemon would repeat itself.
- If this were synthetic, derive short command lifetimes from executable behavior and dependencies. Keep the 84.84-second id invocation only when a modeled directory-service delay, suspension or equivalent condition explains it.
- Preserve the existing source-specific field conventions, process execution identities and coherent network/file relationships. The present checks do not justify inventing missing source families, adding out-of-window initiators, or weakening complete correlations.
