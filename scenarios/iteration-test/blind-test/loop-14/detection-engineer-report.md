# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 43

## Executive Summary

The telemetry is substantially production-like at the parser, field, and lifecycle levels: broad checks did not uncover a hard source-native contradiction or impossible visible process ordering. The clearest synthetic suggestion is a small cluster of repetitive binary-document reads through `/bin/cat`; this is insufficient to distinguish carefully constructed synthetic data from a selected, sanitized production capture with confidence.

## Evidence For Synthetic

- [distribution_texture] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` contains seven executions of `/bin/cat` against PDF, DOCX, or XLSX documents on mounted volumes. Examples are line 32 at `2026-11-02T13:37:11.214478000Z` (`project-plan.pdf`), line 108 at `16:05:48.676562000Z` (`service-review.xlsx`), and lines 118/121 at `17:10:43.529782000Z` / `17:12:27.402087000Z` (`project-plan.docx`, `onboarding.docx`). All seven visible `/bin/cat` execs on that host target these binary-document extensions. Repeatedly treating different Office/PDF documents as shell-readable material resembles a generic file-read command pool. This is a modest behavioral-texture indicator, not an impossible action: inspection, testing, or deliberate bulk reads could produce it.
- [weak_signal] The same host's line 149 at `18:37:47.000074000Z` reads `/Volumes/Users/Reports/draft-draft.pdf`; subsequent lines 155 and 161 read `project-plan-review.docx` and `meeting-notes.docx` through the same executable. The repeated operation across interchangeable document names strengthens the preceding texture observation slightly. It is part of the same finding and is not independently weighted.

## Evidence For Real

- The XML parses successfully across all ten Windows hosts: **17,375 Security records** and **11,315 Sysmon records**. The selected events use appropriate distinctions among decimal PIDs, hexadecimal Security PIDs/LogonIDs, brace-delimited GUIDs, SIDs, audit success/failure keywords, and source-specific timestamp precision.
- Across all 873 visible Sysmon process creations and 747 terminations, checks of process, parent, process-access source/target, and remote-thread source/target GUID references found no occurrence before its same-GUID visible creation or after its visible termination, allowing a 2 ms comparison tolerance for displayed precision. Repeated references also retained the same PID and image.
- The Windows authentication chains preserve useful details. On DC-02, the `13:04:44.0168723Z` 4624 for `diego.ramirez` has Type 3, `NtLmSsp`, `NTLM V2`, a remote IPv4-mapped address, and LogonID `0xcb5c02d`; the `13:04:48.2582995Z` 4634 closes that same user/session. The intervening 5140 names `SYSVOL` and the same source tuple and LogonID.
- All three Zeek sensor sets have internally consistent protocol-to-connection endpoint tuples wherever the UID joins. Their **22,408 connection records** include failed, reset, partial, and successful states rather than a single success template. No tested connection had IP-byte counts below payload counts or impossible packet/header totals.
- TLS versions and cipher suites are compatible in all **3,433 SSL records**, including TLS 1.3 `TLS_AES_*` / `TLS_CHACHA20_*` and TLS 1.2 `TLS_ECDHE_*` families. For the HTTP rows, aggregate reported request and response body lengths do not exceed their corresponding connection payload totals.
- macOS ES rows distinguish fork, exec, and exit, retain PID across exec while changing PID version, and preserve process/executable identity in later observations. The two hosts use different Terminal/iTerm startup chains. The Unified Log SSH acceptance message is written by `sshd-session`, while the security-policy message is attributed to the kernel/AppleSystemPolicy image.
- Linux RFC5424-like records contain correlated SSH acceptance, PAM opening/closing, logind sessions, sudo command/session records, and host-role noise. Process IDs and message structure are not replaced by Windows fields.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. It contains 116 files, including 36,715 normalized eCAR rows, the Windows records above, 322 native-shaped macOS ES records, six Unified Log rows, network telemetry, syslog, web/proxy access logs, and shell histories. The main visible interval is November 2, 2026, approximately 13:00–19:00 UTC.

I parsed the actual XML and JSON records, inspected examples from more than twenty event shapes, and ran whole-file checks for selected invariants. Checks were deliberately conditional on visible initiators: pre-window processes/sessions, unlock records, and shared built-in Windows service identities were not mistaken for impossible lifecycles. I did not use domain resolution, filesystem modification times, attack narrative structure, absent Sysmon types, or cross-source completeness as authenticity evidence.

### Source-native field and event spot checks

Paths in the following table are relative to `data/`; times are UTC on November 2, 2026. Windows examples refer to the named Event ID and timestamp within that host's relevant XML file.

| Source/event | Examined example | Finding relevant to ingestion/detection |
|---|---|---|
| DC-02 Security 4624 v2 | 13:04:44.0168723; Type 3, `0xcb5c02d` | NTLM package/process, remote source, target identity and session fields agree. |
| DC-02 Security 4634 v0 | 13:04:48.2582995; `0xcb5c02d` | User and Type 3 agree with the earlier visible logon. |
| DC-02 Security 4625 | 16:28:25.7067504; `svc_mgmt` | Failure keywords, `Status=0xc000006d`, `SubStatus=0xc0000072`, and NTLM fields form a plausible failed-logon shape. |
| DC-01 Security 4648 | 13:26:35.3357952; `svc_backup`, `DB-PROD-01` | Explicit-credential target, server, process and zero GUID conventions are structurally usable. |
| FILE-SRV-01 Security 4656 | 13:00:05.9844267; handle `0xec6f2c02` | File path, process `0x4`, access list/mask and handle fields present. |
| FILE-SRV-01 Security 4663 | 13:00:06.1459007; same handle | `AccessMask=0x2` and `AccessList=%%4417` express a write to the same file. |
| FILE-SRV-01 Security 4658 | 13:00:09.7044242; same handle | Handle close follows request/access; the field layout differs appropriately from 4663. |
| DC-02 Security 4672 | 13:04:51.5084698; NETWORK SERVICE | Built-in SID `S-1-5-20`, LogonID `0x3e4`, and privilege names are consistent. |
| DC-02 Security 4688 v2 | 13:05:36.8946665; `taskhostw.exe` | New PID `0x1c58`, creator PID `0x1408`, parent image and mandatory label are usable. |
| DC-02 Security 4689 | 13:00:54.2898895; `spoolsv.exe` | PID `0x1710`, process name and exit status have expected types. Its initiating process may predate the slice. |
| DC-02 Security 4768 | 13:11:25.3188395; `MAC-MROSS-02$` | `krbtgt`, AES encryption type `0x12`, preauth type 2, and certificate placeholders are plausible. |
| DC-02 Security 4769 | 13:01:20.9893871; `DC-01$` to `DC-02$` | Service account/SID, encryption type `0x11`, mapped IP and ticket options are structurally coherent. |
| DC-02 Security 4771 | 16:00:40.4625026; `sophia.martinez` | Failure status `0x18`, failure audit keyword, preauth and client tuple are coherent. |
| DC-02 Security 4776 | 13:06:12.2513314; `lina.nguyen` | Uses `PackageName`, `Workstation`, and `Status`, rather than invented network-address fields. |
| DC-02 Security 5140 | 13:04:44.0918417; `\\*\SYSVOL` | Share access joins the preceding target logon. |
| FILE-SRV-01 Security 5145 | 13:00:05.9658107; `ClinicalExports` | Share root, local path, relative target and access mask are separately represented. |
| WS-MCHEN-01 Security 5156 | 13:00:02.0840765 | Decimal `ProcessID=5916`, NT-device application path, protocol 17 and WFP direction/layer fields are consistent. |
| DC-02 Sysmon 1 | 13:05:36.797 event time | PID 7256 agrees with Security `0x1c58`; process/parent GUIDs and user/integrity fields parse. |
| DC-02 Sysmon 10 | 13:00:30.054 | Uses `SourceProcessGUID` / `TargetProcessGUID`, source thread, access mask and call trace. Case-sensitive ingestion must retain this event's actual field names. |
| DC-02 Sysmon 8 | 14:52:22.420 | Remote-thread source/target IDs, start address, module and function are present. |
| DC-02 Sysmon 13 | 13:50:13.363 | Registry `EventType=SetValue`, target object and DWORD detail are consistent. |
| DC-02 Sysmon 22 | 13:00:48.697 | DNS query, status and SRV-style results appear in process-associated DNS fields. |
| DC-01 Security 1102 | 18:42:23.2681586 | Correctly switches to Eventlog provider and namespaced `UserData/LogFileCleared`; it is not an empty Security-Auditing `EventData` record. Record ID is 1. |
| zeek-core DNS/conn | UID `Cz3NMJPqehAd3ATCiW2`, ts 1793624400.617179 | Identical tuple, DNS RTT/duration 0.009835 seconds, and matching query/answer structure. |
| zeek-core SSL/files/x509 | UID `CLuJRjRrOybfV1vBtC`, FUID `FbuozjPXMp7g6NrDLJ` | SSL certificate reference, file-analysis record and X.509 identity connect coherently. |
| MAC-MROSS-01 ES fork/exec | Lines 1–3, 13:07:32.811343–.835499 | launchd child, xpcproxy exec and Terminal exec preserve PID 25527 while versions progress 12→13→14. |

This is a structural/consistency check against known semantics, not an exhaustive certification of every platform-version schema. In particular, I did not declare the version-11 ES extensions invalid merely because their fields are unfamiliar.

### Whole-file identity and timing checks

All tested Sysmon process GUIDs maintained consistent PID/image ownership, including parent and process-access references. For all visible Sysmon creations, the timestamp component of the GUID agreed with the process timestamp to one-second granularity. Hash fields had the expected hexadecimal digest lengths; no same-host image/version group had contradictory repeated process-creation hash values.

Windows session checks found no forbidden visible before-logon/after-logoff use for the tested process, privilege, share and file-access events after excluding Type 7 unlock reuse and the persistent built-in service LogonIDs. A simplistic last-4624-by-LogonID join would falsely flag these legitimate cases.

Both macOS ES streams passed actor-after-exit, fork-parent PID, exec PID continuity, and start-time checks. Repeated `(pid,pidversion)` observations retained executable path, cdhash and start time. This provides substantive lifecycle evidence; it does not establish whether a real collector or a careful simulator produced it. ES notification `action.result.auth=0` was not interpreted as an execution denial or a separate authorization decision.

The network joins found no contradictory UID endpoint tuples, DNS record preceding its joined connection by more than 10 ms, DNS RTT exceeding joined duration by more than 2 ms, or established TLS session on an `S0`/`REJ` transport. All 204 distinct X.509 fingerprints retained consistent certificate metadata across their repeated appearances.

One `zeek-core/smb_mapping.json` row, line 88, uses UID `CPpgHD9SZo76AEy8y4` without a matching visible core conn row. Its timestamp is 1793640924.86979 and tuple is `10.10.1.22:36233 → 10.10.2.20:445`. This is **not scored as synthetic evidence**: a long-lived connection's summary could fall outside the slice, and the observation alone does not prove an impossible relationship.

### Behavioral texture and practical detection consequences

The seven Mac binary-document reads are the principal residual concern. `/bin/cat` can read any byte stream, so these rows are neither malformed nor impossible. Their uniform use across unrelated Office/PDF documents is simply less typical of interactive document work than the otherwise varied Terminal, browser, Office, SSH, inventory and shell activity in the capture.

A SIEM should successfully ingest the tested records if configured for each source's actual serialization. XML extraction must accommodate Event 1102's `UserData`; eCAR milliseconds must not be treated as Zeek epoch seconds; and native ES exec target identity must not be confused with its pre-exec actor. None of those distinctions is itself a dataset defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | macOS ES exec | Seven `/bin/cat` reads of Office/PDF files on MAC-MROSS-02 | Modest upward pressure: suggests a repeated generic file-read operation, but remains possible human/test activity. |
| weak_signal | macOS ES exec arguments | Interchangeable document names within the same seven reads | Small supporting detail only; not independently counted. |
| hard_contradiction / contract_gap / schema_or_format | Tested Windows, Zeek and macOS relationships | Whole-file invariants and the listed event samples | No substantiated high-impact finding; keeps the score below a likely-synthetic judgment. |

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON parse, source-specific fields, IDs, digest lengths and timestamp representations are credible in the tested records.
- **Temporal patterns:** 9 — Visible process/session ordering and network timing checks pass; schedules and bursts coexist without a demonstrated timing contradiction.
- **Cross-source correlation:** 9 — PID, session, tuple, UID, FUID and certificate checks show consistent shared facts; the isolated unmatched SMB UID is unresolved rather than contradictory.
- **Behavioral realism:** 7 — Varied application/admin activity, with a noticeable repeated `/bin/cat` binary-document access pattern on one Mac.
- **Environmental consistency:** 8 — Windows, Linux, macOS and network-source roles are coherent in examined records; exact collection policies are not supplied and are not inferred from absences.

## Recommendations

- If this were synthetic, vary document-access behavior according to file type and user intent instead of repeatedly representing Office/PDF reads as `/bin/cat` executions. Keep shell byte reads when explicitly intended; use application-specific document activity where the intended behavior is interactive document viewing.
- If this were synthetic, retain the observed strengths: preserve source-specific field names and units, the Event 1102 `UserData` exception, persistent built-in Windows logon identities, native ES fork/exec distinctions, and canonical transport/protocol byte accounting. These are concrete properties that materially improve ingestion and detection-rule behavior.
