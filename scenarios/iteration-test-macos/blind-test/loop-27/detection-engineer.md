# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 85
**Synthetic-Confidence Score:** 20

## Executive Summary

The examined records are production-like and should support ordinary SIEM parsing and joins. Representative Windows, Zeek, Linux and macOS checks did not demonstrate a source-native contradiction or an impossible visible lifecycle; this supports a low synthetic-confidence score, but correctly structured and correlated telemetry cannot establish provenance.

## Evidence For Synthetic

- No important synthetic indicator was demonstrated in the bounded checks below. I do not count selected coverage, complete joins, sanitized domains, coherent suspicious activity, or missing out-of-window lifecycle endpoints as evidence of synthesis.
- The macOS exports declare `schema_version=1` and Endpoint Security message `version=11` (`MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, line 1). The exact exporter and OS build are unspecified. This is a verification limitation, not a demonstrated schema defect, and contributes no authenticity penalty.

## Evidence For Real

- Windows records preserve meaningful source distinctions: Security 4688 uses hexadecimal `NewProcessId=0x10bc`, whereas the matching Sysmon 1 uses decimal `ProcessId=4284`; both identify `dllhost.exe` and the same COM command. See `WS-EBROOKS-01.meridianhcs.local/windows_event_security.xml:3` and `windows_event_sysmon.xml:3` (event starts; record IDs 949137 and 359537). Their native timestamps differ rather than being copied verbatim.
- Authentication fields respect local versus network semantics. The workstation's 4624 at `13:34:15.3165336Z` is Type 2 with `User32`, `Negotiate`, and absent network address/port; its Type 2 failure has `Status=0xc000006d`, `SubStatus=0xc000006a`. See workstation Security XML event starts at lines 1804 and 1467.
- Domain-controller records use IPv4-mapped IPv6 client addresses, a `krbtgt` service SID ending in 502 for 4768, and an account service SID for 4769. These are materially different event shapes rather than a single generic authentication schema (`DC-01.meridianhcs.local/windows_event_security.xml:2437`, record 28245437; line 930, record 28245366).
- Zeek's first 300 DNS, first 300 HTTP and all 288 SSL rows in `zeek-core` join to connection rows with matching four-tuples and timestamps inside the observed connection interval, allowing 100 ms tolerance at the close. UDP syslog rows can have `history=D`, no response packets and no duration, while DHCP has bidirectional `Dd` history (`zeek-core/conn.json:1-3`).
- macOS Endpoint Security distinguishes the pre-exec actor from the post-exec target and changes PID version across exec while retaining the PID. Lines 1–3 on MAC-MROSS-01 show launchd fork, xpcproxy exec, and Terminal exec for PID 42169, with PID versions 10, 11 and 12. They are not generic EDR process rows mislabeled as native notifications.

## Detailed Analysis

### Scope and method

Only the supplied data directory was inspected. I parsed representative XML/JSON records, examined more than twenty event shapes, and performed bounded identity/timing checks. Host-wide counts reported below are scopes of those checks, not estimates of enterprise volume. No outside documentation was consulted, so unfamiliar release-specific macOS details remain unverified rather than alleged defects.

### Windows parsing and field shapes

I parsed the complete workstation Security XML (536 events), workstation Sysmon XML (389), DC-01 Sysmon XML (4,395) and WS-AJOHNSON-01 Sysmon XML (478). Parsing succeeded. Representative source-native fields were inspected as follows; line numbers identify the start of each XML event, not its individual Data element:

| Source and location | Event / record | Checks and observations |
|---|---|---|
| WS-EBROOKS Security:3 | 4688 / 949137 | Version 2, success keyword `0x8020000000000000`, hex new/caller PID, token resource value, null target subject and System mandatory label are internally coherent. |
| WS-EBROOKS Security:89 | 5156 / 949154 | Decimal `ProcessID`, device-form `Application`, numeric protocol 17, outbound resource value `%%14593` and a DNS tuple. |
| WS-EBROOKS Security:462 | 4689 / 949176 | Hex PID `0x10a0`, status `0x0`, process-name field and System subject. |
| WS-EBROOKS Security:1467 | 4625 / 949253 | Audit-failure keyword `0x8010000000000000`, failed interactive credentials, no invented remote address. |
| WS-EBROOKS Security:1804 | 4624 / 949263 | Version 2 extension fields, Type 2 user session `0xa3d0cd0`, plausible SID and GUID formats. |
| WS-EBROOKS Security:4477, 5049 | 4800/4801 / 949428, 949452 | Same target user, session ID 2 and LogonID `0xa3d0cd0`; unlock follows lock. |
| WS-EBROOKS Security:7964 | 4634 / 949613 | Type 3 logoff is a different session, `0xa4a50b1`; it must not be mistaken for closure of the Type 2 session above. |
| DC-01 Security:930, 2437 | 4769/4768 | Service-ticket and TGT-request shapes, mapped client addresses, encryption type `0x12`, certificate fields present and empty for password preauthentication. |
| DC-01 Security:43488 | 5140 / 28248222 | Share `\\*\SYSVOL`, NT-style local path, source port and access mask/list. Parsed backslash counts are ordinary Windows values, not double-escaped path corruption. |
| DC-01 Security:63644 | 4779 / 28249440 | Source-specific `LogonID` spelling, RDP session name and client address. |
| DC-01 Security:173121 | 4697 / 28256236 | Service binary `%SystemRoot%\PSEXESVC.exe`, service type `0x10`, start type 3 and LocalSystem account. |
| DC-01 Security:182788, 183037, 183092 | 4720/4738/4728 | Consistent new account SID ending in 4533 across account creation, modification and group membership; account-control values change across the records. |
| DC-01 Security:260252 | 1102 / 1 | Uses Eventlog provider and namespaced UserData/LogFileCleared rather than generic Security-Auditing EventData. Record numbering resets. |

The workstation Sysmon sample includes process creation (line 3), DNS (93), process access (124), termination (350), file creation (406), registry set (436), network connection (997) and image load (2248). Field names, GUID/SID syntax, decimal PIDs, millisecond `UtcTime`, access-mask hex syntax, signatures and hash encodings are plausible for their respective shapes. I did not infer missing event types from the sample.

For three hosts, I indexed process creates and terminations by Sysmon ProcessGuid, then examined visible process/parent/access references for use before a visible create or use after a visible termination. No violation was found in 389 workstation, 4,395 DC and 478 WS-AJOHNSON records. This check compares SystemTime and excludes termination records themselves; it is a useful screen, not proof that every possible parent/user relationship is correct.

### Zeek records and tuple accounting

`zeek-core` contains 11,853 connection rows, 3,006 DNS rows, 2,078 HTTP rows and 288 SSL rows. The bounded joins described above found no absent UID, tuple mismatch or timestamp outside the connection interval.

HTTP CONNECT rows correctly identify the proxy (`10.10.3.20:8080`) as the TCP responder while `host`/`uri` identify the tunnel destination; treating those different addresses as an inconsistency would be incorrect (`http.json:1-3`). The first SMB read's FUID `FHWi70ysEiFCvVUtLq` appears in `smb_files.json:2` and `files.json:1`, with receiver `10.10.1.21`, transmitter `10.10.2.21`, and 5,359,834 bytes. The file record's `is_orig=false` fits that transfer direction.

All 11,853 connection rows passed a basic accounting screen: payload bytes did not exceed IP bytes, zero packets did not carry positive IP-byte counts, and positive packet counts had at least 20 IP bytes per packet. This is deliberately a weak lower-bound check; it does not validate packet captures, retransmission arithmetic or every protocol analyzer field.

### Linux and normalized endpoint records

`APP-INT-01.meridianhcs.local/syslog.log:1` is an RFC5424-shaped CRON record at `13:00:00.161636Z` for sysstat. Its normalized endpoint sequence (`ecar.json:1-3`) shows cron's shell PID 2931365, child debian-sa1 PID 2931366, then the child's termination. The shell principal changes from the root parent to sysstat appropriately. A session close at the beginning of the window is neutral because its opener can precede collection.

I also checked normalized process object/actor references against visible terminal timestamps on APP-INT-01, DB-PROD-01, both Macs and WS-EBROOKS-01. No post-termination use was found. Object UUID checks do not establish the correctness of every principal, source PID or network observation.

### macOS boundaries

Both native Endpoint Security files were parsed: 152 rows on MAC-MROSS-01 and 151 on MAC-MROSS-02, containing fork, exec and exit notifications. Repeated actor snapshots keyed by `(pid,pidversion)` did not change executable path or process start time in either file. A complete native schema audit, entitlement verification and exact release validation would require the exporter/OS specification, so those details remain open.

MAC-MROSS-01 Unified Log lines 1–3 distinguish loginwindow, kernel/AppleSystemPolicy, and sshd-session writers, with separate image identities, subsystems and message formats. The policy wording “would not allow” is not treated as proof of an execution denial. Likewise, I do not require native ES network FLOW rows just because normalized eCAR FLOW observations exist.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| None demonstrated | Windows, Zeek, Linux, macOS, normalized endpoint | Representative field inspections and the bounded checks described above | No concrete defect warranted an increase. Unknown exporter/release details limit the verdict without becoming synthetic evidence. |

## Realism Score by Category

- **Field format accuracy:** 9 — Representative XML/JSON event shapes and value encodings are coherent; exact macOS exporter conformance is unverified.
- **Temporal patterns:** 9 — Visible sampled lifecycle and protocol joins passed; long-window behavioral timing was not evaluated.
- **Cross-source correlation:** 9 — Checked PID, FUID and UID relationships agree without a demonstrated impossible ordering.
- **Behavioral realism:** 8 — Inspected cron, proxy, share and authentication behavior is plausible; representative checks do not establish population-level behavior.
- **Environmental consistency:** 9 — Local/remote authentication, proxy roles and OS-specific source distinctions hold in the examined records.

## Recommendations

- If this were synthetic, preserve the source-specific actor/target, PID encoding, event-version and transport semantics demonstrated here. This review did not find a concrete defect requiring a realism change.
- Provide the native macOS exporter schema and OS/message-version provenance for a later ingestion certification. That would resolve the explicit validation uncertainty; their absence is not an authenticity indicator.
