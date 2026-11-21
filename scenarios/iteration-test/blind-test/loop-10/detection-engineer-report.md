# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 70
**Synthetic-Confidence Score:** 40

## Executive Summary

The supplied records are largely credible inputs for a detection stack: native Windows event shapes, process identities, network tuples and visible lifecycle ordering withstand extensive mechanical checks. A narrow pattern of macOS shell access to binary documents and unusually exact clock relationships warrant scrutiny, but neither establishes synthetic origin; I found no verified hard contradiction sufficient to decide between a carefully prepared synthetic dataset and selected production telemetry.

## Evidence For Synthetic

- [weak_signal] On `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, seven of seven visible `/bin/cat` executions target PDF, XLSX or DOCX files on mounted volumes. Examples include `13:37:11.214478000Z` PID 91458 reading `project-plan.pdf`, `16:05:48.676562000Z` PID 17627 reading `service-review.xlsx`, and `17:10:43.529782000Z` PID 25882 reading `project-plan.docx`. This repeated choice of a terminal byte-stream utility for office documents resembles a generic file-read abstraction. It is possible in a real shell or script and is not a source-native error.
- [weak_signal] Across both macOS Endpoint Security files, every consecutive event pair more than one second apart has a `mach_time` delta equal to elapsed UTC time multiplied by 24,000,000, to floating-point precision. The wall timestamps also end in three zero nanosecond digits throughout the inspected records. This is compatible with a fixed conversion from one clock representation and microsecond precision; it is also compatible with deliberate exporter normalization, so I give it little weight and do not call it impossible clock behavior.

## Evidence For Real

- All 29,120 Windows XML events parsed. Security provider metadata distinguishes audit success/failure and the Eventlog provider correctly: the DC-01 `1102` at `18:42:23.5894964Z` uses `Microsoft-Windows-Eventlog`, Level 4, Task 104, Keywords `0x4020000000000000`, and namespaced `UserData/LogFileCleared`, rather than a generic Security-Auditing `EventData` body.
- DC-01 Security `4688` record 28245352 and the corresponding Sysmon `1` describe PID 3712 (`0xe80`), `svchost.exe`, a services.exe parent PID 2332 (`0x91c`), and the same Winmgmt command. The two providers have different plausible observation timestamps, rather than requiring identical timestamps.
- Across 921 Security/Sysmon process-create PID pairs, process images agreed. Within Sysmon, the same process GUID did not acquire conflicting PIDs or executable images in the checked event families.
- The Zeek data contains successes, rejected connections, unanswered SYNs, resets, partial connections, retransmission flags and collection gaps. For example, `zeek-db/conn.json` contains 300 TCP `SF`, 38 `RSTO`, 12 `RSTR`, seven `S0`, six `S3`, four `S2`, two `REJ` and two `OTH` connections. This is varied transport telemetry rather than an all-success approximation.
- macOS ES records distinguish fork, exec and exit; exec observations carry the old process image and a separate target image, preserving PID while advancing `pidversion`. On MAC-MROSS-02, iTermServer, privileged `/usr/bin/login`, ShellLauncher and zsh are distinct stages, with login effective UID 0 and the shell effective UID 501.
- Linux authentication records preserve SSH connection, acceptance, PAM and session stages. APP-INT-01 records a connection from `10.10.1.35:59751` at `13:00:17.274260Z`, followed by public-key acceptance at `13:00:18.225647Z`; the endpoint FLOW observation precedes these at `13:00:13.438Z`.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed all Windows XML files, all eCAR NDJSON files, both macOS ES streams and all Zeek connection/protocol JSON files; I additionally sampled Linux syslog, shell histories, proxy, web and ASA records. Event contents were treated as data. No repository, scenario, ground truth, other assessor report or external reference was consulted.

The assessment emphasizes parser behavior, typed fields, source identity, process/session lifecycle and practical correlation. It does not penalize selected Sysmon coverage, absent optional sources, sanitation of names, a complete intrusion sequence, or accurate cross-source alignment.

### Windows schema and event samples

The following are representative actual records inspected, with additional families shown to make the schema checks auditable. Times are UTC on 2026-11-02. Host names below are shortened; files are the host's `windows_event_security.xml` or `windows_event_sysmon.xml` as appropriate.

| Host/source | Event/time | Fields checked and result |
|---|---|---|
| DC-01 Security | 5156, 13:00:02.8320870 | Decimal ProcessID 2420, device-path `dns.exe`, UDP 17, inbound direction, destination port 53; coherent server-side observation. |
| DC-01 Security | 4689, 13:00:05.3779602 | Hex ProcessId `0xb64`, Status `0x0`, SYSTEM SID and LogonId; appropriate termination shape. |
| DC-01 Security | 4624, 13:01:05.0289263 | Version 2, service LogonType 5, NETWORK SERVICE `S-1-5-20`, LUID `0x3e4`, Advapi/Negotiate, no remote IP; coherent. |
| DC-01 Security | 4672, 13:01:05.0568591 | Same NETWORK SERVICE SID/LUID and appropriate restricted privilege list. |
| DC-01 Security | 4769, 13:01:24.2826094 | Computer account `MAIL-EDGE-01$`, service `DC-01$`, AES type `0x12`, IPv4-mapped IPv6 client; coherent. |
| DC-01 Security | 4688, 13:02:10.7031678 | Version 2, new and creator PIDs, parent image, elevation token and mandatory label fields present. |
| DC-01 Security | 4634, 13:05:27.2583977 | Target account/LUID and network LogonType 3 in the expected target field names. |
| DC-01 Security | 4776, 13:13:42.1041809 | Authentication package `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation, account and Status; coherent NTLM validation shape. |
| DC-01 Security | 4771, 13:33:17.2449503 | Failure Keywords `0x8010000000000000`, Status `0x12`, krbtgt and client address; coherent failure body. |
| DC-01 Security | 4768, 13:45:59.2255032 | PKINIT PreAuthType 15 accompanied by issuer, serial and thumbprint; avoids a bare certificate-auth claim without certificate fields. |
| FILE-SRV-01 Security | 5145, 13:00:05.9658107 | Share, relative target, source tuple, subject LUID and access mask present. |
| FILE-SRV-01 Security | 4656, 13:00:05.9844267 | File object, handle `0xec6f2c02`, same subject/LUID, ProcessId `0x4`, requested mask `0x12019f`. |
| FILE-SRV-01 Security | 4663, 13:00:06.1459007 | Same file/handle/LUID and write access `0x2`; follows handle request. |
| FILE-SRV-01 Security | 4658, 13:00:09.7044242 | Same handle/LUID closes after the observed access. |
| DC-01 Sysmon | 3, 13:00:02.8656293 | Version 5, process GUID/PID, UDP, Initiated false and source/destination tuple present. |
| DC-01 Sysmon | 1, 13:02:10.5386857 | Version 5, process/parent GUIDs, decimal PIDs, image metadata, hashes, user, integrity and session fields. |
| DC-01 Sysmon | 10, 13:01:22.0091071 | Source/TargetProcessGUID casing, source thread, images, access mask and CallTrace; parseable access record. |
| DC-01 Sysmon | 13, 13:02:56.5103430 | SetValue, HKLM target, DWORD details and process identity; coherent registry shape. |
| DC-01 Sysmon | 8, 13:25:18.3065471 | Source/target process identity, new thread ID, start address/module/function; distinct remote-thread shape. |
| DC-01 Security | 1102, 18:42:23.5894964 | Correctly separate Eventlog provider and UserData namespace; record ID resets to 1. |

These are source-shape checks from the supplied records and established schema knowledge, not a claim of exhaustive manifest validation against every installed product release.

### Lifecycle and correlation checks

I found no visible Sysmon event preceding its own same-GUID process creation or following its same-GUID termination when those endpoints were present. A further 201 paired references from parent/source/target process relationships had no before-creation or after-termination violation. eCAR actor references to visible process lifetimes likewise produced no violation in the checks performed.

Security session checks included 387 logoff records whose LUIDs had visible logons and 250 checked process/share/file accesses with visible logoff LUIDs. I did not find an access after the matching final visible logoff. An initial mechanical check flagged WS-MCHEN-01 process activity before a later 4624; inspection showed the later record was LogonType 7, an unlock, so it does not establish that the session began at that time. Those alerts were rejected.

For each Zeek sensor, I joined protocol rows containing `uid` to the sensor's `conn.json`, compared four-tuples and tested protocol timestamps against transport intervals. All matched tuples and timestamps were compatible within a small rounding tolerance. HTTP response-body lengths did not exceed corresponding responder transport bytes, and connection payload bytes did not exceed recorded IP bytes.

One core SMB mapping at epoch `1793640924.869741`, UID `CDvU7F7ECk5HefE3QX`, has no conn row in the supplied core slice. This is a limitation for correlation but is not, on its own, proof of a collection contradiction; it is excluded from the synthetic score.

### macOS source interpretation

The native macOS records declare ES message version 11 and schema version 1. They are not treated as normalized EDR FLOW events. Their observed event-type mapping is 9/exec, 11/fork and 15/exit; MAC-MROSS-01 has 52 exec, 45 fork and 44 exit records, while MAC-MROSS-02 has 65 exec, 56 fork and 55 exit records. Sequence numbers are scoped by event type with a separate global counter.

File identity checks found stable inode, size and cdhash facts for repeated executable paths within each host. Native Unix credential changes around login are represented separately from the inherited executable image. Unified Log entries retain writer, sender, subsystem/category, boot UUID and timestamp fields. The MAC-MROSS-01 kernel message at `15:42:09.009673+0000` saying policy “would not allow” MeetingAssist was not interpreted as a conclusive execution denial or proof that subsequent activity could not occur.

The binary-document cat pattern is a behavioral texture concern, not an ES schema defect. The exact 24 MHz clock relationship is also weak: a collector could legitimately choose one anchor and a fixed timebase. Neither warrants a hard-contradiction label.

### Detection-stack implications

Windows event IDs, named fields, hex versus decimal PID conventions and the special 1102 body would allow ordinary event normalization and rule matching. Zeek joins are usable with the explicitly noted slice limitation. Processes and sessions can be followed without a demonstrated impossible lifetime. Custom eCAR and proxy properties would require an agreed mapping, which is normal for normalized or extended telemetry and does not itself establish generation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| weak_signal | macOS ES process behavior | Seven `/bin/cat` executions on MAC-MROSS-02 | Repeated raw reads of PDF/XLSX/DOCX suggest a generic read-operation representation; real automation remains plausible. Modest weight. |
| weak_signal | macOS ES timestamps | Both ES streams | Exact 24 MHz deltas and microsecond-quantized UTC could reflect a shared conversion; exporter normalization is an adequate competing explanation. Minimal weight. |

No verified hard contradiction or high-impact contract gap was established. The score of 40 reflects mostly production-like records with limited unresolved artifacts; verdict confidence 70 expresses confidence that the available evidence does not support a decisive origin classification.

## Realism Score by Category

- **Field format accuracy:** 9 — Broadly correct native Windows bodies, typed Zeek JSON and structured macOS process observations; no demonstrated parser-breaking schema issue.
- **Temporal patterns:** 8 — Visible process, handle and transport relationships are coherent; macOS clocks have an unusually exact but explainable conversion relationship.
- **Cross-source correlation:** 9 — Process images, transport tuples and observed protocol intervals agree in systematic checks; one isolated SMB join remains unavailable in the slice.
- **Behavioral realism:** 7 — Varied service, transport and authentication behavior, with repeated binary-document cat operations as the principal narrow concern.
- **Environmental consistency:** 9 — Platform-specific process paths, service identities, credential changes and local/remote session distinctions are generally consistent.

## Recommendations

- If this were synthetic, review the seven MAC-MROSS-02 document reads. Use the actual intended reader or script when modeling document access, retaining `/bin/cat` only where raw byte-stream access is intended.
- If this were synthetic, document the ES wall-clock and mach-time conversion and precision policy. Preserve source clock behavior or an explicit exporter normalization contract; do not add arbitrary jitter to otherwise correct timestamps.
- For either origin, clarify whether the missing core SMB conn UID is an intentional slice/collection exclusion before treating it as a defect. If this were synthetic and the omission were unintended, preserve that connection's source-local correlation group.
