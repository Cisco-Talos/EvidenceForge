# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 73
**Synthetic-Confidence Score:** 62

## Executive Summary

The sampled Windows, Zeek, Linux and macOS records are largely processable and show substantial lifecycle and correlation care. I lean synthetic because embedded macOS file metadata has a strong fractional-timestamp distribution artifact across unrelated executables on both Macs; I found no demonstrated impossible lifecycle or broken network reference in the bounded checks, so this is a qualified verdict rather than certainty.

## Evidence For Synthetic

- [distribution_texture] Embedded file-stat timestamps in both `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` and `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` overwhelmingly have nonzero nanoseconds between 1 and 999: respectively **72 of 77** and **68 of 72** distinct timestamp strings collected recursively from `st_atimespec`, `st_mtimespec`, `st_ctimespec` and `st_birthtimespec`. These are in-record source fields, not the copied log files' filesystem timestamps. For example, MAC-MROSS-01 line 1 has launchd mtime `2026-03-14T03:55:49.000000091Z`, atime `2026-09-29T07:51:20.000000567Z` and ctime `2026-09-09T07:01:57.000000027Z`; line 2 has xpcproxy mtime `.000000748Z` and ctime `.000000308Z`; line 9 has `/usr/bin/id` mtime `.000000395Z` and ctime `.000000443Z`. MAC-MROSS-02 line 1 has launchd ctime `.000000848Z`, line 7 `/usr/bin/login` ctime `.000000718Z`, and line 15 `/usr/bin/uname` ctime `.000000060Z`. The first six fractional digits are consistently zero while the final three vary. This unusual concentration spans access and change times as well as build-preserved modification times; the latter alone could be explained by shared installation media. It resembles generated subsecond components or a systematic units-conversion artifact. A real exporter defect remains an alternative explanation, so I do not label it a hard contradiction.

## Evidence For Real

- Windows representations distinguish hexadecimal Security PIDs from decimal Sysmon PIDs. `WS-EBROOKS-01.meridianhcs.local/windows_event_security.xml`, RecordID 949137 (line 15), reports new PID `0x10bc`; the matching Sysmon process, RecordID 359537 (line 13 of `windows_event_sysmon.xml`), has PID `4284`, the same image and matching command line.
- Security logon fields adapt to context. WS-EBROOKS-01 RecordID 949263 is Type 2/User32/Negotiate with `IpAddress=-`, whereas DC-01 RecordID 28245366 is a Kerberos service-ticket record with IPv4-mapped IPv6 client address and appropriate service/account fields.
- The visible file-access lifecycle on FILE-SRV-01 is coherent: RecordIDs 272183–272187 cover share access, relative target access, handle request, file read and handle close. The 4656/4663/4658 records retain handle `0xc989ded5`, user `aisha.johnson`, LogonID `0xf6c1c4d` and PID `0x4`.
- Bounded scans of all Sysmon rows on WS-EBROOKS-01, DC-01 and FILE-SRV-01 found no later event using an already-terminated ProcessGuid as process, source, target or parent. This checked 389, 4,395 and 552 rows respectively; missing pre-window creators were treated neutrally.
- Zeek file transfers fit their transport budgets. `zeek-core/files.json` line 1 reports 5,359,834 responder-to-originator bytes for UID `CHobQaXTd62NpmDvAm`; `zeek-core/conn.json` line 8 has 5,361,807 responder application bytes and an enclosing transport interval.
- Native Mac process transitions preserve separate fork, exec and exit observations. MAC-MROSS-01 ES lines 1–3 show PID 42169 moving from forked launchd to xpcproxy and Terminal with PID versions 10, 11 and 12. These were not misinterpreted as three independently created PIDs. No post-exit use of the same `(pid,pidversion)` actor identity was found in either Mac's ES file.

## Detailed Analysis

### Scope and method

I inspected only the supplied data directory. This was a bounded representative assessment: field inspection across Windows event types on three hosts; automated identity/lifecycle checks on those hosts; one Zeek sensor's connection/protocol/file relationships; both Macs' compact ES files; and initial Linux eCAR/syslog records. It was not an exhaustive review of every host, sensor or native schema version. Findings about native fields below are limited to demonstrated properties; unfamiliar macOS version-11 export fields were not declared invalid without independent verification.

The following representative records were parsed as XML or JSON and inspected for field shape and meaning. XML RecordIDs provide unambiguous selectors in addition to physical line references above.

| Source/selector | Event | Representative checks and result |
|---|---|---|
| WS-EBROOKS-01 Security 949137 | 4688 v2 | Subject/target identities, creator and new hexadecimal PIDs, parent name, mandatory label and command fields present. |
| WS-EBROOKS-01 Security 949253 | 4625 | `Status=0xc000006d`, `SubStatus=0xc000006a`, Type 2 and User32 give coherent bad-password interactive failure semantics. |
| WS-EBROOKS-01 Security 949263 | 4624 v2 | Type 2, `TargetLogonId=0xa3d0cd0`, local source placeholders and version-2 extension fields present. |
| WS-EBROOKS-01 Security 949291 | 4672 | SYSTEM SID `S-1-5-18`, LogonID `0x3e7` and multiline native privilege names agree. |
| WS-EBROOKS-01 Security 949428 | 4800 | Session 2 and user LogonID `0xa3d0cd0` agree with visible interactive logon. |
| WS-EBROOKS-01 Security 949452 | 4801 | Same session/user identity as the preceding lock. |
| WS-EBROOKS-01 Security 949453 | 4648 | Explicit-credential subject, supplied target account, target server and caller process fields present. |
| WS-EBROOKS-01 Security 949613 | 4634 | Network-logon close uses its own LogonID `0xa4a50b1`, rather than the interactive session's ID. |
| WS-EBROOKS-01 Security 949154 | 5156 v1 | Decimal `ProcessID`, native device application path, protocol 17, DNS destination and direction/layer fields. |
| WS-EBROOKS-01 Sysmon 359537 | 1 | Decimal PID, braced process/parent GUIDs, millisecond UtcTime, hashes and parent identity are usable. |
| WS-EBROOKS-01 Sysmon 359542 | 22 | Query name/status/results and process identity are represented as separate fields. |
| WS-EBROOKS-01 Sysmon 359545 | 10 | Source/target process IDs and GUIDs, granted access and module-offset call trace present. |
| WS-EBROOKS-01 Sysmon 359558 | 5 | Termination has process GUID/PID/image/user identity. |
| DC-01 Security 28245366 | 4769 | Account `FILE-LNX-01$`, `ServiceName=DC-01$`, encryption `0x12`, status `0x0` and client tuple are parseable. |
| DC-01 Security 28245437 | 4768 | `ServiceName=krbtgt`, PreAuthType 2, encryption `0x12`, machine account and empty certificate fields are coherent. |
| DC-01 Security 28256901 | 4728 | Member SID, group SID/name and subject fields are distinct. |
| FILE-SRV-01 Security 272184 | 5145 | Share, local share path, relative file name, access mask and network source are distinct. |
| FILE-SRV-01 Security 272185 | 4656 | Handle request includes transaction, mask and resource fields. |
| FILE-SRV-01 Security 272186 | 4663 | File read `AccessMask=0x1` retains the handle/user/process relationship. |
| FILE-SRV-01 Security 272187 | 4658 | Handle close retains the same identity and follows file access. |

### Windows timing and identity

For the three sampled hosts, I indexed Sysmon creation and termination records by ProcessGuid, then checked later records' process, source, target and parent GUID references against known termination times. No post-termination reference was found. I separately compared Sysmon process LogonID/User/LogonGuid against visible Security 4624 records and checked process creation after visible 4634 for the same LogonID; those checks found no mismatch. These passes support internal consistency but cannot establish authenticity. They do not prove every process parent existed before collection or that every session has closed.

Source times are distinct rather than forcibly identical: WS-EBROOKS-01's matching dllhost creation is Sysmon `2026-11-02T13:00:34.2281179Z` versus Security `2026-11-02T13:00:34.4345990Z`. The delay is plausible between different observation paths. I did not require absent Sysmon event families or domain-ticket companions for local logons.

### Zeek parsing and transport relationships

Within `zeek-core`, 11,853 connection rows provided the UID index. The 2,078 HTTP, 288 TLS and 3,006 DNS rows all resolved to matching connection tuples, with protocol timestamps inside their visible transport intervals allowing 10 ms boundary tolerance. The 584 file rows also resolved, fit their corresponding direction's application byte count, and had start times inside the connection interval. No connection had an IP-byte count below its application-byte count, and no TCP history starting with `ShA` had fewer than two originator or one responder packet. These are narrowly defined checks rather than comprehensive protocol validation.

The conn vocabulary has successful TCP, unanswered TCP, resets, UDP and ICMP rather than just one success shape. The first file-transfer example starts at `1793624460.716762`, inside a connection starting `1793624460.195223` with duration `1.549823`. Completeness of UID matching was not used against authenticity.

### Native macOS metadata and uncertainty

The strongest concern is the source-internal file-stat fraction pattern described above. To reproduce the counts, recursively visit dictionaries/lists in each Mac's ES JSON lines; collect the distinct strings whose keys are `st_atimespec`, `st_mtimespec`, `st_ctimespec` or `st_birthtimespec`; extract the nine-digit fractional part as an integer; count `0 < fraction < 1000`. Deduplicating values prevents frequently repeated process images from inflating the result. The pattern remains on both hosts and in host-specific access/change metadata.

This is not a claim that nonzero nanoseconds below 1,000 are individually impossible. The concern is their overwhelming concentration across independent timestamp fields. A serializer that mistakenly treats microseconds as nanoseconds could produce this pattern from real data; without exporter provenance, that alternative cannot be eliminated. I therefore assign moderate synthetic likelihood, not the 81–100 band reserved for demonstrated hard contradictions or pervasive unambiguous fingerprints.

Native ES rows declare message version 11 and contain audit-token, executable and event-specific structures; no native network FLOW requirement was imposed. Unified Log rows retain their separate timestamp/writer semantics. The MAC-MROSS-01 policy message at Unified Log line 2 says policy “would not allow” MeetingAssist, which alone does not prove a denied execution or prove subsequent child execution; it did not affect the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS Endpoint Security embedded file metadata | 72/77 and 68/72 distinct stat timestamp values on the two Macs lie in the first 999 ns after a whole second; examples at ES lines 1, 2, 7, 9 and 15 | Strong, reproducible distribution artifact; raises likelihood into the low 60s, tempered by the real-exporter conversion-error alternative. |

No hard contradiction or contract gap was established by this bounded review. The absence of such a finding is meaningful counterevidence, not proof that unreviewed records are correct.

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled Windows/XML and Zeek/JSON fields are usable; no demonstrated native schema violation.
- **Temporal patterns:** 6 — Visible event ordering holds, but Mac embedded stat fractions have pronounced artificial texture.
- **Cross-source correlation:** 9 — Sampled process/session identity and core Zeek transport references pass the stated checks.
- **Behavioral realism:** 8 — Observed local, service, network, file and remote-session distinctions are plausible in the inspected records.
- **Environmental consistency:** 8 — Sampled platform paths and source semantics agree; the bounded review did not establish an environmental contradiction.

## Recommendations

- If this were synthetic, fix the owner of native file metadata timestamps: preserve actual nanosecond units or use empirically supported timestamp resolution, rather than placing almost every nonzero fraction below 1,000 ns. Check access/change metadata independently from installation-preserved modification times.
- Retain the observed process GUID, session ID, file handle and transport-byte consistency while changing timestamp generation; the bounded checks found those relationships useful and coherent.
