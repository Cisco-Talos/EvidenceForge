# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 32

## Executive Summary

The supplied telemetry is largely production-like from a detection engineering perspective: the records parse, platform-specific fields are credible, and the tested process, authentication, and network joins preserve their visible lifecycle relationships. I found a weak repeated background-command pattern, but no demonstrated source-native contradiction or impossible ordering strong enough to distinguish sanitized production data from a careful simulation.

## Evidence For Synthetic

- [weak_signal] Both Macs have the same narrow background command: root-owned, launchd-parented `/usr/bin/sw_vers` without arguments, three times per host. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, these occur at `13:31:23.858874`, `15:15:41.909845`, and `17:39:08.118629` UTC; on MAC-MROSS-02 they occur at `13:43:05.345120`, `15:47:19.993574`, and `17:51:40.956050`. This repeated behavioral vocabulary is compatible with a shared synthetic background recipe, but also with deployed inventory software; it has only a small influence on the score.

## Evidence For Real

- All 76,568 JSON/NDJSON records parsed successfully. Windows XML files also parsed successfully. The source formats preserve useful differences rather than imposing one generic record structure on everything.
- The DC-02 SMB sequence uses a consistent user, SID, source tuple, and LogonID: 4624 at `13:04:44.0168723Z`, 5140 at `13:04:44.0918417Z`, and 4634 at `13:04:48.2582995Z`, all for `diego.ramirez`, LogonID `0xcb5c02d`, source `10.10.1.34:57796` where applicable.
- Across the supplied Sysmon files, the checked Event 3/7/11/13/22 records do not precede a visible Event 1 for the same ProcessGuid or follow a visible Event 5 for that ProcessGuid. Visible parent creates also precede child creates.
- All examined DNS, HTTP, SSL, SMB-file and SMTP UID references resolve to connection records within their respective Zeek sensor directories; their timestamps remain within the corresponding connection intervals, allowing a 10 ms rounding/timestamp tolerance.
- TLS visibility is credible: none of the TLS 1.3 rows advertise certificate-chain FUIDs, while many non-resumed TLS 1.2 rows do. Resumed TLS rows omit those chains.
- APP-INT-01 records an SSH connection, public-key acceptance, PAM session opening, logind session creation, and subsequent close for the same sshd PID. The spacing is plausible and is not a set of identical timestamps.
- Native Mac ES records distinguish fork, exec, and exit; exec preserves PID while changing PID version and executable identity. The normalized eCAR FLOW records remain a separate source; they are not misrepresented as native Endpoint Security network notifications.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed the JSON/NDJSON and Windows XML, inspected examples from more than twenty Windows event types plus the Zeek, Linux and Mac families, and ran bounded consistency checks over the supplied records. The examples below are on 2026-11-02, with times in UTC. Successful consistency checks support usability but are not proof that the source is real; complete coverage is not scored as a synthetic tell.

### Windows source-native records

The following distinct record types were inspected directly, including their System metadata and EventData fields. Paths below are parsed values; ordinary backslash escaping in a displayed Python/JSON representation is not an additional path separator.

| Host/source and time | Event | Specific validation |
|---|---:|---|
| DC-01 Security, 13:00:00.8064024 | 5156 | Decimal ProcessID `2420`, native device Application path, protocol `17`, inbound Direction `%%14592`, source `10.10.2.30:36162`, destination DC DNS port 53. |
| DC-02 Security, 13:00:54.2898895 | 4689 | Hex ProcessId `0x1710`, Status `0x0`, SYSTEM SID `S-1-5-18` and well-known LUID `0x3e7`. |
| DC-02 Security, 13:01:20.9893871 | 4769 | Machine principal `DC-01$`, service account `DC-02$`, encryption `0x11`, IPv4-mapped IPv6 client address, numeric port and zero LogonGuid. |
| DC-02 Security, 13:04:44.0168723 | 4624 v2 | Type 3, `NtLmSsp`/`NTLM`, `NTLM V2`, KeyLength 128, mapped source address, linked-logon and elevation fields. |
| DC-02 Security, 13:04:44.0918417 | 5140 v1 | SYSVOL share and native local path; SubjectLogonId and SID agree with the preceding login. |
| DC-02 Security, 13:04:48.2582995 | 4634 | Same target account/LUID and LogonType 3 as the successful login. |
| DC-02 Security, 13:04:51.5084698 | 4672 | NETWORK SERVICE uses `S-1-5-20`, LUID `0x3e4`, and a multiline privilege list. |
| DC-02 Security, 13:05:36.8946665 | 4688 v2 | NewProcessId `0x1c58`, parent ProcessId `0x1408`, taskhostw/svchost paths, SYSTEM mandatory label `S-1-16-16384`, explicit null target principal. |
| DC-02 Security, 13:06:12.2513314 | 4776 | PackageName `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, account, workstation and Status fields. |
| DC-02 Security, 13:11:25.3188395 | 4768 | Machine account `MAC-MROSS-02$`, krbtgt service, AES encryption `0x12`, PreAuthType 2, mapped client address and certificate fields. |
| DC-02 Security, 13:33:18.3996924 | 4779 | Source-specific `LogonID` capitalization, AccountName/Domain, RDP session and client address. |
| WS-PPATEL-01 Security, 15:13:19.5028264 / 15:17:39.5324076 | 4800/4801 | Lock/unlock use the same SID, LUID `0xd958094` and SessionId 2. |
| DC-02 Security, 16:00:40.4625026 | 4771 | Failure Status `0x18`, PreAuthType 2 and client tuple are represented as Kerberos failure fields. |
| DC-02 Security, 16:28:25.7067504 | 4625 | Failure `0xc000006d` plus disabled-account SubStatus `0xc0000072`, Type 3 and NTLM mechanism fields. |
| DC-02 Security, 17:25:33.2643162 | 4697 | Service type `0x10`, start type 3, LocalSystem service account, creator principal and LUID. |
| DC-01 Security, 18:42:23.2681586 | 1102 | Microsoft-Windows-Eventlog provider, Level 4, distinct UserData/LogFileCleared shape, and reset EventRecordID 1. |

I additionally inspected the DC-01 account-management sequence (4720, 4724, 4738, 4728, 4726) and the 4698 task XML. These use distinct account-management fields and the task record contains a complete structured task definition rather than only a command string. I did not independently establish the installed OS patch level, so the use of an older Kerberos event version is not treated as a defect.

Sysmon examples include Event 1 v5, Event 3 v5, Event 5 v3, Event 7 v3, Event 8 v2, Event 10 v3, Event 11 v2, Event 13 v2 and Event 22 v5. DC-02's taskhostw create at `13:05:36.7983456Z` has PID 7256, matching the Security 4688 hexadecimal PID; its SYSTEM identity, parent svchost and integrity level agree. Event 10 uses its own SourceProcessGUID/TargetProcessGUID fields, while Event 8 uses SourceProcessGuid/TargetProcessGuid. This case distinction matters to literal XML-field extraction and is preserved.

The full-file checks found no mismatched target account between a visible 4624 and subsequent 4634 with the same LUID, and no 4688 after a visible 4634 for its SubjectLogonId. These checks do not claim that every process or login begins inside the slice.

### Zeek parsing and connection contracts

There are 12,080 core, 9,839 DMZ and 489 database connection records. Their JSON types are usable: ports and byte counters are numbers, flags are booleans, DNS answers/TTLs and connection references are arrays. The logs contain successful traffic and S0, REJ, RSTO, RSTR, S1/S2/S3 and OTH states; I did not penalize these unusual states merely because application companions are absent.

For example, core DNS UID `Cz3NMJPqehAd3ATCiW2` has matching connection/DNS tuple `10.10.2.30:36162 -> 10.10.2.10:53`, query `DC-02.meridianhcs.local`, answer `10.10.2.11`, RTT and connection duration `0.009835`. Core SSL UID `CLuJRjRrOybfV1vBtC` references certificate FUID `FbuozjPXMp7g6NrDLJ`; that FUID appears in files and X.509, and the X.509 fingerprint matches the files SHA1. An OCSP HTTP response at timestamp `1793624433.347648` uses FUID `FoGQHvTER2GIi0sr0G` and the certificate serial matches the preceding LOG-MON certificate.

I checked protocol-row timestamps against connection start plus duration and found no violation beyond the stated 10 ms tolerance. I also found no TCP row with zero missed_bytes whose IP byte count was smaller than payload bytes plus the minimum 40-byte IPv4/TCP header per packet. These are useful invariants, not a reconstruction of the original packets.

### Linux collection and lifecycle

The Linux logs use RFC5424-like envelopes with priority, version, timestamp, hostname, application, PID and NILVALUE fields. APP-INT-01 sshd PID 3381190 records connection at `13:21:14.744916`, RSA public-key acceptance at `13:21:15.251527`, PAM open at `13:21:15.336114`, and PAM close at `14:01:26.043721`. The user remains priya.patel and the source remains `10.10.1.32:54546`; logind creates session 254 at `13:21:16.094473`.

The same file contains CRON/sysstat, snapd, irqbalance, resolved, rsyslog queue status, unattended upgrades and other maintenance records. Repeated cron timing is expected automation, so it is not a synthetic indicator. Early session-close messages are compatible with the explicit slice-of-time collection context.

### Mac source interpretation

The ES envelopes declare message version 11. I inspected the actor process, fork child, exec target, argument vectors, audit tokens, PID versions, signing metadata and executable file metadata. A representative MAC-MROSS-01 chain is launchd fork at `13:07:32.811343`, xpcproxy exec at `13:07:32.820534`, and later user execution under the same process lineage. Mutable effective credentials between observations do not alone establish an audit-token defect.

The sparse Unified Log exports identify writers and subsystems independently of normalized eCAR. The kernel ASP message at `15:42:09.009673` says policy “would not allow” MeetingAssist; I do not turn that isolated message into proof of denied execution or subsequent effects. I do not require additional Mac event families from a selected export, and I have not independently verified every version-11 serializer detail against an OS build. No claimed native Mac schema defect contributes to the score.

The only residual behavioral concern is the repeated launchd-owned sw_vers activity on both Macs. Shared device-management tooling is a plausible explanation, preventing a stronger authenticity inference.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Mac ES process observations | Three root/launchd-parented argument-free sw_vers executions on each of two hosts | Slight upward influence for repeated vocabulary; common inventory software could explain it. |
| No demonstrated hard contradiction | Windows, Linux, Mac and Zeek samples/checks | Parsed schemas and tested visible lifecycle/UID relationships | Keeps the score in the mostly-realistic band; does not prove production origin. |

## Realism Score by Category

- **Field format accuracy:** 9 — Records parse and inspected event-specific fields are credible; Mac version-specific details were not exhaustively verified.
- **Temporal patterns:** 9 — Tested visible lifecycle order and network interval constraints hold; no impossible sequence demonstrated.
- **Cross-source correlation:** 9 — Windows PID/LUID and Zeek UID/FUID examples agree, with no tested join failure.
- **Behavioral realism:** 8 — Varied operational traffic and maintenance exist; the repeated Mac inventory command remains weakly recipe-like.
- **Environmental consistency:** 9 — Platform paths and source distinctions hold; scanning, failed flows and service activity fit the visible environment.

## Recommendations

- If this were synthetic, make the repeated root/launchd sw_vers observations arise from an explicit, consistent inventory-agent or management-job lineage where that lineage is actually observed. Shared fleet automation is plausible; those records should reflect the same operational owner and timing policy rather than an unexplained reusable command recipe.
- Preserve the source-specific event shapes, selected-collection assumptions, and existing lifecycle/UID integrity. The inspected evidence does not justify adding arbitrary missing sources or introducing mismatches to make the dataset seem messier.
