# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 67

## Executive Summary

The records are highly usable for detection work: the supplied XML and JSON parse successfully, and extensive identity, lifecycle, transport, and byte-accounting joins did not reveal basic causal failures. My synthetic verdict instead rests on two narrower findings: repeated independent Chrome browser instances under the same apparent profile, and widespread inclusion of nonsensitive token privileges in native Security 4672 payloads. These support “likely synthetic,” while the generally strong source formatting and the possibility of unobserved application/audit configuration keep the score below the hard-contradiction band.

## Evidence For Synthetic

- [contract_gap] **Browser instance ownership is inconsistent with the ordinary Chrome singleton model.** In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:19`, PID 42884/pidversion 25 executes the Chrome browser at `13:14:15.939986Z`. Line 86 executes a second browser, PID 64944/pidversion 77, at `16:08:09.172951Z` with `--new-window` and a URL. Both have UID/auid 501, audit session 100001, the same executable, and `HOME=/Users/maya.ross`; neither argument vector supplies `--user-data-dir`. The second spawns its own renderer at lines 87–88, and both browser identities have positive exit observations at `18:54:59.218064Z` and `18:54:59.428842Z` (lines 123 and 125). This is substantially more than a transient URL handoff process.
- [environment_or_collection_plausibility] **The same browser-root pattern recurs on Windows.** `WS-DRAMIREZ-01.meridianhcs.local/windows_event_sysmon.xml:2121` creates Chrome PID 6848 at `14:11:04.276`; line 4460 creates PID 6756 at `14:30:30.018`. Both are browser roots launched by the same Explorer process, user, LogonId `0x9775b87`, and TerminalSessionId 1, with ordinary URL-launch arguments and no distinct data directory. The first remains positively observed making a connection at `15:35:56.524` (line 6877), and the second at `18:30:27.662` (line 12024). `WS-PPATEL-01` repeats this with PIDs 6508/6500, creates at lines 6857/8186 and later network observations at lines 13141/14853. These observations do not depend on assuming an absent termination lies inside the slice. Chromium documents separate data directories for parallel browser instances. [Chromium profile guidance](https://www.chromium.org/developers/creating-and-using-profiles/), [Chromium user-data-directory reference](https://github.com/chromium/chromium/blob/main/docs/user_data_dir.md).
- [schema_or_format] **Security 4672 appears to render a broader token-privilege list than the documented native sensitive-privilege payload.** Across all ten Windows hosts, 271 of 408 events contain `SeChangeNotifyPrivilege`. For example, `DC-01.meridianhcs.local/windows_event_security.xml:1711` at `13:05:38.8981960Z` lists `NETWORK SERVICE`, SID `S-1-5-20`, LogonId `0x3e4`, and `SeAssignPrimaryTokenPrivilege`, `SeAuditPrivilege`, `SeImpersonatePrivilege`, `SeChangeNotifyPrivilege`. `WS-MCHEN-01.../windows_event_security.xml:4655` additionally contains `SeIncreaseWorkingSetPrivilege` and `SeTimeZonePrivilege` for marcus.chen at `13:53:07.4189216Z`; the same six-item list recurs at lines 11753 and 25718. These are valid privilege names, but the event-specific inclusion is the concern: Microsoft defines this field as the sensitive privileges assigned to the logon, and identifies bypass traverse checking and increasing a working set as nonsensitive. I treat this as a documented semantic mismatch, not an assertion that the accounts cannot hold those rights. [Microsoft 4672 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672), [Microsoft audit-category guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/Monitoring-Active-Directory-for-Signs-of-Compromise).

## Evidence For Real

- Source-native formatting is substantially correct. The 19,030 Security events and 11,785 Sysmon events parse as namespaced XML; all 74,633 supplied JSON/NDJSON records parse. Security 4624 v2, 4688 v2, 5156 v1, and the sampled Sysmon families have credible field names, scalar encodings, and header values.
- The dataset handles an easily missed native detail correctly: the DC-01 1102 uses `Microsoft-Windows-Eventlog`, a namespaced `UserData/LogFileCleared` payload, and EventRecordID 1. Records immediately before it have IDs 28261511/28261512; immediately afterward the IDs are 2/3. See `DC-01.../windows_event_security.xml:270291` and adjacent events, `18:42:11.6676456Z`.
- All visible Sysmon process identity and parent references that could be checked against an in-window create/exit were consistent: no checked dependent event preceded its own create, followed its own termination, changed image/PID for its ProcessGuid, or used a visibly exited/not-yet-created parent. This includes the 895 visible Sysmon process-create events.
- Windows 4624/4634 joins preserve target SID, name, and LogonType where both are visible. The checks found no visible logoff-before-logon and no sampled 4688 execution after a matching visible session logoff. Pre-window initiators and post-window closure were treated as neutral.
- The Zeek families preserve useful semantics rather than merely sharing identifier strings: protocol rows join to matching connection tuples and fall within their connection intervals; HTTP bodies and extracted files do not exceed their directional transport payload. DNS, SMB, LDAP, Kerberos, SSH, TLS, incomplete connections, resets, and retransmission/gap histories provide varied network texture.
- Mac ES records distinguish fork, exec, and exit; exec changes pidversion without changing PID, and the executable/identity fields follow the child through the transition. The SSH chain uses a privileged parent, preauthentication components, a user session, and a user shell. The Unified Log denial-like MeetingAssist message is not followed by a visible successful exec of that application; I did not infer execution from the policy message.

## Detailed Analysis

### Input provenance, boundaries, and method

I read the complete neutral briefing at `/private/tmp/log-study-6xx3sa0s/detection-prompt.md` and examined only files under its supplied `data` directory. I did not read repository files, scenarios, project source, TODO/worklogs, prior assessments, other reviewers, or parent inventories. Generic project operating instructions were inherited in the agent environment; I did not use them as evidence of dataset origin. Public-reference searches returned incidental third-party snippets, but the technical judgments and citations in this report rely on primary Microsoft, Chromium, Zeek, and Apple documentation only. No suspicious command appearing in a log was executed.

The supplied directory contains 117 files. I parsed all XML and JSON/NDJSON, enumerated the observed Windows event families, and manually inspected representative payloads across more than twenty event types. I also performed complete joins for the bounded checks described below. Parsing success is not a claim that every field is an exhaustive implementation-level conformance pass.

References below are relative to the supplied data directory. An XML line number identifies the opening `<Event>` line of the cited event; NDJSON line numbers identify the complete record. All stated times are UTC.

### Windows schema and event-specific spot checks

The following are examples from the manual sample. `DCS` means `DC-01.meridianhcs.local/windows_event_security.xml`; `DCM` means that host's `windows_event_sysmon.xml`; `FSS` means `FILE-SRV-01.meridianhcs.local/windows_event_security.xml`; `AJS` means `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml`.

| Source/event start line | Event | Examined payload or header | Result |
|---|---:|---|---|
| DCS:3 | 5156 | v1, Task 12810, decimal ProcessID 2420, device application path, inbound token `%%14592`, UDP protocol 17, receive layer 44 | Credible native shape |
| DCS:208 | 4689 | v0, Task 13313, Status `0x0`, ProcessId `0xcd4` | Credible termination shape |
| DCS:448 | 4769 | machine account, service SID, `TicketEncryptionType=0x12`, IPv4-mapped IPv6 address | Credible service-ticket fields |
| DCS:645 | 4688 | v2, hexadecimal child/creator PIDs, Target* placeholders, ParentProcessName, MandatoryLabel | Credible process-create shape |
| DCS:1656 | 4624 | v2, Type 5, NETWORK SERVICE/S-1-5-20/0x3e4, Advapi/Negotiate, no remote IP | Appropriate service-logon semantics |
| DCS:1711 | 4672 | v0, Task 12548, same service identity and LogonId | Identity matches; privilege membership concern above |
| DCS:2317 | 4768 | machine account, krbtgt SID ending 502, PreAuthType 2, empty certificate fields | Credible password-preauth shape |
| DCS:3090 | 4776 | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation, success status | Appropriate NTLM validation shape |
| DCS:6492 | 4634 | Target* fields, hexadecimal LogonId, Type 3 | Credible logoff shape |
| DCS:20297 | 5140 | NETLOGON share, `\??\C:\Windows\SYSVOL\scripts`, source tuple | Credible share-access shape |
| DCS:22496 | 4648 | caller process, Subject*, target credentials, TargetServerName | Appropriate explicit-credential structure |
| DCS:61701 | 4771 | status `0x18`, PreAuthType 2, failure keyword `0x8010000000000000` | Credible failure shape |
| DCS:140749 | 4625 | disabled account SubStatus `0xc0000072`, Type 3, NTLM V2 | Fields describe a coherent failure |
| DCS:183744 | 4697 | PSEXESVC, `%SystemRoot%\PSEXESVC.exe`, service type `0x10`, start type 3 | Credible service-install fields |
| DCS:195839 | 4720 | target SID ending 2456, account attributes, SAM UAC values | Credible account-creation shape |
| DCS:196405 | 4728 | Domain Admins SID ending 512, member DN and SID | Appropriate global-group member structure |
| DCS:200293 | 4698 | escaped TaskContent XML, matching task URI/name, SYSTEM principal | Credible task-registration structure |
| DCS:270291 | 1102 | Eventlog provider, Level 4, Task 104, UserData namespace, reset record ID | Correct exceptional event shape |
| FSS:97 | 5145 | share/local path/relative target, source tuple, access mask/list | Credible detailed-share shape |
| FSS:146/199/240 | 4656/4663/4658 | common HandleId `0x1b169349`, System PID 4, ordered open/access/close | Consistent object-access lifecycle |
| AJS:6637/9775 | 4800/4801 | same user/session/TargetLogonId | Credible workstation lock/unlock pair |
| DCM:614 | Sysmon 1 | v5, ProcessGuid, SHA hashes, LogonId, parent identity, terminal/integrity fields | Credible process shape |
| DCM:3 | Sysmon 3 | v5, process identity, Initiated=false, tuple and protocol | Credible inbound network shape |
| DCM:238 | Sysmon 5 | v3, ProcessGuid/PID/image/User | Credible process termination |
| DCM:203 | Sysmon 10 | SourceProcessGUID/TargetProcessGUID, access mask, call trace | Credible ProcessAccess shape |
| DCM:54186 | Sysmon 8 | source/target process identity, NewThreadId, start address/module/function | Credible remote-thread shape |
| DCM:57777 | Sysmon 7 | module identity, hashes, signing status | Credible image-load shape |
| DCM:105100 | Sysmon 11 | process, target filename, creation time | Credible file-create shape |
| DCM:1630 | Sysmon 22 | query/status/results and process identity | Credible DNS-query shape |

The sampled Security success rows use Level 0/Opcode 0 and audit-success keywords; the sampled failures use audit-failure keywords. Sysmon rows use the Operational channel, Level 4, and their event-specific versions. The correct decimal 5156 PID should not be rejected merely because other Security process IDs are hexadecimal: Microsoft's own 5156 XML uses decimal. [Microsoft 5156 example](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156). The 4624 v2 sample similarly agrees with the documented service-logon and versioned field model. [Microsoft 4624 reference](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624).

The 4672 finding is a semantic issue that a permissive XML parser would accept. It matters for rules or feature engineering that treat every listed privilege as one of the event's special/sensitive rights. I did not interpret the mere presence of SeBackupPrivilege/SeRestorePrivilege as a defect: audit policy can affect backup/restore privilege recording. Nor did I reject `SeDelegateSessionUserImpersonatePrivilege` merely because an older reference table omits newer platform details. The flagged nonsensitive rights are a narrower concern, and host-specific auditing or enrichment evidence would be useful before classifying them as an absolute native impossibility.

### Application-state ownership versus identifier integrity

A dataset can have entirely valid ProcessGuid joins while describing the wrong application process graph. Chrome is the clearest example here. On the Mac, a normal second browser activation should reach the already running browser for that user's data directory; it should not become a second durable main browser with its own renderer tree under the same apparent configuration. Lines 19, 86, 88, 123, and 125 jointly establish identity, arguments, child ownership, and overlapping lifetime. This is stronger than merely seeing two `exec` notifications.

On Windows, WS-PPATEL-01 has two browser roots for priya.patel in LogonId `0xd9f9479`, TerminalSessionId 2. PID 6508 starts at `16:00:07.135`, PID 6500 at `16:27:13.534`; PID 6508 is still generating native Sysmon network evidence at `17:31:57.787`, while PID 6500 has network evidence as late as `18:20:57.681`. The executable hashes and file versions match. On WS-DRAMIREZ-01 the same pattern occurs for a different user and session. I count this as one repeated defect family, not several unrelated score penalties.

I cannot inspect actual browser profile files, policy, or custom binaries from this slice. Separate data directories, different builds, or a demonstrable application configuration could change the interpretation. Those alternatives are why this is not labeled an unqualified `hard_contradiction`.

### Network schemas and transport correlation

There are 22,148 conn rows across the three Zeek sensors. For DNS, HTTP, SSL, SMB, and SMTP rows carrying `uid`, I checked joins to their same-sensor conn record, equality of the recorded tuple, and whether the protocol timestamp falls between transport start and close (with a one-second upper tolerance). No failures were found. DHCP uses `uids`, so it was handled as a distinct schema rather than incorrectly counted as orphaned `uid` rows.

For every files row, I checked that `seen_bytes` did not exceed the relevant direction's conn payload; for every HTTP transaction I checked body length against responder bytes and looked for bodies on HEAD/204/304. None of these bounded checks failed. Across x509 logs, 211 unique fingerprints and issuer/serial identities had no conflicting certificate metadata.

`zeek-core/conn.json:1` and `dns.json:1` share UID `Cuq507OFNo7MpYfALL`, tuple `10.10.1.31:51161 → 10.10.2.11:53`, DNS rtt/duration `0.028925`, UDP `Dd` history, and consistent IP/payload accounting. Line 3 of conn has a high-volume SMB transfer with 119,613,292 originator payload bytes over 5.921459 seconds; its packet/IP counts do not contradict those bytes. I did not score high byte volume alone as implausible.

Protocol names, field forms, conn-state history, and JSON representation agree with ordinary Zeek exports. [Zeek conn.log reference and examples](https://docs.zeek.org/en/master/reference/logs/conn.html). These results make the data useful to a SIEM, but completeness or exact cross-source matching did not increase my synthetic score.

### macOS and Linux collection interpretation

The ES source declares message `version=11` and export `schema_version=1`; the Unified Log records have separate writer/sender paths, log message categories, boot UUIDs, and wall/mach time fields. I kept these sources separate from normalized eCAR. I did not certify every version-11 SDK field or alleged filesystem/signing subtlety; details I could not independently verify were not scored.

For example, Mac ES lines 1–7 show launchd fork, xpcproxy exec, Terminal exec, login, and zsh with stable PID and successive pidversions. The 16:01 inbound SSH chain later produces an sshd-session Unified Log accepted-key message at `16:01:38.551396Z` and a user zsh exec at ES line 80, `16:01:38.666332Z`. These are distinct lifecycle facts. The MeetingAssist kernel policy message at Unified Log line 2 is not proof of authorization, exec, or downstream effects, and I found no grounds to claim those effects.

Linux syslog is in a credible RFC 5424-like envelope; for example `APP-INT-01.../syslog.log:1` has `<78>1`, an ISO UTC timestamp, host, CRON app, PID, nil MSGID/structured-data, and a sysstat command. Periodic sysstat execution, SSH/PAM records, ordinary user shells, server maintenance, and application traffic are mutually plausible. Thin native Mac Unified Log coverage and absent additional Linux/Windows facilities were not scored, because the slice does not establish that all such events were collected.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `contract_gap` / `environment_or_collection_plausibility` | macOS ES; Windows Sysmon process/network | Demonstrated on MAC-MROSS-01, WS-DRAMIREZ-01, WS-PPATEL-01 | Same apparent profile has independent browser-root ownership and positive overlapping process evidence; ordinary singleton/handoff semantics are not reflected. One repeated family, not separate penalties per event. |
| `schema_or_format` | Windows Security 4672 | 271/408 events; ten Windows hosts | Nonsensitive rights appear inside the documented sensitive-privilege payload; three rows add further ordinary token rights. Broad scope makes this more consequential than a one-record typo, although audit/enrichment configuration remains a caveat. |

No generator identity leak or unconditional impossible visible ordering was established. The score is therefore 67 rather than an 81–100 assertion of hard contradictions.

## Realism Score by Category

- **Field format accuracy:** 8 — Strong XML/JSON and event-specific shapes; 4672 privilege membership remains questionable.
- **Temporal patterns:** 9 — Bounded lifecycle and protocol timing checks pass; source precision and connection durations are plausible.
- **Cross-source correlation:** 9 — Identity, tuple, certificate, and directional byte checks are strong; correct identifiers do not resolve the browser ownership concern.
- **Behavioral realism:** 6 — Repeated browser instances describe an implausible ordinary application-state model despite otherwise credible activity.
- **Environmental consistency:** 8 — Host/source roles and selected collection are coherent; browser profile configuration and audit policy are unobserved caveats.

## Recommendations

- If this were synthetic, preserve the existing browser instance per user/data directory: model subsequent URL activation as handoff, give any transient launcher a short lifetime, and attach renderer/network ownership to the continuing application graph. Where separate durable roots are intended, include the actual separate data-directory arguments/configuration that explain them.
- If this were synthetic, render 4672 from the event-specific sensitive-privilege set rather than a generic token privilege dump. Preserve the full token privilege inventory only in a source that actually exports it, or document and represent the specific native audit/enrichment configuration supporting the broader payload.
- If this were synthetic, retain the working process/session/transport joins, packet accounting, 1102 provider/payload/reset semantics, and the distinction between native macOS notifications, Unified Log messages, and normalized endpoint rows. The observed evidence does not justify adding sources, events, failures, or arbitrary timing noise merely to make the dataset look less complete.
