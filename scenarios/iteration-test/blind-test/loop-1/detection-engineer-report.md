# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 38

## Executive Summary

The supplied telemetry is largely credible at the parser, field-value and correlation layers: I found no demonstrated impossible process lifecycle, conflicting Sysmon process identity, or Zeek protocol-to-connection tuple contradiction in the checks performed. Two sub-millisecond workstation lock/unlock pairs are suspicious timing texture, but they are too limited to establish synthetic provenance. The score reflects mostly production-like telemetry with a concrete, localized timing concern; the inconclusive verdict reflects the absence of decisive evidence in either direction.

## Evidence For Synthetic

- [distribution_texture] Two Windows workstation lock/unlock pairs have essentially zero locked duration despite distinct native event timestamps. In `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml`, 4800 at `2026-11-02T14:24:58.0206366Z` and 4801 at `14:24:58.0209546Z` share user `aisha.johnson`, LUID `0x2584fde`, SessionId `2`: approximately **0.318 ms** apart. In `WS-MCHEN-01.meridianhcs.local/windows_event_security.xml`, the corresponding pair at `17:43:19.5680623Z` and `17:43:19.5690180Z` shares `marcus.chen`, LUID `0x6d0365e`, SessionId `5`: approximately **0.956 ms** apart. Repeated near-zero human lock cycles across two hosts suggest clipping, a timing-construction edge case, or automation. This is a moderate local concern, not proof that the native event sequence is impossible.

## Evidence For Real

- Windows XML is structurally coherent across **19,405 Security events and 12,197 Sysmon events**. Sampled Security auditing events have the expected provider GUID, Security channel, Level 0 and audit keywords; Sysmon records use their separate provider, Operational channel, Level 4 and event-specific field shapes.
- The DC-01 log-clear event is handled differently from ordinary auditing records: Event 1102 at `18:42:20.4194264Z` uses `Microsoft-Windows-Eventlog`, a namespaced `UserData/LogFileCleared` payload, EventRecordID `1`, and different level/task/keywords. Subsequent Security records continue from the reset counter. This is a credible source-native distinction that a simplistic generic EventData renderer could miss.
- All **972 visible Sysmon process-create** records and **815 termination** records were included in GUID-based lifecycle checks. I found no checked own/source/target-process observation preceding its matching visible create or following its visible termination. GUID-to-PID/image consistency checks, including parent references, found no conflicting identity across the ten Windows hosts.
- Across **23,842 Zeek connection records**, there were no within-sensor duplicate UIDs, no checked protocol tuple mismatches, and no tested DNS/HTTP/TLS/SMB/SMTP observation outside its matched connection interval using a 1 ms early and 100 ms late tolerance. The protocol inventory contains sensible failures and alternative outcomes, rather than successful connections alone.
- Linux syslog messages distinguish sshd, sudo, logind, cron and long-running service writers, with plausible per-session PID changes and stable daemon PIDs. For example, APP-INT-01 records the TCP peer, public-key acceptance and PAM session opening separately at `13:00:16.523124Z`, `13:00:17.823059Z`, and `13:00:17.965904Z`.
- macOS ES records distinguish fork, exec and exit, including actor versus exec target and PID-version changes. Unified Log uses its own timestamp/writer/subsystem representation. I found no checked visible macOS actor lifecycle inversion or executable inode-to-path conflict.

## Detailed Analysis

### Examination scope and method

I examined only the assigned instruction file and supplied data directory. The collection covers approximately `2026-11-02T13:00:00Z` through `19:00:00Z`. I parsed all Windows Security/Sysmon XML files, all 39,336 eCAR JSON rows, all 319 ES rows, all five Unified Log rows, and the Zeek connection/protocol files involved in the checks below. I also inspected Linux authentication/service logs, proxy, firewall, IDS, DHCP, SMB and certificate/file samples.

These are structural and semantic checks against expected source behavior, not certification against every installed vendor build. I did not inspect external documentation or implementation code. I did not treat sanitization, filesystem timestamps, selected Sysmon event coverage, complete source alignment, or an easy-to-follow incident sequence as evidence of synthetic origin.

### Representative record verification

The following sample checks cover twenty distinct event/source shapes. Windows filenames below are within the named host directory under `data`.

| # | Source and record | Specific verification and result |
|---|---|---|
| 1 | DC-01 Security 5156, `13:00:02.2084694Z`, RecordID 28245268 | Decimal ProcessID `2420`; device-form application path ending `dns.exe`; inbound `%%14592`; UDP protocol `17`; remote client `10.10.1.31:54926` to DC `10.10.2.10:53`. Appropriate WFP field shape. |
| 2 | DC-01 Security 4688, `13:01:13.8292401Z`, RecordID 28245307 | Version 2 fields include hexadecimal NewProcessId `0xe80`, creator ProcessId `0x924`, parent image, target principal placeholders and MandatoryLabel `S-1-16-16384`. Plausible SYSTEM WMI provider creation. |
| 3 | DC-01 Security 4689, `13:00:39.6018547Z`, RecordID 28245287 | ProcessId `0xc90`, `dllhost.exe`, Status `0x0`, SYSTEM subject: correct process-termination shape. Its initiating process may precede the slice. |
| 4 | DC-01 Security 4624, `13:04:08.0350785Z`, RecordID 28245399 | Machine account `MAIL-FIN-01$`, Type 3, Kerberos, IPv4-mapped IPv6 address `::ffff:10.10.2.27`, LUID `0x537c6e5`; credible remote machine authentication. |
| 5 | DC-01 Security 4634, `13:04:37.3107867Z`, RecordID 28245412 | Same account, Type 3 and LUID `0x537c6e5`; closure follows the visible successful logon by about 29.28 seconds. |
| 6 | DC-01 Security 4768, `13:04:05.6336204Z`, RecordID 28245396 | `MAIL-FIN-01$`, krbtgt SID ending 502, PreAuthType `2`, Status `0x0`, encryption `0x17`. This AS request precedes the related machine logon. RC4 is possible; I did not infer a mandatory patch or encryption policy from the timestamp. |
| 7 | DC-01 Security 4769, `13:01:05.1913419Z`, RecordID 28245302 | Requester `DC-02$`, service account `DC-01$`, AES type `0x12`, mapped source IP, zero LogonGuid; plausible TGS shape. ServiceName need not be a literal `cifs/hostname` SPN. |
| 8 | DC-01 Security 4776, `13:15:20.9289990Z`, RecordID 28245913 | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation `WS-EBROOKS-01`, Status `0x0`; NTLM credential-validation shape is distinct from Kerberos events. |
| 9 | DC-01 Security 5140, `13:15:54.2703252Z`, RecordID 28245961 | ShareName has actual two-leading/one-separator backslashes for `NETLOGON`; local path uses the native `\??\` prefix; mapped client IP and subject LUID are present. JSON/console escaping was not mistaken for doubled native separators. |
| 10 | FILE-SRV-01 Security object access, `13:00:05.9715582Z` onward | 4656 request, 4663 access at `13:00:06.1459007Z`, and 4658 closure at `13:00:09.7044242Z` share HandleId `0xd9de6a80`, SYSTEM server process `0x4`, and the same user context. Requested AccessMask `0x12019f` permits the subsequent write `0x2`. |
| 11 | DC-01 Security 4698, `17:19:50.5815234Z`, RecordID 28257227 | TaskName `\Microsoft\Windows\Maintenance\DeviceSync`; TaskContent is escaped nested task XML with its own namespace, principal and executable. Decoding confirms single native path separators. |
| 12 | DC-01 Security 1102, `18:42:20.4194264Z` | Correctly distinct Eventlog provider and UserData shape; record counter reset. An EventData-only normalizer would miss its clearing subject. |
| 13 | DC-01 Sysmon 1, UtcTime `13:01:13.689`, RecordID 3288917 | WmiPrvSE ProcessId `3712` equals Security NewProcessId `0xe80`; ParentProcessId `2340` equals `0x924`; image and command agree. Version 5 includes ParentUser and process hashes. Source timestamps differ modestly, which is plausible. |
| 14 | DC-01 Sysmon 10, UtcTime `13:02:14.036`, RecordID 3288929 | SourceProcessGUID/TargetProcessGUID capitalization, SourceThreadId, source/target images, GrantedAccess `0x1000` and CallTrace are present. GUID spelling is event-specific, not globally normalized. |
| 15 | DC-01 Sysmon 3, UtcTime `13:00:02.235` | Incoming UDP DNS event attributes the local `dns.exe` while retaining remote-to-local SourceIp/DestinationIp orientation and `Initiated=false`. |
| 16 | `zeek-core/dns.json`, first record | UID `ChCk2OoaKYb22yei6` agrees with conn tuple `10.10.1.31:54926 -> 10.10.2.10:53`; SRV qtype `33`, numeric rcode, boolean flags and TTL array have plausible types. |
| 17 | `zeek-core/ssl.json`, first record | UID `CJv87xekjOqpIKL39Oe`, TLSv12/AES-GCM suite, established non-resumed handshake, certificate FUIDs. Matching files/x509 records use FUID `F6KrtNhNW1rMBquNXL` and consistent SHA1 fingerprint `8087310b139f1969a3ab19f455cd6df5886e6c07`. |
| 18 | APP-INT-01 syslog, `13:00:16Z`–`13:00:17Z` | sshd PID `2931395` keeps the same source `10.10.1.35:53883` through connection and public-key acceptance, then opens the PAM session for `aisha.johnson(uid=2528)`. |
| 19 | MAC-MROSS-01 ES lines 1–3, `13:07:32.811343Z` onward | Fork creates PID `42154`/pidversion `12`; exec target becomes xpcproxy/version `13`, then Terminal/version `14`. Launchd/xpcproxy actor identity is not confused with the executed target. |
| 20 | MAC-MROSS-01 Unified Log, `16:02:04.667986+0000` | Writer `/usr/libexec/sshd-session`, PID `64370`, Info message records public-key acceptance from `10.10.1.42:60080`; ES shows the same PID executing sshd-session at `16:02:03.407392Z`, then the login shell at `16:02:04.785756Z`. Ordering is credible. |

### Correlation and detection-stack behavior

The Windows sources support conventional process and logon joins. I compared GUID identity across Sysmon records with direct, source-process, target-process and parent references. There were no PID/image conflicts. The lifecycle timing check used Sysmon UtcTime rather than assuming its publication TimeCreated equals the activity time. Matching processes can legitimately have no visible create or terminate in a time slice; those cases were not counted as errors.

For authentication, I checked visible nonreserved LUIDs against their visible 4624 records for earlier dependent 4634/4672/4688/5140/5145 evidence. No such inversion was found. Reserved service LUIDs `0x3e7`, `0x3e4` and `0x3e5` were excluded from “first login” reasoning: repeated observations involving SYSTEM or service accounts do not establish that their long-lived security context was created at the last visible 4624.

The Zeek join checks covered all 4,420 DNS, 3,567 TLS, 5,543 HTTP, 261 SMB-file and 79 SMTP rows, plus 153 SMB-mapping rows. All checked protocol tuples agreed with their matched conn rows. No HTTP request/response body length exceeded the corresponding TCP application-byte count; no connection application-byte count exceeded its corresponding IP-byte count. TLSv13 cipher selections were not mixed with TLSv12-only suite names in the checked records.

One SMB mapping in `zeek-core/smb_mapping.json`, line 102, UID `CYShQfyiw2ikMJVrtRS`, timestamp `2026-11-02T17:35:24.870063Z`, tuple `10.10.1.22:55169 -> 10.10.2.20:445`, has no matching visible conn row or same-tuple row. This is an investigation limitation, not scored evidence of synthetic origin: an SMB connection can begin before this slice, and no visible initiating event proves an in-window contradictory creation. I would preserve the orphan as an unmatched record in a SIEM rather than silently discard it.

The HTTP/proxy evidence also makes meaningful source distinctions. A successful CONNECT to `arc.msn.com:443` records zero HTTP response-body bytes while proxy tunnel counters account for opaque traffic separately. HTTP outcomes include 403/407/502/503/504, redirects, 206 and 304. I did not require HTTPS paths or encrypted content to be visible through a tunnel.

### Temporal concern and its limits

There are seven visible 4800 events and six 4801 events. Of six matched locked intervals, two are below one millisecond; other pairs last minutes: for example, Marcus's `15:22:42.6101706Z` lock ends at `15:36:06.2154646Z`, and Diego's `18:20:21.0188846Z` lock ends at `18:44:22.3367360Z`. The mixture makes the near-zero pairs conspicuous rather than a global timestamp-resolution issue.

A real system could still produce closely adjacent events through software-triggered transitions or event-publication effects. The data alone does not document that mechanism, nor does it prove a human completed an unlock in under a millisecond. I therefore classify this as timing texture and avoid calling it an impossible native value.

### macOS interpretation boundaries

The ES rows declare message `version: 11` and encode notification `action_type: 1`; I assessed the visible fork/exec/exit relationships without treating notification results as authorization denials. Per-event-type seq_num and global_seq_num progress coherently in the examined exports; completeness itself was not penalized.

The Unified Log policy message at `15:42:09.009673+0000` says AppleSystemPolicy “would not allow” MeetingAssist. I did not infer successful MeetingAssist execution or a child process from that message. There are no grounds to require a launch-item, filesystem or denied-execution companion merely because the platform can log one. Sparse Unified Log coverage was not scored, since a selected export is a plausible collection choice.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Windows Security 4800/4801 | Two pairs on WS-AJOHNSON-01 and WS-MCHEN-01; six matched pairs examined | Near-zero locked intervals across two hosts are a concrete local timing artifact. Raises concern moderately, but software-driven transitions remain possible. |

No demonstrated hard contradiction or source-native schema defect was established. The unmatched SMB UID is documented as a collection-window limitation and is not included in the synthetic score.

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled event-specific Windows payloads, Zeek field types, Linux writers, and separate macOS export shapes are credible; no verified parser-breaking defect was found.
- **Temporal patterns:** 7 — Broad lifecycle and protocol ordering is coherent, but two near-zero workstation lock cycles merit investigation.
- **Cross-source correlation:** 9 — Checked process IDs/images and connection/protocol tuples agree; no tested impossible lifecycle ordering was found. One SMB mapping cannot be joined within this slice and remains unclassified.
- **Behavioral realism:** 8 — Authentication mechanisms, service activity, failed proxy outcomes and separate lifecycle phases are plausible; the short lock cycles weaken confidence locally.
- **Environmental consistency:** 9 — Host/platform paths and source semantics are coherent in the examined records; no mandatory product or audit coverage was presumed.

## Recommendations

- If this were synthetic, model workstation locked-state duration separately from event publication jitter. Revisit the two cited pairs so a nominal human lock/unlock cycle does not collapse below a millisecond; if the intended cause is automation, generate the behavior according to that cause rather than applying an arbitrary human duration.
- If this were synthetic, retain the existing source-specific rendering distinctions and canonical identity relationships demonstrated here, particularly 1102 UserData handling, decimal versus hexadecimal process IDs, Sysmon GUID continuity, TLS file/certificate references, and macOS fork/exec target semantics. These are useful fidelity properties that should survive any timing correction.
