# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 42

## Executive Summary

The supplied telemetry is substantially compatible with a real detection pipeline: the Windows XML parses, native event fields are generally convincing, and the process identities I could join have coherent visible lifecycles. Repeated shell-command vocabulary and some very short TCP exchanges with bidirectional retransmission history raise distributional concerns, but I found no demonstrated hard contradiction sufficient to confidently classify the collection as synthetic.

## Evidence For Synthetic

- [distribution_texture] Both Mac endpoints repeatedly execute the same small set of discovery/status commands from interactive zsh. On MAC-MROSS-01, Endpoint Security lines 9, 12, and 15 run `id`, `sw_vers -productVersion`, and `uname -a`; lines 33, 36, and 39 run `pwd`, `ls -la /Users/maya.ross/Documents`, and `du -sh /Users/maya.ross/Documents`; lines 52, 55, and 58 run `df -h`, `ps aux`, and the same PDF-oriented `find` used again at line 119. MAC-MROSS-02 repeats much of this vocabulary, including `sw_vers` three times and the identical PDF `find` three times. Counts are 29 zsh-launched exec observations with 21 distinct argument vectors on Mac 01 and 28 with 17 on Mac 02. This looks somewhat pool-driven, although the shared user and possible troubleshooting activity make it a moderate, explainable indicator.
- [weak_signal] TCP retransmission histories deserve scrutiny. In `zeek-core/conn.json`, 787/4,782 successful TCP connections contain uppercase `T`; in DMZ the corresponding figure is 862/5,311, and DB 51/313. More specifically, core lines 7291 and 9657 describe only 43 originator bytes and 59 responder bytes over 7.044 ms and 8.538 ms respectively, yet both carry `history=ShADadTtFf`, indicating retransmission observations in both directions. This is unusual for tiny LAN DNS/TCP exchanges. Duplicate capture, offload effects, or particular loss/reordering conditions could explain it; the overlapping sensor observations are not independent evidence. I do not call these impossible events.

## Evidence For Real

- Native Windows distinctions are preserved. For example, `DC-01.../windows_event_security.xml:739` uses Event 4624 version 2, service LogonType 5, NETWORK SERVICE SID `S-1-5-20`, `TargetLogonId=0x3e4`, and absent remote address/port markers. These are coherent service-login semantics rather than fabricated remote-user fields.
- Failure metadata differs correctly from success metadata. `DC-02.../windows_event_security.xml:118806` is Event 4771 with audit-failure keywords `0x8010000000000000`, status `0x18`, and PreAuthType 2. Success records use audit-success keywords. The schemas retain hexadecimal IDs/statuses, IPv4-mapped Kerberos client addresses, and decimal port values.
- Sysmon process identity is stable across visible creation and termination: `DC-02.../windows_event_sysmon.xml:401` creates PID 7212 / `conhost.exe` at `13:01:34.164`; line 926 terminates that same ProcessGuid at `13:04:38.699`. Native UtcTime and SystemTime have distinct precision and slight recording differences.
- Zeek protocol records join to connections with matching tuples within each sensor. Automated checks found no missing connection UID or tuple disagreement among the supplied UID-bearing protocol rows, no negative connection counters, no positive payload with zero packets, and no DNS RTT exceeding the associated connection duration by more than 1 ms. This is positive functional compatibility, not an argument that complete matching itself establishes authenticity.
- TLS 1.3 rows do not expose certificate-chain FUIDs as though passive sensors could read encrypted certificate messages. TLS 1.2 rows can reference X.509 files, and resumed/nonresumed sessions are distinguished.
- The Mac exports preserve important native process distinctions: fork children, exec actor versus target, audit-token PID versions, and exit notifications. Mac 01 ES lines 1–3 show a launchd child becoming xpcproxy and then Terminal with changing PID version; lines 77–90 show a substantially different SSH server lineage. I found no same PID-version executable mismatch or observation after a visible exit in the audited ES identities.

## Detailed Analysis

### Parsing and scope

I parsed all supplied Windows Security and Sysmon XML documents and all 21,894 Zeek connection JSON records. I also parsed the Zeek protocol files, endpoint eCAR files, and both Mac Endpoint Security exports, and inspected examples of syslog, shell histories, proxy, and ASA records. All inspected structured files parsed successfully. This does not certify every field against every possible product release; it establishes that basic ingestion and several useful joins work.

The Windows files contain 28 distinct Security event IDs and nine Sysmon IDs. I inspected individual records across more than twenty Security event types, including 4624/4625/4634/4648/4672, 4688/4689, 4697/4698, account management, Kerberos, NTLM, shares, filtering-platform events, and 1102. No absent Sysmon type was used as an indicator.

### Windows schema and identity checks

Representative checks included:

| File and event-start line | Event | Observation |
|---|---:|---|
| DC-01 Security:3 | 5156 | Native filtering-platform field names, resource-coded direction/layer, integer protocol and ports |
| DC-01 Security:126 | 4769 | Service ticket fields, ticket/encryption hex values, mapped client address |
| DC-01 Security:739 | 4624 | Version 2 fields and service-login semantics |
| DC-01 Security:794 | 4672 | Privilege list and subject identity fields |
| DC-01 Security:994 | 4768 | TGT fields and certificate placeholders |
| DC-01 Security:2312 | 4634 | Target session ID `0x537fbcf`, FILE-SRV-01$ account, network LogonType 3 |
| DC-01 Security:2672 | 4688 | Version 2 process-creation shape and hex process IDs |
| DC-01 Security:3037 | 4689 | Process termination shape |
| DC-01 Security:3316 | 4648 | Caller PID/process, explicit target credentials, server fields |
| DC-01 Security:183305 | 4697 | Service-install fields |
| DC-01 Security:195159 | 4720 | Account-creation SID and account-property fields |
| DC-01 Security:195372 | 4724 | Password-reset target and subject identities |
| DC-01 Security:195408 | 4738 | Account-change properties |
| DC-01 Security:195463 | 4728 | Member DN/SID and group SID ending in 512 |
| DC-01 Security:200927 | 4698 | Embedded task XML rather than an arbitrary command-only payload |
| DC-01 Security:269727 | 1102 | Eventlog provider, record ID reset to 1, native clear-event shape |
| DC-02 Security:118806 | 4771 | Failure status and failure keyword |
| FILE-SRV-01 Security:434 | 5145 | Share path, relative target, access mask/list and subject session |
| WS-AJOHNSON-01 Security:13140 | 4625 | Failed-logon record with status/substatus fields |

All abbreviated file names above are under the correspondingly named `.meridianhcs.local` directory. Lines refer to the beginning of each XML Event element.

I joined Sysmon records by ProcessGuid and compared timestamps and image identity. Within identities with visible creation/termination, I found no event before creation, event after termination, or conflicting executable image in the checked ProcessGuid fields. I also checked visible Security subject-session use against 4624/4634 for process creation, credential use, share access, and object access. These checks found no use before the earliest visible logon or after the final visible logoff. Repeated 4624 session IDs were not automatically treated as duplicate sessions because unlock semantics can reuse a session.

On Linux I compared syslog PIDs against eCAR visible process lifetimes, allowing five seconds for recording differences; this produced no clear before-start or after-exit example. Processes present before the window, sessions remaining open after it, and source-specific omissions were neutral.

### Network source semantics

The connection and companion record shapes are suitable for common Zeek field-based detection: dotted tuple keys, numeric timestamps, boolean local flags, connection states/history, DNS arrays and TTLs, HTTP method/status and transaction depth, SSL versions/ciphers, and FUID references.

Examples include `zeek-core/dns.json:1`, which records an A query to the domain DNS server with a matching answer and positive RTT; and `zeek-core/http.json:1`, which records a GET `/api/v1/status`, HTTP 200, 41 response bytes, and a response FUID also present in `files.json:1`. `zeek-dmz/ssl.json:1` references a TLS 1.2 certificate whose X.509 fingerprint agrees with the matching file SHA-1. Local and perimeter visibility are represented by distinct sensor-local UIDs, which is appropriate.

The main network concern is the retransmission texture described above. It would be incorrect to infer impossible packet-header accounting simply by subtracting unique payload bytes from IP bytes: retransmissions can legitimately make that difference large. Likewise, the short duration alone is not proof of fabrication because capture duplication can create retransmission observations without waiting for a retransmission timer.

### Mac native telemetry

Both Endpoint Security files declare message version 11 and contain fork, exec, and exit notifications: 139 rows on Mac 01 and 171 on Mac 02. I did not treat the notification result envelope as an endpoint authorization verdict or demand ES file events that were not supplied.

The Mac 01 Unified Log row at line 2 says policy “would not allow” an application. That wording alone does not establish a completed denial or prove subsequent execution. I found no basis to turn it into a contradiction. The SSH acceptance row at Unified Log line 3 is attributed to sshd-session and uses its own timestamp/source representation, rather than masquerading as an ES or normalized FLOW event.

The terminal and SSH ancestry is considerably more credible than a generic shell-only process stream. The repeated interactive command vocabulary remains the chief endpoint texture concern, but it is not enough to override the coherent native identity handling.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Mac ES and shell history | Two hosts, same user; repeated discovery/status argument vectors | Moderate upward pressure; could reflect shared work habits or scripted diagnostics |
| weak_signal | Zeek connection history | About 16% of successful TCP rows contain originator retransmission history; two tiny DNS examples finish in under 9 ms with bidirectional retransmission indicators | Small upward pressure; mirrored traffic and capture artifacts remain plausible explanations |
| hard_contradiction / contract_gap / schema_or_format | Checked records | No demonstrated finding | Keeps the score below a confident synthetic classification |

## Realism Score by Category

- **Field format accuracy:** 9 — Structured records parse and the sampled native schemas are convincing; full release-specific conformance was not independently certified.
- **Temporal patterns:** 8 — Visible process/session lifetimes are coherent; very short retransmission-bearing DNS exchanges remain questionable.
- **Cross-source correlation:** 9 — Tested tuple, process, and session joins work without a demonstrated contradiction.
- **Behavioral realism:** 7 — Diverse application/service activity exists, with noticeable repetition in Mac interactive command pools.
- **Environmental consistency:** 8 — OS-specific paths and service identities generally fit; no demonstrated role or collection contradiction.

## Recommendations

- If this were synthetic, broaden interactive command selection and tie repeated discovery/status commands to specific visible user tasks. Preserve the existing native Terminal/iTerm and SSH process ancestry.
- If this were synthetic, validate retransmission-history selection against exchange duration, payload size, packet counts, and capture assumptions. In particular, explain or reduce tiny sub-9-ms DNS/TCP transactions marked as retransmitted in both directions.
- Preserve the existing process/session identity integrity and source-specific field representations. I found no evidence-based reason to add arbitrary missing event families or to deliberately weaken valid cross-source correlation.
