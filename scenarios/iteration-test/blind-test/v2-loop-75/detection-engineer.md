# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 53

## Executive Summary

The dataset is highly convincing at the schema and source-native correlation layers: Windows metadata, Sysmon fields, Zeek relationships, ASA lifecycles, and role-specific host telemetry would generally ingest and detect correctly in a SIEM. Two concrete defects prevent a real-data verdict: most successful domain NTLM logons lack the authoritative 4776 validation expected from the two visible domain controllers, and one eCAR process is visibly terminated before a correlated OCSP TCP/HTTP transaction attributed to that process begins. Those defects are significant, but they are outweighed enough by the broader realism that the result remains mixed rather than confidently synthetic.

## Evidence For Synthetic

- [hard_contradiction] `LOG-MON-01.meridianhcs.local/ecar.json` terminates Java PID 739650 (`objectID=214686b0-acef-48ea-873a-f0539cc78d7f`) at `2024-03-18T17:47:39.136Z`, then attributes a new FLOW CONNECT to that same process at `17:47:39.266Z`. `zeek-core/conn.json` confirms that tuple `10.10.2.40:34321 -> 10.10.1.10:80` does not begin until `17:47:39.789773Z`, 654 ms after process termination, and `zeek-core/http.json` records a completed OCSP GET on it at `17:47:39.826773Z`. This is not merely delayed rendering of an already-open connection; the network sensor sees the new connection after the actor's terminal event.
- [contract_gap] Of 80 successful Security 4624 events with `TargetDomainName=MERIDIANHCS` and `AuthenticationPackageName=NTLM`, only 11 have a matching Security 4776 for the same account and workstation on either DC within ±2 seconds; 69 lack the authoritative NTLM validation event. For example, DC-02 logs a Type 3 NTLM success for `sophia.martinez` from `WS-SMARTINEZ-01`/`10.10.1.36` at `2024-03-18T12:17:36.251033Z`, but neither DC has the corresponding 4776 within ±120 seconds. This is difficult to explain as an unseen DC because SRV responses in `zeek-*/dns.json` advertise only DC-01 and DC-02, and both DC Security logs otherwise contain 4776 records.
- [distribution_texture] Linux syslog is dominated by a narrow, repeated background-message vocabulary across unrelated hosts. For example, `irqbalance` contributes 49-99 records on several servers and `snapd` contributes 38-101, with repeated forms such as `state ensure starting change N` and `NUMA node N: balancing pass complete`; the same `(sysstat) CMD (command -v debian-sa1 ... debian-sa1 1 1)` pattern appears 10-12 times on nearly every Linux host. A managed Ubuntu fleet can share software, but the consistently high share of these same diagnostic templates and limited source-local long tail looks curated.
- [weak_signal] Ten receiver-side eCAR FILE READ records on DC-01, DC-02, and FILE-SRV-01 carry a remote Linux PID and `/usr/bin/smbclient` in `source_process_uuid`, `source_pid`, and `source_image_path` while the enclosing record's `hostname` is Windows. The UUIDs correctly resolve to the remote client process in another host's eCAR file, so this may be deliberate cross-host enrichment; without an explicit `source_hostname`, however, a host-local EDR parser may misinterpret the Linux path and PID as local endpoint facts.

## Evidence For Real

- All 32,088 eCAR lines and 31,317 Zeek JSON lines parsed successfully; all 29,411 Windows XML events parsed successfully. Regex validation also accepted all 17,391 ASA lines, 158 Snort alerts, 1,926 proxy records, 744 web access records, and 3,717 RFC 5424 syslog records.
- Windows System metadata is source-correct across the sampled Event IDs. Security 4624 v2 uses Task 12544 and success keywords, 4625 uses failure keywords, 4688 v2 uses Task 13312, 5156 v1 uses Task 12810, and Sysmon 1/3/5/7/8/10/11/13/22 use plausible versions, tasks, level 4, and the correct provider/channel.
- Security event field sets are accurate and stable by Event ID/version. Samples included 4624 Types 2, 3, 5, 7, 9, and 10; 4625; 4634; 4648; 4672; 4688/4689; 4697/4698; 4720/4724/4726/4728/4738; 4768/4769/4771/4776; 5140/5145/5156; and 1102. Sysmon samples covered every present type.
- SID and GUID details withstand scrutiny: every SID matched Windows SID syntax, each named principal mapped to one stable SID, Sysmon GUIDs were properly formatted, and the process GUID timestamp component was consistent with event time. Security process IDs are hexadecimal, Sysmon process IDs are decimal, and Sysmon hash lengths and alphabets are valid.
- The DC-01 Security 1102 event at `2024-03-18T17:41:47.8177777Z` correctly uses the `Microsoft-Windows-Eventlog` provider, the `LogFileCleared` UserData namespace, and resets `EventRecordID` from 28260958 to 1; subsequent wevtutil/cmd termination records advance to IDs 2 and 3. That is a subtle, production-like lifecycle detail.
- Of 968 Security 4688 process creations, 967 match Sysmon Event 1 by host, PID, and image; the matching timestamps differ by 35 ms to 1.251 seconds. Of 846 Security 4689 terminations, 845 similarly match Sysmon Event 5. Across all Sysmon records, no visible Event 3/7/10/11/13/22 process reference precedes its visible Event 1 or follows its visible Event 5.
- FILE-SRV-01 contains 27 coherent object-handle lifecycles: 24 follow 4656 -> 4663 -> 4658 and three follow 4656 -> 4658, with stable HandleId, user SID, LogonID, and process identity. The first chain at `12:01:43.988151Z` uses handle `0x409dad16`, reaches 4663 at `12:01:44.0837318Z`, and closes at `12:01:44.2388672Z`.
- Logon field semantics are strong. Type 2/7/9 records use local address placeholders, Type 3/10 records carry remote addresses and ports, Type 9 contains outbound credentials, 4625 status/substatus/reason combinations are coherent, and visible 4634 identities agree with their prior 4624 by SID, username, LogonID, and LogonType.
- Windows network direction is internally correct for all 11,550 Security 5156 records: outbound `%%14593` records use the local host as SourceAddress, and inbound `%%14592` records use it as DestAddress. All 7,434 Sysmon Event 3 records likewise align `Initiated=true/false` with the local endpoint and use appropriate decimal ports and protocol names.
- Zeek correlations are source-native rather than merely narratively convenient. All 3,849 DNS, 3,035 HTTP, 2,197 SSL, 168 SMB file, 95 SMB mapping, and 46 SMTP records reference an existing same-sensor conn UID, retain the same tuple, and fall within the connection interval. No connection UID is duplicated within or reused across the three sensors.
- Zeek TLS behavior is nuanced: TLS 1.2 full handshakes carry certificate chains, resumed sessions omit them, TLS 1.3 commonly lacks visible certificate chains, all 1,021 certificate references resolve, validity intervals contain the handshake timestamp, and repeated server names reuse stable certificate fingerprints. Cipher/version combinations are coherent.
- The Zeek connection population has realistic protocol and state variety (`SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `OTH`, `S1`, `S2`, `S3`) with correspondingly plausible history strings, missing duration on incomplete connections, zero negative durations, and no byte-accounting or local-address flag violations.
- ASA lifecycle handling is strong: 6,679 TCP/UDP connection builds have 6,674 matching teardowns, the paired tuples agree, no teardown precedes its build, and the five unclosed connections occur at the end of the bounded window. All PRI severities agree with the `%ASA-n-...` severity.
- Every one of the 64 core and 94 perimeter Snort alerts has a matching Zeek tuple within two seconds. Alert syntax, GID:SID:revision, classification, priority, protocol, and endpoint formatting are plausible.
- Host roles produce differentiated telemetry: WEB-EXT-01 has 771 UFW blocks and web traffic, FILE-LNX-01 has Samba/audit events, DB-PROD-01 has multipath activity, mail systems have Postfix/Dovecot, and workstation DHCP renewals preserve MAC/IP identity with half-lease jitter. This is much more environment-specific than a flat generic-noise generator.

## Detailed Analysis

### Scope and parsing

I examined only the supplied data directory. The corpus contains approximately 117,418 logical records: 32,088 eCAR, 31,317 Zeek JSON, 29,411 Windows XML events, 17,391 ASA, 3,717 syslog, 1,926 proxy, 744 web, 158 Snort, and 666 bash-history physical lines. The visible data runs from roughly `2024-03-18T12:00Z` through `18:00Z`; I treated missing initiators before noon and missing terminal events after 18:00 as normal bounded-window effects.

### Windows schema and event semantics

The XML is valid and uses the expected provider namespaces. Each Security Event ID/version and Sysmon Event ID/version has one stable field-name layout, including the less forgiving schemas: 4688 v2 has `NewProcessId`, creator `ProcessId`, `TargetLogonId`, `ParentProcessName`, and `MandatoryLabel`; Sysmon 10 correctly uses `SourceProcessGUID`/`TargetProcessGUID`, while Sysmon 8 uses `SourceProcessGuid`/`TargetProcessGuid`; and 5156 contains decimal `ProcessID`, source/destination tuple, protocol number, direction token, filter runtime ID, and layer fields.

Representative records behave as real detection content. DC-01's 4624 Type 3 at `12:06:21.9760817Z` identifies `lina.nguyen`, SID ending `-1001`, LogonID `0x5380a5d`, NTLM V2, workstation `WS-LNGUYEN-01`, and IPv4-mapped source `::ffff:10.10.1.21`; its 5140 at `12:06:22.0015025Z` reuses the SID, LogonID, IP, and port for `\\*\NETLOGON`. FILE-SRV-01's 5145 at `12:01:43.9389524Z` names the `Finance` share, `Procedures\performance-summary-v2.xlsx`, access mask `0x120089`, and a plausible access list.

Process records also contain source-native detail. DC-01's 4688 at `12:02:19.4298911Z` creates PID `0xe0c` for `dllhost.exe`, with parent PID `0x924`/`svchost.exe`, elevation token `%%1936`, and System mandatory SID; Sysmon Event 1 reports decimal PID 3596, the same command line, product metadata, four hashes, parent PID 2340, and a creation time 288 ms earlier. Similar joins hold across the dataset, with only one missing Security/Sysmon creation pair and one missing termination pair.

The account-change and log-clear records are particularly persuasive. The 4720/4724/4738/4728 sequence for `svc_dirsync` uses one stable SID ending `-6155`, realistic UAC transitions, a proper Domain Admins SID ending `-512`, and native message-resource tokens. Event 1102 is represented under `UserData/LogFileCleared`, not incorrectly flattened into EventData, and the record counter resets exactly where expected.

### Authentication correlation

Kerberos evidence is strong: 238 of 241 domain Kerberos 4624 events have a preceding 4768 or 4769 for the same account inside ten minutes; the remaining three can reasonably be explained by prior ticket state or collection boundaries. Ticket encryption values, status values, IPv4-mapped addresses, SRV discovery, and service-account naming are coherent.

NTLM is the major exception. Restricting the test to successful 4624 records explicitly marked `AuthenticationPackageName=NTLM` and `TargetDomainName=MERIDIANHCS` leaves 80 events. Matching by username and `WorkstationName` against both DCs finds only 11 corresponding 4776 events within ±2 seconds, and widening to ±120 seconds does not recover the other 69. The presence of correctly paired examples—for example DC-02's 4776 at `12:43:13.3577215Z` and WS-DRAMIREZ-01's 4624 at `12:43:13.410200Z` for `diego.ramirez`/`MAIL-EDGE-01`—shows the contract exists but is applied inconsistently.

Per-event sampling could explain this in real telemetry, so I did not classify it as a hard contradiction. It nevertheless affects detection realism because an MSSP correlation looking for NTLM authentication at the authoritative DC would fail for 86% of the visible domain NTLM successes while equivalent Kerberos correlations are nearly complete.

### Process and eCAR lifecycle

eCAR structure is mostly sound: all record IDs are valid unique UUIDs, lines are time ordered per host, hostnames match their containing source, process termination reuses the creation object ID and PID, and no other visible actor reference occurs before creation or after termination. The single exception is therefore conspicuous rather than part of general disorder.

LOG-MON-01 creates Java PID 739650 at `17:47:31.788Z` to run `service-healthcheck.jar --target DC-01.meridianhcs.local`. It connects to DC-01 LDAPS at `17:47:35.258Z`, terminates at `17:47:39.136Z`, and then records the OCSP HTTP FLOW at `17:47:39.266Z`; Zeek observes DNS for `ocsp.meridianhcs.local` at `17:47:38.972062Z`, TCP start at `17:47:39.789773Z`, and HTTP GET at `17:47:39.826773Z`. A queued or delayed endpoint notification could move the eCAR row, but it cannot explain the independent network sensor seeing the new successful TCP/HTTP exchange after the only attributed process has ended. A surviving child or system service could perform OCSP, but then assigning the flow to the terminated Java object and PID is wrong.

### Zeek and network-source fidelity

Zeek JSON field names and types are accurate across conn, DNS, DHCP, files, HTTP, OCSP, PE, SMB, SMTP, SSL, and X.509. DNS qtype/rcode numeric-name pairs are valid, TTL vector lengths match answer vectors, A answers are syntactically IPv4, and transaction IDs and RTTs have reasonable ranges. DHCP keeps stable host/IP/MAC relationships and renews approximately at half the 3,600-, 7,200-, or 14,400-second leases with jitter.

Companion timing is causally credible: DNS entries occur 0-4.331 ms after connection start, TLS 5-640 ms after, HTTP 1 ms-4.398 seconds after, and SMB mapping/file operations later but still inside the transport interval. Files and PE records use sensor-local FUIDs; the same downloaded PE observed at core and DMZ has different FUIDs but the same SHA-1, which is exactly the distinction a real multi-sensor deployment should preserve.

The firewall and IDS sources reinforce this. ASA build/teardown IDs and tuples survive automated pairing, while incomplete terminal state is confined to five connections open at the end of the window. Snort records use fast-alert syntax and line up with the corresponding sensor's Zeek tuple with realistic subsecond offset rather than exact timestamp duplication.

### Web, proxy, syslog, and distribution texture

Both HTTP access formats parse cleanly. Web records use valid combined-log placeholders such as `304 -`, coherent methods/statuses, stable asset sizes, browser sessions with consistent user agents, and differentiated scanner traffic. Proxy records distinguish CONNECT control-message bytes from tunnel bytes and link bumped requests with a `tunnel_id` and client source port; denied, authentication-required, gateway-error, tunnel, and SSL-inspection outcomes have compatible fields.

RFC 5424 syslog PRI values, timestamps, application names, PROCIDs, and message layouts are valid. Role-specific content is strong, as are SSH sequences: every one of 44 visible accepted SSH authentications has nearby PAM/session activity and an eCAR login for the same user and source. The weaker aspect is fleet-wide texture. A small set of `irqbalance`, `snapd`, sysstat CRON, D-Bus, and systemd-resolved templates accounts for a large share of otherwise unrelated Linux hosts; values vary, but the message-family mix is more uniform and curated than I normally see across servers, mail relays, appliances, and workstations.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---:|---|
| `hard_contradiction` | eCAR + Zeek DNS/conn/http | One OCSP transaction on LOG-MON-01 | A terminated Java process remains the attributed actor for a successful TCP/HTTP transaction whose independent network-sensor start is after termination. |
| `contract_gap` | Windows Security authentication | 69 of 80 domain NTLM successes | Required authoritative 4776 validation is absent for most visible NTLM successes despite both advertised DC Security logs being present and some correct pairs existing. |
| `distribution_texture` | Linux RFC 5424 syslog | Fleet-wide, moderate | The same high-frequency irqbalance/snapd/sysstat templates dominate many unrelated Linux roles with limited host-specific long-tail variety. |
| `weak_signal` | eCAR FILE activity | Ten records across three Windows receivers | Remote Linux PID/image metadata is embedded in receiver-host records without an explicit source-host field; this may be enrichment, but its local-vs-remote semantics are ambiguous for detection pipelines. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Sysmon, Zeek, ASA, Snort, proxy, web, and RFC 5424 fields are consistently parseable and overwhelmingly source-correct.
- **Temporal patterns:** 7 — Most lifecycles and source delays are credible, but the post-termination OCSP connection is a concrete causal failure.
- **Cross-source correlation:** 7 — Process, file-handle, Zeek UID/FUID, ASA, IDS, and SSH joins are strong; broad NTLM-to-4776 incompleteness is the main gap.
- **Behavioral realism:** 8 — Host activity, authentication modes, process trees, browsing, mail, SMB, scanning, and failure outcomes show convincing variation.
- **Environmental consistency:** 8 — Roles, IPs, SIDs, hostnames, services, certificates, and routing are stable; Linux baseline-message homogeneity and ambiguous receiver-side eCAR attribution reduce the score.

## Recommendations

- If this were synthetic, keep the process that owns certificate validation alive through the OCSP transaction, or represent a surviving child/system process as the actor. Verify the final eCAR actor lifetime against the Zeek SYN/HTTP interval, not only against an earlier DNS prerequisite.
- If this were synthetic, emit an authoritative 4776 on one of the advertised DCs for each domain-account NTLM validation that produces a 4624/4625, preserving username and workstation. If deliberate per-Event-ID sampling is intended, make that observation policy coherent and visible enough that the 4776 deficit does not contradict the otherwise dense DC authentication coverage.
- If this were synthetic, broaden Linux background telemetry with role- and package-specific long-tail messages and reduce the fleet-wide dominance of the same irqbalance, snapd, and sysstat templates. Preserve the good role-specific sources already present, such as multipathd, Samba auditing, Postfix/Dovecot, UFW, DHCP, and desktop services.
- If this were synthetic, clarify eCAR cross-host causality by adding an explicit source hostname for remote process metadata, or render the receiver's local server process as the host-local actor while retaining the remote client identity in separately named fields.
