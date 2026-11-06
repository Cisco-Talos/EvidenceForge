# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 74
**Synthetic-Confidence Score:** 54

## Executive Summary

The supplied telemetry is highly usable for detection engineering: XML and JSON parse, Windows event shapes generally match their declared event IDs, and process/session/network relationships survive substantial identity-based checks. A small number of macOS process-timing and identifier-allocation patterns suggest constructed activity, but the strongest remaining concerns are localized and do not establish an impossible same-identity lifecycle; I cannot confidently distinguish realistic synthetic telemetry from a curated production slice.

## Evidence For Synthetic

- [distribution_texture] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` contains conspicuously block-allocated `audit_token.pidversion` values whose order follows groups of related activities rather than time. Lines 44–46 allocate versions 69–71 to Zoom at 14:22:52; lines 47–61 subsequently allocate versions 47–58 to a newly created SSH tree at 14:24:42–44. Lines 80–81 allocate 84–85 to a new SSH client at 15:00:21, whereas lines 82–96 return to 72–83 for later new processes. This is suggestive of preassigned identity blocks. I treat this as a moderate distribution concern, not a demonstrated collision or an unsupported claim that a numeric comparison alone proves native identity invalidity.
- [environment_or_collection_plausibility] `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` lines 82–83 show `/usr/bin/id`, PID 64542/version 74, executing at 16:03:58.660391 and exiting successfully at 16:05:26.788371: **88.127980 seconds**. This is markedly different from the same executable on that host at lines 9–10 (0.149827 seconds) and 96–97 (0.295586 seconds). Directory-service delay, scheduling suspension, or terminal blockage can explain it, so it is not an impossibility. The normalized evidence repeats the long lifetime in `ecar.json` lines 305–306, making this an underlying activity-timing concern rather than an isolated ES timestamp typo.
- [weak_signal] On MAC-MROSS-02, three separate native executions use `/bin/cat` to read binary Office documents, all with similar lengthy lifetimes: ES lines 102–103, `service-review.xlsx`, 11.861714 seconds; lines 115–116, `project-plan.docx`, 13.135748 seconds; lines 118–119, `onboarding.docx`, 13.989208 seconds. The matching eCAR FILE/READ records occur at lines 257, 315, and 323. Repeatedly using a terminal byte-dump utility for these document types, with this narrow duration band, is a modest behavioral/timing anomaly. It could also be intentional command-line collection or a user workflow, so it carries little weight alone.

## Evidence For Real

- The Windows exports preserve important source-specific distinctions. For example, DC-01 Security EventRecordID 28245320 is Event 4688 version 2 with `NewProcessId`, creator `ProcessId`, target-principal placeholders, and mandatory label. The corresponding Sysmon EventRecordID 3288926 is Event 1 with a decimal PID, process GUID, parent GUID, hashes, image metadata, and a millisecond `UtcTime` distinct from the higher-resolution publication timestamp.
- DC-01 Event 1102 is correctly represented as `Microsoft-Windows-Eventlog` with `UserData/LogFileCleared`, rather than an invented Security-Auditing EventData shape. At 18:42:11.6676456, EventRecordID resets to 1; subsequent Security records use the new numbering epoch. This is a useful subtlety for ingestion and cleared-log detections.
- FILE-SRV-01 Security records 271775–271778 form a coherent share/file access chain: Event 5145 names `ClinicalExports` and `Servers\archive-final.bak`, Events 4656 and 4663 use the corresponding full local path and common handle `0x1b169349`, and Event 4658 closes that handle. Requested access and exercised access are appropriately different (`0x12019f` versus `0x2`).
- Identity-based checks across all supplied Windows Sysmon files found no process GUID referenced more than one second before its visible creation or more than one second after its visible termination. Checks of matching 4624/4634 logon IDs found no user/SID/logon-type mismatches. This supports usable correlation; completeness itself was not scored as suspicious.
- All three Zeek sensor directories have plausible UDP/TCP distinctions, numeric ports and byte counters, boolean locality flags, failure states, incomplete handshakes, resumed TLS sessions, and both TLS 1.2 and TLS 1.3. Protocol records carrying a matching `uid` stayed within the corresponding visible connection interval to a one-second tolerance.
- MAC-MROSS-01 ES lines 1–7 distinguish fork from successive exec images: launchd forks a child, that child runs xpcproxy and Terminal, and subsequent descendants execute login and zsh. PID remains stable across exec while version changes. The exports do not confuse native Endpoint Security notifications with normalized EDR FLOW rows.
- Linux records include believable pre-window session closure, sudo command/open/close ordering, DHCP request/ack pairs, cron/anacron lifecycles, and daemon-specific message content. APP-INT-01 syslog lines 3–4 close a previously existing SSH session; absence of its initiating record in this slice is neutral.

## Detailed Analysis

### Scope and parsing

I examined only the supplied data directory. I parsed all Windows XML exports, comprising **19,030 Security records and 11,785 Sysmon records**, and parsed the supplied JSON/NDJSON for automated relationship checks. There are **35,807 eCAR records**. The Windows sources collectively contain 38 distinct source-family/event-ID combinations. I also examined Linux syslog, proxy access, firewall, Snort, and representative Zeek protocol/file/certificate records.

No filesystem timestamps, domain-resolution expectations, missing Sysmon event types, attack linearity, or general source thinness were used as authenticity evidence. This is a bounded time slice; pre-window processes and post-window survivors were not treated as defects.

### Windows schema and field checks

The following sample spans more than twenty distinct event shapes. References use file plus EventRecordID, which is reproducible without depending on XML pretty-print whitespace. Unless specified otherwise, the file is `DC-01.meridianhcs.local/windows_event_security.xml`.

| Event | Record reference | Fields/semantics checked | Result |
|---|---|---|---|
| 5156 | 28245268 | Decimal PID, device application path, direction/layer message tokens, protocol 17, endpoint ports | Plausible |
| 4689 | 28245287 | Hex PID, subject identity, exit status, image | Plausible |
| 4769 | 28245307 | Machine principal, service account SID, ticket options/encryption, IPv4-mapped IPv6 | Plausible |
| 4688 v2 | 28245320 | New/creator PIDs, target fields, mandatory label, parent image | Plausible |
| 4624 v2 | 28245415 | Type 5 NETWORK SERVICE identity, Advapi, service caller, absent remote endpoint | Plausible |
| 4672 | 28245416 | Same NETWORK SERVICE SID and logon ID `0x3e4`, privilege string | Plausible |
| 4768 | 28245452 | Machine account SID, krbtgt RID 502, preauthentication, client endpoint | Plausible |
| 4776 | 28245477 | NTLM authentication package, workstation and status | Plausible |
| 4634 | 28245660 | Target user, SID, logon ID and logon type | Plausible |
| 5140 | 28246379 | NETLOGON share and local SYSVOL script path | Plausible |
| 4648 | 28246531 | Subject/caller, explicit target credentials, target server fields | Structurally plausible |
| 4779 | 28247531 | RDP session name, account, client endpoint, LogonID spelling | Plausible |
| 4771 | 28248908 | Failure keyword, Kerberos status `0x18`, preauthentication and endpoint | Plausible |
| 4625 | 28253813 | Failure keyword, disabled-account substatus `0xc0000072`, type 3 | Plausible |
| 4697 | 28256455 | Service name, expandable image path, type/start/account fields | Plausible |
| 4720 | 28257154 | Account SID/name, subject, SAM attributes, UAC changes | Plausible |
| 4724 | 28257156 | Password-reset target and subject identity | Plausible |
| 4738 | 28257159 | Same target SID, changed account-control attributes | Plausible |
| 4728 | 28257173 | Member DN/SID and Domain Admins group RID 512 | Plausible |
| 4698 | 28257394 | Escaped task XML, task namespace, principal/action/trigger | XML parses; plausible payload |
| 1102 | Record 1 at 18:42:11 | Provider/channel, UserData namespace and log-clear numbering epoch | Plausible |
| 5145/4656/4663/4658 | FILE-SRV-01 records 271775–271778 | Share/local path, common handle, requested versus used access, close | Coherent |

Sysmon samples included Events 1, 3, 5, 7, 8, 10, 11, 13, and 22. Event 10 uses `SourceProcessGUID`/`TargetProcessGUID`, whereas Event 8 uses the `Guid` spelling appropriate to its own fields; a parser must not assume identical casing across event types. Event 3 on DC-01 record 3288907 has `Initiated=false` for inbound DNS, with remote source 10.10.2.11 and local destination 10.10.2.10, which is internally sensible.

These checks support ingestion and rule-field compatibility; they are not a claim of exhaustive external schema certification.

### Lifecycle and network correlation

For Sysmon, I joined process-related GUID fields to visible Event 1/Event 5 records, including source, target, and parent references. For eCAR, I joined `actorID` and `objectID` against visible process CREATE/TERMINATE records. No greater-than-one-second pre-create/post-exit violations appeared in these checks. This tolerance avoids treating source publication jitter as impossible canonical ordering and means subsecond edge cases have not been exhaustively adjudicated.

For Windows sessions, matching 4624 and 4634 records retained consistent user name, SID, and logon type for the same host/logon ID. Missing starts or closes were not counted as errors.

Zeek has 12,314 core, 433 database, and 9,401 DMZ connection rows. I joined available `uid`-bearing protocol rows to conn rows and checked timestamp placement. No matched protocol record preceded connection start or exceeded connection end by more than one second. There were no positive payload-byte counts with zero corresponding packet counts. TLS certificate key types matched the sampled cipher-authentication families, and repeated issuer/serial pairs did not change certificate content within each sensor's export.

Core DNS line 1 shares UID `Cuq507OFNo7MpYfALL` and timestamp 1793624402.898315 with conn line 1; DNS RTT 0.028925 also matches the connection duration. This supports source-level tuple and timing compatibility. The varied states, including S0, REJ, resets, and OTH, prevent the connection corpus from looking like a success-only fixture.

### macOS interpretation and remaining uncertainty

The ES files declare message version 11 and contain notify-style fork/exec/exit records with audit-token identity, executable metadata, and process snapshots. On MAC-MROSS-01, lines 1–3 preserve the same child PID 42152 through xpcproxy and Terminal with successive versions. MAC-MROSS-02 preserves iTermServer, login, ShellLauncher and zsh as distinct native execution steps. File metadata for a given executable remains stable in the examined native snapshots.

I did not treat an AppleSystemPolicy Unified Log message saying a process “would not” be allowed as proof of denied execution, nor demand that native ES include network FLOW rows. Those are different source semantics.

The main unresolved identifier issue is the temporal order of newly assigned PID-version blocks on MAC-MROSS-02. There are no observed same-version/different-PID collisions. Since the supplied data does not describe identity sanitization or export transformations, I cannot exclude a deliberate remapping. I therefore avoid elevating this numeric pattern into a hard contradiction.

The 88-second `id` lifetime is similarly real-world explainable but unusual. In combination with the narrow lifetimes of the Office-document `cat` operations, it suggests that some command lifetimes may represent activity durations rather than the actual executable's resource demand. The available records do not prove that explanation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS ES, normalized process versions | Repeated out-of-time allocation blocks on MAC-MROSS-02 | Moderate; resembles activity-first identity allocation, but remapping/native details remain unresolved |
| environment_or_collection_plausibility | macOS ES and eCAR process lifecycle | One `/usr/bin/id` execution lasting 88.128 seconds | Small to moderate; unusual executable-specific duration with legitimate alternative explanations |
| weak_signal | macOS ES/eCAR process and file records | Three binary Office-document reads by `cat`, approximately 12–14 seconds each | Small; repeated tool/duration pattern, not an impossibility |

No hard contradiction is asserted. Strong Windows and network consistency offsets these localized concerns, keeping the score in the mixed/inconclusive band.

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON parse and sampled Windows/Zeek/native-macOS structures are generally credible.
- **Temporal patterns:** 7 — Lifecycle checks pass, with localized macOS duration and allocation-order concerns.
- **Cross-source correlation:** 9 — Host-local identities, session joins, protocol UIDs and timing largely agree.
- **Behavioral realism:** 7 — Substantial platform-specific activity, with a few unusual macOS command/duration patterns.
- **Environmental consistency:** 8 — Network roles, endpoint platforms and source-specific semantics are generally coherent.

## Recommendations

- If this were synthetic, allocate native process identity/version values in execution order, or explicitly document any sanitization that maps them into activity-specific blocks. Recheck MAC-MROSS-02 ES lines 44–61 and 80–96.
- If this were synthetic, use executable-specific lifetime models for short local commands. Investigate whether MAC-MROSS-01 PID 64542's 88-second `id` runtime has a modeled blocking cause before retaining it.
- If this were synthetic, tie the three binary Office-document `cat` executions to a concrete intended command-line workflow and derive their duration from the actual operation, byte volume, and storage path. A generic document-access duration is a weaker model for a terminal byte-dump command.
- Preserve the currently strong event-specific XML fields, log-clear namespace/reset behavior, process identity continuity, and connection/protocol interval consistency when addressing these localized issues.
