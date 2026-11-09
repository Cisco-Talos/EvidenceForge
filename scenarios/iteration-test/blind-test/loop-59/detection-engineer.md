# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 94
**Synthetic-Confidence Score:** 81

## Executive Summary

Most of this dataset would ingest cleanly and supports credible process, session, and network correlation. My decisive finding is localized to MAC-MROSS-02: newly allocated native audit-token identity versions repeatedly move backward while both wall time and Mach time advance; a separate set of seven exactly 1 ms process handoffs adds a weaker timing fingerprint.

## Evidence For Synthetic

- [hard_contradiction] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson:1-3` gives a new fork child PID 19775 `pidversion=31`, its exec target `pidversion=32`, and then, over 16 minutes later, a newly forked PID 21356 `pidversion=10`. These are event-specific child/target audit tokens, not an old parent's retained identity. Both `time` and `mach_time` advance, and the new child's `start_time` agrees with the later fork. Darwin uses a shared incrementing identity-version allocator for fork and exec; this is inconsistent with normal native allocation history. Additional examples at lines 80-86 and 111-126 establish recurrence. See the detailed qualification below and Apple's [fork implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c) and [exec implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c).
- [distribution_texture] The same file contains seven adjacent EXIT→FORK handoffs separated by exactly `0.001000` seconds despite retaining microsecond detail: lines 18→19, 21→22, 24→25, 85→86, 88→89, 94→95, and 97→98. The two clusters involve different foreground command sequences. Scripts can produce fast handoffs, so this is supporting evidence of artificial scheduling texture, not an impossible lifecycle claim.

## Evidence For Real

- Windows field shapes are generally careful: Security PIDs use hexadecimal where appropriate, Sysmon PIDs use decimal, source addresses can be IPv4-mapped IPv6, privilege lists retain multiline resource-string formatting, and audit success/failure keywords differ appropriately in inspected records.
- Visible Windows process and session lifecycles are strong. Across 12,058 Sysmon events, my GUID-based scan found no selected process, parent, source-process, or target-process reference visibly before its collected creation or after its collected termination. Across 19,411 Security events, the scan found no non-well-known subject session used before its earliest visible 4624 or after its visible 4634.
- Zeek has varied connection states and histories, including failed SYN attempts, resets, retransmission indicators and content gaps. Protocol timestamps fall inside the corresponding visible connection intervals in the checked DNS, HTTP, SSL, SMTP, and matched SMB records.
- `DC-01.../windows_event_security.xml:2866` and `:3001` preserve the same machine-account SID, `TargetLogonId=0x5382af7`, and Type 3 across logon and logoff, separated by approximately three seconds.
- `FILE-SRV-01.../windows_event_security.xml:146`, `:199`, and `:240` preserve `HandleId=0x8a164b99`, the requesting session, and object identity across request, access, and close. The access request mask `0x12019f` contains the later write mask `0x2`.
- macOS distinguishes exec actor from post-exec target, increments the per-event-type ES sequence numbers coherently, includes signing and executable-file metadata, and models GUI launch chains and SSH helper processes. I found no per-event-type sequence-number reversal in either Mac ES file.

## Detailed Analysis

### Provenance, scope, and method

I read the supplied neutral briefing and files under `/private/tmp/log-study-0kwedkcm/data` only, plus official Microsoft, Apple, Zeek, and Apple upstream kernel documentation for source semantics. I used system `python3` with `/private/tmp` as the explicit working directory. I did not inspect project files, authored scenarios, implementation, prior assessments, other reviewers, or parent-directory inventories. Generic project operating instructions were inherited in the environment; they were not treated as evidence of the logs' origin.

I parsed all Windows XML files and all eCAR NDJSON for the bounded lifecycle checks described here; parsed the three Zeek sensors' connection and protocol JSON; and inspected representative Linux syslog, proxy, web, IDS, and macOS native records. This is a source-schema and correlation review, not a packet reconstruction or a claim that every field has been independently validated against a captured system of the exact release.

The corpus includes 19,411 Security events, 12,058 Sysmon events, 299 ES notifications across two Macs, and 22,509 connection records across three Zeek sensors. The native Mac notifications declare `version=11`; I did not infer an exact macOS build merely from an invoked `sw_vers` command. No absent Sysmon family, sparse Unified Log export, missing out-of-window lifecycle endpoint, sanitized domain, or complete cross-source matching was scored as a defect.

### Native Mac audit identity chronology

For the following table, the path is `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`. Values are the newly created `event.fork.child.audit_token` or post-exec `event.exec.target.audit_token`, not the message actor's old identity.

| Line | Event time, 2026-11-02 UTC | New identity | Mach time |
|---|---|---|---:|
| 1 | 13:20:29.875707 | fork PID 19775, version 31 | 56016717016968 |
| 2 | 13:20:29.882486 | exec PID 19775, version 32 | 56016717179664 |
| 3 | 13:37:11.846603 | fork PID 21356, version 10 | 56040764318472 |
| 80 | 15:25:40.511790 | exec PID 41975, version 89 | 56196972282960 |
| 81 | 15:46:42.616461 | fork PID 44085, version 83 | 56227262795064 |
| 83 | 15:46:42.628448 | exec PID 44085, version 85 | 56227263082752 |
| 86 | 15:48:46.208061 | fork PID 44280, version 72 | 56230228993464 |
| 111 | 16:22:14.840706 | exec PID 47425, version 99 | 56278436176944 |
| 113 | 16:45:30.958506 | fork PID 49701, version 92 | 56311943004144 |
| 124 | 17:12:27.395264 | exec PID 52334, version 112 | 56350737486336 |
| 126 | 17:19:16.246289 | fork PID 53019, version 100 | 56360549910936 |

There are eight downward transitions across 124 observed new child/exec target identities on this Mac; MAC-MROSS-01 has none across 82. I would not treat a lower version on an already existing actor as a defect. Here the low values belong to new children whose `start_time` equals the later fork, and the inversions span minutes, rather than merely near-simultaneous hooks that could race.

Apple's current upstream fork and exec paths increment the shared `nextpidversion` counter when assigning these identities. That supports the inference of a native identity-history contradiction, rather than a JSON naming error. A hypothetical counter wrap would require billions of intervening allocations between small values, repeatedly during this six-hour slice; the supplied activity does not make that credible. An undocumented identity-sanitization transformation could explain the values, but the briefing documents domain sanitization rather than remapping this native counter. Because the exact OS build is not supplied, I keep verdict confidence below certainty. [Apple fork source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c), [Apple exec source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c).

This matters to detection engineering because native audit tokens represent execution identity: preserving the PID while changing its image is different from inventing arbitrary ordinal values for each independently planned activity. A SIEM can ingest these rows, but an authenticity check against kernel allocation chronology fails.

### Timing texture without conflating speed and impossibility

The seven handoffs listed above preserve all six fractional digits from the preceding EXIT and add exactly 1,000 microseconds. For example, line 85 ends an SSH client at `15:48:46.207061`; line 86 forks the next shell child at `15:48:46.208061`. Lines 94→95 repeat the pattern at `15:48:47.982855`→`15:48:47.983855`, and lines 97→98 at `15:48:48.136163`→`15:48:48.137163`.

These could be scripted sequences, and rapid execution alone is neutral. The scored observation is the repeated exact interval with preserved fine timestamp residue across two clusters, not that the activities are compact or narratable. It modestly increases synthetic confidence, while the identity chronology carries most of the verdict.

### Twenty representative Windows event checks

Paths below are relative to the supplied data directory. `DC1-Sec` means `DC-01.meridianhcs.local/windows_event_security.xml`; `DC1-Sys` means its Sysmon XML. The table records actual parsed samples and the specific property checked, not blanket certification of every field.

| Source and start line | Event | Parsed check |
|---|---:|---|
| DC1-Sec:2866 | 4624 v2 | Type 3, Kerberos, mapped source address, target SID/LUID and v2 fields |
| DC1-Sec:3001 | 4634 v0 | Matches preceding target SID/LUID and logon type |
| DC1-Sec:21008 | 4648 v0 | Subject, explicit target credentials, server and caller PID/path are separate |
| DC1-Sec:1023 | 4688 v2 | `NewProcessId=0xe78`, parent `0x91c`, mandatory label and target fields |
| DC1-Sec:1107 | 4689 v0 | Same PID/path; success exit status after creation |
| DC1-Sec:368 | 4768 v0 | `krbtgt`, preauth type 2, encryption 0x12, certificate slots |
| DC1-Sec:167 | 4769 v0 | Service account/SID, encryption, client endpoint and status |
| DC-02.../windows_event_security.xml:123482 | 4771 v0 | Failure status 0x18 with failure keyword 0x8010000000000000 |
| DC1-Sec:178454 | 4697 v0 | PSEXESVC service path, type 0x10, demand start 3, LocalSystem |
| FILE-SRV-01.../windows_event_security.xml:97 | 5145 v0 | Share-relative target, local share path, session and access mask |
| FILE-SRV-01.../windows_event_security.xml:146 | 4656 v1 | Handle, full object path, requested access and resource attributes |
| FILE-SRV-01.../windows_event_security.xml:199 | 4663 v1 | Same handle; specific access bit within request |
| FILE-SRV-01.../windows_event_security.xml:240 | 4658 v0 | Same handle and process, after access |
| DC1-Sys:825 | 1 v5 | Decimal PID 3704 equals 0xe78; parent GUID/PID/image and hash formats |
| DC1-Sys:3 | 3 v5 | `Initiated=false` on inbound UDP DNS, process ownership and endpoint fields |
| DC1-Sys:910 | 5 v3 | Same process GUID/PID/image after Event 1 |
| DC1-Sys:2592 | 10 v3 | Distinct source/target process fields, access mask and CallTrace |
| DC1-Sys:603 | 22 v5 | Query status 0; semicolon-terminated result; process identity |
| DC1-Sys:69435 | 8 v2 | Source/target identities, new thread, address, module and function |
| DC1-Sys:114620 | 13 v2 | SetValue, registry path and typed DWORD details |

The sampled 4688 v2 layout aligns with Microsoft's documented creator, target, process, and mandatory-label structure. I did not reject older Kerberos event versions based only on the calendar date, since the actual Windows releases and patch levels are unknown. [Microsoft Event 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688).

I also inspected `DC1-Sec:263348`, Event 1102: it uses the Eventlog provider, level 4, Task 104, and a namespaced `UserData/LogFileCleared` payload instead of pretending it is ordinary Security-Auditing `EventData`. Its record ID resets to 1. This avoids a common parsing and source-identity error.

### Network and normalized endpoint checks

The Zeek schemas use numeric timestamps/ports/counts, proper connection keys and arrays for DNS answers, certificate chains, and file references. All checked DNS/HTTP/SSL/SMTP records have an extant local connection UID, and their timestamps fit that connection's interval. This is evidence of functionality, not a synthetic tell.

I initially checked apparent TCP overhead shortfalls, but every such row had an explicit `g`/`G` content-gap history. I therefore do not score them: Zeek sequence-derived payload counts and captured IP-byte counts need not obey a simple lossless-capture arithmetic relationship when content is missing. Connection histories also include retransmission indicators rather than using a single universal history string. [Zeek connection-log semantics](https://docs.zeek.org/en/lts/reference/logs/conn.html).

One SMB mapping and two SMB file rows reference UID `Cr7mRCkac27kS4mWeXo` without a supplied connection row (`zeek-core/smb_mapping.json:89`; `smb_files.json:153-154`). I leave this unscored: a sliced export can retain an in-window protocol operation while its long-lived connection record falls outside the export interval. This is not enough to establish a contradictory collection profile.

The eCAR scan found no checked PROCESS object's collected creation/termination interval contradicted by its process or actor references. Its Windows-style `logon_id` fields on Linux are normalized fields, not evidence that native Linux auth logs contain Windows LUIDs. Likewise, Mac eCAR FLOW records are normalized endpoint network observations; I did not apply those fields to native ES notifications.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Native macOS ES audit-token identities | MAC-MROSS-02; eight new-identity order inversions | Main reason for the synthetic verdict; conflicts with shared kernel identity allocation despite increasing wall/Mach time |
| distribution_texture | Native macOS ES event timing | MAC-MROSS-02; seven EXIT→FORK handoffs in two clusters | Modest supporting weight; exact 1 ms residue preservation is suspicious, while scripted rapid execution remains possible |

These are two observations, not nine independent identity defects plus seven independent timing defects. Strong correlation elsewhere meaningfully limits how broadly the localized defect should be generalized.

## Realism Score by Category

- **Field format accuracy:** 8 — Parsing, native layouts and value formats are strong; Mac audit identity allocation is the material semantic exception.
- **Temporal patterns:** 7 — Most visible lifecycles are coherent; Mac counter chronology and repeated exact handoffs lower confidence.
- **Cross-source correlation:** 9 — Windows, endpoint and network checks hold well within the visible window.
- **Behavioral realism:** 8 — Multiple host roles and protocol/error behaviors are represented; no penalty for an understandable activity sequence.
- **Environmental consistency:** 8 — Roles and source families are broadly plausible, with a localized native identity-history problem.

## Recommendations

- If this were synthetic, assign native Mac audit identity versions according to one host-wide execution chronology, including after any event rescheduling. Validate new fork-child and exec-target identities against the actual source OS allocator semantics while retaining old actor identities where appropriate.
- If this were synthetic, replace the seven exact 1 ms handoff repairs with source-supported shell wait/launch timing, or represent an explicitly measured/scripted delay when that is intended. Preserve foreground ordering without repeating the predecessor's fractional timestamp plus a fixed offset.
- Preserve the demonstrated Windows XML layouts, handle/session lifecycles, and Zeek interval/reference consistency while making those localized changes.
