# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 81

## Executive Summary

Most records are well formed and would support useful SIEM detections, including strong Windows process/session and Zeek protocol correlation. The decisive defect is in both native-shaped macOS Endpoint Security streams: newly forked processes receive audit-token PID versions that move backward despite increasing event time, Mach time, and sequence numbers. This is a narrow but reproducible source-native identity contradiction, rather than a judgment about the suspicious activity's storyline.

## Evidence For Synthetic

- [hard_contradiction] Native macOS fork identities violate the host-wide PID-version allocation order. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, line 75 records a newly forked PID 64190 with `event.fork.child.audit_token.pidversion=88` at `2026-11-02T16:00:08.553321000Z`; line 77 records a newly forked PID 64367 with version **70** at `16:02:01.753084000Z`. The latter child's `start_time` equals that later fork time; it is not an old process merely observed late. Mach time increases from `25142605279704` to `25145322074016`, and `global_seq_num` increases from 74 to 76. Apple XNU allocates a newly created process's version by atomically incrementing the shared `nextpidversion`, not by restarting a per-session counter. [Apple XNU fork implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_fork.c)
- [hard_contradiction] The same issue independently affects `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`: line 34 forks PID 21882 with version **42** at `13:42:47.073295000Z`, while line 38 forks PID 22291 with version **39** at `13:47:08.148869000Z`. Lines 111 and 114 later fork versions **114** and **116**, followed by version **94** at line 117. These examples belong to one repeated defect family, not multiple independently weighted indicators.

## Evidence For Real

- Windows process identity and lifetime handling is strong. For example, `DC-01.meridianhcs.local/windows_event_sysmon.xml:846` creates `taskhostw.exe`, PID 3712, GUID `{83eb9c06-89f9-6ae8-9502-0000a239ce2e}`, at `13:02:49.433`; line 891 terminates the same identity at `13:02:56.650`. Security 4688/4689 at lines 1556/1599 use matching hexadecimal PID `0xe80` with plausible source-specific timestamp differences.
- Windows logon and share access correlate meaningfully. `DC-01.meridianhcs.local/windows_event_security.xml:494` logs an NTLM Type 3 logon for `aisha.johnson`, `TargetLogonId=0x5375b2c`, source `::ffff:10.10.2.11:54209`; line 549 accesses NETLOGON using that session, and line 588 logs its Type 3 logoff several seconds later.
- All checked Zeek protocol rows retain valid same-sensor connection references and matching tuples. Protocol timestamps fall within their associated visible connection intervals; HTTP response-body sizes do not exceed their connection's responder byte count. This supports usability and realism, without treating completeness itself as an authenticity tell.
- macOS exec handling distinguishes the initiating process from the post-exec target and advances PID version across exec. For example, `MAC-MROSS-01.../macos_endpoint_security.ndjson:2` transitions PID 42158 from launchd image/version 10 to xpcproxy/version 11, and line 3 transitions it to Terminal/version 12. Apple and third-party signing identities are distinguished, including Chrome's `EQHXZ8M8AV` team identifier and `is_platform_binary=false`.
- Network traffic has substantial variation: successful, rejected, reset, unanswered, retransmitted, and gapped connections coexist. The core sensor includes DNS, Kerberos, LDAP, SMB, HTTP, TLS, SMTP, SSH, RDP, DHCP and RPC traffic, with different service mixes at the database and DMZ sensors.

## Detailed Analysis

### Inputs, provenance, and method

I read the supplied neutral briefing and the 119 files inside `/private/tmp/log-study-yflye15q/data`. I used system `python3` from the explicit neutral working directory `/private/tmp` for parsing and consistency checks. I did not inspect repository files, authored scenarios, project worklogs, previous assessments, or another reviewer's results. Inherited operating instructions were treated as an environment limitation and contributed no authenticity evidence. External checks were limited to Apple upstream source/documentation, Microsoft documentation, and official Zeek documentation.

Parsed source totals include 37,089 normalized eCAR rows across 23 host files, 19,272 Security XML events and 12,097 Sysmon events across ten Windows hosts, 3,991 syslog rows across eleven hosts, 317 macOS ES rows and five Unified Log rows across two Macs. The three Zeek sensor directories contain 38,626 rows across their supplied JSON log families. The visible network interval is approximately 13:00–19:00 UTC on November 2, 2026. These counts establish the examined scope; neither small Unified Log coverage nor selected Sysmon event-family coverage was penalized.

### Source-native macOS identity defect

The ES rows declare `schema_version=1`, message `version=11`, and process events with numeric types 9, 11 and 15 corresponding to exec, fork and exit in their event unions. I evaluated these as ES notifications, not EDR network flow rows or authorization denials. Apple's ES documentation defines the union-specific child and target objects and distinguishes notifications from authorization requests. [Apple ES message model](https://developer.apple.com/documentation/endpointsecurity/es_message_t)

The finding concerns **new fork child allocation**, not the mistaken assumption that every process's version must exceed every other process's version whenever an old process appears. Repeated observations of an old process can legitimately carry a lower version. Here the low versions are attached to newly born children whose recorded start times match the later fork events.

| File, line | UTC fork time | New child PID | New child PID version | Global sequence |
|---|---|---:|---:|---:|
| MAC-MROSS-01 ES, 75 | 16:00:08.553321 | 64190 | 88 | 74 |
| MAC-MROSS-01 ES, 77 | 16:02:01.753084 | 64367 | 70 | 76 |
| MAC-MROSS-02 ES, 34 | 13:42:47.073295 | 21882 | 42 | 33 |
| MAC-MROSS-02 ES, 38 | 13:47:08.148869 | 22291 | 39 | 37 |
| MAC-MROSS-02 ES, 114 | 17:12:27.393377 | 52334 | 116 | 113 |
| MAC-MROSS-02 ES, 117 | 17:19:16.577170 | 53019 | 94 | 116 |

Within each example, Mach time advances too. Thus source clock steps and file sorting do not explain the backward allocator values. An intervening reboot would not preserve an uninterrupted increasing Mach-time relationship and the same launchd start-time context. A 32-bit allocator wrap is not a credible explanation for repeated small backwards excursions interleaved with the surrounding low values.

The allocator rule is visible in both Apple's current XNU code and its fixed `xnu-11215.41.3` version: `forkproc` sets the new child's `p_idversion` from the shared atomic counter. This is a process-identity semantic invariant, not a guessed missing event requirement. [Apple fixed-version XNU source](https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-11215.41.3/bsd/kern/kern_fork.c)

As an alternative explanation, a sanitizer might have deliberately remapped PID versions using a nonchronological scheme. The files do not disclose such a transformation. That possibility limits verdict confidence; it does not make the supplied native-shaped identity values internally convincing. I have not used the mere presence of low values, sequential ES client counters, or complete process companions as separate score penalties.

### Twenty concrete record spot checks

Paths in this table are relative to the supplied data directory; XML line numbers identify the opening `<Event>` line. `D1` means `DC-01.meridianhcs.local`, `FS` means `FILE-SRV-01.meridianhcs.local`, and `M1` means `MAC-MROSS-01.meridianhcs.local`.

| # | Record | Fields and result |
|---:|---|---|
| 1 | D1 Security XML:3, 5156 | Decimal `ProcessID=2420`, inbound direction token, UDP protocol 17, device-form DNS image path and source/destination tuple are coherent. |
| 2 | D1 Security XML:240, 4624 v2 | NETWORK SERVICE, SID `S-1-5-20`, reserved logon ID `0x3e4`, service Type 5 and no remote IP are coherent. |
| 3 | D1 Security XML:295, 4672 | Subject session `0x3e4` and NETWORK SERVICE privileges follow the preceding service logon. |
| 4 | D1 Security XML:494, 4624 v2 | NTLM V2, key length 128, Type 3 and IPv4-mapped remote address are internally consistent. |
| 5 | D1 Security XML:549, 5140 | NETLOGON share and SYSVOL scripts local path agree; session and remote port agree with record 4. |
| 6 | D1 Security XML:588, 4634 | The same account, SID, session ID and Type 3 close after access. |
| 7 | D1 Security XML:1556, 4688 v2 | Hex new PID `0xe80`, creator PID `0x930`, parent process name, target-subject fields and mandatory label are populated in the expected shape. |
| 8 | D1 Security XML:1599, 4689 | PID `0xe80`, matching image and success exit status close that process. |
| 9 | D1 Security XML:1675, 4769 | Computer-account target, service machine account, AES ticket type `0x12`, mapped client IP and status `0x0` form a plausible service-ticket event. |
| 10 | D1 Security XML:4121, 4768 | `krbtgt`, domain SID with RID 502, preauthentication type 2 and AES ticket type are coherent. |
| 11 | D1 Security XML:151420, 4625 | Failure keyword is `0x8010000000000000`; disabled-account substatus `0xc0000072` accompanies network logon failure. |
| 12 | D1 Security XML:185773, 4697 | Service `PSEXESVC`, `%SystemRoot%\PSEXESVC.exe`, type `0x10`, demand start 3 and LocalSystem agree. |
| 13 | FS Security XML:228, 5145 | Share `Users`, local path `D:\Users` and relative target `Documents\checklist-draft.txt` agree with the next handle request. |
| 14 | FS Security XML:273, 4656 | Handle `0xfed56f79`, PID 4 and read-oriented access mask `0x120089` are coherent; line 322 closes the same handle. |
| 15 | D1 Sysmon XML:846, Event 1 | Decimal PID, braced process/parent GUIDs, hash formats, user, session and integrity fields are structurally coherent. |
| 16 | D1 Sysmon XML:594, Event 10 | Source/target `GUID` capitalization differs correctly from Event 1's `Guid`; IDs, granted-access mask and stack trace are populated. |
| 17 | zeek-core/conn.json:1 | UDP DNS tuple, numeric ports, `SF` and history `Dd` are coherent; UDP `SF` is valid Zeek behavior. |
| 18 | M1 ES NDJSON:1, fork | The child initially inherits the parent's executable snapshot, carries its own child audit token and new start time; this is distinct from the later executed image. |
| 19 | M1 ES NDJSON:2, exec | Actor and target have the same PID with version 10→11, executable transition, argument vector, cwd and signing metadata. |
| 20 | M1 ES NDJSON:10, exit | Event type 15 contains exit status `stat=0` and the exiting `id` process's audit identity, not a fabricated authorization result. |

Microsoft's examples confirm the 4688 v2 creator/target and label shape and the 4697 service fields; the sampled system headers also match those examples. The native 1102 at D1 Security XML:273431 uses the Eventlog provider and `UserData/LogFileCleared` rather than an empty Security-Auditing EventData interpretation. [Microsoft 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688), [Microsoft 4697](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697), [Microsoft 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)

### Broader correlation and timing checks

For each Windows Sysmon stream, I checked available create/terminate GUID relationships against subsequent process-dependent rows, including case-normalized `SourceProcessGUID` and `TargetProcessGUID` fields. I found no process-dependent row preceding its visible create, following its visible terminate, or visibly spawning from a terminated parent. The analogous eCAR object/actor identity check across all 23 hosts likewise found no actor row before a visible process create or after a visible process terminate. This is bounded evidence of sound lifecycle handling, not proof of every possible process relationship.

For the supplied DNS, HTTP, SSL, SMTP and SMB families I checked same-sensor UID existence, all four tuple fields, and timestamp containment within conn intervals. There were zero missing/mismatched UIDs or tuples and zero interval violations in those checks. I also checked HTTP body sizes against responder stream bytes. TCP history/state and minimum header-byte sanity checks did not identify an obvious contradiction; retransmission and capture-gap cases were handled conservatively rather than forcing payload-equals-capture accounting. Zeek documents the distinction between sequence-derived payload bytes, observed IP bytes, and connection duration. [Zeek connection field definitions](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)

The ES `seq_num` values advance independently by event type while `global_seq_num` follows the combined stream, which is the documented distinction. Those working client counters do not repair the separate kernel process-version problem. [Apple ES sequence-number documentation](https://developer.apple.com/documentation/endpointsecurity/es_message_t/seq_num)

I do not claim every macOS version-11 field, signing entitlement, or export convention has been exhaustively certified. The tiny Unified Log selection and absence of other ES event types do not establish a collection contradiction. I found no additional issue strong enough to add a separate authenticity penalty.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Native-shaped macOS Endpoint Security process events | Both Mac files; explicit newly forked-child PID-version reversals at the lines listed above | Decisive source-native identity inconsistency, sufficient for the bottom of the 81–100 band despite otherwise strong telemetry. One defect family counted once. |

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON structures, Windows event-specific field names and native ES union shapes are generally convincing; the decisive problem is semantic identity allocation.
- **Temporal patterns:** 8 — Useful event jitter and coherent lifetimes; Mac child PID versions contradict the otherwise increasing native chronology.
- **Cross-source correlation:** 9 — Checked host process/session and Zeek tuple/reference relationships hold well; no broad correlation penalty is justified.
- **Behavioral realism:** 8 — Varied ordinary administration, process, authentication and network behavior; no score deduction for incident compactness or completeness.
- **Environmental consistency:** 9 — Windows, Linux, macOS and segmented network source roles are largely coherent within the visible collection scope.

## Recommendations

- If this were synthetic, allocate macOS audit-token PID versions at the actual host execution order through one shared host identity allocator, then propagate each resolved token into actor, target, parent and responsible-process snapshots. The explicit fork reversals above should disappear without changing valid process relationships.
- If this were sanitized real data, document any deliberate PID-version transformation and preserve the native allocation-order semantics when claiming native ES fidelity. Otherwise identity-aware detection tests can learn behavior the source platform would not emit.
- Add a source-semantic check over each Mac's newly forked children using event time, Mach time, start time and audit tokens together. Preserve the already effective process lifetimes, signing distinctions, and network/session relationships; the supplied evidence does not justify broad changes to source coverage.
