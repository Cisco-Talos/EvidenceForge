# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 91
**Synthetic-Confidence Score:** 84

## Executive Summary

The data is highly usable for detection engineering: the XML and JSON parse, Windows schemas are largely faithful, process identities correlate, and network protocol records retain coherent connection tuples. My synthetic verdict rests primarily on native macOS process-generation identities moving backwards across newly created processes, reinforced by repeated exact one-millisecond process handoffs; it does not rest on the suspicious activity's completeness or narrative shape.

## Evidence For Synthetic

- [hard_contradiction] In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, newly forked children's native `audit_token.pidversion` values repeatedly move backwards in creation time. Line 1 creates PID 19775, version 31, at `13:20:29.875707`; line 3 creates PID 21356, version 10, at `13:37:11.846603`. A second, particularly clear example is line 79, PID 41975/version 88 at `15:25:40.506474`, followed by line 86, PID 44280/version 72 at `15:48:46.208061`. Both of the latter children come from the continuing PID 21359/version 19 shell. Each child's `start_time` agrees with the later event time. Eight backwards transitions occur across the host's 57 fork notifications. This contradicts XNU's shared incrementing process-generation counter unless an undocumented identity remapping transformed the export. [Apple XNU fork implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_fork.c).
- [distribution_texture] The same Mac has seven shell handoffs exactly `0.001000` seconds after a previous child exits, despite reporting microsecond-resolution timestamps and variable fork-to-exec delays. Examples are exit/fork line pairs 18/19 (`13:37:33.139751` / `.140751`), 21/22 (`.437983` / `.438983`), 24/25 (`.499775` / `.500775`), 85/86 (`15:48:46.207061` / `.208061`), 88/89, 94/95, and 97/98. This has the texture of a fixed scheduling floor, not simply a reasonable shell wait relationship. It is supporting evidence, not an impossibility in isolation.

## Evidence For Real

- All 19,411 Security and 12,058 Sysmon events parsed as XML; all supplied JSON/NDJSON records parsed. The 37,394 eCAR rows have coherent object/action structure and source-appropriate normalized fields.
- Across 1,000 nearby Security 4688 / Sysmon 1 process pairs matched by host, PID and a two-second window, parent PID and image agreed in every matched pair. This is useful evidence of consistency, without treating completeness itself as suspicious.
- A GUID-based Sysmon lifecycle check found no dependent or parent references more than one second before their visible creation or after visible termination. eCAR's corresponding object/actor-ID check likewise found no such one-second violations across its 23 host files. These are bounded checks, not proof that every source detail is correct.
- All 4,196 DNS, 4,713 HTTP, 3,041 SSL and 79 SMTP rows joined to a `conn.json` UID on their own sensor. Endpoint tuples matched, and protocol timestamps were within the checked connection interval (10 ms early tolerance / 500 ms late tolerance).
- Zeek's packet accounting has meaningful imperfections: `missed_bytes`, gap flags, retransmission flags, failed connections, and ICMP records are present. Apparent minimum-header deficits disappeared when connections with missed bytes were excluded, so those were not scored as impossible packet accounting.
- Security event 1102 uses its own provider/UserData shape and starts a new record-number sequence. The remaining log slice is consistent with a pre-clear export followed by later collection, rather than mechanically requiring that old rows disappear.
- macOS ES rows distinguish fork, exec and exit; exec keeps the PID while changing image identity, and GUI launch chains include `launchd`, `xpcproxy`, terminal/login and shell stages. Unified Log rows use their own writer/message representation instead of pretending to be ES notifications.

## Detailed Analysis

### Input provenance, boundaries and qualifications

I read the supplied neutral briefing and the 117 files beneath `/private/tmp/log-study-0sx5q8_q/data`. Parsing used system `python3` with `/private/tmp` as the explicit working directory, using only standard-library readers and read-only data access. Logged commands were treated as inert strings. I did not access project files, source code, scenarios, TODO/worklogs, neighboring assessment material or prior results. Generic project-oriented instructions were inherited environmental context and were not used as evidence of origin.

Public lookups used actual domain restrictions for Microsoft Learn, Apple Developer and Zeek documentation, or direct official Apple upstream source URLs. The scored source-semantic finding uses Apple's XNU implementation, not third-party reverse engineering. No task-project public material was consulted or exposed. I inspected current upstream source; the dataset declares ES message version 11 but does not independently declare an exact macOS build. Thus I do not claim an exhaustive build-specific ES schema certification. An undocumented transformation of native identity values would weaken the native-counter finding; the supplied collection context does not describe one.

Missing pre-window initiators and post-window terminations were neutral. I did not penalize absent Sysmon event types, thin Unified Log coverage, fully correlated evidence, sanitized domains, record-file modification times, attack linearity, absence of mistakes, or narratability.

### Windows schema and detection parsing

Security contains 28 event IDs. Its principal volumes are 12,577 WFP 5156, 2,072 Kerberos 4769, 1,004 process-create 4688, 832 process-exit 4689, 828 successful-logon 4624, and 789 TGT 4768 events. Sysmon contains 8,083 network events, 1,235 DNS queries, 1,001 process creates, 843 process exits, and smaller access, image-load, registry, file-create and remote-thread groups. These counts alone are not an authenticity indicator.

The following spot checks cover 20 event shapes. XML citations name the line where the corresponding `<Event>` starts; all times are UTC on 2026-11-02. “Pass” means the inspected fields were consistent with the event's expected semantics, not that every possible Windows build was validated.

| Source / event | Reproducible example | Field check and result |
|---|---|---|
| Security 5156 v1 | DC-01, line 3, 13:00:07.5257163 | Decimal `ProcessID=2420`, device path for dns.exe, UDP protocol 17, inbound direction and DNS tuple; pass. |
| Security 4769 v0 | DC-01, line 167, 13:00:54.3867357 | Service account `DC-01$`, service SID, ticket options/encryption and mapped IPv4; previous-version shape is coherent. |
| Security 4768 v0 | DC-01, line 368, 13:01:28.2103308 | `krbtgt`, RID 502 service SID, successful status and preauth type 2; pass. |
| Security 4688 v2 | DC-01, line 1023, 13:02:58.1951694 | Hex PID 0xe78, parent 0x91c, target fields and mandatory label; pass. |
| Security 4689 v0 | DC-01, line 1107, 13:03:10.9108534 | Same PID/image and SYSTEM session as create; pass. |
| Security 4624 v2 | DC-01, line 2866, 13:07:15.9751026 | Type 3 Kerberos machine logon, LUID 0x5382af7, full v2 flag/link fields; pass. |
| Security 4634 v0 | DC-01, line 3001, 13:07:19.0025931 | Same LUID, SID, account and type as the preceding logon; pass. |
| Security 4776 v0 | DC-01, line 3483, 13:08:24.4633269 | NTLM package, workstation and status fields; pass. |
| Security 4779 v0 | DC-01, line 12952, 13:16:05.9335231 | RDP session name, account, LUID and client address; pass. |
| Security 4672 v0 | DC-01, line 13935, 13:17:29.4324985 | NETWORK SERVICE SID, service LUID and privilege list; pass. |
| Security 4648 v0 | DC-01, line 21007, 13:26:35.3357955 | Separate subject/target identity, caller PID/path and target server; pass. |
| Security 4697 v0 | DC-01, line 178472, 17:00:00.0433845 | Service name, path, type, start type and account fields; pass. |
| Security 4724 v0 | DC-01, line 188823, 17:15:14.5692698 | Target SID and reset actor fields match the documented shape; pass. |
| Security 5145 v0 | FILE-SRV-01, line 97, 13:00:05.9658107 | UNC share, local mount path, relative filename and access mask; pass. |
| Security 4656 v1 | FILE-SRV-01, line 146, 13:00:05.9772321 | Handle 0x8a164b99, object path and requested access; pass. |
| Security 4663 v1 | FILE-SRV-01, line 199, 13:00:06.1459007 | Same handle/object, used access 0x2, before close; pass. |
| Security 4658 v0 | FILE-SRV-01, line 240, 13:00:09.7044242 | Matching handle and process identity; pass. |
| Security 4800 v0 | WS-AJOHNSON-01, line 24918, 17:37:18.3005450 | Account SID/LUID and SessionId 2; pass. |
| ES fork / exec | MAC-MROSS-01, lines 1–3, 13:07:32 | Forked child PID 42154 keeps PID through xpcproxy and Terminal execution; actor/target distinction is present. |
| ES exit | MAC-MROSS-01, line 10, 13:07:35.323806 | PID 42158/version 18 exits after its visible id execution; pass. |

Microsoft's [4624 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624), [5156 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156), [4724 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724), and [4800 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4800) support those source-native field checks. In particular, 4800 v0 can contain SessionId and 5156's documented XML uses a decimal ProcessID; neither is a defect.

All 2,072 4769 rows use version 0. Microsoft documents a newer version on patched Server 2016+ systems after January 2025, but also documents the previous version. Windows file-version strings do not establish patch state, and the exact server release/patch provenance is absent, so I did not score outdated Kerberos event versions. [Microsoft 4769 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769).

The 145 distinct populated SHA256 identities in inspected Sysmon 1/7 records did not associate one hash with multiple FileVersion values. Several legitimate binaries lack PE metadata, but the majority have detailed metadata; I did not extrapolate the missing examples into a dataset-wide deficiency.

### macOS process identity and timing

Apple describes the message's `process` as the actor and the event union as operation-specific information; it separately documents target identity and process audit tokens. Notification rows therefore need not be authorization requests. I did not treat `action_type=1` with an allowed-result field as an execution-policy defect, or the Unified Log “policy would not allow” message as proof of denied execution. [Apple message documentation](https://developer.apple.com/documentation/endpointsecurity/es_message_t), [Apple process documentation](https://developer.apple.com/documentation/endpointsecurity/es_process_t).

These are fresh `event.fork.child` identities, not observations of old parents. XNU atomically increases `nextpidversion` at new-process allocation. MAC-MROSS-02 instead shows 31→10, 22→20, 40→38, 38→36, 88→83, 83→72, 98→92, and 111→100 across chronological fork children. Continuing shell identity and increasing mach times exclude normal reboots for later reversals; these small values do not resemble counter wrap. This is decisive.

The seven exact millisecond exit-to-fork handoffs are a separate timing artifact. A shell may immediately launch the next command in a batch, so seriality itself is valid; the repeated identical microsecond difference is the issue. The 88-second `/usr/bin/id` lifetime on the other Mac could reflect directory-service blocking and was not scored as impossible.

### Zeek and normalized endpoint correlation

There are 22,509 connection records across the core, DMZ and DB sensors. Protocol UID joins described above passed. The histories include failed opens, retransmissions and stream gaps; failed connections were not incorrectly treated as necessarily established sessions. Zeek documents packet counts as observed wire packets and `orig_ip_bytes`/`resp_ip_bytes` as IP-level totals, so missing payload bytes can invalidate a simplistic header-budget comparison. [Zeek connection documentation](https://docs.zeek.org/en/lts/reference/logs/conn.html).

Two `zeek-core/smb_files.json` rows (153–154) reference UID `Cr7mRCkac27kS4mWeXo`, absent from that slice's conn file: SMB open/read for `10.10.1.32:61160 → 10.10.2.21:445` at epoch `1793639425.411423` / `.484617`. I did not score this as a gap: protocol activity can appear within a slice while a long-running connection's summary falls outside it. It is a qualification to the otherwise strong join results.

For Linux, `APP-INT-01/syslog.log` lines 3–6 show connection, accepted key, PAM session opening, and logind session creation with appropriately distinct times. Line 8 closes a different sshd PID/session, so it is not an early close of that newly opened session. Periodic sysstat jobs occurring 12 times over the visible six-hour interval are an expected schedule, not automatically a uniform-generation defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Native macOS Endpoint Security fork audit tokens | Eight backwards fresh-child generation transitions in 57 fork rows on MAC-MROSS-02 | Decisive source-native identity defect; places the score in the 81–100 band, subject to the explicit transformation/build qualification. |
| distribution_texture | Native macOS Endpoint Security process timing | Seven exact 1 ms exit-to-next-fork gaps on MAC-MROSS-02 | Additional fixed-floor timing texture; modest supporting weight. |

The 84 score describes apparent synthetic character. The separate 91 verdict-confidence figure describes my confidence that the supplied data is synthetic. The score is not an average of the realism ratings below: a localized native-identity contradiction can outweigh otherwise strong formatting and correlations.

## Realism Score by Category

- **Field format accuracy:** 8 — Native XML/JSON structures and most values are faithful; macOS fork-generation values are the material exception.
- **Temporal patterns:** 7 — Broadly coherent visible lifecycles, with repeated exact millisecond shell handoffs.
- **Cross-source correlation:** 9 — Strong process and protocol tuple integrity in the bounded checks.
- **Behavioral realism:** 8 — Credible application, maintenance, authentication and interactive activities; no deduction for narrative completeness.
- **Environmental consistency:** 8 — Host roles and platform-specific source shapes generally cohere; exact OS/collector build provenance remains unspecified.

## Recommendations

- If this were synthetic, allocate native macOS process-generation identities in actual chronological kernel creation order, and carry each resulting token through fork, exec, parent/responsible-token references and exit. Retain the existing actor/target distinction. Verify that newer fork children cannot acquire lower counter values in the same boot when their recorded start times are later.
- If this were synthetic, replace the repeated exact 1 ms shell scheduling floor with behavior appropriate to the execution mechanism: a batch may launch immediately with measured scheduling variation; interactive commands need input timing; background commands need independent lifecycle ownership. The issue is repeated fixed microsecond spacing, not the presence of orderly or successful activity.
- Preserve the existing correct Windows field conventions, typed JSON values, matching parent identities, source-specific delays and nontrivial Zeek histories while correcting those specific macOS defects.
