# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 46

## Executive Summary

The dataset is substantially more production-like than a simple collection of event templates: XML and JSON parse correctly, visible process identities remain coherent, and protocol companions fit their connection intervals. Repeated Linux daemon vocabulary and nonstandard Zeek service labeling are meaningful residual concerns, but neither establishes synthetic origin without knowing the deployment's logging configuration. I found no hard contradiction sufficient to confidently classify the whole dataset as synthetic.

## Evidence For Synthetic

- [distribution_texture] Linux IRQ logging repeatedly rotates through a very small message vocabulary across otherwise different systems. There are 538 `irqbalance` records across 11 hosts; for example, WEB-EXT-01 has 87 records comprising exactly four host-specific messages, with frequencies 26, 24, 22 and 15. LOG-MON-01 has 97 with four messages at frequencies 31, 23, 22 and 21. The recurring forms include `IRQ ... classified for CPU ... balancing on ...`, `IRQ ... affinity hint keeps vector on CPU ...`, `Skipping IRQ ...: banned by affinity mask ...`, and `NUMA node ...: balancing pass complete, ... IRQs moved`. The combination of narrow vocabulary and broad host deployment resembles a reusable background-message pool. Repetitive daemon logs are possible in production, so this is a texture concern, not an impossible-value finding.
- [schema_or_format] Kerberos connection records use the service label `krb` for both transport analyzers. In `zeek-core/conn.json`, 1,470 UDP and 636 TCP port-88 rows carry `service="krb"`; `zeek-db/conn.json` adds six UDP and three TCP examples, and the DMZ source adds one TCP example. Standard Zeek analyzer naming commonly distinguishes `krb_udp` and `krb_tcp`; the supplied taxonomy therefore deserves validation before using native-service predicates in detections. Customized analyzer names or an export normalization could explain this, so I do not classify the label alone as an impossible schema value.
- [contract_gap] The connection service field appears to retain a single application label even when another analyzer demonstrably produced records. All 56 core SMTP UIDs that also have an SSL record retain `service="smtp"` rather than exposing SSL alongside SMTP. Example: `CGM7wKi8qQBpK7C6MjF`, at `2026-11-02T13:08:53Z`, has SMTP `tls=true`, an established TLS 1.2 SSL record, and a connection labeled only SMTP. Zeek's service field normally reflects confirmed analyzers, but scripts can alter that field. This is a bounded source-profile inconsistency to investigate, rather than proof of missing TLS traffic or failed correlation.

## Evidence For Real

- All inspected Windows XML documents and the JSON/NDJSON records exercised by the analysis parse. Windows sources preserve source-specific capitalization such as Security `ProcessId` versus Sysmon `ProcessId` and WFP `ProcessID`, with the expected hexadecimal-versus-decimal representations.
- Across all ten Sysmon host files, the automated checks found no dependent event preceding the visible creation of its referenced process GUID and no dependent event following the visible termination of that GUID. For GUIDs with visible creation, PID and image references also agreed, including parent and injection/access references.
- The 37,414 normalized eCAR records include distinct process, session, file, registry, module and network shapes. Process objects checked by identity did not show termination-before-creation or later events on the same process object after its recorded termination.
- The three Zeek sensors contain 23,141 connection records with a meaningful range of `SF`, `S0`, `OTH`, reset, rejection and partial-close states. Their service distributions differ with apparent observation position: database traffic dominates the database sensor, while HTTP/TLS and unsuccessful inbound connections are prominent at the DMZ sensor.
- Matching protocol UIDs have consistent connection tuples. DNS RTTs fit their connection durations; checked HTTP bodies do not exceed corresponding connection payload bytes; and established SSL records do not attach to the explicitly failed connection states checked.
- DC-01's `1102` at `18:42:20.0702537Z` uses the Eventlog provider and namespaced `UserData/LogFileCleared`, not the Security-Auditing provider's ordinary `EventData`. Its record ID resets to `1`; later visible Security IDs are `10`, `13`, and `14`, following pre-clear ID `28261098`.
- The macOS exports distinguish ES notifications, Unified Log writer metadata, normalized endpoint records and shell histories. Visible ES fork/exec examples preserve PID while incrementing PID version across exec and changing executable/signing identity appropriately.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed Windows XML across ten hosts, the eCAR files, the three Zeek sensor families and their protocol companions, the macOS native exports, and representative Linux/proxy/firewall text records. Checks included visible process lifecycle order, GUID-to-PID/image agreement, selected logon relationships, connection/protocol tuple agreement, protocol timestamps, payload accounting, certificate-chain metadata consistency, and daemon-message distributions.

The connection timestamps span approximately `2026-11-02T13:00Z` through `19:00Z`. I treated this as a collection slice. A missing pre-window process or logon was not counted as a defect. Similarly, absence of another product's telemetry, selected Sysmon event types, or an optional protocol family was not penalized.

### Windows schema and event spot checks

The following checks sample more than twenty event types and source-native shapes. These are positive checks unless explicitly stated otherwise; they do not establish that every operating-system release-specific detail is perfect.

| Source and time on 2026-11-02, UTC | Record and fields checked | Result |
|---|---|---|
| DC-02 Security, 13:00:04.6195699 | 5156: decimal `ProcessID=5272`, NT-device `Application`, UDP `Protocol=17`, inbound `Direction=%%14592`, destination port 53 | Consistent with inbound DNS filtering-platform evidence. |
| DC-02 Sysmon, 13:00:04.6692736 | 3: same DNS PID, `Initiated=false`, source `10.10.1.31:49610`, destination `10.10.2.11:53` | Source fields and network direction agree. |
| DC-02 Security, 13:00:08.9498956 | 4776: `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, machine account and workstation `WS-DRAMIREZ-01`, status zero | Plausible NTLM credential-validation shape. |
| DC-02 Security, 13:00:27.0756073 | 4769: service account `DC-02$`, AES encryption type `0x11`, mapped IPv4 client address | Correct basic ticket-event field families and value types. |
| DC-02 Sysmon, 13:00:48.9197436 | 22: `QueryName=_kerberos._tcp.meridianhcs.local`, SRV-style result strings, status zero | Plausible DNS-query event shape; not confused with a process-start event. |
| DC-02 Sysmon, 13:01:05.0313067 | 5: spoolsv PID 5904 and process GUID | Termination shape is distinct from creation. |
| DC-02 Sysmon, 13:01:05.8754957 | 1: WmiPrvSE PID 6804, parent svchost PID 5116, command, hashes, SYSTEM logon ID and integrity | Fields are internally coherent; visible reference checks found no conflicting identity. |
| DC-02 Security, 13:01:05.9719627 | 4688: new PID `0x1a94` (6804), creator PID `0x13fc` (5116), version 2 target/mandatory-label fields | Correlates with the Sysmon process and uses native hexadecimal PID representation. |
| DC-02 Sysmon, 13:03:35.6937584 | 10: source/target GUIDs, PIDs, images, `GrantedAccess=0x1010`, call trace and users | Coherent process-access shape. |
| DC-02 Sysmon, 13:03:35.8585455 | 8: same source/target identities, new thread ID, start module and address | Properly distinct remote-thread semantics. |
| DC-02 Security, 13:04:44.0171612 | 4624: type 3, NTLM, `NtLmSsp`, `NTLM V2`, remote source `::ffff:10.10.1.34`, LUID `0xcb5c02d` | Consistent network logon fields. |
| DC-02 Security, 13:04:44.0918410 | 5140: same LUID and source tuple, SYSVOL share | Share evidence follows authentication. |
| DC-02 Security, 13:04:47.0513596 | 4634: LUID `0xcb5c02d`, same user and type 3 | Correct matching logoff within the visible window. |
| DC-02 Security, 13:06:22.9288926 | 4672: SYSTEM SID `S-1-5-18`, LUID `0x3e7`, privilege list | Appropriate special-privilege shape. |
| DC-02 Security, 13:22:14.0689810 | 4768: krbtgt, target SID, preauthentication type 2, mapped IPv4 address, empty certificate fields | Internally plausible password-based Kerberos request. |
| DC-02 Sysmon, 13:52:37.0171391 | 7: `ImageLoaded=...MpOAV.dll`, signed=true, signature status Valid, metadata and hashes | Distinguishes module identity from owning process identity. |
| DC-02 Sysmon, 14:24:10.6141263 | 11: Defender process, target detection-history path and creation timestamp | File-create shape is plausible. |
| DC-02 Security, 16:00:29.4769631 | 4771: status `0x18`, preauthentication type 2, failure audit keyword | Failure semantics are not rendered as success. |
| WS-PPATEL Security, 17:11:56.5878667 | 4625: type 2, User32/Negotiate, status `0xc000006d`, substatus `0xc000006a`, absent network address | Plausible local bad-password failure. |
| WS-PPATEL Security, 17:13:13.3257413 and 17:27:25.8412949 | 4800/4801: same principal, LUID `0xd9f40cf`, session ID 2 | Compatible lock/unlock pair. |
| DC-01 Security, 17:15:05.8149075 onward | 4720, 4724, 4738, 4728: account creation, password reset, change and group addition for SID ending 2188 | Consistent target identity and event-specific field families. |
| DC-01 Security, 17:19:47.7438924 | 4698: task name and embedded task XML with action executable | Embedded XML is represented as task content rather than invented top-level process fields. |
| DC-01 Security, 18:42:20.0702537 | 1102: Eventlog provider, namespaced UserData, record-ID reset | Correctly handles a significant special-case event. |
| FILE-SRV Security, 13:00:05.9658109 through 13:00:09.7044244 | 5145 → 4656 → 4663 → 4658: matching account/LUID, file path, handle `0xb013d0ff`, System PID 4 | File-access lifecycle is coherent; the access performed (`0x2`) is within requested `0x12019f`. |

The systematic Sysmon checks covered 927 process creations and 791 terminations, along with direct process, parent, process-access and remote-thread references in the supplied events. No visible same-GUID creation/end ordering or PID/image mismatch was found. These checks do not assume every referenced process began within the window.

Some apparent logon-before-process problems disappear on examining actual event type. For example, WS-DRAMIREZ's `0x970e485` has a visible 4624 at `18:55:45.7967551Z`, after earlier processes, but that record is **type 7 unlock**, not the original session creation. WS-AJOHNSON similarly reuses `0x254febf` in unlock records at `16:20:40.9385034Z` and `18:34:37.4967213Z`. Those are not causality defects. Well-known service LUIDs such as `0x3e7`, `0x3e4`, and `0x3e5` also require different treatment from newly allocated human logon IDs.

### Zeek correlation and detection behavior

I found no tuple disagreement between the checked protocol records and their same-sensor connection UID. Companion timestamps fit the connection intervals using a one-second tolerance at the end and a ten-millisecond tolerance at the beginning; DNS RTT and HTTP payload checks independently passed. Certificate metadata was consistent for repeated fingerprints, and supplied ordered certificate-chain subjects/issuers and CA flags did not contradict one another.

An example of useful native coherence is `CmN2OeyFuu5qT4yxIk`: DNS and connection records both use `10.10.1.31:49610 → 10.10.2.11:53`, with query `FILE-SRV-01.meridianhcs.local`, answer `10.10.2.20`, and RTT/connection duration `0.000678` seconds. Another is the SMTP/SSL example above: despite the service-label concern, the shared tuple and UID are preserved and TLS occurs during the connection.

One SMB mapping, `zeek-core/smb_mapping.json` line 93, has UID `C4bqaKVpaYQLPkuTrz` without a supplied connection record. Its timestamp is `1793640924.871449`, and the tuple is `10.10.1.22:59392 → 10.10.2.20:445`. I do **not** count this isolated missing row as evidence of synthetic origin: collection/export omissions are possible and it does not establish an impossible relationship.

The residual Zeek concerns are thus about native analyzer labeling and potential detection predicates, not UID integrity or mere completeness. A deployment normalization that deliberately writes `krb` and selects only the primary application service would substantially reduce their authenticity significance.

### Linux message texture and collection interpretation

The IRQ message pool is the clearest distribution concern. In `WEB-EXT-01.meridianhcs.local/syslog.log`, the recurring operational phrases form a narrow vocabulary. At `13:05:17.913312Z` the precise message is `NUMA node 0: balancing pass complete, 2 IRQs moved`. LOG-MON-01 repeatedly uses IRQ 137 and ens192; WEB-EXT-01 repeatedly uses IRQ 86 and mlx5_comp1; APP-INT-01 repeatedly uses IRQ 16 and ahci. The hardware tokens are host-specific, which is a positive detail, but the shared four-form construction remains conspicuous.

DB-PROD-01 adds 68 multipath messages to 62 IRQ records: `sda`, `sdb`, and `dm-0` cycle through `add missing path` and `remaining active paths: 1/2`. Such real errors can repeat, and this could be deliberately selected verbose logging. I therefore score the common message-pool texture moderately and do not claim that a noisy daemon, large count, or a particular missing daemon is independently a contradiction.

SSH, sudo, cron and Samba records have source-specific forms rather than all being generic key/value events. For example, DB-PROD-01's sudo record at `13:13:25.383320Z` has invoking user, TTY, working directory, target user and command, followed by PAM session open and close records. FILE-LNX-01's `13:15Z` Samba records distinguish authentication, share connection and open/read/close operations. These are useful positive source-native details.

### macOS interpretation

The ES exports declare message `version=11` and encode notification action type 1. I did not treat them as authorization denials. In MAC-MROSS-01's first records, launchd forks PID 25527 at `13:07:32.811343Z` with PID version 2482477; exec into xpcproxy keeps PID 25527 and advances PID version to 2482478; exec into Terminal advances it to 2482479. Actor and target executable identities are separately represented, with distinct signing identities and metadata. This supports meaningful exec-aware identity handling.

The Unified Log `ASP: Security policy would not allow process...` message at `15:42:09.009673+0000` is not, by itself, proof that execution was denied. I did not infer prohibited child execution from its wording. Unified Log rows include writer and sender paths/UUIDs, subsystem/category fields and boot/mach timestamps, while eCAR FLOW rows remain normalized network observations. Native macOS ES has only fork/exec/exit notifications here; I did not require an unadvertised file or network subscription merely because those event classes exist on the platform.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux syslog, irqbalance | 538 records on 11 hosts; several hosts reduce to four fixed message forms | Moderate upward influence; resembles a parameterized message pool, but verbose real daemons can repeat. |
| schema_or_format | Zeek connection service labels | 2,116 port-88 connections use `krb` across TCP and UDP | Small-to-moderate upward influence; deviates from common native analyzer taxonomy, with customization a credible alternative. |
| contract_gap | Zeek SMTP/SSL versus conn service field | 56 matching core SMTP/SSL UIDs show only `smtp` service | Small upward influence; analyzer-service representation needs configuration context. |
| hard_contradiction | All reviewed families | None established | No upward influence; prevents a high synthetic-confidence score. |

## Realism Score by Category

- **Field format accuracy:** 8 — Parseable, event-specific representations with plausible IDs, SIDs, paths, keywords and timestamps; Zeek service naming remains a concern.
- **Temporal patterns:** 8 — Visible process ordering and checked protocol intervals pass; repetitive background messages weaken texture.
- **Cross-source correlation:** 9 — Strong identity/tuple coherence and several verified lifecycle chains; SMTP service metadata has a bounded ambiguity.
- **Behavioral realism:** 7 — Varied connection outcomes and source-native administrative records, offset by the narrow common daemon vocabulary.
- **Environmental consistency:** 8 — Roles, sensor distributions and operating-system source shapes broadly agree; collection configuration is insufficiently known to resolve remaining ambiguities.

## Recommendations

- If this were synthetic, derive IRQ/multipath logging from an explicit daemon/version/configuration profile, including realistic debug verbosity and message transitions, instead of repeatedly selecting among four message forms across many unrelated hosts.
- If this were synthetic, preserve the intended native Zeek analyzer service names, including Kerberos transport distinctions, or consistently describe the output as normalized telemetry with the normalization contract available to detection authors.
- If this were synthetic, ensure conn service metadata reflects confirmed protocol analyzers for SMTP STARTTLS connections, unless an explicit source-profile transformation intentionally selects only a primary service. The existing UID, tuple and interval relationships should be retained.
