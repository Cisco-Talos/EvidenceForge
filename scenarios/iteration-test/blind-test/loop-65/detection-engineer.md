# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 67

## Executive Summary

The dataset is unusually competent at source formatting and identity correlation, and would generally ingest successfully into a detection stack. I nevertheless judge it likely synthetic because Windows session bootstrap repeatedly assigns different sessions to the same SMSS process instance, while Linux snapd messages repeatedly reuse tiny task numbers across unrelated changes; a narrow, host-parameterized irqbalance message pool provides additional, weaker support. These are specific ownership and distribution findings, rather than objections to comprehensive collection or an easily reconstructed intrusion.

## Evidence For Synthetic

- [contract_gap] **Per-session Windows process ancestry is flattened to one SMSS identity per host.** In `DC-02.meridianhcs.local/windows_event_sysmon.xml`, EventRecordIDs `1368912` (line 10812, `2026-11-02T13:28:18.0484663Z`) and `1369754` (line 33293, `14:25:35.1764688Z`) create `winlogon.exe` PIDs `7236` and `7552` for TerminalSessionIDs `5` and `6`. Both name parent PID `5072` and exactly the same ParentProcessGuid `{d55311aa-1fd0-6ad2-c100-000039590a46}`. The pattern extends to 24 Winlogon creations on six hosts with multiple visible sessions. Modern Windows uses a new SMSS instance to initialize each session. The finding concerns the visible parent identities, not absent SMSS records.
- [contract_gap] **snapd task identity appears to reset to a small ordinal for every change.** `LOG-MON-01.meridianhcs.local/syslog.log` line 22 reports `change 2393 task 9 done for snapd-desktop-integration`, line 92 reports `change 2398 task 9 done for lxd`, and line 165 reports `change 2408 task 9 done for microk8s`, all from snapd PID `23765`. Across ten hosts, all 137 matching task-completion messages use task numbers `1`–`9`, and every host reuses a task number across changes. Native snapd task IDs are allocated from a state-wide increasing counter, independently of change IDs. A custom exporter could label change-local ordinals this way, but the records present themselves as native `taskrunner.go:271` messages and provide no such distinction.
- [distribution_texture] **irqbalance noise has a very small, fixed parameter set despite substantial volume.** All 80 irqbalance records on LOG-MON reduce to four exact message strings; all 23 balancing-completion messages say `NUMA node 0: balancing pass complete, 2 IRQs moved`. Examples occur at lines 26 (`13:07:29.711370Z`), 39 (`13:13:39.961631Z`), 63 (`13:18:34.436048Z`), and 101 (`13:43:53.867716Z`). FILE-LNX has 84 records/four strings and WEB-EXT 109/four strings, likewise with fixed IRQ/device/CPU and fixed completion count per host. Repetitive daemon diagnostics are possible, so this receives substantially less weight than the identity findings.

## Evidence For Real

- Windows records preserve useful native distinctions: Security PIDs are hexadecimal where appropriate, Sysmon PIDs are decimal, local service logons use absent network endpoints, domain ticket clients use IPv4-mapped IPv6, and failure events use audit-failure Keywords. For example, DC-01 Security record `28245289` has Type `5`, NETWORK SERVICE SID `S-1-5-20`, LUID `0x3e4`, `Advapi`, and `IpAddress=-`; record `28245407` uses the native NTLM package name `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`.
- Visible process causality generally survives identity-based checks. Across all ten Sysmon exports, I found no use of a visibly created ProcessGuid before its create or after its visible termination, no child created after its identified parent's visible termination, and no PID/image disagreement for a ProcessGuid with a visible creation. Across all 23 eCAR exports, actor references likewise produced no activity before the actor's visible process creation or after termination under the same object identity.
- Zeek references and transport accounting behave credibly. Within each sensor, the inspected DNS, HTTP, SSL, SMTP, and SMB records resolve to conn UIDs with matching tuples and timestamps inside their transport intervals, allowing a small timestamp tolerance. File direction agrees with `is_orig` and conn endpoints, observed file bytes do not exceed the corresponding transport direction's byte total, and HTTP body lengths fit transport byte counts.
- TLS visibility reflects encryption constraints: the supplied TLS 1.3 rows do not advertise certificate file chains, while ordinary full TLS 1.2 handshakes can link SSL → files → X.509. For example, `zeek-dmz/ssl.json` line 1 has TLSv13, `ssl_history=Cs`, and no certificate chain; line 2 has TLSv12 and two chain FUIDs. This is consistent with Zeek's description of passive TLS visibility. [Zeek SSL log documentation](https://docs.zeek.org/en/current/reference/logs/ssl.html).
- macOS records distinguish fork, exec, and exit, carry actor/target audit tokens and PID versions, and retain a separate Unified Log view. The kernel's policy message does not by itself establish denial, and the ES notification result is not evidence that execution was authorized by the logger. I found no demonstrated macOS native-schema contradiction in the sample examined.

## Detailed Analysis

### Scope, provenance, and method

I read the complete supplied detection briefing and examined only `/private/tmp/log-study-sucvw85x/data` for dataset evidence. Parsing used system Python with the explicit neutral working directory `/private/tmp/log-study-sucvw85x`. External reference checks were restricted to upstream/vendor documentation and repositories; no project files, scenario, TODO, worklogs, prior assessments, or other reviewer material were accessed. Inherited general operating instructions were not treated as evidence of origin.

I parsed 19,234 Security XML records and 11,972 Sysmon XML records across ten Windows hosts, 36,352 eCAR JSON records across 23 hosts, and the supplied Zeek families across three sensors. I also parsed both macOS ES exports (374 records total), both Unified Log exports (five records total), and inspected Linux syslog, histories, ASA, and IDS records. The slice covers November 2 activity, approximately 13:00–19:00 UTC. This was a structured record and relationship review, not packet-level validation or proof that every optional source field was present.

XML citations below point to the EventRecordID line inside the relevant event. JSON and syslog citations use physical one-based lines. Paths are relative to the supplied data directory.

### Twenty representative record checks

`DC-S` below means `DC-01.meridianhcs.local/windows_event_security.xml`; `DC-Y` means the corresponding `windows_event_sysmon.xml`; `FS-S` means `FILE-SRV-01.meridianhcs.local/windows_event_security.xml`.

| Record | Location | Fields and result |
|---|---|---|
| Security 5156 | DC-S:15, record 28245268 | Inbound UDP/53; decimal ProcessID `2420`; device application path; inbound WFP layer fields. Plausible native shape. |
| Security 4769 | DC-S:179, record 28245285 | Computer account `DC-02$`, service `DC-01$`, AES type `0x12`, mapped client address, hexadecimal status. Plausible v0 TGS shape. |
| Security 4768 | DC-S:218, record 28245286 | `krbtgt`, RID 502 service SID, PreAuthType `2`, empty certificate fields. Plausible password-based TGT request. |
| Security 4624 | DC-S:260, record 28245289 | Type 5 NETWORK SERVICE, LUID `0x3e4`, no remote IP/port. Correct service-logon semantics. |
| Security 4672 | DC-S:315, record 28245290 | Same NETWORK SERVICE SID/LUID and service-appropriate privilege names. Correct nearby correlation. |
| Security 4688 | DC-S:596, record 28245308 | Version 2, hex PID `0xcd4`, SYSTEM subject, null target identity, system mandatory label. Parses coherently. |
| Security 4689 | DC-S:639, record 28245310 | Exit status `0x0`, hex ProcessId `0xcc0`, Winlogon image. No malformed field type. |
| Security 4776 | DC-S:1689, record 28245407 | Native package name, target machine account, workstation, status `0x0`. Suitable for NTLM detections. |
| Security 4634 | DC-S:2169, record 28245432 | Target identity/LUID and Type 10 fields; no inappropriate 4624-only fields. Window-boundary initiators remain neutral. |
| Security 4648 | DC-S:19363, record 28246454 | Explicit `svc_backup` credentials, Veeam caller process, target-server fields and source endpoint. Plausible explicit-credential shape. |
| Security 5145 | FS-S:991, record 271811 | Share `\\*\Users`, relative file path, hex access mask and localized resource tokens. Plausible share-access event. |
| Security 4656 | FS-S:1036, record 271812 | Handle `0xd72bd2b0`, System PID `0x4`, local object path derived from the share path. Coherent handle-open shape. |
| Security 4658 | FS-S:1085, record 271814 | Same handle and process as the nearby open. Correct handle-close fields. |
| Sysmon 1 | DC-Y:448, record 3288920 | Decimal PID, brace GUIDs, millisecond UtcTime, image hashes and parent identity. Parses correctly. |
| Sysmon 10 | DC-Y:173, record 3288912 | Native `SourceProcessGUID`/`TargetProcessGUID` capitalization, thread ID, hex GrantedAccess and CallTrace. Suitable for process-access parsing. |
| Zeek conn | `zeek-core/conn.json`:1 | Numeric ports and epoch time; UDP DNS `Dd`, one packet each way; IP bytes exceed payload by 28 bytes each. Coherent IPv4/UDP accounting. |
| Zeek DNS | `zeek-core/dns.json`:2 | SRV query, numeric and text type/rcode, parallel answers/TTLs; UID/tuple match its conn record. |
| Zeek HTTP | `zeek-core/http.json`:1 | CONNECT authority URI, 200 Connection Established, zero body lengths, proxy destination port 8080. Plausible explicit-proxy transaction. |
| macOS ES exec | `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`:2 | Declared message version 11; event_type 9; distinct pre-exec process and xpcproxy target; PID stable, pidversion advances 10→11. No demonstrated shape error. |
| macOS Unified Log | `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson`:2 | Kernel writer PID 0, AppleSystemPolicy sender image, numeric placeholders and rendered message; policy warning interpreted separately from execution outcome. |

The ES version and exporter-specific output are important limitations: Apple's documentation explicitly warns that eslogger output changes with software updates. I did not infer a native schema failure from unfamiliar fields or impose normalized EDR FLOW requirements on ES rows. [Apple's eslogger overview](https://developer.apple.com/videos/play/wwdc2022/110345/).

### Windows session ancestry: the principal ownership finding

On DC-02, four Winlogon creations for sessions 5, 6, 7, and 8 share parent PID 5072 and the same ParentProcessGuid. On DC-01, six creations for sessions 6, 7, 8, 2, 9, and 10 share parent PID 2228 and ParentProcessGuid `{83eb9c06-a054-6ae0-6700-0000016d5d7c}`. DC-01 records `3289314` at line 14154 and `3290217` at line 44702 are a reproducible pair. FILE-SRV, MAIL-FIN, WS-AJOHNSON, and WS-EBROOKS show the same per-host reuse pattern.

Microsoft's session architecture describes the initial SMSS creating a new SMSS instance for each session, with that instance creating its session's CSRSS and Winlogon. Consequently, using the same exact parent process identity across these new session bootstraps is a substantive ancestry inconsistency. This is an inference from visible parent/session fields against the documented architecture, not a claim that the slice must contain every SMSS creation. [Microsoft session architecture](https://techcommunity.microsoft.com/blog/askperf/ws2008-terminal-services-architecture/372783).

The same ancestry appears in eCAR: DC-02 `ecar.json` lines 363 and 1130 assign Winlogon PIDs 7236/session 5 and 7552/session 6 the same parent actor UUID `98e8d999-1a15-4959-9ea9-0a7505459c67`. Agreement between sources therefore preserves this ownership issue rather than resolving it.

Other parts of the bootstrap are substantially better. DC-02 Winlogon creation occurs at `13:28:18.0484663Z`, Security 4624 record `25378220` follows at `13:28:19.3032172Z` with caller PID `0x1c44` (=7236), userinit follows at `13:28:20.8495827Z`, and Explorer follows at `13:28:23.5831085Z`. Their user LUID is `0xcb8b292`. I did not score these valid relationships as suspicious completeness.

### Linux task identities and low-entropy daemon messages

The snapd examples repeat `task 9` across five different changes on LOG-MON, for different snaps, with the same daemon PID. More generally, the 137 completion rows span ten hosts yet their task-number vocabulary never exceeds nine. Canonical's implementation increments `lastTaskId` in `State.NewTask`, while `NewChange` maintains a separate change counter; tasks retain an association with a specific change. The logged pattern is inconsistent with treating these numbers as native task IDs. [Canonical task allocation implementation](https://raw.githubusercontent.com/canonical/snapd/master/overlord/state/state.go), [Canonical task structure](https://raw.githubusercontent.com/canonical/snapd/master/overlord/state/task.go).

There is an uncertainty here: the exact snapd release is not declared, and a customized diagnostic could print a change-local ordinal rather than the native identifier. I therefore classify this as a contract gap with a clear alternative explanation, rather than an absolute hard contradiction or a claim that the current upstream source line number must match the host's build.

The irqbalance distribution independently resembles a finite message pool. LOG-MON's four strings occur 23, 22, 20, and 15 times. FILE-LNX's four occur 24, 21, 20, and 19 times; WEB-EXT's four occur 34, 28, 28, and 19 times. Fixed device configuration can legitimately make diagnostics repetitive, but the combination of sizable volume, four strings per host, and invariant completion counts across repeated passes reduces the texture of this source family. It is a supporting signal only; I did not infer omitted Linux facilities or require additional source coverage.

### Network, timestamp, and lifecycle checks

The Zeek conn files contain 12,286 core, 9,634 DMZ, and 485 DB records, with a mix of established, rejected, reset, incomplete, and one-sided observations. I checked protocol companions against sensor-local conn maps, not global UIDs across different sensors. There were no tuple mismatches or absent conn references in the checked DNS/HTTP/SSL/SMTP/SMB families, and no protocol timestamps before conn open by more than 5 ms or after close by more than 100 ms.

All examined file-transfer directions matched their conn endpoints. Observed file payload totals stayed within the corresponding conn direction's payload accounting; request and response body lengths also fit the HTTP flows. DNS answers had appropriate IP address families for A/AAAA and matching answer/TTL lengths. These are meaningful detection-quality strengths, not evidence that the data is synthetic because it matches well.

I treated cached Kerberos tickets, pre-window process/session initiators, and post-window survivors conservatively. For example, a TGS before a nearby TGT for the same user does not establish impossible ordering when an earlier cached TGT can exist. Repeated well-known service LUIDs `0x3e7`, `0x3e4`, and `0x3e5` were not treated as newly allocated interactive session IDs.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Sysmon and eCAR Windows process ancestry | 24 Winlogon creations on six hosts with multiple sessions | Highest weight: exact parent identity reused across session-specific SMSS bootstrap boundaries. |
| contract_gap | Linux snapd syslog | 137 completion rows on ten hosts, task vocabulary 1–9 | Moderate weight: native task identity allocation conflicts with apparent per-change ordinal reuse; custom diagnostics remain an alternative explanation. |
| distribution_texture | Linux irqbalance syslog | Recurrent three/four-message pools; prominent on LOG-MON, FILE-LNX and WEB-EXT | Supporting weight: fixed host parameters and completion counts over many messages; ordinary daemon repetition limits certainty. |

No generator identity leak, impossible visible same-ProcessGuid lifecycle ordering, or demonstrated macOS native-schema failure was found. The score is in the “likely synthetic” range because the substantive findings recur across hosts, while the bulk of the records retain strong field and transport consistency.

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON fields, numeric representations and source-specific timestamp precision generally support direct parsing; task-number semantics warrant scrutiny.
- **Temporal patterns:** 9 — Visible process and network relationships generally respect lifecycles, with source timing differences rather than indiscriminate equality.
- **Cross-source correlation:** 8 — Transport, process and session identities mostly align, but Windows session-parent ownership is coherently wrong in two sources.
- **Behavioral realism:** 7 — Most activity is credible; repeated daemon message pools and task-number patterns constrain realism.
- **Environmental consistency:** 8 — The observed roles and routing are broadly plausible; repeated Windows bootstrap ancestry is the principal platform-consistency defect.

## Recommendations

- If this were synthetic, allocate the session-specific SMSS parent identity when constructing each Windows session bootstrap. Preserve that identity in both Sysmon and eCAR; correcting only the image name or numeric PID would leave the GUID/UUID ownership defect.
- If this were synthetic, allocate snapd task identities from host-persistent task state independently of change IDs, and keep each task's change and snap association stable. If the intended value is an ordinal, label and document it as such instead of presenting it ambiguously as a native task identifier.
- If this were synthetic, derive irqbalance diagnostics from changing IRQ affinity/load and actual balancing decisions, or use a quieter collection profile. The concrete target is the four-string/high-volume/invariant-result pattern, not adding arbitrary unrelated noise.
