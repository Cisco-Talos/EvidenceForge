# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 83
**Synthetic-Confidence Score:** 38

## Executive Summary

Most supplied telemetry should parse and correlate credibly in a SIEM. I found a small Windows native-schema extension and some questionable repeated command behavior, but no demonstrated impossible lifecycle or network accounting relationship in the automated checks; these findings do not justify a confident synthetic verdict.

## Evidence For Synthetic

- [schema_or_format] `FILE-SRV-01.meridianhcs.local/windows_event_security.xml:7943–7978`, EventRecordID `272101`, presents Event 4658 version 0 with an additional `EventData/ProcessName=System` field at line 7974. The native 4658 v0 event payload ends with `ProcessId`; the process name is normally an enrichment rather than a field from that event's native payload. All 38 supplied 4658 records carry this extra field. This suggests a reconstructed/enriched representation, although enrichment of authentic logs is an alternative explanation and this would not generally break name-based parsing.
- [weak_signal] Repeated Mac file-reading behavior warrants scrutiny: `MAC-MROSS-01.../macos_endpoint_security.ndjson` lines 61, 65, 78 and 103 execute `/bin/cat` against mounted-volume files; lines 61, 65 and 78 name `.xlsx` or `.pdf` files. `MAC-MROSS-02.../macos_endpoint_security.ndjson` lines 48, 103, 112, 150 and 161 show the same `/bin/cat` pattern, including `.pdf` and `.xlsx` at lines 112 and 150. Five of these nine explicit `cat` executions target normally binary document formats. This is unusual as routine document consumption, but it can occur during shell-based inspection, automation or malicious collection, and the files' actual contents are unavailable. It carries little weight by itself.

## Evidence For Real

- Native Windows source distinctions are largely preserved. Event 1102 uses the Eventlog provider and namespaced `UserData/LogFileCleared`, rather than pretending to be a normal Security-Auditing `EventData` record (`DC-01.../windows_event_security.xml`, EventID at line 268429). Its EventRecordID resets to `1`, consistent with the reported clear.
- Authentication events distinguish service, network, interactive and unlock semantics. For example, `WS-EBROOKS-01.../windows_event_security.xml` has a Type 2 logon at `17:49:16.5789376Z`, lock at `18:01:24.4154522Z`, and Type 7 unlock at `18:53:49.8858568Z`, retaining LogonID `0xa5cf116`. Repeated logon identifiers here are not evidence of fabricated new sessions.
- Across all three Zeek sensors, the examined protocol records reference existing sensor-local connection UIDs and matching tuples. No tested HTTP, TLS, DNS, SMTP or SMB record fell substantially outside its connection interval.
- All tested Zeek connection byte totals fit their packet/IP-byte accounting bounds. File `seen_bytes` never exceeded the corresponding connection-direction payload total in the checked file records.
- The 747 matched WEB-EXT UFW-blocked TCP tuples all map to `S0` connections in `zeek-dmz/conn.json`; none mapped to an established `SF` connection. That is a useful positive check against a common cross-source contradiction.
- Mac endpoint records preserve fork/pre-exec/post-exec distinctions, audit-token PID versions, signing identity and executable file metadata. The first Terminal chain on MAC-MROSS-01 goes from launchd fork to xpcproxy exec to Terminal exec with PID `42171` and PID versions `10`, `11`, `12` (ES lines 1–3).
- Linux SSH records contain distinct connection, authentication and PAM session-open observations rather than collapsing those facts into one message. `FILE-LNX-01.../syslog.log:76–78` shows `13:34:09.530220Z` transport arrival, `13:34:10.637798Z` accepted public key, then `13:34:10.685521Z` session open for priya.patel, all PID `2679470`.

## Detailed Analysis

### Scope and method

I restricted inspection to the supplied data directory and used its raw XML, JSON/NDJSON, syslog and histories. I parsed the Windows XML rather than relying on text snippets, sampled more than twenty distinct Windows event IDs, inspected each present Sysmon family, checked both Mac ES streams, and ran relationship/accounting checks over the network records. I did not verify binary contents, consult project material or infer authenticity from copied filesystem timestamps.

The JSON files contain 73,711 records, in addition to native XML, text logs and 329 Mac ES notifications. The network connection population consists of 12,279 core, 9,287 DMZ and 464 database sensor rows. These are bounded observations, so missing initiators before the window, missing exits after it, and thin source coverage are neutral.

### Representative schema and field checks

The following are actual parsed examples, not assertions that every field of every event has been independently validated against a live vendor manifest. Host names below abbreviate the supplied `.meridianhcs.local` directories.

| Source/example | Fields examined and finding |
| --- | --- |
| DC-01 Security 4624, `13:00:22.7331903Z` | v2, Type 5, SYSTEM/S-1-5-18, `0x3e7`, Advapi, services.exe caller; no remote IP. Internally coherent service logon. |
| DC-01 Security 4672, `13:00:22.7458394Z` | Same SYSTEM LogonID; native multi-line privilege list. |
| DC-01 Security 5156, `13:00:57.9077322Z` | Decimal ProcessID `2420`, device-form application path, numeric protocol `17`, inbound direction token `%%14592`, UDP/53 target. |
| DC-01 Security 4768, `13:01:40.7220046Z` | Machine-account target, krbtgt service SID ending 502, hexadecimal options/status/encryption, IPv4-mapped IPv6 client. |
| DC-01 Security 4769, `13:01:40.7252215Z` | TGS follows sampled TGT; client address/port retained; service account `DC-01$`. |
| DC-01 Security 4688, `13:01:42.9596624Z` | v2, hexadecimal child and creator PIDs, parent image, token-elevation resource token, mandatory-label SID. |
| DC-01 Security 4689, `13:02:19.0122734Z` | Hexadecimal exit PID, status `0x0`, user SID/LogonID and process image. |
| DC-01 Security 4648, `13:07:17.1513339Z` | Caller SYSTEM/Veeam process, explicit target svc_backup, target server PROXY-01; source-address interpretation is plausible. |
| DC-01 Security 4776, `13:08:51.3917027Z` | Native package name, target username, workstation and status; no invented Kerberos ticket fields. |
| DC-01 Security 5140, `14:09:06.2457795Z` | SYSVOL share path, native `\\*\` share notation, subject LogonID and access mask. |
| FILE-SRV-01 Security 5145/4656/4663/4658, `13:59:21Z` | Share-relative path resolves to audited local file path; handle `0x6e8fb701` links open/access/close, ProcessID `0x4`. Extra 4658 ProcessName is the schema concern above. |
| WS-AJOHNSON-01 Security 4625, `13:31:46.1856281Z` | Type 2, `0xc000006d` with bad-password substatus `0xc000006a`, User32/winlogon and no remote address. |
| DC-01 Security 4697, `16:59:44.8958060Z` | PSEXESVC executable under SystemRoot, service type `0x10`, demand start `3`, LocalSystem. |
| DC-01 Security 4720/4724/4738/4728 | Creation/reset/change/group membership share svc_dirsync SID ending 8400; group SID ends 512 for Domain Admins. |
| DC-01 Security 4698, `17:19:55.0522831Z` | Embedded Task Scheduler XML has matching task URI, SYSTEM principal and executable action. |
| DC-01 Security 1102, `18:42:26.0007020Z` | Correctly distinct Eventlog provider, Level 4, namespaced UserData and record reset. |
| DC-01 Sysmon 1/5/10/22 | Child/parent GUIDs, numeric PIDs, user identities, query fields and access rights use recognizable native shapes. |
| DC-01 Sysmon 8/11 | Remote-thread source/target GUID identities and file-create target/time fields are differentiated correctly. |
| Core Zeek `conn.json:1`, `dns.json:1`, `http.json:1` | Numeric times/ports, Boolean flags and source-specific fields have suitable JSON types. CONNECT response has zero HTTP entity body, which is compatible with tunneled payload accounting elsewhere. |
| Core Zeek `ssl.json:3`, `files.json:2`, `x509.json:1` | Certificate FUID is shared; X.509 fingerprint matches the file SHA1; connection UID references and endpoints agree. |

### Lifecycle and correlation checks

For every Windows Sysmon file, I indexed visible process creates and terminations by ProcessGuid. Among the checked direct and source-process references, I found no occurrence before that same GUID's visible create or after its visible termination. Windows Security subject-LogonID checks likewise found no tested post-logoff use. These are useful positive checks, but do not prove every possible target-process, parent-process or session relationship.

The apparent repeated non-reserved LogonIDs on WS-MCHEN-01 and WS-EBROOKS-01 resolve to unlock events, not duplicated fresh Type 2 sessions. Reserved service identities `0x3e4`, `0x3e5` and `0x3e7` should also not be naively treated as ordinary session-ID collisions.

For Zeek I checked 2,294 core HTTP, 360 core TLS, 3,039 core DNS, 67 SMTP, 218 SMB-file and 126 SMB-mapping records, plus 19/17/40 HTTP/TLS/DNS database records and 2,512/2,729/914 DMZ records. All had sensor-local connection references with matching endpoint tuples. The interval check allowed 100 ms early and 500 ms late tolerance rather than equating independent source timestamps exactly. DNS answer/TTL lengths matched, with no NXDOMAIN rows containing answers in the checked records. I do not treat this extensive agreement as a synthetic indicator.

### macOS and source interpretation

The native Mac ES rows declare message version 11 and are notifications (`action_type=1`). I treated their action results as notification context, not independent proof of an authorization decision. Fork/exec/exit event types are separated and carry audit-token identities. No same `(pid,pidversion)` identity was observed after its exit or with conflicting executable/CDHash identity in the examined streams.

The Mac Unified Log rows have a different representation: wall-clock strings with timezone offset, mach timestamps, boot UUIDs, writer/sender image information and formatted messages. I did not impose normalized eCAR FLOW semantics on these rows. In particular, MAC-MROSS-01 Unified Log line 2 says an AppleSystemPolicy policy *would not allow* a MeetingAssist process; this alone does not establish a denied process later executing, and I did not score it as such.

The repeated `cat` use is the main behavioral reservation. Its native process records are entirely possible; the concern is the observed mix of document extensions and repeated command choice, not a claim of impossible execution. There is no binary-content evidence to establish whether those files really contain Office/PDF data.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
| --- | --- | --- | --- |
| schema_or_format | Windows Security 4658 v0 | 38 file-handle-close events on FILE-SRV-01 | Small but concrete deviation from native payload shape; could be collector enrichment. |
| weak_signal | macOS ES command behavior | Nine mounted-file cat executions across two Macs, five aimed at normally binary document formats | Slight concern about activity vocabulary; not a contradiction and readily explainable by inspection/automation. |

No high-impact hard contradiction was established. The score remains in the mostly realistic/minor-artifact band; uncertainty about provenance remains substantial.

## Realism Score by Category

- **Field format accuracy:** 8 — Broad native compliance; the 4658 payload includes an apparent enrichment field.
- **Temporal patterns:** 9 — Examined process, authentication, protocol and SSH ordering are compatible with source timing.
- **Cross-source correlation:** 9 — Checked UIDs, tuples, file byte bounds and blocked-flow states agree; checks were not exhaustive for all relationship types.
- **Behavioral realism:** 7 — Plausible administrative and application activity, with an unusual repeated binary-document cat pattern.
- **Environmental consistency:** 9 — Roles, routing and host-native representations generally agree in inspected records; sparse sources are not penalized.

## Recommendations

- If this were synthetic, keep Event 4658 v0's native EventData payload limited to its native fields. Put a resolved process name in an explicitly normalized/enrichment representation.
- If this were synthetic, make mounted-document access follow the actual intended activity. Human document reading should produce the relevant application or renderer activity; shell inspection may legitimately use cat, but its selection should reflect the actual file content and purpose rather than document extensions alone.
- Preserve the demonstrated transport/auth separation, GUID lifecycle consistency, source-native log-clear representation and network byte accounting. No addition of otherwise uncollected sources is required by these findings.
