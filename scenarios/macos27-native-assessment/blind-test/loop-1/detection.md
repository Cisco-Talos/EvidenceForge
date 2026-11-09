# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 96
**Synthetic-Confidence Score:** 92

## Executive Summary

Most records parse correctly and carry credible endpoint identities, event versions, and cross-source references. Two independently verified Zeek field-semantics defects strongly support synthetic origin: TLS history loses direction across almost the whole SSL source, and 352 TCP connection histories repeat flags that native Zeek records at most once per direction. These are source-native contradictions, rather than judgments about narrative completeness, source selection, or suspicious activity.

## Evidence For Synthetic

- [hard_contradiction] **TLS history direction is wrong across the source.** In `office-span/ssl.json`, 686 of 689 rows contain uppercase `S` and no lowercase characters; all 680 rows marked `established:true` are affected. Zeek capitalizes client-sent messages and lowercases server-sent messages. Line 1, `2026-10-20T13:04:52.851856Z`, UID `Ccqm0bUSkySepOecTL`, reports a completed TLS 1.3 handshake with `ssl_history:"CSD"`: both ClientHello and ServerHello are attributed to the client. Line 2, `13:04:58.487558Z`, UID `C1zhfwA8fxOVmqbrgQq`, similarly reports `CSXKNGIFIFD` for TLS 1.2, attributing ServerHello, certificate, server key exchange, and server-hello-done to the client. This conflicts with the [Zeek SSL field definition and history implementation](https://raw.githubusercontent.com/zeek/zeek/v8.0.0/scripts/base/protocols/ssl/main.zeek).
- [hard_contradiction] **TCP history repeats flags whose native representation is unique per direction.** `office-span/conn.json` has 873 TCP rows; 352 repeat at least one of `a`, `A`, `d`, `D`, `i`, `I`, `q`, or `Q`. Line 1, `13:01:30.950880Z`, UID `CFC20K6LLHisX5lUJlx`, has `history:"ShADaDadfFa"`, with two `D` and three `a` flags. Line 4, `13:04:52.720510Z`, UID `Ccqm0bUSkySepOecTL`, has `ShADaDadfF`. Zeek explicitly records ACK/data/inconsistent/multiflag indicators a maximum of once per direction; additional packets do not create these repeated letters. This affects SSL, SMB, HTTP, SSH, and unlabeled TCP traffic, rather than a single unusual connection. See [Zeek connection history semantics](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info).

## Evidence For Real

- All **7,953 JSON/NDJSON rows** parsed successfully; both Windows XML files parsed, containing **600 Security** and **422 Sysmon** events. All **473 Linux syslog lines** had a consistent RFC 5424-style envelope. The problem is semantic authenticity, rather than widespread malformed serialization.
- The Windows sources use credible provider GUIDs, channels, event levels, success/failure keywords, hexadecimal Security PIDs, decimal Sysmon PIDs, and event-specific data. The 4688 version-2 records include target-subject and mandatory-label fields; process starts use Security execution PID 4, authentication events use LSASS PID 5592, and Sysmon consistently uses service PID 2180.
- Every examined DNS, HTTP, SSL, NTP, SMB-file, and SMB-mapping UID resolved to a `conn.json` row. Their endpoint tuples matched, and their timestamps fell within the corresponding visible connection intervals, allowing a 10 ms boundary tolerance. Certificate-chain FUID references resolved to both file and X.509 records, and the available SHA-1 file hashes matched X.509 fingerprints.
- Visible process lifecycles are credible in several important respects. No duplicate eCAR PROCESS/CREATE durable IDs were found; no same-ID process operation preceded its visible creation or followed its visible termination in the checks performed. Sysmon operations likewise did not occur outside their same-GUID visible process lifetimes.
- macOS Endpoint Security records distinguish fork children from exec targets and preserve process start time across exec. For example, native lines 6–8 trace PID 49369 from a `/bin/zsh` fork at `15:15:41.075970Z`, through exec into `/usr/bin/id` at `15:15:41.080215Z`, to exit at `15:16:00.011283Z`; audit-session identity stays coherent.

## Detailed Analysis

### Scope and method

I examined the supplied dataset only, using aggregate parsing and bounded record excerpts. The 25 files cover four endpoint directories and an `office-span` network sensor: one Windows workstation, two Macs, and a Linux host providing SSH and Samba services. The visible interval is approximately `2026-10-20 13:00–18:59 UTC`. Host roles follow executable paths, service names, endpoint tuples, and records; no organization or ground-truth context was used.

I parsed all JSON/NDJSON and Windows XML records, counted event families, checked protocol-reference joins and basic packet accounting, and inspected 18 distinct Windows event types plus native macOS fork/exec/exit records. I did not execute any recorded commands, resolve dataset domains, or perform live collection. File modification times, sanitized names, absent Sysmon types, independent source selection, and out-of-window lifecycle gaps were excluded as evidence.

### Zeek parser and semantic compatibility

The flat field names and JSON value types are generally usable by normal Zeek ingestion: numeric timestamps/ports/counts, Boolean flags, string UIDs, and arrays for answers, TTLs, FUIDs, and connection references. No protocol UID or tuple mismatch emerged among the six checked companion source families. No originator/responder payload-byte total exceeded its IP-byte total, and no row violated the minimum IPv4/TCP or IPv4/UDP header allowance in the accounting check.

The two history fields would nevertheless mislead rules that rely on native Zeek semantics. The SSL issue is especially clear because `conn.json` retains mixed case while the SSL source uses uppercase histories throughout. The standard is not that TLS histories should vary more; it is that they must attribute protocol messages to the correct sender.

The 680 established SSL rows break down as:

| TLS version | History | Count |
|---|---|---:|
| TLS 1.3 | `CSD` | 319 |
| TLS 1.3 | `CSDD` | 101 |
| TLS 1.3 | `CSDDD` | 38 |
| TLS 1.2 | `CSXKNGIFIFD` | 100 |
| TLS 1.2 | `CSIFIFD` | 61 |
| TLS 1.2 | `CSXKNGIFIFT` | 41 |
| TLS 1.2 | `CSXKNGIFIFL` | 20 |

The nine unsuccessful rows comprise three `C`, three `CS`, and three `CSL`. The three client-only histories are not counted in the directional contradiction. TLS version/cipher combinations and selective certificate visibility are otherwise plausible; I do not require passive TLS 1.3 certificate visibility or infer a defect from its absence.

For connection history, the 352 affected TCP records include **307 SSL, 22 SMB, 19 HTTP, two SSH, and two unlabeled** connections. The most frequent invalid forms are `ShADaDadfF` (103), `ShADaDaDadfF` (71), `ShADadfFa` (55), and `ShADaDadfFa` (44). They are invalid because of repeated once-only flags, not because they are frequent. Connection-state/termination checks were stronger: all `RSTO` histories contained `R`, all `RSTR` histories contained `r`, and TCP `SF` histories contained both FIN directions.

The SSL and TCP-history defects are related in source family but independent in meaning: case encodes TLS message sender, whereas repeated connection flags violate per-direction history accumulation. A downstream transformation could corrupt real logs in these ways; there is no visible transformation declaration, and privacy substitution does not explain either change. That alternative limits confidence below absolute certainty.

### Windows event-by-event review

Line numbers below identify each event's opening XML tag, not an Event Viewer display line. All paths in this subsection are under `NS-WIN-01.northstar.example/`.

| Source / event | Line; UTC timestamp | Representative field check |
|---|---|---|
| Security 4688 v2 | 3; 13:03:21.1518319 | `NewProcessId=0x1978` equals decimal PID 6520; parent `0x15e4` equals 5604. `MandatoryLabel=S-1-16-16384` agrees with SYSTEM context. |
| Security 5156 v1 | 46; 13:05:15.1584876 | Decimal `ProcessID=5624`, device-form application path, UDP protocol 17, DNS destination port 53, and direction resource token have expected shapes. |
| Security 4689 v0 | 339; 13:05:58.8289497 | Process termination uses hexadecimal `ProcessId=0x1808`, status `0x0`, and account/logon fields. |
| Security 4624 v2 | 374; 13:06:19.3581489 | Type 3, Kerberos, source `::ffff:10.42.0.11:64893`, and LUID `0x1037d607` describe network authentication. |
| Security 4634 v0 | 470; 13:07:12.8290179 | Same account, Type 3, and LUID `0x1037d607` close the preceding visible session. |
| Security 4672 v0 | 656; 13:09:10.9853430 | Subject SID/LUID and privilege-name list are structurally credible. Privileges alone do not establish that the user should be unprivileged. |
| Security 4648 v0 | 1235; 13:09:50.6586285 | Distinct `nora.ellis` subject and `nora.ellis-admin` credential target, caller PID/path, and server fields provide usable explicit-credential evidence. |
| Security 4800 v0 | 7524; 14:41:29.5953149 | Account, LUID `0x1034393e`, and SessionId 1 describe a workstation lock. |
| Security 4801 v0 | 7751; 14:43:37.0025373 | Same account, LUID, and SessionId unlock after the lock. |
| Security 4625 v0 | 10160; 15:15:12.1659525 | Type 2 with `IpAddress=-`; `0xc000006d` plus `0xc000006a` represents a bad-password failure and uses audit-failure keywords. |
| Sysmon 10 v3 | 3; 13:02:09.3983940 | Distinct source/target GUIDs and PIDs, `GrantedAccess=0x1400`, call trace, and source/target users are present. |
| Sysmon 13 v2 | 38; 13:02:31.6022096 | `EventType=SetValue`, registry `TargetObject`, and `DWORD (0x00000001)` details have the appropriate event shape. |
| Sysmon 1 v5 | 69; 13:03:20.8900373 | PID 6520 and parent 5604 match Security 4688; image metadata, hashes, logon fields, and parent identity are present. |
| Sysmon 22 v5 | 284; 13:05:56.8753400 | DNS event provides QueryName, numeric-string QueryStatus, semicolon-delimited QueryResults, and process identity. |
| Sysmon 5 v3 | 315; 13:05:58.7530013 | PID 6152 equals Security `0x1808`; image and account agree with the Security termination. |
| Sysmon 3 v5 | 523; 13:09:35.6760754 | TCP connection uses process identity, initiated flag, IPv4 flags, endpoint addresses, decimal ports, and hostname fields. |
| Sysmon 11 v2 | 932; 13:14:39.6551353 | File-create event carries process GUID/PID, target filename, and CreationUtcTime. |
| Sysmon 7 v3 | 1510; 13:19:59.9812139 | Distinct process/image-loaded paths, DLL metadata, hash strings, signing flag, signer, and signature status have credible shapes. |

The 4688 version and added fields agree with [Microsoft's event reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688). Security timestamps and EventRecordIDs increase in file order; Sysmon timestamps and EventRecordIDs do likewise. Sysmon `UtcTime` has millisecond precision while XML `SystemTime` has finer precision, with plausible small delivery offsets in the samples. Stable image/version pairs did not change their hash strings in the checked Sysmon records.

The 57 successful logons and 46 logoffs are not expected to balance in a bounded, selectively collected window. I found no later subject activity using a LUID after its paired visible final logoff in the performed check. I did not require domain-controller events for local logons or treat unavailable domain-controller collection as a defect.

### macOS native exports and normalized endpoint events

`NS-MAC-02.northstar.example/macos_endpoint_security.ndjson` contains 14 version-11 messages: eight fork-shaped, four exec-shaped, and two exit-shaped notifications, all with `action_type=1`. These are treated as Endpoint Security notifications; the result union is not interpreted as a separate policy-denial record. The export contains audit tokens, executable file metadata, process start times, signing fields, per-type sequence numbers, and global sequence numbers.

At native line 4 (`15:15:28.323212Z`), PID 45496 `/bin/zsh` forks PID 49280. Line 5 (`15:15:28.328829Z`) represents PID 49280's exec using actor pidversion 61 and target pidversion 62, while retaining the original `15:15:28.323212Z` process start time. Lines 6–8 then preserve the corresponding fork/exec/exit chain for PID 49369. Keeping start time at fork across exec agrees with [Apple's start_time definition](https://developer.apple.com/documentation/endpointsecurity/es_process_t/start_time).

I did not infer an exact macOS release from this message version alone, nor claim full byte-for-byte eslogger or version-11 SDK conformance from the available evidence. The older-process/later-executable distinction is handled substantially better than a naive process-per-exec export.

The Unified Log rows use timestamp strings with UTC offset, a boot UUID, process/sender paths and UUIDs, subsystem/category, format string, and formatted message. They are distinct from the normalized eCAR FLOW/USER_SESSION records. Their small count is not evidence against authenticity because source filters may be independent.

For an explicit network/session join, `office-span/conn.json:771` observes SSH tuple `10.42.0.21:51078 → 10.42.0.12:22` at `15:07:42.656634Z`. The destination eCAR FLOW at `NS-MAC-02.../ecar.json:427` occurs at `15:07:42.776Z`, before the matching successful SSH USER_SESSION at line 431 (`15:07:46.608Z`). This transport-before-auth relationship is credible. Native and normalized event timestamps have differing observation offsets; I did not convert those differences alone into a causality contradiction.

### Linux and collection plausibility

`NS-BUILD-01.northstar.example/syslog.log` combines Samba/auth/audit, SSH/PAM/logind, sudo, cron, DNS resolver, package maintenance, and system-service messages. Their RFC 5424-style presentation is consistent across all 473 rows. A bounded sample includes CRON line 13 (`13:04:00.108918Z`, sysstat command), sudo line 27 (`13:12:53.350224Z`, `maya.chen`, `TTY=pts/1`, explicit PWD/USER/COMMAND), and systemd-journald line 83 (`13:43:09.915736Z`, journal vacuum message).

Samba file evidence uses SMB tuples to a Linux host with `/usr/sbin/smbd` and `/srv/samba/...` paths. Advertising `NTFS` in SMB mapping alone is not proof that the underlying server is Windows. I found no basis to penalize the observed source mix, selected native macOS rows, or absence of additional audit products. The endpoint visibility is sufficient for useful detections, while the Zeek histories would need correction before relying on direction/state-dependent content.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Zeek SSL | 686/689 rows contain a client-attributed ServerHello; all 680 established rows affected | Very high: violates documented direction encoding in a source-wide field; completed handshakes cannot have both peer roles assigned this way. |
| `hard_contradiction` | Zeek TCP connection | 352/873 TCP histories, across five service groupings | High: repeats flags that the native analyzer records only once per direction, independently of TLS semantics. |

The indicators are not additive probabilities. The score reflects their definitive source-native nature and broad scope, balanced against strong parsing, stable endpoint identities, credible visible lifecycles, and intact cross-source references. Possible downstream field corruption of real telemetry remains an alternative explanation.

## Realism Score by Category

- **Field format accuracy:** 7 — Strong JSON/XML structure and endpoint schemas; broad Zeek history semantics are incorrect.
- **Temporal patterns:** 8 — Credible source precision and ordering in the checks performed; the bounded window limits deeper day-scale judgments.
- **Cross-source correlation:** 9 — Protocol UID/tuple joins, certificate references, and sampled Windows process identities agree.
- **Behavioral realism:** 8 — Plausible service and user actions with varied connection outcomes; no score penalty for compact suspicious activity.
- **Environmental consistency:** 8 — Platform-specific paths and service roles are coherent; selected source coverage does not establish an inconsistency.

## Recommendations

- If this were synthetic, build `ssl_history` from sender-aware TLS message observations, following Zeek's case semantics. Include conformance examples for TLS 1.2 full handshakes, resumed handshakes, TLS 1.3, and failed negotiations. Check field meaning rather than only allowing a string of valid letters.
- If this were synthetic, model connection history with Zeek's per-direction accumulation rules. Emit `a/d/i/q` once per direction, and use the documented distinct rules for retransmission, gap, handshake, and close indicators. Validate histories such as the invalid `ShADaDadfFa` before export.
- Retain the current durable process/session identities, source-specific PID formats, certificate references, and transport-before-auth ordering while fixing those fields. Verify the repaired outputs against primary source semantics so that detection content sees native-equivalent history values.
