# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 85
**Synthetic-Confidence Score:** 48

## Executive Summary

The collection would mostly behave correctly in a detection stack: Windows events have convincing source-specific schemas, network protocol records join cleanly to their transports, and visible process/session relationships passed several mechanical checks. Repeated exact subsecond phases in macOS shell-command bursts raise a concrete suspicion of scheduled construction, but scripts could also produce this behavior; I did not establish an impossible native event relationship or a definitive schema violation.

## Evidence For Synthetic

- [distribution_texture] Native macOS process forks repeatedly preserve an identical six-digit fractional second across different commands tens of seconds apart. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 32, 35 and 38 have times `13:48:48.715405000Z`, `13:49:18.715405000Z` and `13:50:08.715405000Z`; their immediate execs launch `pwd`, `ls` and `du`. Lines 49, 52 and 55 similarly share `.314210000` while launching `df`, `ps` and `find` after intervals of exactly 37 and 52 seconds. This is more specific than generally regular activity.
- [distribution_texture] The same texture recurs on the second Mac: `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` lines 120, 123 and 126 have `17:32:54.495937000Z`, `17:33:42.495937000Z` and `17:34:30.495937000Z`, followed by `du`, `df` and `ps`. Across all native fork rows, 20/48 on the first Mac and 23/52 on the second belong to repeated fractional-second groups. Those totals include browser helper launches, which are less probative than shell diagnostics. Recurrence in multiple shell bursts drives the moderate score impact; legitimate automation remains a viable explanation.
- [weak_signal] `MAC-MROSS-01.meridianhcs.local/ecar.json` has ambiguous serialization of same-millisecond process transitions. Lines 206–207 both have `timestamp_ms=1793634437395`: the `service_drop` for PID 62981 and execution suffix `:exec:1` appears before the `exec` establishing `:exec:1`. Lines 247–248 show the same ordering for PID 64356; lines 371–372 put `job_control` before the relevant exec for PID 73873. A simple timestamp-ordered stateful consumer can apply stale credentials/group state. This is replay ambiguity, not demonstrated impossible chronology: truncation to milliseconds can explain equal timestamps. It contributes little independent authenticity weight.

## Evidence For Real

- All 72,794 supplied JSON/NDJSON records and all 30,734 Windows XML event elements parsed successfully. Windows hash strings and GUID-bearing fields checked had valid lengths and hexadecimal/GUID syntax.
- Windows schemas distinguish different native shapes. `DC-01.meridianhcs.local/windows_event_security.xml:260270` renders Event 1102 with provider `Microsoft-Windows-Eventlog`, `UserData/LogFileCleared` and record ID 1. Subsequent record numbers restart.
- `FILE-SRV-01.meridianhcs.local/windows_event_security.xml:5573` and `:5669` pair Type 3 logon/logoff for `ANONYMOUS LOGON`, SID `S-1-5-7`, LUID `0xf6867b2`, with matching identity and about 26 seconds duration.
- No Sysmon process use occurred more than 100 ms after its same-GUID termination, and no eCAR actor use occurred more than 100 ms after its visible object-ID termination in the checks performed. No Security event subject used a non-reserved LUID more than 100 ms after its visible 4634 closure.
- All checked Zeek protocol UID references resolved to connections on the same sensor. DNS, HTTP, TLS, SMB and SMTP timestamps fell inside the associated visible connection intervals, allowing 100 ms before open and 500 ms after close for observation/rounding.
- Native macOS records retain fork/exec distinctions, executable replacement under the same PID, audit-token PID versions and separate actor/target identities. Terminal and iTerm startup chains differ substantively.
- Linux SSH evidence separates connection, accepted authentication, PAM session and logind messages. `APP-INT-01.meridianhcs.local/syslog.log:59–62` uses PID 2939047 and source `10.10.1.35:61718`, then records PAM opening and session 376026.

## Detailed Analysis

### Scope and mechanical checks

I examined only the supplied data directory. I parsed every JSON/NDJSON row and Windows event element, inspected representatives of all 28 Security event IDs and all nine Sysmon IDs present, and sampled native macOS, Linux, firewall and network records. Windows timestamps span approximately `2026-11-02T13:00:13Z` through `18:59:48Z`.

Checks covered same-identity process use after termination, Security subject use after logoff, Zeek protocol/connection reference integrity and temporal intervals, payload/IP-byte accounting, and Windows hash/GUID syntax. These establish the stated invariants, not complete semantic correctness of every field. Missing pre-window starts and post-window ends were neutral.

### Representative source-native records

Paths below are relative to the supplied data directory; XML line numbers point to event starts.

| Event | File/line | Fields examined |
|---|---|---|
| Security 5156 | `DC-01.meridianhcs.local/windows_event_security.xml:3` | Version 1; decimal PID 2420; device application path; inbound direction; protocol 17; receiver port 53. |
| Security 4776 | same file, line 167 | Native package name; machine account `WS-PPATEL-01$`; workstation; status `0x0`. |
| Security 4689 | same file, line 199 | Hex PID `0xcc0`; image; subject LUID; exit status. |
| Security 4688 | same file, line 556 | Version 2; creator/target subject fields; child/parent PIDs; `TokenElevationType=%%1936`; integrity SID. |
| Security 4624 | same file, line 640 | Version 2; Type 5 LOCAL SERVICE; Advapi; service creator; absent network address; reserved LUID. |
| Security 4672 | same file, line 695 | Subject SID/LUID agree with preceding service logon; multiline privilege list. |
| Security 4769 | same file, line 930 | Requester machine account; account-style service `DC-01$`; service SID; AES `0x12`; mapped IPv6 client address. |
| Security 4768 | same file, line 2437 | krbtgt; RID 502 service SID; client SID; preauthentication 2; certificate placeholders. |
| Security 4648 | same file, line 4395 | Explicit-credential subject/caller process and target server represented separately. |
| Security 5140 | same file, line 43488 | SYSVOL share; native local path; subject LUID; client tuple and access mask. |
| Security 4771 | same file, line 127670 | Audit-failure keywords; preauthentication 2; failure `0x18`. |
| Security 4697 | same file, line 172261 | PSEXESVC; own-process type `0x10`; demand start 3; LocalSystem. |
| Security 4698 | same file, line 190213 | Embedded Task Scheduler XML with principal, trigger and executable action. |
| Security 4656/4663/4658 | `FILE-SRV-01.meridianhcs.local/windows_event_security.xml:9711`, `:9760`, `:9801` | Handle `0xc989ded5`; same file/user/process; requested rights, actual read and close in order. |
| Sysmon 1 | `DC-01.meridianhcs.local/windows_event_sysmon.xml:564` | Version 5; process/parent GUIDs; PID 3876; image/version metadata; hashes; logon/integrity. |
| Sysmon 10 | same file, line 3 | Source/target GUIDs, PIDs/images; `GrantedAccess=0x1410`; call trace; user fields. |
| Native ES fork/exec | `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson:1–3` | Version 11; NOTIFY action; launchd fork then xpcproxy/iTerm exec; PID 18976 persists and PID version advances 10→11→12. |
| Native ES exec/exit | same file, lines 12–13 | sw_vers target and subsequent exit use PID 18980/version 21; native exit-status payload. |

Windows SystemTime uses seven fractional digits; Sysmon payload UtcTime uses milliseconds and can precede the SystemTime observation slightly. This is normal, not a defect. Security success/failure metadata and Sysmon informational metadata differ appropriately.

### Network joins and accounting

There are 11,927 core, 379 database-segment and 9,167 DMZ connection rows. None had directional application bytes exceeding corresponding IP bytes, or IP bytes exceeding 65,535 times the packet count. This is a broad physical-consistency check, not packet reconstruction.

`zeek-db/conn.json:1` records MySQL from `10.10.3.10:37018` to `10.10.4.10:3306`, with SF state, packet counts, directional bytes and duration. `zeek-db/http.json:1` records CONNECT to proxy `10.10.3.20:8080`, with authority-form URI and `200 Connection Established`. `zeek-db/ssl.json:1` distinguishes resumed TLS. These support ordinary field-based rules.

I found no connection UID with conflicting endpoint tuples and no X.509 fingerprint with conflicting certificate identity/validity metadata. Complete joins are positive consistency evidence, not a synthetic clue.

### macOS semantics and temporal reservations

The native ES files remain distinct from normalized eCAR and Unified Log. They contain versioned headers, audit tokens, executable stat metadata, actor/target structures and native exit status. I found no same-host executable inode collisions among different paths and no changing inode/size/mtime tuple for unchanged executable paths in those observations.

The strongest reservation is selective timing regularity. Neighboring exec rows show varied microsecond offsets while separate shell forks retain a shared phase over 30–65-second gaps. This suggests common scheduling anchors rather than a global precision limitation. Scripted diagnostics could explain it, so this is a distribution indicator rather than a contradiction.

For the eCAR equal-time pairs, serialized order would apply a credential drop in xpcproxy, then a root-credential exec into xpcproxy, followed by an exec expecting the dropped credentials. The corresponding native ES executable changes are correctly ordered. Equal normalized milliseconds support a missing tie-breaker concern; they do not establish strictly inverted timestamps. A consumer using execution dependencies can reconstruct the intended order.

### Collection interpretation

Thin Unified Log coverage can represent filtered exports; native ES supplies a separate process view. Absent Sysmon types and boundary-crossing lifecycles were not penalized. Neither completeness nor narrative clarity of suspicious activity contributed to the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affects the score |
|---|---|---|---|
| distribution_texture | Native macOS ES | Repeated shell diagnostic bursts on both Macs | Main upward pressure: exact shared microsecond phases at integer-second gaps; scripts remain an alternative. |
| weak_signal | Normalized macOS eCAR | Three equal-millisecond transition pairs on MAC-MROSS-01 | Small pressure: serialized replay ambiguity; no demonstrated impossible chronology. |

No demonstrated hard contradiction or high-confidence native schema defect was established. The score stays in the mixed/inconclusive band because the strongest evidence concerns temporal texture rather than broken native contracts.

## Realism Score by Category

- **Field format accuracy:** 9 — Native fields, identifiers, hashes and event-specific shapes are convincing.
- **Temporal patterns:** 6 — Mostly sound lifecycles; exact subsecond phases recur in diagnostic bursts.
- **Cross-source correlation:** 9 — UID, certificate and lifecycle checks passed; equal-time normalized transitions need care.
- **Behavioral realism:** 7 — Coherent browser, shell, authentication and service activity; structured Mac diagnostic bursts are less organic unless scripted.
- **Environmental consistency:** 8 — Mixed platforms/roles and source distinctions are plausible; collection limits alone do not warrant penalties.

## Recommendations

- If this were synthetic, add independent subsecond scheduling variation to distinct shell commands, retaining causal dependencies. Avoid copying one microsecond phase across 30–65-second gaps unless intentionally representing a script/timer.
- If modeling scripted diagnostics, represent the script invocation/process context so integer-spaced shell activity has a visible explanation.
- Preserve dependency order or a transition sequence number for eCAR updates collapsing into one millisecond. Establish the exec identity before its service-drop/job-control update in the cited chains.
- Retain the present source-specific schemas and identity consistency; adding unrelated audit families would not address these findings.
