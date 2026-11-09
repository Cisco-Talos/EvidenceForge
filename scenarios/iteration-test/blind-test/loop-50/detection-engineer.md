# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 82

## Executive Summary

Most of the Windows, normalized endpoint, and Zeek records would parse and correlate convincingly in a SIEM. The decisive exception is a repeated reversal in newly forked processes' native macOS audit-token PID-version allocation: four chronological reversals on one host conflict with the kernel's global allocation semantics. This is a specific identity-field defect, not an inference from attack completeness, collection breadth, or sanitized names.

## Evidence For Synthetic

- [hard_contradiction] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, lines 44 and 47: at `2026-11-02T14:22:52.776507000Z`, a `fork` child PID `29633` has `audit_token.pidversion=69`; at `14:24:42.387235000Z`, a newly forked child PID `30060` has `pidversion=47`. Both actors are the same root `/sbin/launchd`, PID 1/version 1. Fork `seq_num` advances 16→17, `global_seq_num` advances 43→46, and `mach_time` advances `56106546636168`→`56109177293640`, so this is not merely a file-order or wall-clock reversal. Apple's kernel allocates fresh process PID versions from a global incrementing counter. [Apple XNU fork implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_fork.c)
- [hard_contradiction] The same native field reverses on three further visible fresh-fork pairs in that file: lines 80→82, `15:00:21.710528000Z`→`15:23:41.846670000Z`, child versions 84→72; lines 101→105, `16:05:46.686677000Z`→`16:25:23.065029000Z`, 95→88; lines 117→120, `17:12:27.393377000Z`→`17:19:29.440742000Z`, 111→97. Their per-type and global sequence numbers also advance. These are four instances of one identity-allocation defect, not four independent defect families.

## Evidence For Real

- Windows XML is well formed and generally respects source distinctions. DC-01 Security Event 1102 at line 270291 uses the `Microsoft-Windows-Eventlog` provider, Level 4, Task 104, Keywords `0x4020000000000000`, and namespaced `UserData/LogFileCleared`, rather than incorrectly treating it as ordinary Security-Auditing `EventData`. This matches the documented event shape. [Microsoft Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- Within each of the three sensors, every checked DNS, HTTP, TLS, SMB mapping/file, and SMTP row's UID resolves to a connection with the same four-tuple. There are 22,148 connection rows across the three sensors; no checked companion tuple mismatch was found. This supports usability and consistent underlying events; completeness itself is neutral for authenticity.
- All 3,957 explicitly present Sysmon hash values checked have appropriate hexadecimal lengths: 992 SHA1, 992 MD5, 992 SHA256, and 981 IMPHASH. The records also distinguish decimal Sysmon PIDs from hexadecimal Security process IDs.
- In all 11,785 Sysmon records, there was no checked same-GUID observation before its visible creation or after its visible termination, using the event's `UtcTime`. Equivalent checks on the normalized eCAR process `objectID`/`actorID` relationships found no impossible visible lifecycle ordering.
- Of 398 Security 4634 logoffs, 393 have a visible same-host 4624 with the same Logon ID; every one of those has a preceding logon with the same SID. The five without a visible initiator are neutral at a collection boundary.
- FILE-SRV-01's visible file-handle chain has coherent sequencing and shared identity: 5145, 4656, 4663, 4658 at `13:00:05.9658107Z`, `13:00:05.9698262Z`, `13:00:06.1459007Z`, and `13:00:09.7044242Z`. The latter three share Handle ID `0x1b169349` and subject Logon ID `0xf62b74b`.

## Detailed Analysis

### Input provenance, scope, and limitations

I read the complete neutral briefing at `/private/tmp/log-study-mytn1lc8/detection-prompt.md` and inspected only files under `/private/tmp/log-study-mytn1lc8/data`. I inventoried the supplied files, parsed all supplied Windows XML, all normalized eCAR JSON files, the three sensors' connection/protocol JSON, and both macOS Endpoint Security files; I also sampled Linux syslog and macOS Unified Log records. Supplemental research used Microsoft Learn and Apple Developer documentation, official Zeek documentation, and direct URLs into Apple's upstream XNU repository. An official-domains search also returned unrelated software-project results; those were not used as authority or inspected further.

The execution environment supplied inherited generic project/agent operating metadata before this review. That limits a strict claim of laboratory blinding, but it was not used as origin evidence. I did not access project source, scenarios, repository memory files, previous assessments, other reviewers, or origin-bearing parent inventories. Logged commands were treated as inert strings. File modification times and domain/IP real-world resolution were not used.

The substantive finding depends on interpreting `audit_token.pidversion` as the native field claimed by the export. A disclosed transformation that deliberately reassigned audit tokens could explain it without proving synthetic generation. The briefing gives no such transformation, so the repeated contradiction remains strong evidence while preventing absolute confidence. Message `version=11` is an ES message-version declaration, not sufficient evidence of an exact macOS release; I do not allege a message-version schema defect.

### Native macOS identity allocation

The two macOS files expose structured ES notifications with separate actor `process` and event-specific `fork.child` or `exec.target` objects. They declare `action_type=1` and use event types 11/9/15 for fork/exec/exit. I analyzed fork child identities directly, rather than confusing an exec actor with a new executable or inferring execution from a policy message.

The fresh-fork counter reversals are reproducible by filtering `event.fork.child.audit_token.pidversion` in timestamp order. For example:

| File line | UTC time | New child PID | New child PID version | Fork seq_num | Global seq_num |
|---|---|---:|---:|---:|---:|
| 44 | 14:22:52.776507000 | 29633 | 69 | 16 | 43 |
| 47 | 14:24:42.387235000 | 30060 | 47 | 17 | 46 |
| 80 | 15:00:21.710528000 | 38957 | 84 | 28 | 79 |
| 82 | 15:23:41.846670000 | 41771 | 72 | 29 | 81 |
| 101 | 16:05:46.686677000 | 45878 | 95 | 35 | 100 |
| 105 | 16:25:23.065029000 | 47721 | 88 | 36 | 104 |
| 117 | 17:12:27.393377000 | 52334 | 111 | 40 | 116 |
| 120 | 17:19:29.440742000 | 53037 | 97 | 41 | 119 |

In these rows each child's `start_time` matches its fork time, so these are not ordinary observations of old processes appearing out of order. Native sequence counters and Mach time advance through the reversals. There is no observed reset that would reconcile the continuing launchd identity with a reboot. Missing earlier events cannot make a global counter allocate a lower version later; repeated full integer-counter wraps over these short intervals are not a plausible explanation. Apple's implementation assigns the fresh process `p_idversion` using `OSIncrementAtomic(&nextpidversion)`; the audit-token PID/version pair is also used in kernel identity checks. [Apple XNU allocation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_fork.c), [Apple XNU PID-version access and token validation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_proc.c)

By contrast, MAC-MROSS-01's fork-child version series has no reversal in this check. Its Terminal sequence at ES lines 1–7 models launchd→xpcproxy→Terminal→login→zsh with actor/target separation and changing image identity. A kernel policy message at Unified Log line 2 says a security policy “would not allow” a process; that wording alone was not treated as proof of denied execution or a contradiction with later unrelated activity.

### Twenty-record field and event-shape examination

The following actual records were inspected in addition to aggregate checks. `DC Security` abbreviates `DC-01.meridianhcs.local/windows_event_security.xml`; `DC Sysmon` abbreviates that host's `windows_event_sysmon.xml`; `FILE Security` refers to FILE-SRV-01's Security XML. Line numbers identify the opening XML event; JSON uses physical line numbers.

| Record | Fields checked and result |
|---|---|
| DC Security line 208, 4689 | Version 0; process `0xcd4`; status `0x0`; System subject. Appropriate termination shape. |
| DC Security line 448, 4769 | Version 0; service account `DC-01$`; encryption `0x12`; IPv4-mapped IPv6 client. Appropriate legacy TGS shape. |
| DC Security line 645, 4688 | Version 2; new process `0xd94`; creator `0x8cc`; parent image, command line, target-subject fields and mandatory label present. |
| DC Security line 1656, 4624 | Type 5, NETWORK SERVICE SID `S-1-5-20`, Logon ID `0x3e4`, Advapi/Negotiate, absent remote IP. Coherent service login. |
| DC Security line 2317, 4768 | Version 0; `krbtgt`; target machine SID; PreAuthType 2; `Status=0x0`; certificate fields empty. Coherent legacy TGT event. |
| DC Security line 3090, 4776 | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation and account fields, `Status=0x0`. Correct event-specific naming. |
| DC Security line 6492, 4634 | Type 3, machine account and hexadecimal TargetLogonId; appropriate logoff fields. |
| DC Security line 140749, 4625 | NTLM Type 3; `Status=0xc000006d`, disabled-account SubStatus `0xc0000072`; remote DC-02 address. No demonstrated field contradiction. |
| DC Security line 270291, 1102 | Eventlog provider, separate UserData namespace, System subject; clear event uses record ID 1. |
| FILE Security line 97, 5145 | UNC share, local NT path, relative target name, source address/port and requested mask distinct from later access. |
| FILE Security line 146, 4656 | File handle `0x1b169349`, requested mask `0x12019f`, ProcessId `0x4`; same file/subject as chain. |
| FILE Security line 199, 4663 | Same handle and file; actual write mask `0x2`/`%%4417`, after handle request. |
| FILE Security line 240, 4658 | Same handle/subject/process; closure after access; no invented file-name requirement. |
| DC Sysmon line 3, Event 3 | Version 5; decimal PID 2420; UDP; Initiated=false; source DC-02→local DNS/53. Direction coherent. |
| DC Sysmon line 203, Event 10 | Version 3; `SourceProcessGUID`/`TargetProcessGUID`; access `0x1410`; thread ID and module-offset call trace. |
| DC Sysmon line 238, Event 5 | Version 3; same process PID 3284 (`0xcd4`) as Security 4689, source-specific timestamp. |
| DC Sysmon line 614, Event 1 | Version 5; PID 3476 (`0xd94`), parent PID 2252 (`0x8cc`), conhost command matches Security 4688. |
| DC Sysmon line 1630, Event 22 | QueryName, QueryStatus `0`, semicolon-terminated QueryResults `10.10.2.11;`, process identity and user. |
| zeek-core/conn.json line 1 | UDP DNS, numeric ports, payload/IP byte distinction: 46→74 and 167→195; one packet each, SF, history `Dd`. |
| zeek-core/dns.json line 1 | Same UID/tuple/time; numeric SRV qtype 33, answer/TTL vectors of equal length, boolean flags and numeric rtt. |

Microsoft's documented 4688 version 2 includes the additional target-subject, mandatory-label, and parent-image fields present here; the share-event fields and handle close structure also match the documented shapes. These are concrete positive checks, not certification of every event version. [Microsoft Event 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688), [Microsoft Event 5145](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145), [Microsoft Event 4658](https://learn.microsoft.com/ja-jp/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4658)

I did not penalize 4768 version 0 solely because later Windows updates introduced a new version: the records do not establish the installed cumulative-update level. [Microsoft Event 4768 version context](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)

### Correlation and SIEM behavior

I parsed 19,030 Security events and 11,785 Sysmon events. Process correlation used case-insensitive GUID equality rather than PIDs alone, preventing PID reuse from creating false anomalies. The normalized eCAR checks used durable object/actor identifiers. No asserted orphan was based solely on a missing pre-window creation or post-window close.

For each sensor I joined protocol rows to its own `conn.json`, preserving sensor-local UIDs. Cross-sensor UID equality was not required. Established TLS rows had nonzero payload in both directions; their connection states were SF. The 13 unestablished TLS rows were S1, which does not itself establish an impossible handshake. Certificate rows sharing a fingerprint had consistent certificate attributes across inspected sources. HTTP-linked file `seen_bytes` did not exceed its corresponding response-body length in the checked links.

Zeek connection `ts` means first packet time, so conn/protocol timestamps were interpreted as event times, not file write/ingestion time. UDP connection SF records were not incorrectly held to TCP teardown semantics. [Zeek connection schema](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html), [Zeek DNS schema](https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html)

The eCAR JSON is a normalized source, not native macOS ES. I did not impose its FLOW or USER_SESSION concepts on ES notifications, nor treat normalized UUIDs or string-valued properties as a demonstrated format violation without a supplied formal collector schema. Likewise, the low count of Unified Log rows and selected ES event families is neutral under the supplied collection assumptions.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Native macOS Endpoint Security audit tokens | Four fresh-fork PID-version reversals on MAC-MROSS-02; eight cited rows | Strong source-native allocation contradiction, sufficient to cross the 81 threshold despite otherwise convincing evidence. Counted as one defect family. |

No independent Windows, Zeek, Linux, or normalized-eCAR hard contradiction was established by the checks performed. This report does not claim all records or all source semantics were exhaustively validated.

## Realism Score by Category

- **Field format accuracy:** 7 — XML/JSON fields and typed values are strong; native macOS PID-version values violate allocation semantics despite valid syntax.
- **Temporal patterns:** 7 — Most checked lifecycles are coherent; the native allocation sequence contradicts advancing timestamps and sequence counters.
- **Cross-source correlation:** 9 — Same-host Logon ID/SID, process identities and sensor-local network tuples pass the stated checks.
- **Behavioral realism:** 8 — Inspected service, process, share and network events have plausible operational semantics; no narrative-based penalty applied.
- **Environmental consistency:** 8 — Windows, Linux, normalized endpoint and native macOS sources remain distinguishable; one host's native identity chronology is inconsistent.

## Recommendations

- If this were synthetic, allocate native macOS fresh-process PID versions in execution-time order from one host-wide counter, preserving existing actor/parent audit tokens and the appropriate exec semantics. Recheck the four cited fork pairs after the change.
- If this were synthetic, validate chronological fork-child audit-token allocation alongside per-type/global ES sequence numbers and Mach time. The existing parser and same-process lifecycle checks would not catch this defect because individual records are structurally valid.
- If these were transformed production exports, document any PID/audit-token remapping and preserve native ordering constraints through that transformation so SIEM identity joins and authenticity review remain meaningful.
