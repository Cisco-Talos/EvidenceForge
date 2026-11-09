# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 82

## Executive Summary

The data is highly usable for detection engineering: the inspected source envelopes, identity relationships, and network joins are mostly convincing. The decisive contrary evidence is a successful Windows task-creation audit containing a principal logon type that is invalid in Task Scheduler XML; that specific native-content contradiction drives the synthetic verdict, rather than the completeness or narrative shape of the activity.

## Evidence For Synthetic

- [hard_contradiction] `DC-01.meridianhcs.local/windows_event_security.xml`, event beginning at line 200293, RecordID `28257394`, EventID `4698`, `2026-11-02T17:19:48.9866198Z`: the successful task-creation record contains `<LogonType>ServiceAccount</LogonType>` inside `TaskContent` (escaped XML at line 200342). This is an API concept incorrectly used as an XML enumeration value. Microsoft's XML `logonType` enumerates `S4U`, `Password`, `InteractiveToken`, and `InteractiveTokenOrPassword`; it does not enumerate `ServiceAccount`. The separate COM enum does contain `TASK_LOGON_SERVICE_ACCOUNT=5`, which does not make the string legal in task XML. A successful native registration audit carrying this task definition contradicts the documented schema. [Task XML simple type](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-logontype-simpletype), [COM enumeration](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type).

## Evidence For Real

- Windows event envelopes are substantially source appropriate. Security successes use level `0` and audit-success keywords; `4771` and `4625` failures use audit-failure keywords. The `1102` record correctly switches to `Microsoft-Windows-Eventlog`, level `4`, and namespaced `UserData/LogFileCleared`, instead of treating the event as ordinary Security-Auditing `EventData`.
- Visible Windows lifecycle evidence survived identity-specific checks: no inspected Sysmon GUID occurrence preceded its visible create or followed its visible termination, and no non-system Security logon identity was used before its visible `4624` or after its visible `4634`. Processes or sessions beginning outside the slice were left neutral.
- All 22,148 supplied Zeek connection records supported the checked DNS, HTTP, TLS, file, and SMB references: no missing referenced UID, endpoint-tuple disagreement, or companion timestamp outside the connection interval at the stated tolerances. This is positive correlation evidence, not a claim that completeness establishes authenticity.
- macOS ES records distinguish fork, exec, and exit; exec actor and target preserve PID while changing PID version. The first three records on `MAC-MROSS-02` show launchd → xpcproxy → iTerm, including executable/signing changes and a transition into the user audit session. These are richer and more plausible than generic process-create rows relabeled as native ES.
- TLS records distinguish full TLS 1.2 handshakes, TLS 1.2 resumption, incomplete negotiation, and TLS 1.3. In the supplied TLS 1.3 rows, certificate-chain FUIDs are absent; TLS 1.2 certificate records link to file and X.509 evidence. DNS includes several query types and successful, NXDOMAIN, SERVFAIL, and REFUSED responses rather than only successful A lookups.

## Detailed Analysis

### Input provenance and method

All data examination was restricted to `/private/tmp/log-study-pdlkpnp9/data`; all file references below are relative to that root. I read the supplied `/private/tmp/log-study-pdlkpnp9/detection-prompt.md`, enumerated the supplied data, parsed records with Python's standard-library JSON and XML parsers, and consulted the primary Microsoft, Zeek, and Apple documentation linked in this report. Public searches used actual domains restrictions; direct opens used upstream documentation URLs. No repository code, scenarios, roadmap/worklog files, previous assessments, or other reviewers' reports were inspected.

The inherited session included repository-oriented operating metadata and a delegation instruction. That is a limitation on environmental blinding; it was not treated as evidence of the data's origin. Commands appearing in log fields were analyzed as inert strings and were not executed. Copied filesystem timestamps, potentially sanitized domains, selected Sysmon coverage, and missing out-of-window lifecycle records were excluded as authenticity indicators.

The inventory contains 117 files. All 74,631 records across 54 JSON/NDJSON files parsed successfully. The Windows XML files parsed to 19,030 Security events and 11,785 Sysmon events. The data spans approximately six hours on 2 November 2026 across Windows, Linux, macOS, network, firewall, proxy, and application sources. Successful syntax parsing is distinct from semantic/schema validity.

### Twenty record-level checks

The following are concrete parsed examples, not assertions that every provider field was independently certified against every historical manifest. Line numbers identify the start of an XML Event, or the NDJSON record itself.

| Source / line | Event identity | Fields and result |
|---|---|---|
| `DC-02.meridianhcs.local/windows_event_security.xml:360` | 4624 / RID 25377478 / 13:00:52.1498733Z | Version 2; local-service SID `S-1-5-19`, Type 5, `Advapi`, local `services.exe`, absent remote IP, and extended v2 fields fit service logon semantics. |
| Same file:415 | 4672 / RID 25377479 / 13:00:52.1656750Z | `SubjectLogonId=0x3e5` and LOCAL SERVICE identity match the preceding logon; privilege assignment follows it. |
| Same file:2402 | 4634 / RID 25377573 / 13:05:28.7368298Z | Type 3, `TargetLogonId=0xcb5d4ec`, user `lina.nguyen`; no inverted visible same-logon lifecycle found. |
| Same file:2476 | 4768 / RID 25377578 / 13:05:37.8741801Z | `krbtgt`, domain SID ending `502`, AES type `0x12`, PreAuthType 2, and IPv4-mapped client IP fit a machine TGT request. |
| Same file:738 | 4769 / RID 25377495 / 13:01:27.6928621Z | `FILE-LNX-01$` requests service `DC-02$`; service SID, mapped IPv4, ticket options, status, and encryption fields are structurally credible. An earlier TGT may be cached/pre-window. |
| Same file:3360 | 4776 / RID 25377604 / 13:05:55.4389867Z | Uses `PackageName`, `TargetUserName`, `Workstation`, `Status`, without inventing 4624-style session fields. |
| Same file:4730 | 4688 / RID 25377656 / 13:07:04.7804805Z | Version 2; new PID `0x1bdc=7132`, creator PID `0x13fc=5116`, `dllhost.exe` image, creator image, and integrity SID align with the matching Sysmon create. |
| Same file:85339 | 4771 / RID 25380784 / 14:53:08.9599020Z | Audit-failure keywords, status `0x18`, PreAuthType 2, target SID, `krbtgt`, and mapped client address form credible failed Kerberos preauthentication evidence. |
| `FILE-SRV-01.meridianhcs.local/windows_event_security.xml:146` | 4656 / RID 271776 / 13:00:05.9698262Z | Handle `0x1b169349`, file object, access mask `0x12019f`, subject logon `0xf62b74b`, and process `0x4` establish the file-handle context. |
| Same file:199 | 4663 / RID 271777 / 13:00:06.1459007Z | Same handle/file/subject; used access `0x2` is included in the earlier requested access mask. |
| Same file:240 | 4658 / RID 271778 / 13:00:09.7044242Z | Same handle and process close after visible use; event shape appropriately omits a fabricated object pathname. |
| `DC-01.meridianhcs.local/windows_event_security.xml:200293` | 4698 / RID 28257394 / 17:19:48.9866198Z | Embedded task XML parses, but its principal `LogonType=ServiceAccount` fails the documented enumeration. This is the scored defect. |
| Same file:270291 | 1102 / RID 1 / 18:42:11.6676456Z | Correct Eventlog provider and `LogFileCleared` UserData; record ID resets to 1. A forwarded/exported slice may retain earlier records, so retention of earlier events is not scored. |
| `DC-02.meridianhcs.local/windows_event_sysmon.xml:2490` | Sysmon 1 / RID 1368617 / 13:07:04.5861676Z | ProcessGuid `{d55311aa-8af8-6ae8-4c02-00001f4dc1b2}`, PID 7132, parent 5116, image, user, hashes, and process command agree with Security 4688; separate native timestamps differ by about 194 ms. |
| Same file:3 | Sysmon 3 / RID 1368530 / 13:00:03.6990009Z | UDP, `Initiated=false`, remote source `10.10.1.31:51161`, local destination `10.10.2.11:53`, local `dns.exe`, and process identity coherently describe inbound DNS. |
| Same file:83 | Sysmon 10 / RID 1368534 / 13:00:16.4959935Z | `SourceProcessGUID`, `TargetProcessGUID`, source thread, source/target users, `GrantedAccess=0x1010`, and call trace fit process-access evidence. |
| Same file:249 | Sysmon 22 / RID 1368539 / 13:00:48.4736078Z | `_kerberos._tcp.meridianhcs.local`, status 0, and semicolon-separated SRV-style results are source-appropriate rather than an A-record-only representation. |
| `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson:1` | ES fork / event_type 11 / 13:12:24.801753000Z | launchd PID 1 forks child PID 19023; child inherits launchd executable and gets PID version 10. |
| Same file:2 | ES exec / event_type 9 / 13:12:24.808641000Z | Actor PID 19023/version 10 targets the same PID/version 11 as `/usr/libexec/xpcproxy`; target executable, args, signing, and CPU fields describe exec separately from fork. |
| Same file:157 | ES exit / event_type 15 / 18:56:59.867523000Z | iTerm PID 19023/version 12 exits with `stat=0`; it is an ES notification, not an execution-denial decision. |

Microsoft documents the relevant [4624 semantics](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624), [handle-close shape](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4658), and [Sysmon event families and process GUID correlation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Apple distinguishes notification from authorization and identifies event-specific unions in [es_message_t](https://developer.apple.com/documentation/endpointsecurity/es_message_t?changes=__1_5_1&language=objc); I did not reinterpret native ES rows as normalized EDR FLOW records.

### Why the task-content defect matters

The task is `\Microsoft\Windows\Maintenance\DeviceSync`, runs as `NT AUTHORITY\SYSTEM`, and names `C:\Windows\System32\DeviceSyncSvc.exe`. These names and the suspicious behavior are not the indicator. The problem is that the record asserts successful creation while its serialized definition uses an enumeration that cannot be validated against Microsoft's published Task Scheduler XML type.

The nested XML was extracted after parsing the outer event; it contains 41 actual newlines and parses as XML. Thus the finding is not confusion about XML escaping, literal `\n`, JSON escaping, or malformed outer XML. Its task namespace is `http://schemas.microsoft.com/windows/2004/02/mit/task`. The documented schema restriction is precisely at the principal's `LogonType` element. A SYSTEM security context is legitimate; substituting a COM enum label into XML is the defect. Microsoft's [4698 documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698) identifies `TaskContent` as the task's XML definition.

A transformed or damaged export of real events remains an alternative explanation. There is no supplied transformation specification showing that task XML logon methods were rewritten, and this particular value is not a privacy-sensitive identifier. I therefore weight the contradiction strongly but do not assert that every row or every source is independently synthetic. I also do not promote uncertain provider-version differences into additional findings: Microsoft event documentation itself contains historical-version inconsistencies, and the actual installed provider manifests were not supplied.

### Cross-source and temporal checks

The checked Zeek sensors contain 12,314 core, 433 database, and 9,401 DMZ connections. For DNS, HTTP, SSL, files, SMB files, and SMB mappings, I joined the logged `uid` or `conn_uids` to each sensor's connection table; compared the four-tuple wherever both records supplied it; and tested companion time against `[conn.ts - 0.01, conn.ts + duration + 0.1]`. No violations were found. This is bounded validation of the supplied records, not packet-level proof.

For example, `zeek-db/conn.json:3` UID `CRSc35LDhIYfLFcvj9p` opens at `1793624701.305365` with duration `3.822977`; `zeek-db/http.json:1` reports its CONNECT at `1793624701.491673`, retaining `10.10.4.10:54870 → 10.10.3.20:8080`. The TCP `SF` record contains handshake/data/close history `ShADadfF`. Packet/IP-byte lower bounds were checked for TCP and UDP without treating ICMP type/code ports as TCP semantics. No bound violations were found. This interpretation follows [Zeek's connection-field definitions](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

The 3,142 SSL rows have distinct handshake outcomes. All supplied TLS 1.3 examples omit chain FUIDs, while full TLS 1.2 examples may include them. `zeek-db/ssl.json:3` identifies certificate FUID `FeLtr64jeZOQESJ26Jm`; `files.json:1` and `x509.json:1` agree on its SHA-1 fingerprint. Optional fields and separately observed handshake times fit [Zeek's SSL record model](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html).

For Windows, I checked each host's visible GUID references, including parent and source/target process references, against visible Sysmon creates and terminations. I also checked overlapping PID/GUID spans and non-system logon references against visible 4624/4634 bounds. Those checks found no contradictions. Millisecond Sysmon `UtcTime`, higher-precision event envelope time, epoch-float Zeek timestamps, and epoch-millisecond eCAR times need source-aware normalization; differing precision is not a defect.

For normalized eCAR, the 23 host files parsed with consistently typed timestamp/object/action/identity structures. Visible actor UUIDs did not occur before their visible PROCESS/CREATE or after their visible PROCESS/TERMINATE. I did not impose an undocumented universal vendor-specific schema on eCAR extensions.

### macOS and collection limits

The two ES files contain 283 notifications: 107 execs, 89 forks, and 87 exits. Their per-type and global sequence fields are structured coherently. Across repeated `(pid,pidversion)` snapshots, executable metadata, start time, signing identity, hash, team ID, and parent PID did not disagree in the fields tested. The rows declare message version 11; I did not score the presence of newer version-gated fields as invalid using an older mental model.

Unified Log records have separate writer/process and sender image fields, boot identifiers, subsystem/category information, and their own timestamp representation. The six supplied rows are a narrow selection; their low volume alone is neutral. Shell histories and normalized eCAR were not treated as native Unified Log or ES schemas. I found no separately verified macOS source-native defect. Source selection means absence of other endpoint families is also neutral.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Windows Security 4698 / embedded Task Scheduler XML | One record, DC-01 RID 28257394; task logon type at line 200342 | High: successful native task creation is inconsistent with the documented XML enumeration. This is the only scored synthetic indicator. |

The score of 82 reflects the rubric's hard-contradiction tier. It does not imply a dataset-wide rate of malformed events; most inspected evidence remains production-like.

## Realism Score by Category

- **Field format accuracy:** 8 — Strong event envelopes and value typing; one decisive embedded native-schema error.
- **Temporal patterns:** 9 — Source-specific precision and visible lifecycle ordering passed the stated checks; limited-duration slice.
- **Cross-source correlation:** 9 — Checked process, session, UID, tuple, and certificate relationships were coherent.
- **Behavioral realism:** 9 — No independently demonstrated behavioral-distribution defect; suspicious activity itself is not penalized.
- **Environmental consistency:** 9 — Heterogeneous platforms and services are represented without a verified role/collection contradiction.

## Recommendations

- If this were synthetic, validate embedded task definitions against the Task Scheduler XML schema before rendering a successful 4698 record. Represent the SYSTEM principal through the appropriate task XML/registration semantics; do not serialize `ServiceAccount` merely because the COM API has `TASK_LOGON_SERVICE_ACCOUNT`.
- If this were synthetic, retain the current process/session and network correlation properties while adding semantic checks inside embedded payloads. Well-formed outer Windows XML does not validate the nested TaskContent enumeration that caused this finding.
