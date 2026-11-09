# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 46

## Executive Summary

The supplied logs are broadly credible and would support substantial SIEM parsing and correlation: the tested process identities, network tuples, certificate identities and visible lifecycles held together. A repeated Windows failure-reason mismatch and a smaller metadata-quality concern prevent an unqualified production verdict, but the demonstrated problems are too localized to establish that the whole dataset is synthetic.

## Evidence For Synthetic

- [schema_or_format] Three Event 4625 records on `MAIL-FIN-01.meridianhcs.local/windows_event_security.xml`, starting at lines **12225, 17912 and 25750**, combine `Status=0xc000006d`, `SubStatus=0xc0000072`, and `FailureReason=%%2307`. The substatus denotes an account disabled condition; the resource token is the account-locked-out reason shown in Microsoft's 4625 example. Their times are **14:43:18.7251933Z, 15:42:35.7361706Z and 17:02:42.7585752Z on 2026-11-02**, with EventRecordIDs **1447507, 1448219 and 1449167**. A detection that trusts the rendered reason could classify these differently from one using the numeric substatus. This is one repeated reason-mapping problem, not three independent findings. [Microsoft 4625 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625), [Microsoft NTSTATUS definitions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55).
- [weak_signal] A subset of recognizable Windows binaries has entirely absent PE version metadata despite useful hashing or signature fields. For example, `DC-01.meridianhcs.local/windows_event_sysmon.xml:825`, Event 1 for `C:\Windows\System32\MpCmdRun.exe`, has `FileVersion`, `Description`, `Product`, `Company` and `OriginalFileName` all `-`, while providing SHA1, MD5, SHA256 and IMPHASH. The Event 7 beginning at line **12991** similarly reports Microsoft's `MpClient.dll` as signed with a valid signature and hashes but all five version fields `-`. Across the supplied Sysmon files, **77/943 Event 1** and **25/130 Event 7** records have this five-field pattern. This could reflect inaccessible metadata or a selective export; it contributes only weakly and does not establish fabrication.

## Evidence For Real

- The XML files are well formed and expose useful source-native distinctions: Security Event 4688 uses hexadecimal process IDs and Event 1 uses decimal IDs, with matching identities in checked examples. XML namespaces, provider/channel names, timestamps, SIDs and GUIDs in the reviewed records have credible syntax.
- `DC-01.meridianhcs.local/windows_event_security.xml:2866` logs Event 4624 at **13:07:15.9751026Z**, `TargetLogonId=0x5382af7`, Type 3, user `MAIL-FIN-01$`. Event 4634 at line **3001**, **13:07:19.0025931Z**, preserves that LogonID, SID, username and type. The short network-session duration is plausible.
- The DC-01 process-create example agrees across Security and Sysmon: Security at line **1023** identifies `NewProcessId=0xe78` and parent `0x91c`; Sysmon at line **825** identifies **3704** and parent **2332**, respectively, for `MpCmdRun.exe` and `services.exe`. The two source timestamps differ by roughly 309 ms rather than being forced to exact equality.
- All **21,936 Zeek connection UIDs** were unique within their respective sensors. Every examined DNS, HTTP and SSL row referenced an existing same-sensor connection with the same four-tuple and a timestamp inside its connection interval. File references also resolved in the supplied data.
- Certificate reuse is internally coherent: **1,236 X.509 rows** represent **186 distinct fingerprints**, and repeated fingerprints retained their certificate attributes across observations and sensors. Observation-specific timestamps, IDs and host/client flags were allowed to differ.
- Native macOS records distinguish fork, exec and exit; an exec's target can have a new PID version while keeping the PID. For example, MAC-MROSS-01 ES lines **1–3** show PID **42154** moving from inherited `launchd`, through `xpcproxy`, to Terminal, with PID versions **10 → 11 → 12**. This is richer and more useful than a generic process-create-only representation.
- Linux syslog carries credible application and authentication detail, including PAM open/close records, sudo caller UIDs, SSH key fingerprints, systemd-logind sessions and DHCP lease text. The initial close-only records on DB-PROD-01 and FILE-LNX-01 are compatible with sessions that started before this slice.

## Detailed Analysis

### Scope, provenance and method

The actual review inputs were the neutral detection briefing and files beneath `/private/tmp/log-study-rfg61n4z/data`, supplemented by official Microsoft, Apple and Zeek documentation and Apple's upstream XNU source. Generic inherited operating instructions were visible as an environment limitation; they were not evidence of origin. I did not read project files, scenarios, roadmap/worklog material, prior assessments or another reviewer's output.

I inventoried **116 data files** and used system `python3` with `/private/tmp` as the explicit working directory. I parsed all **19,003 Security events**, **11,995 Sysmon events**, **35,885 normalized eCAR records**, and the network and native macOS JSON discussed below. Automated checks covered a wider population than the manual field inspection. I did not execute commands present inside the telemetry.

I treated the visible window as a slice. Missing pre-window parents and sessions, post-window exits, selected-out Sysmon families, domain sanitization, source coverage and high source matching were not scored as synthetic indicators.

### Representative Windows field inspection

The following are concrete event starts in `DC-01.meridianhcs.local/windows_event_security.xml`, except the explicitly named mail-host example. These checks inspected actual records, not only event counts.

| Event / start line | Fields and semantics checked | Result |
|---|---|---|
| 5156 / 3 | Decimal `ProcessID`, device-form `Application`, numeric protocol, direction/layer resource tokens | Credible shape; inbound DNS process association is supported by Sysmon. |
| 4769 / 167 | Service computer account, service SID, ticket options/encryption, mapped IPv4 address | Credible v0 fields. |
| 4768 / 368 | Target SID, `krbtgt`, preauthentication, client address/port, certificate placeholders | Credible v0 fields. |
| 4688 / 1023 | v2 creator/new process IDs, target-subject split, parent name, mandatory SID | PID conversion matches Sysmon. |
| 4689 / 1107 | Process ID/name, subject and exit status | Corresponds to the checked process termination. |
| 4624 / 2866 | v2 target SID, Type 3, Kerberos fields, address and LogonID | Credible successful network logon. |
| 4634 / 3001 | Target identity, type and LogonID | Matches the preceding checked logon. |
| 4776 / 3483 | NTLM package, workstation, account and result | Credible credential-validation shape. |
| 4779 / 12952 | Account/domain, `LogonID`, RDP session name, client address | Uses event-specific field names. |
| 4672 / 13935 | Service SID, subject LogonID, multiline privileges | Credible privilege assignment. |
| 5140 / 19445 | Subject LogonID, source endpoint, share/local paths and mask | Credible share-access shape. |
| 4648 / 21008 | Subject/target account split, caller process, target server | Contains explicit-credential caller information. |
| 4771 / 73614 | Target SID, Kerberos failure status, preauth and client tuple | Failure keyword is present; wrong-password status is plausible. |
| 4697 / 177183 | Subject, service name, image path, type/start/account | Credible service-installation fields. |
| 4720 / 186510 | New account SID, account attributes and old/new SAM flags | Stable identity across the subsequent account events. |
| 4724 / 186567 | Target and subject identities | Same new account SID. |
| 4738 / 186603 | Attribute changes, password-set time, old/new SAM flags | Did not confuse SAM flags with AD's different flag layout. |
| 4728 / 187119 | Member DN/SID and target group SID | Domain Admins RID 512 and member SID align. |
| 4698 / 191703 | Task name and embedded task XML | Embedded XML parses; v0 was not penalized without host-release proof. |
| 4625 / MAIL-FIN-01:12225 | Failure status, substatus and reason | Reason mapping concern described above. |

I also inspected Event 1102 beginning at **DC-01 Security line 267884**. It uses source-specific clear-log payload semantics rather than an ordinary EventData account event, and its EventRecordID is **1**. Subsequent low record numbers are compatible with clearing the channel; I did not flag their reset as impossible ordering.

Across all supplied Sysmon files, a check keyed on visible ProcessGuid identities found no dependent event before that identity's visible Event 1 and no subsequent dependent event after its visible Event 5, using source `UtcTime`. The check included source/target process references on access and remote-thread events. This is a bounded consistency result, not proof that every parent existed or that unobserved events were collected.

The failure-reason concern is materially different: it is a disagreement within the same native event. Disabled and locked-out are different account conditions, and substatus-based detections should not silently be taught a locked-out textual label. A real exporter or sanitizer could introduce such a problem, which is why I classified it as a format/semantic defect and kept the authenticity verdict inconclusive.

### Zeek and transport/application consistency

Sensor connection populations were **12,162 core**, **9,382 DMZ**, and **392 DB**. The interval/tuple check covered **4,235 DNS**, **4,631 HTTP**, and **3,059 SSL** records. No tested application row fell before the referenced connection opened or after its observed duration, and no tested four-tuple disagreed with that connection.

For **2,318 files.json rows**, I checked single-connection file observations against connection direction and byte totals. There was no observed file payload larger than its direction's connection payload; transmitter identities agreed with `is_orig`, and file-observation intervals remained inside connection intervals. Basic transport checks also found no positive payload with zero packets and no IP-byte total below the corresponding payload total. These findings support useful training correlations without treating completeness itself as evidence of either origin.

Representative source-native details include `zeek-core/conn.json:1` (`uid=C811ndvH4HplPDAtP9L`, UDP/53) and `zeek-core/dns.json:1`, which share the tuple and **1793624402.512987** timestamp; the DNS RTT and connection duration are both **0.001519 s**. SSL line **1** references the certificate FUIDs found in X.509 lines **1–2**, including a leaf for LOG-MON-01 and the issuing CA. The source has distinct TCP connection, TLS handshake and certificate-observation times.

Proxy line **1** distinguishes CONNECT control-message bytes from tunnel bytes using explicit `byte_scope` and `tunnel_*` fields. I treated that as a declared custom access-log format, not a mandatory stock proxy schema. Likewise, the normalized eCAR source was evaluated on its own identity fields, not assumed to be native ES output.

### macOS and Linux interpretation

MAC-MROSS-01 has **125 ES rows** and MAC-MROSS-02 **159**, declaring message `version=11`. I checked the supplied fork/exec/exit structures, PID/PID-version continuity, per-type sequence progression and visible post-exit references. No tested same-identity action occurred after its visible exit. The **33 distinct code hashes** did not acquire conflicting signing IDs, team IDs or platform-binary flags in the supplied observations.

I did not allege a version-11 schema defect merely because older public examples have fewer fields. Apple's description of [Endpoint Security event types](https://developer.apple.com/documentation/endpointsecurity/event-types?language=objc) distinguishes event unions, and its [exec notification documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_exec?changes=la_10) identifies execution notification semantics. The Unified Log policy message at **MAC-MROSS-01 line 2**, about MeetingAssist at **15:41:53.698001+0000**, was not treated as proof that a process executed or that an authorization request was denied. The native ES source has process notifications, whereas FLOW records are in normalized eCAR.

For Linux, `APP-INT-01.meridianhcs.local/syslog.log:3–5` shows connection, accepted-key and PAM-session opening at **13:00:15.633505Z**, **13:00:22.231675Z** and **13:00:22.298841Z** for PID **2931388**, user aisha.johnson and source **10.10.1.35:65202**. That ordering is credible. Sudo lines preserve separate command and PAM facts. Boot-window completeness and optional shell histories were not assumed.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| schema_or_format | Windows Security 4625 | Three MAIL-FIN-01 failures, one repeated mapping pattern | Main concern: disabled-account numeric evidence paired with a locked-out reason token; can change detection categorization. Could also arise from a real export defect. |
| weak_signal | Sysmon PE metadata | 77/943 process-create and 25/130 image-load records have all five version fields absent | Small contribution only; recognizable Microsoft binaries with hashes/signatures deserve investigation, but missing metadata has alternative explanations. |

No dataset-wide lifecycle contradiction, generator identity leak, or demonstrated native macOS schema impossibility was established. The score reflects mixed evidence with strong practical correlation quality and localized defects, not confidence that the dataset's origin has been identified.

## Realism Score by Category

- **Field format accuracy:** 8 — Most source-native formats parse and look credible; failure-reason mapping is the clearest limitation.
- **Temporal patterns:** 9 — Tested visible process and network intervals held; source-specific latencies and lifecycle phases are present.
- **Cross-source correlation:** 9 — Tested PIDs, LogonIDs, network tuples, UIDs and certificates agree; bounded checks do not prove every possible relationship.
- **Behavioral realism:** 8 — Host/service/process details and authentication mechanisms are plausible in the inspected records.
- **Environmental consistency:** 9 — Windows, Linux and macOS evidence is differentiated, with custom normalized sources interpreted separately.

## Recommendations

- If this were synthetic, derive Event 4625 status, substatus and reason from one validated failure condition. Recheck the three MAIL-FIN-01 records against a native disabled-account example so numeric and rendered-message detections learn the same outcome.
- If this were synthetic, investigate the completely absent version metadata on the cited MpCmdRun and MpClient observations. Preserve authentic unavailable metadata when warranted; otherwise populate it from the same binary identity that supplies hashes/signature information.
- Retain the currently useful PID/LogonID/UID relationships and source-specific timing. There is no evidence-based reason from this review to add arbitrary missing companions, increase thin-source volume, or perturb correct correlations merely to make the data look messier.
