# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 83
**Synthetic-Confidence Score:** 34

## Executive Summary

The data is largely production-like at the parser, field, and correlation levels: the supplied XML and JSON parse, Windows event shapes are coherent, and broad same-identity lifecycle checks did not uncover an impossible ordering. I found a small, reproducible timing fingerprint in macOS command launches and a narrow repeated command vocabulary, but both have reasonable automation explanations; they do not establish a synthetic origin.

## Evidence For Synthetic

- [distribution_texture] Both Mac endpoint streams contain multiple shell-child launches exactly 1,000 microseconds after the preceding child exits. In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, exit/fork pairs at lines 18/19, 21/22, and 24/25 have precisely this separation; `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` has it at lines 10/11 and 13/14. Five identical delays across two separate host streams suggest a scheduling floor or constructed command-batch texture. This is a limited statistical indicator, not impossible execution: scripted or pasted commands can run this way.
- [weak_signal] The two Mac zsh histories repeat a small collection of almost identically parameterized inventory commands: `sw_vers -productVersion`, `uname -a`, `id`, `pwd`, `ls -la /Users/maya.ross/Documents`, `du -sh /Users/maya.ross/Documents`, `ps aux`, `df -h`, and the same `find ... -maxdepth 2 ... '*.pdf'`. See Mac 01 history lines 1–6, 8–15, and 17–20; Mac 02 lines 1–9 and 11–18. These repeated source-visible arguments are compatible with a small behavior pool, but the same user performing inventory on two machines is an equally viable explanation. This adds little weight independently.

## Evidence For Real

- All 77,042 supplied JSON/NDJSON rows parsed with Python's standard JSON parser; all 20 Windows event XML files parsed with a namespace-aware XML parser. These are substantive ingestion checks rather than visual judgments about the file extension.
- Windows schemas distinguish event families correctly. For example, DC-02 Security 4624 uses Version 2 and the extended logon fields, 4688 uses Version 2 with target principal and integrity label, and DC-01 1102 uses a distinct Eventlog provider and `UserData/LogFileCleared` rather than pretending it is an ordinary Security-Auditing `EventData` event.
- No visible Sysmon create/dependent/terminate reversal was found using per-host `ProcessGuid`; no visible parent GUID/PID/image mismatch was found when the parent creation was present. Likewise, matched per-host Windows logon/logoff identities did not have logoff before logon.
- Protocol evidence joins sensibly. Across all three Zeek sensors, DNS, HTTP, TLS, SMTP, and SMB file rows with an available conn UID fall within that connection's timestamp interval. HTTP request and response bodies did not exceed the joined directional TCP byte counts. Nearly all application UIDs have conn companions; the three unmatched application rows are at the end of the slice and are neutral under the supplied collection-window rule.
- Mac rows preserve distinctions a naive normalization could lose: fork child state, exec actor and target, PID-version changes on exec, credential changes, launchd/xpcproxy application launches, terminal helpers, SSH monitor/session/shell processes, and native exit status. Native ES and normalized eCAR are visibly different source representations.
- There is meaningful network noise rather than only successful sessions. For example, Zeek-core has 1,451 TCP `S` histories and 258 UDP `D` histories; Zeek-dmz has 2,474 TCP `S` histories. Gap-bearing connection histories carry nonzero `missed_bytes`, not just ornamental gap flags.

## Detailed Analysis

### Inputs, provenance, and method

I read the complete supplied briefing `/private/tmp/log-study-_yn9uggi/detection-prompt.md` and inspected only files beneath `/private/tmp/log-study-_yn9uggi/data` for the dataset analysis. I used system `python3` from `/private/tmp`, standard-library XML/JSON parsing and counters, plus primary public vendor/protocol documentation. No project tooling, source, scenario, roadmap, prior assessment, or neighboring review input was accessed. Generic inherited operating instructions were an environment limitation and were not used as authenticity evidence. Logged command strings were treated only as inert data.

Primary web searches used actual domain filters for `learn.microsoft.com`, `docs.zeek.org`, and `developer.apple.com`; direct opens used the specific official URLs cited below and RFC Editor. Search results included official Apple documentation, Apple developer forum material, and WWDC material; no forum claim was used to establish a defect. The Apple page bodies were partly JavaScript-only, so I did not claim a complete byte-for-byte eslogger schema certification or infer an unsupported native macOS schema failure.

The dataset contains 23 host directories with eCAR telemetry, ten Windows Security/Sysmon pairs, two Mac ES streams totaling 304 records, Linux syslog, shell histories, three Zeek sensor directories, ASA syslog, and Snort alerts. I parsed 77,042 JSON/NDJSON rows and every XML document. Windows totals include 12,770 Security 5156, 949 Security 4688, 873 Security 4624, 437 Security 4634, 8,185 Sysmon 3, 948 Sysmon 1, and 789 Sysmon 5. The different create/terminate counts are not a defect in a bounded slice.

### Windows source-native schema and values

The following is a concrete 20-record spot check. XML line numbers identify the opening `<Event>`; record IDs are additional stable anchors. Paths below are relative to the supplied data root. Abbreviations: `D2` = `DC-02.meridianhcs.local/windows_event_security.xml`; `D1` = `DC-01.meridianhcs.local/windows_event_security.xml`; `FS` = `FILE-SRV-01.meridianhcs.local/windows_event_security.xml`; `PP` = `WS-PPATEL-01.meridianhcs.local/windows_event_security.xml`.

| File:line / record | Type | Actual fields checked and result |
|---|---:|---|
| D2:3 / 25377457 | 5156 | Decimal `ProcessID=5272`, device-path `Application`, inbound `Direction=%%14592`, UDP `Protocol=17`, remote client `10.10.1.31:57900` to DNS endpoint `10.10.2.11:53`; coherent endpoint view. |
| D2:44 / 25377459 | 4624 | Version 2, Type 5, SID `S-1-5-19`, LOCAL SERVICE LUID `0x3e5`, Advapi, local source placeholders, extended token/link fields; coherent service logon. |
| D2:99 / 25377460 | 4672 | Subject SID/name/LUID agree with preceding LOCAL SERVICE logon; privilege names are token-style strings. |
| D2:1433 / 25377531 | 4769 | Service `DC-02$`, domain service SID, AES encryption `0x12`, IPv4-mapped client address and decimal port, Status `0x0`; plausible TGS event shape. |
| D2:1513 / 25377533 | 4688 | Version 2, hex `NewProcessId=0x1c7c`, `ProcessId=0x13fc`, WmiPrvSE child of svchost, null target principal, system integrity SID `S-1-16-16384`; coherent creation. |
| D2:1775 / 25377550 | 5140 | User LUID `0xcb5c02d`, mapped source address, SYSVOL share, local path, access mask and message tokens; coherent share access. |
| D2:1814 / 25377552 | 4634 | Same user/LUID as the visible share-session evidence; Type 3; correct target-principal shape. |
| D2:2052 / 25377559 | 4768 | `krbtgt`, domain krbtgt SID ending 502, client machine account, PreAuthType 2, Status `0x0`, empty certificate fields; plausible password-derived TGT evidence. |
| D2:3161 / 25377604 | 4689 | Hex PID `0x1c7c`, matching WmiPrvSE name and SYSTEM principal, Status `0x0`; matches observed create identity. |
| D2:3278 / 25377609 | 4776 | Native NTLM package name, machine account, source workstation, Status `0x0`; no fabricated Kerberos fields. |
| D2:60328 / 25379813 | 4771 | Failure Status `0x12`, client source/port, PreAuthType 2, failure audit keyword; internally consistent failed pre-authentication. |
| D2:98313 / 25381402 | 4779 | `AccountName`, `LogonID`, `SessionName=RDP-Tcp#5`, `ClientAddress`; event-specific names are retained. |
| D2:180967 / 25384809 | 4697 | Subject principal/LUID, service binary path, ServiceType `0x10`, demand start `3`, LocalSystem account; coherent service-install shape. |
| PP:7109 / 358567 | 4800 | Principal SID/name, `TargetLogonId=0xd919960`, `SessionId=2`; workstation-lock shape. |
| PP:7673 / 358596 | 4801 | Same principal/LUID/session as lock, later unlock; coherent pairing. |
| PP:18175 / 359018 | 4625 | Type 2, User32, `0xc000006d`/`0xc000006a`, `%%2313`, local IP placeholders; consistent local bad-password failure. |
| FS:97 / 271775 | 5145 | Detailed share fields, relative path, access mask `0x12019f`, source endpoint and subject LUID; correctly distinct from 5140. |
| FS:146 / 271776 | 4656 | Object type File, handle `0x8a164b99`, requested access, PID `0x4`, System process; coherent SMB server file handle. |
| FS:199 / 271777 | 4663 | Same handle/principal/object, used access `0x2` and `%%4417`; requested versus exercised access are distinguished. |
| FS:240 / 271778 | 4658 | Same handle and subject, later close; lifecycle references retained. |

For the versioned logon/process schemas I checked against Microsoft's [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634), and [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688) references. The observed field names, principal roles, hex identifiers and version-specific structure support successful ingestion; this does not certify every Windows value in the dataset.

DC-01 line 272496 is a useful additional edge-case check: its Event 1102 has record ID 1, an Eventlog provider, and namespaced `LogFileCleared` user data. This conforms to the distinct source layout in Microsoft's [1102 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102). The Security record-number reset therefore has visible supporting context and was not scored as an inconsistency.

### Lifecycle and timing checks

I indexed Sysmon Event 1 creations and Event 5 terminations by host plus ProcessGuid, then compared dependent Events 3, 5, 7, 11, 13 and 22 to visible endpoints. No dependent event preceded its visible creation or followed its visible termination. Visible parent process creations agreed on GUID, PID and image. Microsoft explicitly documents GUIDs as enabling correlation despite PID reuse in its [Sysmon reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

For example, DC-02 WmiPrvSE PID 7292/`0x1c7c` has Sysmon create record 1368562 at `13:03:41.7599252Z` and terminate record 1368608 at `13:06:55.9068639Z`; Security records 25377533 and 25377604 follow at `13:03:41.9227384Z` and `13:06:55.9629316Z`. These small source-observation offsets are credible; insisting that sources be timestamp-identical would be wrong.

I also checked per-host Security 4624/4634 matching and normalized eCAR actor relationships against visible process terminations. The checks found no logoff-before-logon relationship or actor evidence after a matching visible process termination. Unmatched starts/ends were neutral because collection is a slice.

The five exact one-millisecond exit-to-next-fork delays are the main remaining timing concern. Mac 02's concrete times include exit `13:37:33.139751000Z` followed by fork `13:37:33.140751000Z`, then exit `13:37:33.437983000Z` followed by fork `13:37:33.438983000Z`, and exit `13:37:33.499775000Z` followed by fork `13:37:33.500775000Z`. These concern native event timestamps and explicit parent/child identities, not an impression that activity is easy to narrate. Five examples are too few, and too compatible with automation, to justify a high synthetic score.

### Network formats and correlation

Zeek conn totals are 448 db, 12,556 core and 9,646 dmz rows. All checked packet counts have sufficient IP bytes for minimum headers. For ordinary, gap-free TCP histories `ShADadfF` or `ShADadFf`, directional IP-minus-payload byte differences were multiples of four in all 8,182 eligible connections, consistent with ordinary IP/TCP header accounting. This is a narrow consistency test, not proof of packet capture origin. The field meanings and history notation follow [Zeek's connection reference](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

Examples include db `conn.json:1`, UID `C45tbtlzyYRpqcdUeA`, application-to-database TCP/3306 with `service=mysql`, and db DNS line 1, where address answers, TTL arrays and response flags have sensible types. TLS fields distinguish TLS 1.2 ciphers from TLS 1.3 suites; resumed TLS 1.2 handshakes use shorter histories without fabricated full certificate chains. I found no TLS-version/cipher mismatch in the inspected sets. Zeek describes these fields in its [SSL reference](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html).

The unmatched application UIDs are core HTTP line 2221, dmz HTTP line 2493 and dmz SSL line 2759, all at approximately `18:59:57Z`. An application log can precede a connection summary beyond the slice boundary. I did not turn this into a missing-companion finding.

Linux syslog uses a recognizable RFC 5424 envelope, including PRI, VERSION, timestamp, host, application, process ID, NILVALUE message ID and structured-data positions. For example WEB-EXT syslog lines 292–293 show accepted public-key authentication at `13:54:54.273801Z`, then PAM session opening at `13:54:54.384682Z`, with the same sshd PID 2699953; line 353 closes that same user's session. The format interpretation follows [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html). I did not require unrelated audit sources or missing Sysmon types.

### macOS semantics and limits

The supplied ES streams declare message `version=11`, use NOTIFY `action_type=1`, and contain event types 9/11/15 with exec/fork/exit payloads. I examined actor versus target, audit token fields, executable paths, parent identities, sequence counters and same-file inode metadata. Repeated inode identities did not change executable path, size or cdhash within either host stream.

Mac 02 lines 3–12 provide a concrete launch chain: launchd forks PID 21356; that PID execs xpcproxy and iTerm2 with successive PID versions; an iTermServer child launches login and ShellLauncher before zsh. The root-to-user credential changes and preserved process start times across exec are substantially more realistic than treating every exec as a new process. Apple's [process structure reference](https://developer.apple.com/documentation/endpointsecurity/es_process_t) and [Endpoint Security WWDC overview](https://developer.apple.com/videos/play/wwdc2020/10159/) establish the distinct process/target and authorization/notification concepts used here. I did not interpret an allowed notify result as a separate policy authorization record.

Only five Unified Log rows are supplied across the two Macs. Their sparse presence is not an authenticity penalty without a declared broader collection contract. Nor did I impose network FLOW schemas on native ES records. The eCAR rows are normalized endpoint telemetry: I tested their actual JSON structure and lifecycle references, but no versioned eCAR vendor schema was supplied, so I do not claim a formal schema conformance certification.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS ES process lifecycles | Five exit/fork pairs across two hosts | Exact 1 ms delays suggest a repeated scheduling rule; moderate local concern, explainable by automation. |
| weak_signal | Mac zsh history plus matching process arguments | Both Macs, one user, repeated inventory command arguments | Small vocabulary is compatible with a behavior pool but also normal repeated inventory work; low weight. |
| hard_contradiction / contract_gap / schema_or_format | Checked Windows, Zeek, ES and eCAR relationships | Broad parser and identity checks described above | No demonstrated high-impact defect; none was added merely to force a binary verdict. |

## Realism Score by Category

- **Field format accuracy:** 9 — Valid parsing and coherent sampled Windows/Zeek fields; exact eslogger and eCAR exporter certification remains limited.
- **Temporal patterns:** 8 — Correct observed lifecycle ordering, with five repeated 1 ms shell handoffs.
- **Cross-source correlation:** 9 — Strong explicit identity, byte and time-interval consistency in checked relationships; slice-edge unmatched summaries are explainable.
- **Behavioral realism:** 8 — Plausible service, authentication and application evidence; repeated Mac command arguments have limited variety.
- **Environmental consistency:** 9 — Endpoint versus network perspectives, Windows principal roles, Linux authentication and Mac process trees are coherent in the inspected evidence.

## Recommendations

- If this were synthetic, preserve the existing identity and lifecycle alignment while replacing an exact 1 ms minimum between sequential Mac commands with an execution-path-specific model validated against real shell batches. Keep genuinely scripted batches possible; the issue is repeated fixed latency, not the presence of fast commands.
- If this were synthetic, broaden Mac command arguments only where the modeled user actually needs them. The evidence supporting this recommendation is the repeated inventory paths and flags in both zsh histories; do not add arbitrary mistakes or attack detours to manufacture realism.
- For reproducible ingestion validation, supply the exporter/version contract for normalized eCAR and the precise eslogger/OS build alongside the collection profile. This would resolve the present certification limit without requiring more source coverage or treating absent log families as defects.
