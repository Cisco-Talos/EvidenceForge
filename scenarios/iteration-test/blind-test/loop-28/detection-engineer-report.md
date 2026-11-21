# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 75
**Synthetic-Confidence Score:** 28

## Executive Summary

The supplied records look substantially production-like from a detection engineering perspective: the native schemas parse, process identities survive cross-event joins, and the tested visible lifecycles do not contradict their initiators. I found weak behavioral repetition and a small number of unresolved Zeek references, but neither establishes synthetic origin under the stated collection assumptions; the evidence supports a low synthetic appearance score without a confident provenance verdict.

## Evidence For Synthetic

- [weak_signal] The two Mac shell histories reuse a small administrative vocabulary with very similar arguments. Both `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` and the equivalent MROSS-02 file include `/usr/bin/find /Users/maya.ross/Documents -maxdepth 2 -type f -name '*.pdf'`, `/usr/bin/id`, `/usr/bin/uname -a`, `/bin/ps aux`, and `/bin/df -h`. This could reflect a shared command pool, but the same user operates both machines and the commands are commonplace. This is weak evidence only, not a demonstrated generation artifact.
- No hard contradiction, impossible visible lifecycle ordering, or generator identity leak was demonstrated in the checks below. In particular, I do not count source completeness, scheduled cron repetition, domain sanitization, or an easy-to-follow suspicious sequence as synthetic indicators.

## Evidence For Real

- Windows event shapes vary correctly by source and event: DC-01 Event 1102 at `2026-11-02T18:42:20.0702537Z` uses the Eventlog provider and namespaced `UserData/LogFileCleared`, while Security-Auditing events use named `EventData` fields. Its record ID is 1, consistent with a cleared log rather than a malformed ordinary Security-Auditing row.
- DC-02's `4624` at `13:04:44.0171612Z` is an NTLM Type 3 logon for `diego.ramirez`, with `NtLmSsp`, `NTLM V2`, workstation `WS-DRAMIREZ-01`, source `::ffff:10.10.1.34:51922`, and LogonID `0xcb5c02d`. Event 5140 and the subsequent 4634 preserve that session identity and source information.
- Process events preserve identity across source-native events. The dataset-wide Sysmon join found no ProcessGuid mapping to multiple PIDs, no dependent event before its visible creation, no dependent event after visible termination, and no child created after its visible parent termination.
- Zeek contains varied connection outcomes and imperfect collection, not just successful sessions: core `conn.json` includes 1,670 S0, 435 OTH, 156 RSTO, 104 RSTR, and 44 REJ records among 12,230 connections. Protocol records with matching connections preserve all four tuple fields and fall within the tested connection intervals.
- Native macOS ES observations distinguish fork, exec, and exit. For example, MROSS-02 PID 88252 first appears as a launchd fork child, then execs xpcproxy, then iTerm2, with successive PID versions and changing executable/signing metadata. The normalized eCAR stream separately records execution generations rather than treating every exec as a new PID.
- Linux sudo records retain plausible command, PAM, and timing relationships. MAIL-EDGE-01's `sudo[2284020]` command at `13:00:20.836610Z`, PAM open at `13:00:20.946540Z`, and close at `13:00:23.820886Z` agree with eCAR's command and process ownership.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory after reading the designated instructions. I parsed all 17,780 Windows Security XML events and 11,606 Sysmon XML events, all eCAR files, the three Zeek directories, both native macOS ES files, and samples of Linux syslog, shell history, firewall, and other protocol records. The network directories contain 23,141 connection rows in total: 430 database-sensor, 12,230 core-sensor, and 10,481 DMZ-sensor observations. The native ES files contain 144 and 163 records.

The automated checks were bounded to relationships actually visible in the slice. I did not require an absent creation for a preexisting process, a logon for a preexisting session, or a termination beyond the collection window. Parser success establishes structural usability, not complete conformance to every possible vendor version. I did not consult external schema documentation, so unfamiliar version-specific details are not asserted to be defects.

### Windows schemas and field semantics

I inspected representatives of more than twenty event types, including Security 1102, 4624, 4625, 4634, 4648, 4656, 4658, 4663, 4672, 4688, 4689, 4697, 4698, 4720, 4768, 4769, 4771, 4776, 4800, 4801, 5140, 5145, and 5156, and Sysmon 1, 3, 5, 7, 8, 10, 11, 13, and 22.

The Security events generally have Level 0, Opcode 0, the Security-Auditing provider GUID, success/failure keyword distinctions, hexadecimal logon and process identifiers, and appropriately named event data. A local failed Type 2 logon on WS-PPATEL at `17:11:56.5878667Z` uses `User32`, `Negotiate`, winlogon, no network source, Status `0xc000006d`, and SubStatus `0xc000006a`. This is meaningfully different from DC-02's NTLM network logon.

DC-02 Event 4688 at `13:01:05.9719627Z` describes WmiPrvSE PID `0x1a94` with parent PID `0x13fc`, parent `svchost.exe`, SYSTEM subject, `%%1936` token elevation, and mandatory label `S-1-16-16384`. Its Sysmon counterpart has decimal PID 6804, parent 5116, the same executable and command, System integrity, and process/parent GUIDs. The source timestamps differ by roughly a tenth of a second, which is compatible with distinct observation timing. Windows paths contain ordinary single separator characters after XML parsing; display escaping is not a path defect.

File auditing also retains native structure. FILE-SRV's `5145` at `13:00:05.9658109Z` identifies source `10.10.1.31:53486`, share `ClinicalExports`, relative name `Servers\archive-final.bak`, and access mask `0x12019f`. Event 4656 at `13:00:05.9709815Z` allocates handle `0xb013d0ff`; 4663 records access at `13:00:06.1459007Z`; 4658 closes the same handle at `13:00:09.7044244Z`. These are separate, causally ordered records rather than interchangeable file events.

All 11,773 Event 5156 records use coherent inbound/outbound layer combinations: 6,709 inbound `%%14592` / Receive-Accept `%%14610` / layer 44, and 5,064 outbound `%%14593` / Connect `%%14611` / layer 48. Application fields use device paths, and ProcessID is decimal, appropriately distinct from hexadecimal Security process-creation fields.

Sysmon events use the Sysmon provider/channel, Level 4, decimal PIDs, braced GUIDs, and per-event data. Event 10 uses `SourceProcessGUID`/`TargetProcessGUID`; Event 8 uses `SourceProcessGuid`/`TargetProcessGuid`. A parser that indiscriminately normalizes capitalization could obscure these source-native distinctions. DNS Event 22, process-access masks/call traces, image-load signature fields, and registry SetValue shapes were present and parseable. I did not penalize any absent Sysmon type.

### Windows lifecycle and authentication joins

Of 388 visible 4634 events, 383 have a visible 4624 with the same host-local LogonID. The five without a visible logon are compatible with pre-window sessions. No matched logoff predates its first visible matching logon, and the matched identity does not switch username or SID. A separate 4689-to-4688 PID check found no termination whose only visible matching creation lies later.

The stronger GUID-based Sysmon checks found no PID mutation for the same GUID, image mismatch for a visible creation GUID, dependent-before-create relationship, dependent-after-termination relationship, or child-after-parent-exit relationship. eCAR checks likewise found no dependent timestamp before a matching visible PROCESS/CREATE, and no activity more than 100 ms after matching PROCESS/TERMINATE. These results support detection usability; high matching rates are not evidence of synthetic generation.

Kerberos and NTLM were not collapsed into one generic schema. DC-02 4768 records include krbtgt, preauthentication type, ticket encryption, and client address/port. Event 4769 carries service identity, ticket options, encryption, logon GUID, and transmitted services. Event 4771 carries failure status `0x18`, and 4776 uses `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation, and status. Previously cached tickets and pre-window sessions mean that every observed service ticket or logon need not have a new visible TGT.

### Zeek and network correlation

For DNS, HTTP, SSL, SMTP, and SMB records that reference a visible conn UID, I compared origin/responder addresses and ports. No tuple mismatch appeared. I also checked protocol timestamps against connection start and duration, allowing 10 ms at the start and 500 ms at the end; none fell outside these bounds. Those tolerances are stated because this check does not establish submillisecond wire ordering.

TCP payload counts never exceeded their respective IP-byte counts, and no TCP direction claimed positive payload with zero packets. Connection states, transport protocols, and service distribution vary by sensor: the database sensor is dominated by MySQL (273/430), whereas the core has DNS, Kerberos, LDAP, SMB, HTTP, and mail, and the DMZ has substantial HTTP/SSL traffic and unsuccessful connections. That is compatible with different network roles.

A representative DB proxy connection UID `CejGkF1Vxdvx1XEH8` starts at epoch `1793624609.669453`, carrying `10.10.4.10:42023` to `10.10.3.20:8080`. Its HTTP record at `1793624609.745278` is a CONNECT receiving 407, with a 753-byte HTML response and FUID `FQ0iz2f8E8pfvGFcC`. The files row at `1793624609.803541` records the proxy as transmitter, the DB host as receiver, and 753 bytes. This would support useful proxy-authentication and file joins.

I found 13 HTTP file references without a files row in the same sensor directory: six core and seven DMZ. For example, core HTTP row 310 at epoch `1793627880.147836` has UID `CgBPYANzYH4mXpVjAO`, GET `/about`, response length 65,300, and FUID `FcbDE1N9ivu5iMLyHD`, absent from that directory's files file. Core SMB mapping row 93 at `1793640924.871449` references UID `C4bqaKVpaYQLPkuTrz`, absent from core conn. These impair an exhaustive local join but are not independently authenticity indicators: selective logging, file filtering, rotation, or record loss can explain them, and no claim of complete collection accompanies the data. I have not scored them as contradictions or assumed a missing source is an error.

### Linux, macOS, and normalized endpoint semantics

Linux records use plausible RFC5424-style framing, facilities, process tags, PAM messages, and collection-time precision. Sysstat runs are repetitive: ten Linux hosts each show 36 `debian-sa1 1 1` creations and 36 associated shell invocations. Over a six-hour window that is compatible with a ten-minute schedule. MAIL-EDGE-01 CRON records at `13:05:00.242634Z`, `13:15:00.268100Z`, `13:25:00.174519Z`, and `13:35:00.288545Z` directly support that interpretation; WEB-EXT uses a one-minute different phase. Some syslog command companions are absent, which I do not assume is an error. Equal counts here are not persuasive evidence of synthesis.

Both macOS ES streams declare schema version 1, message version 11, notification action type 1, and event-specific payloads for exec (9), fork (11), and exit (15). Each event-type sequence is contiguous from zero. I checked actor executable paths against prior visible fork-child and exec-target identities keyed by `(pid,pidversion)` and found no mismatches. In MROSS-02's initial chain, PID 88252 changes from launchd to xpcproxy to iTerm2 while its PID version advances from 6461355 to 6461356 to 6461357. The audit-token identity and executable fields are not treated as interchangeable with normalized eCAR process UUIDs.

MROSS-01's Unified Log at `15:42:09.009673+0000` says the security policy would not allow MeetingAssist PID 42008. I found no native ES record containing that application path; I therefore do not infer successful execution or an executed child from the policy message. The Unified Log's kernel writer and AppleSystemPolicy sender are appropriately distinct. Sparse native Unified Log coverage is not itself an indicator of synthesis.

The shared Mac command vocabulary remains the only positive, albeit weak, synthetic suggestion. These are two machines used by the same person, and there is no impossible value, wrong native event shape, or causal inversion associated with that repetition. It has little weight in the verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | macOS zsh histories | Two hosts operated by `maya.ross`; repeated administrative commands and argument strings | Small residual concern about behavioral variety; readily explained by a shared operator |
| No demonstrated hard contradiction | Windows, Sysmon, eCAR, Zeek, native ES | The visible identities and lifecycles tested above | Prevents a high synthetic-confidence score; does not prove real provenance |

Unresolved Zeek references and absent out-of-window initiators are collection limitations, excluded from the synthetic indicator score.

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON parse successfully, native event shapes vary appropriately, and no demonstrated schema defect emerged from the sampled types.
- **Temporal patterns:** 9 — Tested visible lifecycles are ordered coherently; scheduled repetition has a plausible operational explanation.
- **Cross-source correlation:** 9 — Process identities, session identities, and connection tuples are consistent; a small number of unresolved Zeek references limits exhaustive joining.
- **Behavioral realism:** 8 — Host roles and authentication mechanisms vary plausibly, with modest residual concern about repeated Mac command vocabulary.
- **Environmental consistency:** 9 — Native Windows, Linux, and macOS semantics remain distinct, and sensor traffic distributions fit different roles.

## Recommendations

- If this were synthetic, expand ordinary Mac command/argument variety only where the visible common operator's actual workflow warrants it; preserve the existing correct fork/exec/PID-version relationships.
- If this were synthetic and intended to represent complete Zeek log-family collection, reconcile the 13 dangling HTTP FUID references and the single SMB mapping UID. If the intended profile permits filtering or record loss, retain the gaps and make that collection assumption available to downstream evaluators; the records alone do not justify repairing them.
- No mandatory source-native schema or lifecycle correction is supported by this review. Preserve the distinct Event 1102 UserData schema, Windows identifier representations, Mac notification semantics, and source-specific timing when making any changes.
