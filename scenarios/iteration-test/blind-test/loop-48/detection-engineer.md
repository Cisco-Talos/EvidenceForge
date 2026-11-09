# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 54

## Executive Summary

Most of this collection would ingest and correlate credibly in a detection stack: the Windows, normalized endpoint, and network records have strong identity and lifecycle consistency. A concrete account-change field inconsistency and a narrow repeated macOS command vocabulary make me cautious, but they do not establish that the full collection is synthetic. My score reflects mixed evidence, rather than the confidence with which I can prove the isolated field discrepancy.

## Evidence For Synthetic

- [hard_contradiction] **One account-change record describes two flag changes with only one change token.** In `DC-01.meridianhcs.local/windows_event_security.xml:196058–196061`, Event 4738, record `28257159`, at `2026-11-02T17:15:22.3256574Z`, has `OldUacValue=0x15`, `NewUacValue=0x10`, and only `%%2081` in `UserAccountControl`. The masks clear both SAM `USER_ACCOUNT_DISABLED` (`0x1`) and `USER_PASSWORD_NOT_REQUIRED` (`0x4`). Microsoft's event documentation says the change-list field contains a line for each change. This is an internally inconsistent source-native description, regardless of whether the underlying activity was legitimate. [Microsoft 4738](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4738), [Microsoft SAM account codes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec).
- [distribution_texture] **The two Mac shell histories draw heavily from the same small inventory-command vocabulary.** The 39 history entries comprise 15 distinct exact command strings, including five `/bin/ps aux`, four `/usr/bin/id`, four `/usr/bin/sw_vers -productVersion`, and four identical `find ... Documents ... '*.pdf'` commands. For reproducible examples, compare `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history:1–6,9–10,13–14,17–20` and `MAC-MROSS-02.meridianhcs.local/zsh_history/maya.ross.zsh_history:1–7,9–10,12–19`. This is a limited texture concern: the same user is using both machines, and repeated administration could explain it. It carries much less weight than the 4738 discrepancy.

## Evidence For Real

- The Windows formats are substantially faithful. For example, the examined 4624 records use version 2 and its extended fields, while 5156 uses version 1, decimal `ProcessID`, NT device paths, numeric IP protocol values, and the documented task/keyword envelope. These agree with the published examples. [Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [Microsoft 5156](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156).
- Across all 11,785 Sysmon records, checks using exact `ProcessGuid` found no visible process use before its supplied create record, no use after its supplied terminate record, and no child creation after the supplied parent's termination. Unmatched starts or ends were treated as neutral at the collection boundaries.
- Across the Security XML, SID-to-name and name-to-domain-SID checks found no conflicting mappings. For 288 relevant records referencing ordinary, non-special logon IDs, I found no supplied subject activity before its supplied non-unlock login or after its supplied logout. Repeated well-known service LUIDs and type-7 unlocks were excluded from an inappropriate one-login-per-ID assumption.
- The first file-server file operation has a convincing handle lifecycle: `FILE-SRV-01.../windows_event_security.xml:97,146,199,240` contains 5145, 4656, 4663, and 4658 at `13:00:05.9658107`, `13:00:05.9698262`, `13:00:06.1459007`, and `13:00:09.7044242Z`; the handle is consistently `0x1b169349`, the file path agrees, and the executed access mask `0x2` is within the requested `0x12019f`.
- Zeek connection data includes failed attempts, resets, retransmissions, and explicitly represented gaps rather than only successful traffic. Payload/IP-byte arithmetic passed the checked lower bounds, and content-gap history flags consistently had nonzero `missed_bytes`. This is meaningful source-native consistency, rather than treating complete matching as an authenticity clue.
- The macOS records distinguish native fork, exec, and exit events from normalized endpoint PROCESS records. The first Mac's first three ES rows preserve PID `42152` through launchd → xpcproxy → Terminal exec transitions while changing image and PID version. That is considerably more realistic than modeling every exec as a new PID.

## Detailed Analysis

**Inputs and independence.** Actual inputs were the full supplied neutral briefing at `/private/tmp/log-study-gel6klid/detection-prompt.md`, file inventories and file contents only under `/private/tmp/log-study-gel6klid/data`, and the primary public documentation linked in this report. I parsed all 19,030 Security XML and 11,785 Sysmon XML records; inspected the normalized eCAR JSON, all supplied Zeek JSON families, both native macOS ES files and Unified Log files, both zsh histories, and sampled Linux syslog, firewall, IDS, proxy, and web records. No project source, scenario, TODO, AGENTS file, worklog, prior assessment, or another reviewer's results was opened. Generic inherited operating metadata is an independence limitation and was not used as evidence about origin. Logged commands were treated only as inert data.

**Windows event inspection.** I inspected more than twenty distinct event shapes, including Security 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4768, 4769, 4771, 4776, 4697, 4720, 4738, 5145, 4656, 4663, 4658, and 1102, plus Sysmon 1, 3, 5, 7, 8, 10, and 22. Representative reproducible checks:

| Source and location | Observed fields / result |
|---|---|
| DC-02 Security, record 25377478, `13:00:52.1498733Z` | 4624 type 5, LOCAL SERVICE SID `S-1-5-19`, LUID `0x3e5`, Advapi/Negotiate; no remote IP required for this service logon. |
| DC-02 Security, `13:01:27.6928621Z` | 4769 uses `TicketEncryptionType=0x12`, `Status=0x0`, IPv4-mapped client address and a domain-computer service SID. |
| DC-02 Security, `13:05:37.8741801Z` | 4768 has `ServiceName=krbtgt`, RID 502 service SID, `PreAuthType=2`, and empty certificate fields; no certificate-auth assumption imposed. |
| DC-02 Security, `14:53:08.9599020Z` | 4771 failure has failure keyword `0x8010000000000000` and `Status=0x18`. |
| DC-02 Security, `16:03:46.0720516Z` | 4625 type 3 carries `Status=0xc000006d`, disabled-account substatus `0xc0000072`, and remote source address/port. |
| DC-02 Sysmon XML:2490 | Event 1 has decimal PID `7132`, parent PID `5116`, SYSTEM context, SHA1/MD5/SHA256/IMPHASH fields of appropriate lengths, and millisecond `UtcTime`. |
| DC-02 Security, `13:07:04.7804805Z` | 4688 represents the same dllhost process as hexadecimal `NewProcessId=0x1bdc` and parent `ProcessId=0x13fc`; these convert to 7132 and 5116. |
| DC-02 Sysmon XML:158 | Event 5 has process GUID, PID, image and user rather than borrowing a process-create field structure. |
| DC-01 Security XML:270291 | 1102 uses the Eventlog provider and `UserData/LogFileCleared`, with Security record ID reset to 1. This is a source-specific detail handled credibly. |
| DC-01 Security XML:196014 | The 4738 envelope is plausible, but mask/change-list semantics disagree as described above. |

The 4738 issue matters to rules that detect changes to password requirements: a detector using the old/new mask can derive a different set of changes from a detector using the translated change list. I have not converted this one affected record into a claim that all Windows events are invalid. Export processing or a faulty field transformation could also produce a local discrepancy in otherwise real telemetry.

**Network and application correlation.** I indexed the 12,314 core, 9,401 DMZ, and 433 database conn rows by UID. Every directly UID-bearing protocol record checked had a matching conn row and matching four-tuple. Protocol timestamps fell within the corresponding connection interval with a two-second tolerance; this is a bounded consistency check, not proof about packet-level chronology. Fields with different join semantics, such as `files.conn_uids`, DHCP `uids`, and certificate `id`, were not misrepresented as direct `uid` joins.

For example, `zeek-core/conn.json:1` and `dns.json:1` share UID `Cuq507OFNo7MpYfALL`, UDP endpoints `10.10.1.31:51161 → 10.10.2.11:53`, and `0.028925` seconds for connection duration / DNS RTT. The conn row has one packet per direction and IP byte counts exactly 28 above the corresponding UDP payload sizes. These field semantics follow the [Zeek connection reference](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

The SSL collection also respects an important visibility distinction: TLS 1.3 rows have no certificate-chain FUIDs, while non-resumed TLS 1.2 rows can have them. `zeek-core/ssl.json:10` is a TLS 1.3 example with `ssl_history=Cs`; `ssl.json:1` is a non-resumed TLS 1.2 example with server certificate references. I found no TLS-version/cipher contradiction in the examples reviewed. The history alphabet was interpreted using the [Zeek SSL reference](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html), not the unrelated conn history alphabet.

**macOS and Linux interpretation.** The ES exports declare message version 11 and contain only fork/exec/exit shapes. Both per-type and global sequence numbers were inspected; global sequence order increased in both files. I did not infer missing native file or authorization events from their absence, and did not impose Windows or normalized FLOW requirements on native ES messages. Apple's documentation distinguishes the event-specific target process from general message metadata; its [exec documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t) and [event-types documentation](https://developer.apple.com/documentation/endpointsecurity/event-types) support that separation. I did not establish the exact OS build from the records and therefore do not score unfamiliar version-dependent fields as defects.

The Unified Log policy line at `MAC-MROSS-01.../macos_unified_log.ndjson:2` says policy “would not allow” MeetingAssist. That sentence alone is not proof that execution was denied, and I did not use it to allege an impossible child or file effect. Native Unified Log rows and normalized eCAR observations were kept semantically separate.

Linux examples use RFC5424-style headers, PAM session language, sshd key fingerprints, and service-specific process IDs. Examples include `MAIL-EDGE-01.../syslog.log:51` successful public-key SSH and `DB-PROD-01.../syslog.log:101` a PAM session open. I did not require a full boot, complete auth facility, or other unprovided event families merely because these systems could produce them.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---|---|
| hard_contradiction | Windows Security 4738 | One record, DC-01, `17:15:22.3256574Z` | Material: numeric SAM flag delta and textual change list disagree. A real export defect remains an alternative explanation. |
| distribution_texture | Mac zsh history | 39 entries across two hosts used by the same user | Small: repeated exact generic command vocabulary; explainable by recurring administration. |

No score was assigned for attack linearity, completeness, narratability, lack of mistakes, matching references, sanitized domains, shared filesystem timestamps, absent Sysmon event types, or thin source coverage.

## Realism Score by Category

- **Field format accuracy:** 8 — Strong native structures and types, with the isolated 4738 semantic discrepancy.
- **Temporal patterns:** 9 — No impossible visible process or ordinary-session ordering found in the checks performed.
- **Cross-source correlation:** 9 — PID representations, handle identities, network UIDs and tuples agree in tested relationships.
- **Behavioral realism:** 7 — Broad service activity is credible; the two Mac histories have a noticeably narrow repeated command vocabulary.
- **Environmental consistency:** 9 — Mixed-platform evidence is internally compatible in the examined records; no demonstrated host-role contradiction.

## Recommendations

- If this were synthetic, derive Event 4738 `OldUacValue`, `NewUacValue`, and every `UserAccountControl` change entry from one account-state transition. A transition clearing both `0x1` and `0x4` should represent both changes consistently; changing only the enablement state should preserve the other bit.
- If this were synthetic, broaden Mac shell activity according to observable task context rather than repeatedly choosing the same exact inventory commands. Preserve legitimate repeated administration where intended; the specific target for improvement is the measured 39-entry / 15-command vocabulary, not a requirement for arbitrary complexity.
- Preserve the demonstrated distinctions between process lifetime and exec image, ordinary sessions and special Windows LUIDs, handle lifecycle phases, and TLS 1.2 versus TLS 1.3 sensor visibility. These are strengths of the supplied records.
