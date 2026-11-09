# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 94
**Synthetic-Confidence Score:** 81

## Executive Summary

Most records should ingest and correlate successfully in an ordinary detection stack: the Windows XML, Zeek JSON and endpoint records have substantial source-specific detail and coherent visible lifecycles. However, both native macOS Endpoint Security exports contain newly allocated process-generation values that run backward while their kernel clocks and event sequence numbers advance, contradicting the host-wide allocator represented by those fields. This is a concrete native identity defect, rather than an inference from attack narrative or collection completeness.

## Evidence For Synthetic

- [hard_contradiction] `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 46 and 49: the child of a NOTIFY_FORK at `2026-11-02T14:34:22.665490000Z` has PID `53438`, `pidversion=54`, but a later new child at `14:38:20.924113000Z` has PID `54162`, `pidversion=48`. Their `mach_time` values advance from `25019103971760` to `25024822178712`; `global_seq_num` advances from 45 to 48; each child's `start_time` equals its displayed fork time. This is not reuse of an old generation in an exit record. The same file repeats the problem at lines 90 and 92: new-child generations 81 then 77 at `16:20:51.905655000Z` and `16:34:18.540152000Z`.
- [hard_contradiction] The same allocator inconsistency occurs independently in `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`: lines 88 and 93 show newly forked PID `44149` with generation 83 at `15:47:27.396195000Z`, followed by newly forked PID `44833` with generation 79 at `15:54:39.807415000Z`. Kernel ticks advance from `56228337508680` to `56238715377960`; global sequence numbers advance from 87 to 92. Lines 114 and 120 provide another separated example: generation 108 at `17:10:43.515652000Z`, then 96 at `17:19:04.671053000Z`. These are repetitions of one defect family, not four independent scoring penalties.

## Evidence For Real

- All 74,198 JSON/NDJSON records parsed, and all 20 Windows XML documents parsed, containing 30,998 events. Native JSON numbers, booleans and arrays are retained rather than flattened indiscriminately into strings.
- Across `zeek-core`, `zeek-db` and `zeek-dmz`, every examined protocol record carrying a `uid` found its local `conn.json` row with the same endpoint tuple. Protocol timestamps were inside the associated transport interval under a 1 ms start tolerance and 100 ms end tolerance. This is positive evidence of useful correlation, not a synthetic indicator.
- All Windows Sysmon records carrying `ProcessGuid` were checked against visible Event 1 and Event 5 rows on the same host: no corresponding observation occurred before its visible creation or after its visible termination. Processes whose initiation is outside the slice were not counted as defects.
- `DC-02.meridianhcs.local/windows_event_sysmon.xml`, EventRecordID `1368562` (line 757), creates `WmiPrvSE.exe` PID 7292; its termination is EventRecordID `1368607` (line 1917). Security 4688 and 4689 on the same host use hexadecimal PID `0x1c7c` and the same image, with plausible source timing differences.
- File access records have meaningful lifecycle details. `FILE-SRV-01.meridianhcs.local/windows_event_security.xml`, records `271775`–`271778`, progresses through share access checking (5145), handle request (4656), object access (4663) and handle close (4658), retaining handle `0x8a164b99`, user `marcus.chen` and logon `0xf62b74b` where applicable.
- The macOS records distinguish pre-exec actor from post-exec target and preserve same-PID image replacement. For example, MAC-MROSS-01 lines 2–3 show launchd-derived PID 42154 becoming `xpcproxy`, then Terminal, with successive process-generation values and the original process start time retained. I did not mistake the top-level actor for the executed target.

## Detailed Analysis

### Input provenance and scope

I read the supplied neutral briefing and files under `/private/tmp/log-study-boe6lty3/data` only, using system `python3` from `/private/tmp` for parsing. I did not inspect repository code, scenarios, worklogs, prior assessments or other reviewer reports. External references were official vendor/protocol documentation and upstream source, reached with direct URLs or a domains-filtered search. Generic inherited operating context was not used as evidence of origin.

The directory contains 116 files spanning Windows Security and Sysmon, Linux syslog and histories, eCAR, native macOS Endpoint Security and Unified Log, Zeek, proxy/web access, ASA and Snort. The visible records are from a time slice on 2 November 2026. I treated out-of-window starts/ends, source selection and domain sanitization as neutral. XML line numbers below identify the beginning of the event; EventRecordID provides a second reproducible locator.

### Native macOS identity semantics: decisive finding

The macOS files declare `schema_version=1`, message `version=11`, numeric event types 9/11/15 and action type 1, with event objects for exec/fork/exit. They include full audit tokens, process/file metadata and nanosecond-formatted times. These are native-style Endpoint Security records, not network observations or generic EDR FLOW rows.

The decisive invariant is allocator behavior. Apple's upstream XNU `forkproc` allocates a newly created process's `p_idversion` by atomically incrementing the shared `nextpidversion` counter. The non-fork exec-clone case is separate. See [Apple XNU kern_fork.c](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_fork.c), specifically the new-process allocation around lines 902–929. Apple's [audit_token documentation](https://developer.apple.com/documentation/endpointsecurity/es_process_t/audit_token) identifies this token as the process auditing identity.

I therefore compared `event.fork.child.audit_token.pidversion` only at new-child allocation observations, rather than expecting every occurrence of an old parent's token to increase. Among 40 fork rows on MAC-MROSS-01, there are two downward transitions between successive observed fork allocations. Among 50 on MAC-MROSS-02, there are eight. The several-minute examples cited above avoid an argument about tiny scheduler races around concurrent creation. The observation order is corroborated by wall time, monotonic kernel time, sequence numbers and child start times. A wall-clock adjustment cannot explain them; old actors legitimately retaining old tokens cannot explain them either. A full 32-bit counter wrap is not a credible explanation for these repeatedly small decrements within minutes.

This is a host-global identity-field contradiction. It does not allege that one unrelated process caused another, nor rely on a missing pre-window event. The report does not penalize the low absolute generation numbers independently: anonymization could remap identifiers. A documented non-order-preserving sanitization of all process generations could explain this specific defect in otherwise real data, but none was supplied; that possibility keeps verdict confidence below certainty.

The limited Unified Log files do not independently establish denied execution. In particular, MAC-MROSS-01 Unified Log line 2 contains an AppleSystemPolicy message saying policy “would not allow” a process. I have not converted this into proof that an ES notification could not exist or that child execution was denied. Sparse Unified Log coverage is not penalized.

### Windows schema and lifecycle verification

I inspected representative fields for 20 distinct event types, as follows. These are successful shape/semantic spot checks, not a claim of exhaustive manifest certification for every installed Windows/Sysmon version.

| Source and event | Reproducible locator | Check and result |
|---|---|---|
| DC-02 Security 4624 v2 | line 1274, record 25377537 | Service LogonType 5; SYSTEM SID/logon 0x3e7; Advapi; no remote IP required. |
| DC-02 Security 4634 | line 1549, record 25377552 | Target identity/logon fields and Type 3 shape are appropriate. |
| DC-02 Security 4688 v2 | line 1149, record 25377530 | NewProcessId 0x1c7c, creator PID 0x13fc, parent image, mandatory label and target-subject placeholders present. |
| DC-02 Security 4689 | line 2938, record 25377606 | Same PID/image as the WMI creation; success status 0x0. |
| DC-02 Security 4768 | line 1918, record 25377565 | krbtgt service, domain SID, AES type 0x12, preauth type 2, mapped IPv4 address and numeric port. |
| DC-02 Security 4769 | line 1069, record 25377527 | Service account/SID, ticket options, encryption and status fields are structured for a service-ticket event. |
| DC-02 Security 4776 | line 2288, record 25377579 | NTLM package, account, workstation and status fields. |
| FILE-SRV-01 Security 5145 | line 97, record 271775 | Share name, local path, relative target, mask and source tuple are distinct fields. |
| FILE-SRV-01 Security 4656 | line 146, record 271776 | File object, handle, access list/mask and requester identity. |
| FILE-SRV-01 Security 4663 | line 199, record 271777 | Same handle/object; actual write access 0x2. |
| FILE-SRV-01 Security 4658 | line 240, record 271778 | Same handle closes after access. |
| DC-02 Sysmon 1 | line 757, record 1368562 | GUIDs, decimal process IDs, image, parent, user, integrity and multiple hash algorithms. |
| DC-02 Sysmon 3 | line 3, record 1368530 | UDP/DNS tuple, Initiated=false on receiving DNS host, port/IP fields and source/destination roles. |
| DC-02 Sysmon 5 | line 1917, record 1368607 | GUID/PID/image agrees with visible creation. |
| DC-02 Sysmon 7 | line 49416, record 1370345 | Loaded DLL distinguished from process image; signing and signature-status fields. |
| DC-02 Sysmon 8 | line 8092, record 1368804 | Separate source/target identity, thread ID, address, module and function. |
| DC-02 Sysmon 10 | line 442, record 1368549 | SourceProcessGUID/TargetProcessGUID casing, access mask and call trace. |
| DC-02 Sysmon 11 | line 69756, record 1371093 | Creator process, TargetFilename and CreationUtcTime. |
| DC-02 Sysmon 13 | line 47062, record 1370247 | SetValue, registry target and DWORD Details. |
| DC-02 Sysmon 22 | line 163, record 1368537 | DNS query, numeric result status and SRV result representation. |

The 4688 v2 structure agrees with [Microsoft's documented event schema](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688), including target-subject and mandatory-label additions. Repeated workstation logon IDs initially warranted inspection, but were Type 7 unlock records retaining an existing interactive identity: for example WS-AJOHNSON-01 `0x25f0f66` appears as Type 2 at `14:04:23.8377293Z` and Type 7 at `15:33:46.5508299Z` and `18:35:04.2855900Z`. I did not score this as independent duplicate session creation.

### Network and SIEM ingestion checks

There are 21,936 Zeek connection rows: 12,162 core, 392 DB and 9,382 DMZ. I checked protocol UID existence/tuple agreement in each sensor independently, avoiding an assumption that sensors must share the same UID namespace. No mismatches were found. No conn row had IP byte totals below its corresponding payload byte totals in the simple sanity check. These checks support useful transport/protocol correlation but do not prove the captured packet accounting in every row.

`zeek-core/conn.json` line 1 and `dns.json` line 1 share UID `C811ndvH4HplPDAtP9L`, UDP source `10.10.1.31:57900`, destination `10.10.2.11:53`, and the same initial timestamp. Payload accounting is plausible for this DNS exchange: 46/167 payload bytes, 74/195 IP bytes, one packet each direction and history `Dd`. The SRV query has arrays for answers and TTLs. The transport interpretation and first-packet timestamp agree with [Zeek's Conn::Info documentation](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

HTTP CONNECT rows retain authority-form targets, e.g. `clients6.google.com:443` and status 200 in core HTTP line 1; proxy access line 1 records the same client and authority while distinguishing control-message from tunnel byte accounting. Such a customized proxy log format is not itself a schema error. SMB files/mapping, TLS certificates, PE metadata and SMTP records contain source-specific structures rather than a common flattened template. Linux syslog uses a recognizable RFC5424-style envelope and distinct application writers. I did not find a demonstrated schema defect in these spot checks and did not infer native macOS endpoint requirements from Zeek traffic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Native macOS Endpoint Security audit-token identity | Both hosts: 2 and 8 downward transitions among successive observed new-child generation allocations, with separated multi-minute examples | Decisive source-native allocator contradiction; raises the score into the rubric's 81–100 band despite generally strong format and correlation quality. Counted as one defect family. |

## Realism Score by Category

- **Field format accuracy:** 8 — Broadly parseable, source-aware schemas; native macOS generation values violate the allocator semantics behind an otherwise correctly shaped field.
- **Temporal patterns:** 8 — Visible process/transport ordering generally holds; macOS allocation chronology is the material exception.
- **Cross-source correlation:** 9 — Zeek tuples/UIDs and sampled Windows process identities align; no scored missing-source assumptions.
- **Behavioral realism:** 9 — Observed service, interactive, unlock, network and file activities have plausible source semantics; no penalty for narrative compactness.
- **Environmental consistency:** 8 — Platforms are rendered distinctly, but two Mac hosts share the same native identity-allocation flaw.

## Recommendations

- If this were synthetic, allocate native macOS process generations in actual host execution order from one host-wide counter. Preserve each existing generation in later parent/actor/exit observations; allocate a new value only at the kernel transition that owns it.
- If this were synthetic, test newly forked child tokens against monotonic kernel time and their creation times across all activity families on the host. The multi-minute reversals above should fail validation even when every individual process's own fork/exec/exit chain is valid.
- If these identifiers were intentionally sanitized from production, document the transformation and preserve ordering when remapping a host-global allocator. That would retain native identity semantics for downstream validation and detection engineering.
