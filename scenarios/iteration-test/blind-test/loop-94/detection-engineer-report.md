# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 65
**Synthetic-Confidence Score:** 20

## Executive Summary

The inspected records look production-like to a detection parser: Windows event-specific fields, numeric representations, identities, and source timestamp conventions are credible, and two exact cross-source pivots preserve their underlying facts. I found no substantiated synthetic indicator in this bounded review; the verdict remains tentative because a capable synthetic dataset could satisfy these same contracts.

## Evidence For Synthetic

- No demonstrated synthetic indicator in the inspected sample. I did not treat source completeness, sparse macOS Unified Log coverage, an easy-to-follow activity sequence, sanitized names, or absent out-of-window lifecycle records as synthetic evidence.

## Evidence For Real

- `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml`, record 129968, uses Security 4688 version 2 fields including `NewProcessId=0x143c`, `ProcessId=0x1104`, target-subject placeholders, and `MandatoryLabel=S-1-16-16384`; its SYSTEM subject and system integrity level agree.
- The same host's Sysmon record 30326 and eCAR CREATE agree on PID 5180, parent PID 4356, `taskhostw.exe /Run`, SYSTEM, and logon ID `0x3e7`. Later exact-identity termination observations preserve the process identities within each source.
- `zeek-core/conn.json` and `zeek-core/dns.json`, UID `ClnAf4xMznbwm13HlN`, agree on timestamp `1793624400.006178`, UDP tuple `10.10.2.20:58104 -> 10.10.2.11:53`, and `duration/rtt=0.000469`. DNS query `DC-01.meridianhcs.local` has an A answer, a same-length TTL array, and consistent numeric/text class/type/response fields.
- Sysmon record 30311 uses a millisecond `UtcTime` and a finer `TimeCreated`, while Security uses seven fractional decimal digits and eCAR uses integer epoch milliseconds. These are source-specific representations rather than an imposed universal timestamp shape.
- The sampled macOS fork and exec observations distinguish the pre-exec actor from the exec target: PID 41136 advances from pidversion 12 to 13 as `/sbin/launchd` transitions to `/usr/libexec/xpcproxy`. I do not infer authorization denial from a notification result or the separate Unified Log policy message.

## Detailed Analysis

### Scope and method

I read only the assigned briefing and data directory. This is a bounded detection-engineering review, not an exhaustive audit. I selected 20 representative records, then used focused exact-identity lookups for two cross-source pivots; returned lifecycle continuations are discussed only as part of the process pivot. Aggregate counts were limited to the inspected host's event-type/path fields and counts for the few inspected macOS/Linux files. I did not inspect scenarios, code, ground truth, evaluation results, previous reports, or other reviewers.

The representative sample comprised these source records (indices below are zero-based parsed file indices):

| Source, relative to data directory | Selected records | Checks |
|---|---|---|
| `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml` | indices 0, 2, 10, 12; record IDs 129948, 129955, 129968, 129973 | 4689, 5156, 4688, 4648 field names, IDs, paths, subject identities, and numeric forms |
| `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml` | indices 0, 2, 4, 7, 9; record IDs 30296, 30308, 30311, 30319, 30326 | 5, 13, 22, 10, 1 source-specific payloads and identity fields |
| `zeek-core/conn.json` | first two records | tuple typing, UDP accounting, duration, state, UID |
| `zeek-core/dns.json` | first two records | answers, TTL arrays, class/type/response pairs, exact first-record join |
| `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` | first two records | declared version, fork actor/child, exec actor/target, audit token PID version |
| `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson` | first two records | writer/sender distinction, timestamp representation, policy-message interpretation |
| `WS-AJOHNSON-01.meridianhcs.local/ecar.json` | first record and index 16 | termination shape and exact process CREATE pivot |
| `APP-INT-01.meridianhcs.local/syslog.log` | first record | RFC5424-shaped priority/version/header/message split |

### Windows parsing and field semantics

The sampled Security XML has the Windows event namespace and distinct provider/channel metadata. Record 129948 is a 4689 termination at `2026-11-02T13:00:22.3504973Z`, with `ProcessId=0x13fc`, `Status=0x0`, and subject `MERIDIANHCS\\aisha.johnson`. Its initiating event could precede the visible slice; its absence from this sample is not a defect.

Record 129955 is 5156 version 1 at `13:05:17.4861147Z`, with decimal `ProcessID=4528`, device-style `Application=\device\harddiskvolume1\windows\system32\svchost.exe`, UDP `Protocol=17`, `SourceAddress=10.10.1.35`, destination DNS port 53, and resource-token values for direction and layer. These fields are distinguishable from the hexadecimal process identifiers in Security process auditing, which matters for SIEM normalization.

Record 129973 is 4648 with an explicit-credential target `svc_monitor` in `MERIDIANHCS`, target server `MAIL-EDGE-01`, local SYSTEM subject, monitoring-agent image, and zero GUID placeholders. Nothing in these fields alone establishes remote logon success, so I did not invent a required successful target logon.

The inspected Sysmon 13 record represents `SetValue` on a DHCP name-server registry value, with an associated process GUID and user. The Sysmon 22 record has query status zero and a semicolon-delimited result. Sysmon 10 preserves separate source/target process identifiers, images, users, `GrantedAccess=0x1000`, and a pipe-delimited call trace. These would support ordinary parser extraction and detection predicates.

As a narrow format sanity check, I decoded actual strings rather than interpreting JSON display escaping: all 366 selected Security path fields and 666 Sysmon path fields on this host contained no doubled backslash separator. All 1,437 eCAR `image_path` values on this host also contained no doubled separators. A double-escaped display was therefore not a real path defect.

The host contains 833 Security and 593 Sysmon records. Security counts include 117 creates, 97 terminations, 24 logons and 14 logoffs; Sysmon includes 118 creates and 99 terminations. These unequal totals are not evidence of synthetic data: collection windows, per-source selection, and source timing can affect visible totals. No whole-dataset distribution conclusion is drawn from them.

### Exact pivot 1: Windows process across three sources

For `WS-AJOHNSON-01`, Security record 129968 reports new process `0x143c` (5180), parent `0x1104` (4356), SYSTEM subject/logon `0x3e7`, and `C:\Windows\System32\taskhostw.exe`.

Sysmon record 30326 identifies PID 5180 and parent 4356, command `taskhostw.exe /Run`, SYSTEM user, system integrity and logon `0x3e7`. Its process GUID is `{fd907e59-8ba9-6ae8-5f00-00102d8b8bdb}`. The corresponding eCAR CREATE at `timestamp_ms=1793625002033` has PID 5180, PPID 4356, matching command, path and logon ID, object ID `c1768f0c-97ca-49d9-8ee4-a5716307f697`, and a distinct source-process UUID referenced by `actorID`.

Observed timestamps are Sysmon `UtcTime=2026-11-02 13:10:01.794`, eCAR `13:10:02.033Z`, and Security `13:10:02.1751666Z`. A subsecond difference between distinct sources is not impossible causal ordering.

The focused continuation lookup returns Sysmon record 30338, Event 5, with the same process GUID and PID at `13:14:10.780` (`TimeCreated=13:14:10.7818499Z`), and eCAR TERMINATE at `1793625250939` with the same eCAR object ID and PID. Both preserve the process identity and occur after creation. This checks a visible lifecycle without demanding out-of-window companions or equating the two products' identity encodings.

### Exact pivot 2: Zeek DNS to connection

The exact UID `ClnAf4xMznbwm13HlN` joins the first DNS and connection records. Both have `ts=1793624400.006178`, `proto=udp`, and the complete tuple `10.10.2.20:58104 -> 10.10.2.11:53`. Connection payload counts are 41 originator and 57 responder bytes, one packet each, with IP byte counts 69 and 85 respectively: the 28-byte increment is consistent with IPv4/UDP accounting.

DNS gives transaction 46234, query `DC-01.meridianhcs.local`, `qtype=1/A`, `qclass=1/C_INTERNET`, `rcode=0/NOERROR`, answer `10.10.2.10`, TTL 300, and RTT `0.000469`. Connection duration is also `0.000469`, with state `SF` and history `Dd`. This is consistent network/protocol evidence. The second record pair also has matching displayed UID/tuple/time, but the detailed pivot is confined to the first pair.

### Linux and macOS interpretation

The first APP-INT syslog line is `<30>1 2026-11-02T13:00:32.218756Z APP-INT-01 rsyslogd 36008 - - main Q: queue fwdRule1 has 2028 messages pending, worker threads 2`. Its priority, version, timestamp, host, app, process, MSGID and structured-data placeholders have a credible RFC5424 arrangement. One message cannot establish organic volume or cadence.

The first two Mac Endpoint Security records declare schema version 1 and message version 11. Their fork/exec structure contains audit-token identities, parent and responsible tokens, executable/stat data, code-signing metadata and an exec argument/environment representation. The fork child has PID 41136/pidversion 12; the exec actor retains that identity and the target has the same PID/pidversion 13. The different pre/post image is therefore not a contradictory process identity. I did not verify every version-11 field against primary platform documentation, so I make no native-schema compliance guarantee or defect allegation.

The Unified Log sample includes loginwindow at `13:03:16.611945+0000` and a kernel writer with an AppleSystemPolicy sender at `15:47:27.953941+0000`. A different writer/sender is permitted by this representation. The latter says a policy “would not allow” PID 62993; I do not treat that wording as a demonstrated denial or correlate it to unsampled effects. The inspected Mac file has 141 ES records and three Unified Log records; that asymmetry alone says nothing about authenticity without a specified collection profile.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| None substantiated | Inspected Windows Security/Sysmon, eCAR, Zeek, Linux syslog and macOS sample | Bounded representative sample and two exact pivots | No concrete contradiction, contract gap or demonstrated distribution/format defect supports an upward adjustment. The score of 20 reflects production-like appearance within this limited inspection, not proof of origin. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled parser shapes and identifier representations are credible; full macOS version-specific conformance was not independently established.
- **Temporal patterns:** 9 — Sampled source precisions and exact process lifecycle ordering are plausible; broad activity cadence was outside scope.
- **Cross-source correlation:** 9 — Two exact pivots preserve tuples or process facts and identities; this is a bounded check.
- **Behavioral realism:** 8 — Sampled service, process, DNS and syslog activity is plausible, with insufficient sampling for long-tail claims.
- **Environmental consistency:** 8 — Sampled paths and source/platform roles agree, without enough host coverage to certify the entire environment.

## Recommendations

- If this were synthetic, preserve the demonstrated source-specific timestamp representations, process identities, numeric forms and DNS/connection tuple relationships. No defect-specific change is justified by this sample.
- Do not add events or alter collection volume solely to equalize create/terminate totals or populate sparse source families; this review did not establish a required missing companion or contradictory collection profile.
