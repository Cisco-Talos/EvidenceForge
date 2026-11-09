# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 92
**Synthetic-Confidence Score:** 82

## Executive Summary

Most of this dataset should ingest successfully into a detection stack: the Windows event shapes, network protocol references, and visible process lifecycles are unusually well preserved, without being suspicious merely for matching. The strongest authenticity defect is in MAC-MROSS-02's native Endpoint Security process identity: newly created process versions repeatedly move backward across minutes of increasing event time and uninterrupted ES sequence numbers, contradicting XNU's shared identity allocation counter.

## Evidence For Synthetic

- [hard_contradiction] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` contains repeated reversals in newly allocated `audit_token.pidversion`. Line 2, at `13:20:29.882486Z`, execs PID 19775 into version **32**; line 3, at `13:37:11.846603Z`, forks a newly born PID 21356 with version **10**. Both wall time and Mach time advance, and `global_seq_num` advances from 1 to 2. The fork child's `start_time` is the later event time, so this is not merely an old process appearing in a new observation. XNU allocates new fork and exec identity versions using the same atomic `nextpidversion` counter. The counter would need to wrap roughly four billion allocations between these small values to make this natural. See [Apple's fork implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c) and [exec implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c).
- [hard_contradiction] The same identity defect recurs well beyond one startup sequence. Line 80 at `15:25:40.511790Z` execs PID 41975 with version **89**, but line 81 at `15:46:42.616461Z` forks newly born PID 44085 with version **83**. After its exec reaches **85** at line 83, line 86 at `15:48:46.208061Z` forks PID 44280 with version **72**. Further examples are **99 → 92** at lines 111/113 and **112 → 100** at lines 124/126. These are repeated instances of one defect, not independent score multipliers.

## Evidence For Real

- Windows XML is well formed throughout 19,411 Security events and 12,058 Sysmon events. Across the selected event families, provider/channel, EventID, version, field naming, PID representation, null placeholders and success/failure keyword choices are coherent. Native XML paths contain ordinary single separators after XML parsing; there is no demonstrated double-escaping issue.
- All 53 JSON/NDJSON files parsed successfully, totaling 76,577 records. This includes the normalized endpoint, native macOS, and Zeek exports.
- All 12,029 examined DNS/HTTP/TLS/SMTP protocol rows have a matching `conn` UID within their sensor, matching endpoint tuple, and a timestamp within the associated transport interval under a 0.5-second endpoint tolerance. Matching itself is neutral for authenticity, but it materially supports SIEM usability.
- Visible Windows parent GUIDs resolve consistently when their creation is also visible. No checked Sysmon occurrence uses a matching process GUID after its visible Event 5 termination; no checked Windows subject uses a visible non-system logon ID before its visible logon or after its visible logoff. Initiators and closures outside the window were not penalized.
- Native ES actor/target separation is present. For example, MAC-MROSS-01 lines 1–3 show launchd fork, xpcproxy exec, and Terminal exec under the same PID with changing PID version; the pre-exec actor and post-exec target differ appropriately. The SSH chains contain distinct wrapper, sshd, session/auth helper and shell identities.
- Certificates are stable across repeated observations. `CN=LOG-MON-01.meridianhcs.local` appears in 44 x509 rows with one fingerprint/serial/validity pair; the same identity agrees across sensors. No fingerprint was observed with contradictory certificate fields.
- Network state diversity includes rejected, reset, no-response, partial and normally closed connections, rather than exclusively successful flows. DNS includes A, AAAA, PTR, SRV, TXT, NS, MX and SOA queries, with no demonstrated wrong IP-family answer in the A/AAAA checks.

## Detailed Analysis

### Scope and provenance

I read the supplied neutral briefing and files exclusively beneath `/private/tmp/log-study-kl_ep_px/data`, and used system `python3` from `/private/tmp` for read-only parsing. I did not inspect the project, authored scenarios, prior reports, sibling reviewer output or parent directory inventories. Generic inherited operating instructions were not treated as origin evidence. External references were confined to Microsoft/Apple/Zeek documentation and directly opened Apple upstream source; searches used actual domain filters. I did not use filesystem modification times, domain resolvability, collection completeness, or the shape of the suspicious narrative to infer authenticity.

The evidence includes Windows Security/Sysmon, Linux syslog and shell history, native macOS ES/Unified Log exports, normalized eCAR, Zeek, proxy, firewall, web and IDS records. The principal structured checks covered every Windows XML event, every eCAR record, every native macOS record, all protocol/connection joins noted above and all x509 rows. This is not an exhaustive validation of every vendor's complete message catalog.

### Primary native macOS identity defect

The key distinction is between observing an old identity and allocating a new identity. A low PID version on an old parent would be normal; the cited low values belong to **new fork children or new exec targets**. The child `start_time` agrees with its new fork occurrence, and the actor and target records preserve those values into later events.

In the table below, all paths are under `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`. Each arrow joins a later new-identity allocation to the preceding relevant allocation, not an arbitrary observation of a long-lived process.

| Lines | Earlier allocation | Later allocation | ES global sequence |
|---|---|---|---|
| 2 → 3 | 13:20:29.882486, exec PID 19775, version 32 | 13:37:11.846603, fork child PID 21356, version 10 | 1 → 2 |
| 80 → 81 | 15:25:40.511790, exec PID 41975, version 89 | 15:46:42.616461, fork child PID 44085, version 83 | 79 → 80 |
| 83 → 86 | 15:46:42.628448, exec PID 44085, version 85 | 15:48:46.208061, fork child PID 44280, version 72 | 82 → 85 |
| 111 → 113 | 16:22:14.840706, exec PID 47425, version 99 | 16:45:30.958506, fork child PID 49701, version 92 | 110 → 112 |
| 124 → 126 | 17:12:27.395264, exec PID 52334, version 112 | 17:19:16.246289, fork child PID 53019, version 100 | 123 → 125 |

XNU's fork implementation atomically increments `nextpidversion` for a new child, and exec updates the process version from that shared counter. This makes repeated downward allocation blocks materially different from ordinary PID reuse. The observation time, child birth time and Mach time agree on chronological progression, so sorting the export by arrival time does not resolve the problem. Short concurrency effects could complicate millisecond-scale allocation ordering; I have deliberately emphasized reversals separated by minutes.

The export declares ES message version 11. Its per-type `seq_num` values are validly increasing within each event type, and `global_seq_num` increases consecutively across the host's file. I specifically checked both counters: **there is no demonstrated per-type sequence-number reversal**. Apple documents these as client/type and client-wide counters respectively, available in message versions greater than 2 and 4; both therefore apply to version 11. [Apple seq_num documentation](https://developer.apple.com/documentation/endpointsecurity/es_message_t/seq_num?language=objc), [Apple global_seq_num documentation](https://developer.apple.com/documentation/endpointsecurity/es_message_t/global_seq_num?changes=_6).

An undocumented transform that replaced PID versions could explain this as damaged production export rather than generated data, which prevents a 100-confidence verdict. A collector doing that should identify the values as normalized identifiers, rather than placing them in native audit-token identity fields. No such transform is visible in the supplied records. MAC-MROSS-01 did not exhibit the same new-allocation reversals in my check.

### Windows source-native spot verification

The following 18-event sample spans authentication, process, access, account and collection semantics. Line numbers identify the opening `<Event>` line; `RecordID` gives an additional reproducible locator. Host names below omit only `.meridianhcs.local` for readability.

| Event | File and line | RecordID | Check and result |
|---|---|---:|---|
| 4769 | DC-02/windows_event_security.xml:1069 | 25377527 | Version 0 service-ticket fields, mapped-IPv4 source, hex ticket options/encryption/status: coherent. |
| 4688 | DC-02/windows_event_security.xml:1149 | 25377530 | Version 2, child PID `0x1c7c`, creator PID `0x13fc`, mandatory SID and parent name: coherent. |
| 4624 | DC-02/windows_event_security.xml:1274 | 25377537 | Type 5 SYSTEM service logon, Advapi/Negotiate, absent remote address: coherent. |
| 4672 | DC-02/windows_event_security.xml:1329 | 25377538 | SYSTEM logon `0x3e7`, multiline privilege list after logon: coherent. |
| 5140 | DC-02/windows_event_security.xml:1509 | 25377549 | SYSVOL share, remote address, subject LUID, native path prefixes: coherent. |
| 4634 | DC-02/windows_event_security.xml:1548 | 25377552 | Type 3 session `0xcb5c02d` and subject identity: coherent closing shape. |
| 4768 | DC-02/windows_event_security.xml:1918 | 25377565 | krbtgt SID ending 502, preauth type 2 and empty cert fields: coherent password/preauth shape. |
| 4776 | DC-02/windows_event_security.xml:2288 | 25377579 | NTLM package, workstation and status fields: coherent; no inappropriate IP requirement imposed. |
| 4689 | DC-02/windows_event_security.xml:2939 | 25377606 | Child PID `0x1c7c`, matching WmiPrvSE image after its creation: coherent. |
| 4771 | DC-02/windows_event_security.xml:123501 | 25382520 | Failure keyword `0x8010000000000000`, status `0x18`, preauth and source address: coherent. |
| 4625 | WS-PPATEL-01/windows_event_security.xml:4265 | 358448 | Local Type 2 failure; `0xc000006d`/`0xc000006a`, User32, no remote source: coherent. |
| 4648 | WS-PPATEL-01/windows_event_security.xml:11421 | 358845 | Subject and target credentials separated, caller PID/name and target server present: coherent. |
| 5145 | FILE-SRV-01/windows_event_security.xml:97 | 271775 | Share-relative target, access mask/list, subject and source endpoint: coherent. |
| 4656 | FILE-SRV-01/windows_event_security.xml:146 | 271776 | Handle `0x8a164b99` opened for the corresponding absolute file: coherent. |
| 4663 | FILE-SRV-01/windows_event_security.xml:199 | 271777 | Same handle and file, write access `0x2`: coherent. |
| 4658 | FILE-SRV-01/windows_event_security.xml:240 | 271778 | Same handle closes after the access: coherent. |
| 4698 | DC-01/windows_event_security.xml:192482 | 28257135 | Embedded task XML, task path, principal and action command: parseable/coherent. |
| 1102 | DC-01/windows_event_security.xml:263368 | 1 | Eventlog provider, EventRecordID reset and source-specific payload placement: not misclassified as a missing EventData problem. |

Microsoft's [4688 schema](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688) supports the version-2 process fields and hexadecimal PID interpretation used in this check. Sysmon Event 1/3/5/7/8/10/11/13/22 samples also had recognizable native shapes. All 4,447 examined hash values had the expected hexadecimal alphabet and algorithm-specific lengths. Selected Sysmon event-family absence was not scored.

### Correlation and rejected candidate findings

The normalized eCAR process streams contained no observed `PROCESS` operation after a matching `TERMINATE` object identity. Native macOS actor identities similarly were not reused after an observed exit of the same `(pid,pidversion)` in the stream.

For network validation, protocol UID lookup and tuple equality were checked independently within zeek-core, zeek-dmz and zeek-db. Successful matching was not treated as a synthetic tell. Some partial TCP records have payload-byte versus observed-IP-byte relationships that would be suspicious for a completely captured flow; these did **not** survive restriction to ordinary closed `SF` records with no gap/partial flags at a material deficit. They were excluded from the verdict. Zeek documents TCP payload counts as sequence-derived and potentially inaccurate, while IP-byte totals describe observed packets. [Zeek Conn::Info](https://docs.zeek.org/en/v6.2.1/scripts/base/protocols/conn/main.zeek.html).

The five Unified Log rows have source-specific writer/process fields rather than being treated as normalized endpoint flow records. In particular, the AppleSystemPolicy message at MAC-MROSS-01 Unified Log line 2, `15:41:38.930666`, says a policy “would not allow” MeetingAssist. I did not infer a definite denial, launch or child execution from that message alone, nor require a native ES notification for a denied or unobserved execution.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| hard_contradiction | Native macOS Endpoint Security | MAC-MROSS-02; repeated new fork/exec identity allocation reversals across minutes | Main reason the score enters 81–100: native identity allocation contradicts the shared XNU counter while event clocks and ES delivery counters advance. Counted as one recurring issue. |

No independent Windows schema, source-coverage, attack-narrative, packet-accounting or missing-lifecycle issue was established strongly enough to add to this table.

## Realism Score by Category

- **Field format accuracy:** 8 — Broadly parseable native fields; macOS audit-token values have a substantive semantic identity defect.
- **Temporal patterns:** 8 — Transport and lifecycle timing largely pass; new macOS identity versions conflict with chronological allocation.
- **Cross-source correlation:** 9 — Windows parent/process/session relationships and 12,029 protocol joins were consistent in the stated checks.
- **Behavioral realism:** 9 — Diverse normal and failed network activity and plausible OS-specific process chains; no narrative-based penalty.
- **Environmental consistency:** 9 — Host-specific source families and certificate identities are largely coherent; limited collection windows were respected.

## Recommendations

- If this were synthetic, allocate native macOS PID versions from one host-wide chronological fork/exec identity counter at the actual execution occurrence. Preserve those identities through process snapshots, parent/responsible tokens and exits; visibility filtering should not reset or privately renumber the kernel identity domain.
- Add a native ES consistency check joining fork child birth, exec identity allocation, wall/Mach time and per-type/global sequence counters. Include activity planned in a different order from its eventual execution, since MAC-MROSS-02's version blocks appear out of chronological allocation order.
- If these fields were deliberately transformed for privacy, document the transformation and expose pseudonymous identities in a normalized layer so detection consumers do not interpret them as native `audit_token.pidversion` values.
