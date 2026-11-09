# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 94
**Synthetic-Confidence Score:** 86

## Executive Summary

The data is broadly parseable and has unusually substantial engineering behind its Windows process, session, and network relationships. Nevertheless, native macOS audit-token identity counters move backward between demonstrably new processes within a continuous host timeline, and two separate macOS distribution patterns support synthetic construction: implausibly constrained file timestamp fractions and repeated command/timing templates. These findings outweigh the considerable evidence of realistic schema and correlation behavior; the verdict does not depend on intrusion narrative, collection completeness, sanitized domains, or missing Sysmon families.

## Evidence For Synthetic

- **[hard_contradiction] P1 — Native macOS PID-version allocation contradicts chronological process creation.** In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, line 9, `2026-11-02T13:05:36.214210000Z`, an exec target has PID `18386`, `pidversion=51`, `mach_time=55995269141040`, and `global_seq_num=8`. Line 10, six minutes later at `13:11:56.322327000Z`, records a newly forked PID `18976` with **`pidversion=10`**, the same timestamp as its `start_time`, a higher `mach_time=56004391735848`, and `global_seq_num=9`. Modern XNU allocates fork and exec identity versions from a shared increasing counter. This is not a case of comparing a new process with an old surviving process. There are four decreases among newly allocated fork/exec identities on this host and one on MAC-MROSS-01. Primary-source verification and caveats appear below.
- **[distribution_texture] P2 — Native executable metadata has a dataset-wide fractional timestamp fingerprint across both Macs.** Deduplicating by executable path, timestamp field, and timestamp value yields **124/124** distinct observations on MAC-MROSS-02 and **104/104** on MAC-MROSS-01 with nanosecond fractions below `1000`, across 31 and 26 executable paths respectively. These include access, modification, change, and birth timestamps, not repeated copies of a single record. For example, MAC-MROSS-01 line 1 gives launchd modification time `2026-03-14T03:55:49.000000091Z` and change/birth time `2026-09-09T07:01:57.000000027Z`. Every distinct executable timestamp occupies the first microsecond of its second while retaining small, varying nonzero nanoseconds. Ordinary coarse timestamp rounding would produce zeros, not this consistent tiny nonzero range. A systematic serializer or sanitization defect remains an alternative to generation, so this is a distribution finding rather than an impossible individual field value.
- **[distribution_texture] P2 — Command selection and timing reveal the same sliding template on both Macs.** The two `zsh_history/maya.ross.zsh_history` files contain the same ordered pool of basic commands, shifted by one position between hosts. More decisively, successive three-command blocks share the gap pairs **30/50, 37/52, 44/54, 51/56, 58/58, and 65/60 seconds**, although the commands and wall-clock block times differ. For example, MAC-MROSS-01 lines 4–6 are `pwd → ls → du` at `13:48:56`, `13:49:26`, `13:50:16`; MAC-MROSS-02 lines 5–7 are `ls → du → df` at `14:11:50`, `14:12:20`, `14:13:10`. The next blocks are `df → ps → find` at `14:37:57/14:38:34/14:39:26` and `ps → find → ifconfig` at `14:51:46/14:52:23/14:53:15`. Native exec rows confirm these commands really are represented in endpoint evidence. Repeated administration scripts or a common user checklist could explain some command reuse, but the shared changing gap schedule across shifted command sequences is a stronger artificial texture signal.

## Evidence For Real

- **Windows schemas are generally convincing.** The XML parses successfully, uses the Windows event namespace, and distinguishes hexadecimal Security PIDs from decimal Sysmon PIDs. Representative events have appropriate audit-success/failure keywords, Security Level `0`, Sysmon Level `4`, event-specific versions, named fields, SIDs, and GUIDs. DC-02's `4688` at `13:00:35.4671210Z` reports `NewProcessId=0x1b54`, matching Sysmon Event 1 PID `6996` and the same `conhost.exe` command line.
- **Visible Windows process and session lifecycle checks pass.** Across all 11,632 Sysmon events, I found no same-GUID dependent event more than one second before its visible creation or after its visible termination, and no visible child creation more than one second outside its visible parent's lifetime. Across Security events, the corresponding checks found no `4688` more than one second before a visible non-service logon or after its visible logoff. No SID-to-username conflicts were found in the parsed Security records.
- **Audit-log clearing is rendered as a different provider and payload shape.** DC-01's `1102` at `18:42:21.0745228Z` uses `Microsoft-Windows-Eventlog`, `Level=4`, `Task=104`, `Keywords=0x4020000000000000`, a namespaced `UserData/LogFileCleared` payload, and `EventRecordID=1`. The resulting one record-ID decrease has an explicit log-visible explanation.
- **Network correlation is strong without being used as evidence against authenticity.** The three Zeek sensors contain 22,400 connection records. For protocol rows whose UID was present in the same sensor's connection file, I found no tuple mismatches or protocol timestamps more than one second outside the connection interval. Protocol outcomes vary: TLS establishment failures, TCP resets, rejections and partial connections, HTTP errors, and DNS negative/error responses are present.
- **Native Mac process modeling has meaningful detail beyond normalized FLOW records.** The ES data distinguishes fork from exec, retains a process lifetime through multiple image changes, increments the same process's version through exec transitions, and exposes actor versus exec-target audit tokens. MAC-MROSS-01 PID `42171` moves from inherited launchd to xpcproxy to Terminal while keeping `start_time=13:07:43.411700Z`. The next `login` transition has a root-owned setuid executable (`st_mode=0o104555`) and appropriately changes effective UID to zero; later shell execution returns to UID 501. Audit session and POSIX session/group fields are distinct.
- **Mac policy evidence is not overclaimed.** MAC-MROSS-01's kernel-written Unified Log at `15:41:59.392044+0000` says security policy “would not allow” MeetingAssist. I did not find a corresponding successful MeetingAssist exec in the inspected native records, and did not infer success or a child effect from this policy message. SSH acceptance messages identify `/usr/libexec/sshd-session` as their writer, with native process evidence for the same daemon PID.
- **Linux authentication records are source-shaped rather than Windows-shaped.** Examples include RFC 5424-style sshd records with PID, authentication method, key type/fingerprint, client address and port; DB-PROD-01 at `13:01:47.369176Z` logs an ECDSA public-key acceptance for `marcus.chen` from `10.10.1.31:60624`. File and proxy access formats also retain source-specific fields and timestamp representations.

## Detailed Analysis

### Scope and method

I read only the supplied data directory and the assigned briefing, and wrote local analysis outputs in the assigned reviewer directory. Records were parsed as data; no embedded commands, URLs, hosts, or payloads were executed or contacted. Public documentation was consulted only for disputed source semantics.

The slice covers approximately `2026-11-02 13:00–19:00 UTC`. It contains 23 endpoint host directories, **18,838 Security XML events**, **11,632 Sysmon XML events**, **36,022 normalized eCAR records**, and **39,088 Zeek JSON records**, plus syslog, web/proxy/firewall/IDS logs and shell histories. Both native Mac files were parsed in full: MAC-MROSS-01 has **44 fork, 50 exec, 42 exit** notifications; MAC-MROSS-02 has **54 fork, 65 exec, 52 exit** notifications. There are five Unified Log rows total. Their low count was not scored as a defect.

The checks used XML `iterparse`, JSON decoding, counters and bounded examples. Lifetime checks use Sysmon `UtcTime` for source-native process events and a one-second allowance to avoid classifying ordinary timestamp latency or precision differences as causality failures. This does not prove absence of subsecond problems. It also does not prove complete source coverage or runtime equivalence to a specific SIEM parser. eCAR is treated as normalized telemetry, not as a native Windows or macOS schema.

### F1: macOS kernel identity counter chronology — P1, hard_contradiction

The disputed semantic is not that a process's `pidversion` must equal its PID, nor that every extant process must have a newer version than every preceding record. The relevant facts are that fork allocates a new identity and exec replaces the executable identity, and that modern XNU uses a shared counter for those allocations. Apple's source explicitly uses `OSIncrementAtomic(&nextpidversion)` in [fork allocation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c#L923) and [exec identity replacement](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c#L6630); the same exec behavior is visible in the [tagged XNU 11417.101.15 source](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.101.15/bsd/kern/kern_exec.c#L6679).

Reproduction: read ES rows chronologically, select `event.fork.child.audit_token.pidversion` for fork and `event.exec.target.audit_token.pidversion` for exec, and compare successive selected allocations within each host. This yields **119 allocations and four decreases** on MAC-MROSS-02 and **94 allocations and one decrease** on MAC-MROSS-01. All selected versions are unique within their respective host; uniqueness alone therefore misses the defect.

| Host and lines | Earlier newly allocated identity | Later newly allocated identity | Supporting clock/identity evidence |
|---|---|---|---|
| MAC-MROSS-02, 9 → 10 | `13:05:36.214210000Z`, exec PID 18386, version 51 | `13:11:56.322327000Z`, fork PID 18976, version 10 | Global sequence 8 → 9; mach time 55995269141040 → 56004391735848; later child's start equals its fork time |
| MAC-MROSS-02, 42 → 43 | `13:37:29.212060000Z`, exec PID 21374, version 54 | `13:43:12.427761000Z`, fork PID 21921, version 37 | Global sequence 41 → 42; mach time increases; later child's start equals its fork time |
| MAC-MROSS-01, 103 → 104 | `17:13:57.143786000Z`, exec PID 71340, version 102 | `17:26:16.202102000Z`, fork PID 72649, version 92 | Global sequence 109 → 110; mach time 25248891450864 → 25266628850448 |

These are separated by minutes, rather than a plausible short concurrency or export-order race. The monotonic clock, continuous sequence, stable long-lived parent and host-local Unified Log boot identity do not support a reboot explanation. Ordinary 32-bit wrap would require billions of hidden allocations between small positive versions, repeatedly, in these short intervals.

**Limits:** the records declare ES message version 11 and include contemporary process fields but do not declare an exact macOS build. The conclusion applies to modern native XNU audit-token semantics, verified above; I did not infer a precise OS release from message version alone. A collector that deliberately replaces kernel PID-version values could produce this result, but would be exporting transformed identities, and the provided fields do not disclose such a transformation. This is the dominant authenticity finding and would also invalidate assumptions made by detection logic that treats these fields as authentic kernel identity generations.

### F2: executable stat timestamp texture — P2, distribution_texture

For every ES actor and fork-child/exec-target executable, I collected `executable.stat` fields ending in `timespec`, then deduplicated `(path, field, timestamp)` within each host. This avoids counting the same installed file hundreds of times simply because it appears in many events.

| Host | Distinct executable paths | Distinct path/field/time observations | Fractions below 1,000 nanoseconds | Largest fraction |
|---|---:|---:|---:|---:|
| MAC-MROSS-01 | 26 | 104 | 104 | 984 ns |
| MAC-MROSS-02 | 31 | 124 | 124 | 977 ns |

The issue is the shared narrow fractional range across independently varying access/change/install times and executable classes. It is not that modification must follow birth: copying software can legitimately preserve an older mtime. Nor is it the copied dataset's filesystem timestamps, which were excluded. A formatter that systematically mishandles fractional units or a timestamp sanitizer could create this pattern in otherwise real data; that alternative lowers confidence relative to an absolute provenance claim. Either way, the exported native-looking metadata has a reproducible artificial texture that SIEM consumers could learn as a dataset fingerprint.

### F3: repeated command/timing blocks — P2, distribution_texture

After excluding SSH invocations, MAC-MROSS-02 contains 21 commands forming a repeated cycle of `sw_vers, uname, pwd, ls, du, df, ps, find, ifconfig, dscl, id`. MAC-MROSS-01 contains the same pool starting at `id`, with an extra remote-session `id` at `16:03:44`; the remaining local sequence follows the same cycle.

The paired history evidence is especially specific:

| Gap pair | MAC-MROSS-01 block, UTC | MAC-MROSS-02 block, UTC |
|---|---|---|
| 30 / 50 s | `pwd, ls, du` — 13:48:56, 13:49:26, 13:50:16 | `ls, du, df` — 14:11:50, 14:12:20, 14:13:10 |
| 37 / 52 s | `df, ps, find` — 14:37:57, 14:38:34, 14:39:26 | `ps, find, ifconfig` — 14:51:46, 14:52:23, 14:53:15 |
| 44 / 54 s | `ifconfig, dscl, id` — 15:23:11, 15:23:55, 15:24:49 | `dscl, id, sw_vers` — 15:31:22, 15:32:06, 15:33:00 |
| 51 / 56 s | `sw_vers, uname, pwd` — 16:34:17, 16:35:08, 16:36:04 | `uname, pwd, ls` — 16:45:41, 16:46:32, 16:47:28 |
| 58 / 58 s | `ls, du, df` — 17:26:16, 17:27:14, 17:28:12 | `du, df, ps` — 17:32:35, 17:33:33, 17:34:31 |
| 65 / 60 s | `ps, find, ifconfig` — 18:11:56, 18:13:01, 18:14:01 | `find, ifconfig, dscl` — 18:24:29, 18:25:34, 18:26:34 |

This is scored as a repeatable distribution artifact, not as a judgment about whether suspicious activity is too linear or complete. The same account uses both hosts, so shared operator habits are a real alternative explanation; that explains vocabulary more readily than a changing but identical timing schedule.

### Bounded source-native verification examples

These are representative checks across more than the requested 10–20 event types. Times are UTC on 2026-11-02; Windows examples are identified by file, event ID and timestamp rather than XML line numbers.

| Source and example | Fields/relationship inspected | Result |
|---|---|---|
| DC-02 Security 5156, 13:00:22.5741467 | PID 5096, UDP protocol 17, inbound direction token, local destination 10.10.2.11:88 | Consistent with receiving host and paired Sysmon network evidence |
| DC-02 Security 4769, 13:00:22.5756309 | Service account `DC-02$`, AES encryption 0x12, mapped IPv4 client, status 0 | Plausible ticket event shape |
| DC-02 Security 4768, 13:00:35.7509016 | `krbtgt`, preauth 2, AES 0x11, empty certificate fields | Plausible password-based preauthentication shape |
| DC-02 Security 4688, 13:00:35.4671210 | Hex PID 0x1b54, parent 0x13d8, conhost command, mandatory integrity SID | Matches Sysmon PID 6996 / parent 5080 |
| DC-02 Sysmon 1, 13:00:35.3831140 | GUID, logon ID 0x3e7, system integrity, parent image and PID | Shared identity and image consistent |
| DC-02 Sysmon 5, 13:01:04.5759312 | Same conhost GUID/PID and image | Visible termination follows create |
| DC-02 Security 4624, 13:03:22.5504611 | NETWORK SERVICE SID S-1-5-20, type 5, Advapi, local service source fields | Appropriate service-logon semantics |
| DC-02 Security 4672, 13:03:22.5576655 | Same SID and logon ID 0x3e4 | Aligned privilege assignment |
| DC-02 Security 4771, 15:59:44.8967584 | Status 0x18, failure keywords 0x8010000000000000, mapped client IP | Correct distinction from successful ticket events |
| DC-02 Security 4625, 16:24:36.8685478 | NTLM/type 3, status/substatus, client host/IP/port, failure keywords | Parseable and source-shaped |
| FILE-SRV-01 Security 4656/4663/4658, 13:05:35.0638074–.3211878 | Handle 0xdba6a9f4, same subject/logon ID and System PID 4 | Open/access/close handle sequence holds |
| DC-01 Security 1102, 18:42:21.0745228 | Eventlog provider, namespaced UserData, record ID 1 | Correctly distinct payload shape; reset explained |
| zeek-core DNS first row, ts 1793624433.502349 | A/NOERROR, boolean flags, aligned answer/TTL arrays, numeric transaction ID | Parseable native field types |
| zeek-core HTTP first row, ts 1793624490.744763 | CONNECT authority URI, HTTP/1.1, 200 Connection Established, zero HTTP bodies | Consistent tunnel-control transaction |
| zeek-core TLS first row, ts 1793624565.081302 | TLSv12/cipher, SNI, established flag, certificate FUIDs | Compatible suite/version and source shape |
| zeek-core X.509 first row, ts 1793624565.119035 | Certificate field namespace, serial, validity, key algorithm/length, SANs | Source-shaped metadata |
| MAC-MROSS-01 ES lines 1–7 | Fork/exec actor/target, PID/version, setuid login, unchanged process birth through exec | Lifetimes modeled coherently; global allocation issue remains separate |
| MAC-MROSS-02 Unified Log line 2, 14:24:27.825271 | sshd-session writer PID 30016, Accepted keyboard-interactive/PAM, source tuple | Writer exists in native ES; acceptance does not imply arbitrary child effects |
| DB-PROD-01 syslog line 6, 13:01:47.369176 | sshd PID 1043619, account, ECDSA key, remote address and port | Plausible Linux auth fields |

### Correlation checks and observations not scored

Same-GUID Windows process checks and normalized eCAR actor lifetime checks found no failures at the stated one-second threshold. These are positive validity results, not synthetic clues. All parsed Security SID/name pairs were internally consistent. The 37 distinct XML event IDs include nine Sysmon and 28 Security/eventlog IDs; unfamiliar or absent Sysmon IDs were not penalized.

There is one unresolved SMB connection reference: `zeek-core/smb_mapping.json` line 94 and `smb_files.json` lines 153–162 use UID `CfwamgYPNpASbWX3cXo`, tuple `10.10.1.35:52840 → 10.10.2.20:445`, at approximately `18:01:11–18:01:13`. Five files rows also reference that UID. No exact tuple/UID exists in the provided connection file. This is useful investigation context, but **not scored as a synthetic indicator**: a long-lived connection starting before the slice or ending after it, or an intentional source-specific export filter, could explain the missing connection row. Zeek documents the [SMB UID as the underlying connection's identifier](https://docs.zeek.org/en/v6.1.1/scripts/base/protocols/smb/main.zeek.html#type-SMB::FileInfo), but that does not require its connection summary to fall in this slice.

A few file-byte totals exceeded the corresponding connection's visible payload counts; all such cases had nonzero connection `missed_bytes`. I did not turn these into byte-accounting contradictions without resolving reassembly and capture-loss semantics. I also did not penalize the Mac policy message for lacking a successful exec, nor infer a denial from the wording alone. Unknown exact collector configurations, OS builds and audit policies limit claims about required companions.

## Synthetic Indicator Summary

| Finding | Priority | Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|---|---|
| F1: newly allocated PID versions move backward | P1 | hard_contradiction | Native macOS Endpoint Security | Five decreases across 213 visible fork/exec allocations on two hosts | Dominant: conflicts with modern kernel identity allocation, with continuous event/monotonic timelines |
| F2: stat fractions restricted to <1 microsecond | P2 | distribution_texture | Native macOS executable metadata | 228 distinct path/field/timestamp observations across 57 host/path combinations | Strong supporting fingerprint; serializer/sanitizer alternative acknowledged |
| F3: shifted command cycle plus matching changing gap schedule | P2 | distribution_texture | zsh history, corroborated by native exec evidence | Both Macs; six matching three-command gap pairs | Moderate supporting fingerprint; common-user automation remains possible |

## Realism Score by Category

- **Field format accuracy:** 8 — XML/JSON fields and most native event shapes are convincing, but native macOS identity values and stat fractions undermine semantic fidelity.
- **Temporal patterns:** 6 — Local process lifetimes and most network intervals hold; counter chronology and repeated command-gap scheduling are material defects.
- **Cross-source correlation:** 9 — Shared PIDs, GUIDs, handles, sessions and network tuples are generally consistent at the tested precision; unresolved slice-dependent SMB references were not penalized.
- **Behavioral realism:** 6 — Platform-specific activity exists, but the repeated macOS command cycle and shared changing timing schedule have conspicuous template texture.
- **Environmental consistency:** 8 — Windows, Linux and native Mac roles and source forms largely coexist plausibly; exact collector/OS configuration is undisclosed and was not assumed.

## Recommendations

- If this were synthetic, allocate native Mac fork/exec PID versions in actual host execution order from the appropriate shared kernel-style sequence. Preserve each process's birth time through exec, and keep actor, target, parent and responsible audit-token references coherent with the resulting versions. Validate cross-process allocation chronology in addition to same-process version transitions.
- If this were synthetic, generate or preserve executable stat timestamps using meaningful filesystem timestamp precision. Avoid filling every independent access/change/birth/modify fraction with a small nonzero number below one microsecond. If a serializer is responsible, correct its units and document any deliberate timestamp transformation.
- If this were synthetic, replace the shared rotating macOS command schedule with activity tied to the user's visible task and host/session context, varying timing independently. Reusing standard administrative commands is realistic; repeatedly applying the same changing gap schedule to shifted command sequences across hosts creates the observed fingerprint.
- Preserve the successful source-native distinctions already present: setuid login transitions, fork versus exec lifetime semantics, process GUID/PID alignment, Windows eventlog UserData, and protocol/connection tuple agreement. Fix the identified semantics without weakening those useful detection contracts.
