# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 91
**Synthetic-Confidence Score:** 72

## Executive Summary

Most records are readily parseable and exhibit convincing source-specific fields, process lifecycles, and network correlations. However, native macOS Endpoint Security process-generation identities move backwards across visibly later process births on both Macs; this is a concrete identity-allocation inconsistency, rather than a complaint about completeness or attack narrative. Its repeated occurrence supports a synthetic verdict despite otherwise strong realism.

## Evidence For Synthetic

- [hard_contradiction] **Process-generation counter chronology reverses on MAC-MROSS-01.** In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:75`, a newly forked child PID 64190 has `event.fork.child.audit_token.pidversion=88`, `start_time=2026-11-02T16:00:08.553321Z`, and `mach_time=25142605279704`. Line 77 creates a later child PID 64367 with version **70**, `start_time=2026-11-02T16:02:01.753084Z`, and greater `mach_time=25145322074016`. Both are new-child snapshots, so this is not comparing an old parent with a new child or confusing exec with fork. Apple's XNU assigns new forked processes their versions from the host-wide incrementing `nextpidversion` counter. [Apple's fork implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c)
- [hard_contradiction] **The same defect recurs independently on MAC-MROSS-02.** In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson:114`, child PID 52334 receives version **116** at `17:12:27.393377Z` (`mach_time=56350737441048`). Line 117 creates child PID 53019 with version **94** at `17:19:16.577170Z` (`mach_time=56360557852080`). Its recorded start time is also later. There are additional backward transitions among freshly forked children at lines 34→38, 92→96, and 101→105 in this same file. These repetitions make isolated delivery jitter an inadequate explanation.
- [distribution_texture] **Identity numbering resembles a small selected-event counter.** Both Macs' first visible new children have version 10 despite PIDs 42158 and 19006, respectively (`macos_endpoint_security.ndjson:1` in each host directory). Later selected forks/execs use a compact range into the low hundreds, including the backward blocks above. This supports the identity issue but is not counted as a second independent major defect: identifier sanitization could also create low numbers.

## Evidence For Real

- The Windows records use differentiated event shapes and metadata rather than one generic envelope. For example, DC-01 Security 4688 is version 2/task 13312 with hexadecimal process IDs and `MandatoryLabel`, while 5156 is version 1/task 12810 with decimal `ProcessID`, an NT device path, and direction/layer fields (`windows_event_security.xml:1556` and `:3`). These distinctions agree with Microsoft's documented shapes. [4688 reference](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688), [5156 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156)
- DC-01 has a coherent visible NTLM network session: Security 4624 at `13:00:58.3507162Z` establishes `0x5375b2c` for `aisha.johnson`, Type 3, from `::ffff:10.10.2.11:54209`; 5140 at `13:00:58.3749078Z` uses that identity for NETLOGON; 4634 closes it at `13:01:04.1812095Z` (`windows_event_security.xml:494`, `:549`, `:588`). NTLM is explicitly declared, so I do not require Kerberos tickets for this example.
- The DC-01 taskhostw process agrees between Sysmon create/terminate and Security create/terminate. Sysmon GUID `{83eb9c06-89f9-6ae8-9502-0000a239ce2e}`, PID 3712, image, and termination all remain consistent with Security PID `0xe80` (`windows_event_sysmon.xml:846`, `:891`; `windows_event_security.xml:1556`, `:1599`). Different source timestamps are credible observation differences.
- Zeek DNS uses the connection UID and complete tuple consistently; UDP DNS `SF`/`Dd` is valid, rather than an invalid TCP-state assumption (`zeek-core/conn.json:1`, `zeek-core/dns.json:1`). [Zeek connection reference](https://docs.zeek.org/en/lts/reference/logs/conn.html)
- The macOS records distinguish forked inherited images from subsequent exec targets. MAC-MROSS-01 native ES lines 8–10 show a zsh child execing `/usr/bin/id`, then exiting; eCAR lines 16–18 describe the corresponding CREATE, exec MODIFY, and TERMINATE. The initial inherited shell image is not an erroneous final executable attribution.

## Detailed Analysis

### Inputs, provenance, and reproducibility

I read the complete neutral briefing at `/private/tmp/log-study-if4zptfd/detection-prompt.md`. Local examination was restricted to `/private/tmp/log-study-if4zptfd/data`; the report is written to the explicitly designated sibling path. All shell parsing used system `python3` with working directory `/private/tmp/log-study-if4zptfd`; no project tools or `uv` were invoked. Commands contained in logs were treated as inert text.

The data directory contains 119 files. I inventoried their relative names, first records, and line counts; parsed all 76,037 JSON/NDJSON records and all 31,369 Windows XML events (19,272 Security and 12,097 Sysmon); ran identity, lifecycle, byte-accounting, certificate-consistency, and UID/time-interval checks described below; and inspected bounded text examples. This is not an exhaustive semantic audit of every syslog, firewall, shell-history, or IDS line.

External references were Microsoft Learn, Zeek's official documentation, Apple Developer documentation, and Apple's public XNU source. Searches used actual domain restrictions; direct upstream URLs were also used. A GitHub-restricted search returned ancillary third-party snippets about Darwin identity handling; I did not use those as evidence. No repository files, authored scenario, TODO, worklog, previous assessment, other reviewer report, or task-project public documentation were accessed. Generic inherited operating instructions were present as an environment limitation and were excluded from authenticity reasoning.

All relative paths below are relative to the supplied `data` directory. XML line citations identify the opening `<Event>` line; JSON citations identify the physical record line. Timestamps are UTC.

### Native identity inconsistency and its limits

The important distinction is between ES `process` (actor), `event.fork.child` (the new child), and `event.exec.target` (the new image). [Apple's message documentation](https://developer.apple.com/documentation/endpointsecurity/es_message_t?changes=__1_5_1&language=objc) defines the actor relationship. The scored comparison uses **new fork children only**, avoiding the normal reuse of old versions in parent snapshots.

Apple's fork source declares the global counter and assigns the new process `p_idversion` by atomically incrementing it. Separately, Apple's process source returns that field as the PID version and compares it with audit-token word 7 during identity validation. This makes the chronology relevant to native identity semantics, not merely to a naming preference. [Apple fork source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c), [Apple process identity source](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_proc.c)

Reproduction: iterate each ES file in time order, select records whose `event` contains `fork`, and compare consecutive `event.fork.child.audit_token.pidversion` values along with the child's `start_time` and envelope `mach_time`. MAC-MROSS-01 has one backward transition; MAC-MROSS-02 has four. The strongest examples are:

| Host | Earlier fork line / time / PID / version | Later fork line / time / PID / version |
|---|---|---|
| MAC-MROSS-01 | 75 / 16:00:08.553321 / 64190 / 88 | 77 / 16:02:01.753084 / 64367 / 70 |
| MAC-MROSS-02 | 114 / 17:12:27.393377 / 52334 / 116 | 117 / 17:19:16.577170 / 53019 / 94 |

The wall clocks and monotonic Mach clocks advance, and each child's start time equals its own later fork time. Old-process observations, missing pre-window events, and normal exec identity updates do not explain these examples. Nor is a normal reboot consistent with the continuously increasing Mach clock and retained actor lifetimes. Counter wraparound is theoretically possible, but repeated tiny backward blocks on both hosts without any visible wrap-scale values are not a credible routine explanation.

An undocumented privacy transformation could have reassigned PID versions while leaving other fields native-looking. That would be a transformation artifact rather than proof of a particular generator, and is one reason verdict confidence is below 100. The supplied native-looking records nevertheless contain this concrete inconsistency. I do not infer the precise macOS release merely from message `version=11`; no unsupported message-version or signing-schema allegation is scored.

### Twenty representative event checks

The following are actual parsed records, covering varied event semantics. This table documents both ordinary checks and the specific exception rather than claiming every source/version combination has been independently certified.

| Record | Fields and result |
|---|---|
| DC-01 Security XML:3, 5156 | Decimal PID 2420, inbound UDP tuple, `Direction=%%14592`, layer `%%14610`/44; device-path application matches dns.exe. |
| DC-01 Security XML:44, 4776 | `PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, machine account/workstation, success status `0x0`; expected credential-validation shape. |
| DC-01 Security XML:240, 4624 | Type 5 NETWORK SERVICE, reserved LUID `0x3e4`, local services.exe and no remote endpoint; reasonable service-logon semantics. |
| DC-01 Security XML:295, 4672 | Same NETWORK SERVICE SID/LUID with service-relevant privilege list; consistent subject. |
| DC-01 Security XML:494, 4624 | Type 3, NTLM/NTLM V2, key length 128, source endpoint and named domain user; consistent mechanism. |
| DC-01 Security XML:549, 5140 | NETLOGON share, matching subject LUID and remote port; coherent share access. |
| DC-01 Security XML:588, 4634 | Same user/SID/LUID and Type 3; later visible closure. |
| DC-01 Security XML:1556, 4688 | Version 2; new PID `0xe80`, creator `0x930`, taskhostw/svchost paths and System integrity SID. |
| DC-01 Security XML:1599, 4689 | Terminates `0xe80`/taskhostw with status `0x0`; matches creation. |
| DC-01 Security XML:1675, 4769 | Computer client, service-account SID, AES encryption type `0x12`, IPv4-mapped client address and zero GUID; valid-looking TGS shape. |
| DC-01 Security XML:4121, 4768 | krbtgt service, RID 502, preauthentication type 2, port and empty certificate fields; appropriate password-based ticket shape. |
| DC-01 Sysmon XML:3, 3 | GUID, decimal PID, UDP, `Initiated=false`, source/destination fields and lowercase Boolean strings; inbound DNS process observation. |
| DC-01 Sysmon XML:443, 22 | QueryName, QueryStatus 0, semicolon-terminated QueryResults, process identity and User; source-specific DNS schema. |
| DC-01 Sysmon XML:594, 10 | Distinct Source/Target GUIDs and PIDs, GrantedAccess `0x1000`, SourceThreadId and module-offset CallTrace; ProcessAccess shape. |
| DC-01 Sysmon XML:846, 1 | Create GUID/PID, parent identity, hashes, logon/integrity fields; correlates with Security create. |
| DC-01 Sysmon XML:891, 5 | Same GUID/PID/image, later termination; valid selected lifecycle. |
| zeek-core/dns.json:1 | Typed transaction ID, query type 33/SRV, Boolean flags, answer and TTL arrays, and UID match; no parser issue. |
| zeek-core/http.json:1 | GET `/blog`, HTTP 1.1, 200 status, integer response length 16612, file reference; source-specific HTTP shape. |
| MAC-MROSS-01 native ES NDJSON:9 | NOTIFY exec actor zsh, target `/usr/bin/id`, same PID 42166, version 17→18, args and tty; distinguishes actor/target properly. |
| MAC-MROSS-01 native ES NDJSON:77 | New fork child PID 64367/version 70; structurally parseable but violates the earlier-child identity chronology described above. |

In this table, “Security XML” and “Sysmon XML” refer to `DC-01.meridianhcs.local/windows_event_security.xml` and `windows_event_sysmon.xml`. Native ES paths use the host directory plus `macos_endpoint_security.ndjson`. Microsoft's Sysmon documentation supports using ProcessGuid for lifecycle correlation and distinguishes the selected event families. [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### Bulk correlation checks and neutral observations

- All JSON/NDJSON records decoded and all Windows XML files parsed. This does not itself establish production origin.
- Across the selected Sysmon records, no GUID-matched terminate-before-create or ordinary `ProcessGuid`-bearing activity-after-termination was found. This check excludes SourceProcessGUID/TargetProcessGUID relationships, which require a separate join. There are 972 process-create rows and 826 terminate rows; the unequal counts are neutral at the collection boundaries.
- I checked Windows user-process creation against visible non-unlock logon starts and logoffs by host/LUID, excluding reserved built-in LUIDs. No impossible visible ordering was found. Repeated Type 7 unlock records and repeated reserved service LUIDs must not overwrite the actual session start in such a check.
- Within each Zeek sensor, DNS, HTTP, SSL, SMB file, and SMTP records had matching local conn UIDs. Their timestamps did not precede connection start by more than 1 ms or exceed the recorded interval by more than 10 ms in this check. This is positive consistency, not a synthetic indicator based on completeness.
- No TCP row with `missed_bytes=0` had IP-byte totals below payload bytes plus the minimum 40-byte IPv4/TCP header cost per recorded packet. Retransmissions and options can increase that cost, so excessive overhead was not treated as impossible. [Zeek byte and packet semantics](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)
- Identical X.509 fingerprints did not change certificate fields across the supplied records. Sysmon image hashes did not change for the same host, image path, and recorded file version. Hash differences between operating-system builds were not scored.
- Linux syslog uses a plausible RFC5424-style envelope; for example APP-INT-01 line 1 carries `<78>1`, a precise UTC timestamp, CRON PID 2931365, and a sysstat job. Repeated sysstat commands are expected automation and are not scored merely for recurring.
- Thin Unified Log exports, selected ES event families, and absent Sysmon event types are not scored. Network sensor coverage does not establish native endpoint collection obligations. Native ES notifications were not interpreted as proof of an authorization denial or approval policy beyond their event meaning.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| hard_contradiction | Native macOS Endpoint Security | Five backward new-child PID-version transitions across both Macs | Principal reason for a likely-synthetic score: native identity allocation contradicts visible process-birth chronology. |
| distribution_texture | Native macOS Endpoint Security identity fields | Both hosts begin selected child numbering at 10 and remain in compact ranges | Supporting texture only; shares the identity root cause and is not double-counted. |

The score is 72 because the defect is concrete and repeated, while the extensive Windows and network samples are convincing. It is not 91 merely because verdict confidence is 91, and I did not extrapolate this defect into unobserved failures in every source family.

## Realism Score by Category

- **Field format accuracy:** 9 — Source envelopes, event-specific fields, numerical encodings, and parser behavior are convincing; native identity values have the noted semantic exception.
- **Temporal patterns:** 7 — Ordinary lifecycle ordering holds, but native PID-version allocation contradicts the chronology of new process births.
- **Cross-source correlation:** 9 — Tested Windows process/session and sensor-local Zeek joins work; fork/exec normalization was handled distinctly.
- **Behavioral realism:** 8 — Visible service, user-shell, DNS, file-share, and network activity is plausible; no penalty for narrative compactness or missing mistakes.
- **Environmental consistency:** 8 — Mixed Windows/Linux/macOS semantics generally respect host/source boundaries; the native identity-counter behavior remains a material exception.

## Recommendations

- If this were synthetic, assign native macOS PID versions using one host-scoped allocation sequence in actual process-birth/exec chronology. Preserve those identities consistently in ES actor, child, target, parent, and responsible tokens; do not allocate them in the order activity batches happen to be assembled.
- If the observed identity values were changed for privacy, document that remapping in collection metadata or preserve monotonic generation relationships when transforming them. This would let analysts distinguish a deliberate transformation from an invalid native identity stream.
- Retain the successful source distinctions already visible: NTLM versus Kerberos, reserved Windows service LUIDs versus ordinary sessions, Sysmon GUID lifecycles, and macOS fork versus exec. No additional source families or invented companion events are required by this assessment.
