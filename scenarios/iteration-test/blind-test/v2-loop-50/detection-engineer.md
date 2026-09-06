# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 96  
**Synthetic-Confidence Score:** 86

## Executive Summary

The corpus is highly parseable and much of its Windows, Sysmon, eCAR, and Zeek structure is
convincing, but several record-level contradictions are not credible as production telemetry.
The strongest indicators are repeated Kerberos 4769/4624 causality and `LogonGuid` failures, an
eCAR process that terminates before six of its module loads, and a sub-millisecond workstation
lock/unlock cycle.

## Evidence For Synthetic

- **P0 — [hard_contradiction] Kerberos service tickets repeatedly occur after the successful
  target logon they enable.** I matched Event 4769 to Event 4624 using the requesting user,
  client IP, and target computer account. There were 20 exact-context pairs involving a nonzero
  4624 `LogonGuid`; 18 place 4769 after 4624 by 0.061–1.128 seconds. For example,
  `WS-MCHEN-01.../windows_event_security.xml` Event 4624 record 949397 logs a successful
  Kerberos Type 3 logon for `marcus.chen` from `::ffff:10.10.2.27` at
  `2024-03-18T15:08:10.2455473Z`, while `DC-02.../windows_event_security.xml` Event 4769 record
  25382421 issues the ticket to `marcus.chen` for `WS-MCHEN-01$` at
  `2024-03-18T15:08:11.3739299Z`, 1.128 seconds later.

- **P0 — [contract_gap] The same 20 exact-context Kerberos pairs disagree on `LogonGuid`.** Every
  matched Event 4769 has `{00000000-0000-0000-0000-000000000000}`, while each corresponding
  Event 4624 has a nonzero GUID. In the example above, the 4624 GUID is
  `{2c5b2d40-2f98-4d9c-ad02-354fbf00c95b}`. A second pair does have correct causal order but the
  same GUID failure: `DC-01.../windows_event_security.xml` Event 4769 record 28248931 at
  `13:20:11.5504405Z` is followed by `WS-DRAMIREZ-01.../windows_event_security.xml` Event 4624
  record 236163 at `13:20:12.5381636Z`; the former GUID is zero and the latter is
  `{ec7fd84a-d0f7-45ac-8ca0-3d66a1f5463a}`. This defeats the native correlation field a SIEM rule
  would use.

- **P0 — [hard_contradiction] eCAR records module loads after their owning process terminates.**
  In `WS-AJOHNSON-01.../ecar.json`, line 860 creates Teams utility PID 6212 with object ID
  `83166db9-4507-45e7-8353-7ffe35c45eb4` at epoch-ms `1710778237468`; line 862 terminates that
  exact object at `1710778237492`. Lines 863–868 then emit six `MODULE/LOAD` records attributed to
  the terminated object at `1710778237497` through `1710778237575`. These are visible events for
  one durable process identifier in one source, so collection-window boundaries cannot explain
  the inversion.

- **P1 — [schema_or_format] Nonzero GUIDs are assigned systematically to native NTLM logons.**
  Of 175 successful Event 4624 records with `AuthenticationPackageName=NTLM` and
  `LogonProcessName=NtLmSsp`, 151 carry nonzero `LogonGuid` values. One example is
  `DC-02.../windows_event_security.xml` Event 4624 record 25379145 at
  `2024-03-18T13:05:20.2502700Z`, whose NTLM Type 3 logon has GUID
  `{d6bf9004-eace-4f0c-ae85-190c877118e1}`. Native NTLM logons normally expose the null GUID;
  this high-frequency pattern would mislead correlation logic and reads like a shared GUID
  assignment path that is not authentication-package-aware.

- **P2 — [distribution_texture] One workstation locks and unlocks in 0.635 milliseconds.**
  `WS-AJOHNSON-01.../windows_event_security.xml` Event 4800 record 131199 locks session 2,
  Logon ID `0x263743b`, at `2024-03-18T17:48:17.3933800Z`; Event 4801 record 131200 unlocks the
  same session at `2024-03-18T17:48:17.3940149Z`. A human unlock at this interval is not credible.
  Other lock cycles lasted minutes, which makes this isolated lifecycle edge especially visible.

- **P3 — [schema_or_format] Sysmon Event 22 renders SRV answers without the native RR-type
  annotation.** Across 46 `_ldap._tcp...` or `_kerberos._tcp...` queries, every `QueryResults`
  value is rendered as bare SRV RDATA rather than entries prefixed with `type: 33`. For example,
  `WS-MCHEN-01.../windows_event_sysmon.xml` Event 22 record 525181 at
  `2024-03-18T12:04:49.7548227Z` reports
  `0 100 389 DC-01.meridianhcs.local;0 100 389 DC-02.meridianhcs.local;`. Parsers that preserve or
  tokenize native Sysmon DNS result syntax would not see the expected record-type marker.

## Evidence For Real

- All 18,473 Security events and 4,816 Sysmon events parsed as well-formed XML; all 32,914 eCAR
  records and sampled Zeek families parsed as JSON. Event-specific field sets were stable without
  obvious cross-event field leakage.

- Windows provider metadata was generally accurate. Security Event IDs 4624, 4625, 4634, 4648,
  4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4779,
  4800, 4801, 5140, 5145, 5156, and 1102 used plausible providers, channels, versions, tasks,
  keywords, and field names. The 1102 record correctly used `Microsoft-Windows-Eventlog`,
  `UserData/LogFileCleared`, and reset the Security `EventRecordID` to 1.

- Security/Sysmon process creation correlation was strong but not used as a synthetic clue.
  Across ten Windows hosts, 926 of 930 Security 4688 records had matching Sysmon Event 1 records
  by host, PID, and image; the four unmatched Security records are compatible with selective
  observation. Process GUID lifecycle checks found no Sysmon dependent event before its visible
  Event 1 or after its visible Event 5.

- Visible Windows logon lifecycle ordering was coherent. Across 872 Event 4624 records and 447
  Event 4634 records, no matched `TargetLogonId` logged off before its visible login. No Event
  4672 for a visible Logon ID preceded its 4624.

- Sysmon field detail was convincing in many areas: GUIDs and hashes had valid shapes, executable
  hashes varied with OS/file version rather than per execution, Event 10 had 179 distinct call
  traces and realistic access masks, and `TimeCreated` consistently followed `UtcTime` by a small
  positive collection delay.

- Zeek correlation was internally sound in the inspected families. Every DNS, HTTP, SSL, SMTP,
  SMB mapping/file, and file-analysis UID referenced a visible `conn.json` row on the same sensor;
  companion records did not precede their connection start and their five-tuples agreed. The
  connection-state mix included `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `OTH`, `S1`, `S2`, and `S3`
  rather than collapsing to a single successful state.

## Detailed Analysis

### Corpus and sampling

The visible window is approximately `2024-03-18 12:00:01Z` through `17:59:54Z`. I parsed the
complete Security, Sysmon, eCAR, and Zeek JSON/XML files, then manually inspected representative
records from more than 20 Security Event IDs and all nine present Sysmon Event IDs (1, 3, 5, 7,
8, 10, 11, 13, and 22). The principal SIEM-facing checks were event metadata, event-specific
field sets, value formats, durable identifiers, causal ordering, and cross-source joins.

### Windows Security schema and authentication semantics

The basic schemas are credible. Event 4624 version 2 includes the extended fields expected for
that version; Event 4688 version 2 includes command line, target subject, parent image, and
mandatory label; Events 5140/5145 use sensible share and access fields; and Event 5156 uses
numeric protocol values and localized direction/layer tokens. SIDs, hexadecimal IDs, IPv4-mapped
IPv6 addresses, and status values are correctly shaped.

Kerberos correlation is the central failure. Exact-context joins were deliberately conservative:
same requesting account, same client IP, and Event 4769 `ServiceName` equal to the computer whose
Security log contains the 4624. Twenty such pairs corresponded to nonzero 4624 GUIDs. All 20 GUID
joins failed, and 18 had the ticket event occur after authentication on the target. Because this
is repeated across `WS-AJOHNSON-01`, `WS-DRAMIREZ-01`, `WS-EBROOKS-01`, and `WS-MCHEN-01`, it is
not an isolated clock anomaly. The approximately one-second bounded spread also has the texture
of independently jittered sibling events rather than a prerequisite/consumer timestamp contract.

The NTLM GUID issue is separate and broader. The corpus correctly emits null GUIDs for 24
anonymous NTLM logons, but assigns nonzero GUIDs to 151 named-account NTLM logons. That split by
account type is internally systematic but not faithful to the `NtLmSsp`/NTLM source semantics.

### Sysmon and process correlation

Sysmon schemas and most values are strong. Event versions and field names are consistent, the
same binary metadata produces stable hashes within a version, and Event 1 parent GUIDs do not
create visible child-before-parent contradictions. Security 4688/Sysmon 1 and Security
4689/Sysmon 5 pairs differ by plausible source collection delays, including small inversions
between different channels; I did not score those as contradictions.

The eCAR process lifecycle does contain a same-source contradiction. Teams PID 6212 exists for
only 24 ms in eCAR, then loads six core DLLs after its termination. The corresponding Sysmon
records show Event 1 `UtcTime=16:10:37.306` and Event 5 `UtcTime=16:10:37.467`, with no Sysmon
dependent event after termination. That contrast localizes the defect to eCAR ordering rather
than the underlying process identity.

Sysmon Event 22 otherwise has plausible status codes (`0`, `9002`, `9003`), A/PTR/SRV-style
answers, process attribution, and semicolon-delimited results. The repeated omission of `type: 33`
on SRV RDATA is a smaller source-native formatting defect, but one that a raw-field detection or
normalizer could expose.

### Session and temporal behavior

Most visible 4624/4634 and 4672 sequences are causally ordered, and longer lock intervals on
`WS-MCHEN-01` are credible. The 0.635 ms 4800/4801 pair on `WS-AJOHNSON-01` is therefore not a
general timestamp precision artifact: it is a specific impossible human session transition.
The assessment does not penalize sessions or processes merely because their other endpoint lies
outside the six-hour collection window.

### Zeek and eCAR SIEM usability

Zeek JSON keys and types were consistent across the three sensors. UID and tuple joins succeeded
for every inspected protocol companion, and JSON omission was used for unset optional fields
rather than malformed placeholder types. eCAR records also had unique event IDs and coherent
process object identities in nearly all cases. Those strengths would make the corpus useful for
detection testing, but they cannot offset the explicit authentication and process-lifecycle
contradictions above.

## Synthetic Indicator Summary

| Severity | Category | Affected source family | Scope | Effect on score |
|---|---|---|---|---|
| P0 | `hard_contradiction` | Windows Security 4769/4624 | 18 of 20 exact-context pairs | A prerequisite ticket is visibly issued after successful use; decisive authenticity failure. |
| P0 | `contract_gap` | Windows Security Kerberos | 20 of 20 exact-context pairs | Native `LogonGuid` correlation fails systematically. |
| P0 | `hard_contradiction` | eCAR process/module | One process, six post-termination loads | Same-source durable identity proves impossible lifecycle ordering. |
| P1 | `schema_or_format` | Windows Security NTLM | 151 of 175 successful NTLM 4624s | Authentication-package semantics are systematically wrong and would pollute joins. |
| P2 | `distribution_texture` | Windows Security session lifecycle | One lock/unlock pair | A 0.635 ms human session transition is not credible. |
| P3 | `schema_or_format` | Sysmon DNS Event 22 | All 46 LDAP/Kerberos SRV queries | Bare SRV RDATA omits native `type: 33` rendering expected by raw-field parsers. |

## Realism Score by Category

- **Field format accuracy:** 7/10 — Most XML/JSON schemas and scalar formats are strong, but NTLM
  GUID semantics and SRV result rendering are conspicuous exceptions.
- **Temporal patterns:** 4/10 — Most event streams are ordered, but repeated TGS-after-logon pairs,
  post-termination module loads, and a sub-millisecond lock cycle are material failures.
- **Cross-source correlation:** 5/10 — Process and Zeek joins are excellent, while the native
  Kerberos GUID contract fails in every exact-context sample.
- **Behavioral realism:** 6/10 — Process, network, and authentication variety is convincing, but
  impossible lifecycle edges reduce confidence sharply.
- **Environmental consistency:** 8/10 — Hostnames, accounts, OS paths, service placement, network
  ranges, and binary versions are generally coherent across the visible corpus.

## Recommendations

- If this were synthetic, make Kerberos ticket issuance a prerequisite of the target logon and
  propagate one canonical `LogonGuid` into both Event 4769 and Event 4624. Apply source-specific
  delay only after enforcing the visible causal bound; validate exact joins by requester, client
  IP, target service account, and GUID.

- If this were synthetic, make eCAR process termination the final event in that process object's
  lifecycle. Module, flow, file, registry, and process-access observations for an object should
  be constrained to the interval between its create and terminate records after source timing is
  resolved.

- If this were synthetic, make 4624 GUID population authentication-package-aware. Native NTLM
  (`NtLmSsp`/`NTLM`) records should use the null GUID unless there is a verified Windows-native
  case that supplies one.

- If this were synthetic, impose a realistic minimum workstation lock duration and test every
  same-session 4800/4801 pair for positive, human-plausible elapsed time.

- If this were synthetic, render Sysmon Event 22 SRV answers with their source-native RR-type
  annotation (`type: 33`) and add raw-format samples for SRV, PTR, CNAME, and multi-answer
  responses to parser tests.
