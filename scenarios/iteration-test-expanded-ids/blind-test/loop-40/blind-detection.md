# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 87  
**Synthetic-Confidence Score:** 52

## Executive Summary

The telemetry is exceptionally strong at the schema, identifier, timestamp, and cross-source correlation layers: 18,347 Windows events parsed cleanly, Windows/Sysmon process pairs preserve PID, parent, image, command line, and LogonID truth, and Zeek/ASA/eCAR lifecycle checks produced no visible causal inversions. The principal counterweight is a dataset-wide Sysmon registry pattern in which the same Windows KB package name appears with dozens of apparently fabricated version identities and is written by implausible owning processes across all nine Windows hosts; that is a concrete generator-like fingerprint strong enough to prevent a Real verdict.

## Evidence For Synthetic

- `[distribution_texture]` Sysmon Event 13 contains 293 writes beneath `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages` across all nine Windows hosts. Of these, 290 set `CurrentState` to the identical `DWORD (0x00000070)`, creating a dominant and highly repetitive registry family.
- `[schema_or_format]` The single package name `Package_for_KB5034122~31bf3856ad364e35~amd64~~...` appears in 52 records with 51 distinct package versions. Within build 20348 alone it has 25 suffixes, including `10.0.20348.6`, `.11`, `.14`, `.17`, `.32`, `.35`, `.39`, `.40`, `.43`, `.45`, `.46`, `.50`, `.53`, `.54`, `.56`, `.61`, `.64`, `.65`, `.68`, `.72`, `.74`, `.75`, `.77`, `.78`, and `.79`. A named KB can vary by OS branch, but this many quasi-random revisions under the same package identity on one branch is not credible CBS inventory.
- `[environment_or_collection_plausibility]` The same CBS `CurrentState` writes are attributed exclusively to `services.exe` (95), `svchost.exe` (96), and `msiexec.exe` (102), rather than the usual servicing owner processes such as `TrustedInstaller.exe` or `TiWorker.exe`. Examples include DC-01 at `2024-03-18T12:02:21.6955994Z`, where `services.exe` writes `Package_for_KB5034122...10.0.20348.72\CurrentState`, and at `12:04:00.0583222Z`, where `msiexec.exe` writes `Package_for_RollupFix...10.0.20348.47\CurrentState`.
- `[weak_signal]` All 677 Sysmon Event 3 records have `Initiated=true`, including on DC-01, FILE-SRV-01, and MAIL-FIN-01. An outbound-only Sysmon rule can explain this, but the complete absence of server-side accepted connections is a noticeably narrow collection texture given the otherwise broad Sysmon policy.
- `[weak_signal]` All 4,362 Sysmon events use `RuleName=-`. This is legal and common when rule names are not configured, so it had little independent score impact, but it adds to the impression of a uniformly rendered fleet policy.

## Evidence For Real

- All nine Security XML files and nine Sysmon XML files parsed successfully. The 13,985 Security records and 4,362 Sysmon records use stable event-specific field sets and correct provider/channel/system metadata.
- Security Event metadata is accurate across the observed IDs. Examples include 4624 Version 2/Task 12544, 4688 Version 2/Task 13312, 5156 Version 1/Task 12810, and 1102 from `Microsoft-Windows-Eventlog` with Level 4, Task 104, and audit-success keywords.
- Sysmon metadata and field layouts match the event types present: Event 1 Version 5, Event 3 Version 5, Event 5 Version 3, Event 7 Version 3, Event 8 Version 2, Event 10 Version 3, Event 11 Version 2, Event 13 Version 2, and Event 22 Version 5.
- Windows value formats are strong. SIDs, LogonIDs, GUIDs, hex process IDs, status codes, WFP resource strings, integrity labels, hash bundles, and IPv4-mapped IPv6 client addresses are consistently well formed.
- The 893 Security 4688 records and 893 Sysmon Event 1 records correlate almost perfectly. I matched 890 pairs by host, PID, image, and timestamp; all 890 also agreed on command line, parent PID, parent image, and LogonID. The three unmatched Security events and three unmatched Sysmon events are plausible source-local drops rather than contradictions.
- Cross-source process timing has organic jitter. Matched Security/Sysmon creation deltas range mostly across approximately ±20 ms with both signs represented; two larger outliers are 117 ms and 205 ms. This does not look like identical timestamp copying.
- Hashes behave like stable binary identity. Repeated executions of the same image/version on a host never changed SHA1, MD5, SHA256, or IMPHASH, and image/module metadata is populated for most standard and third-party binaries.
- Logon lifecycle checks found no visible close-before-open contradictions. Of 765 Security 4634 records, 759 had a prior matching 4624 in the window; the six without visible opens had no later matching open and are consistent with pre-window sessions.
- The DC Security log clear is especially convincing. Event 1102 at `2024-03-18T17:41:43.5234846Z` uses the proper `UserData/LogFileCleared` structure, resets `EventRecordID` from 28262290 to 1, and subsequent records continue at 4, 6, and 7.
- Kerberos and NTLM fields are coherent: 4768/4769 successes use plausible AES/RC4 encryption types, 4771 failures use `Status=0x18` and `PreAuthType=2`, and 4776 uses `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` with appropriate success/bad-password statuses.
- The 25,535 eCAR JSON records all parse, have unique event IDs, valid UUID fields, correct per-directory hostnames, monotonic timestamps, and no visible process-dependent record preceding a later creation of the same object.
- Zeek is highly usable. Across both sensors, all 11,788 conn UIDs are unique per sensor; every DNS, HTTP, SSL, and SMTP UID resolves to a conn record; all shared tuples agree; and no protocol record precedes its connection.
- TLS details are internally credible: TLS 1.3 uses TLS 1.3 cipher names and normally lacks visible certificate chains, while non-resumed TLS 1.2 records carry chains. All 560 visible X.509 certificates are valid at observation time.
- The ASA stream has 4,875 builds and 4,873 teardowns, with no duplicate connection IDs and no teardown preceding or lacking its build. The two open connections are valid bounded-window endpoints, and every PRI severity matches the embedded ASA severity.
- All 197 Snort records parse in canonical fast-alert form. Spot checks of `.bit`, `.cloud`, `.tk`, and `.top` DNS signatures resolve to same-tuple Zeek DNS records whose query suffix matches the signature.

## Detailed Analysis

### Quantitative inventory and parsing

I parsed 13,985 Security events across nine Windows hosts:

- 5156: 8,250
- 4769: 1,252
- 4624: 1,107
- 4688: 893
- 4634: 765
- 4689: 639
- 4768: 529
- 4672: 363
- 4776: 87
- 4625: 40
- 4648: 32
- Remaining account, service, task, lock/unlock, audit-clear, and Kerberos-failure records: 28

I parsed 4,362 Sysmon events:

- Event 1: 893
- Event 22: 756
- Event 3: 677
- Event 5: 648
- Event 13: 543
- Event 10: 538
- Event 7: 205
- Event 11: 95
- Event 8: 7

All XML and JSON sources parsed without malformed records. Windows `EventRecordID` values and timestamps are monotonic within each file except for the correct Security-log reset caused by Event 1102.

### Windows event schema and value checks

I examined records from 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4800, 4801, 5156, and 1102.

The event-specific data names are stable and credible. For example, all 4624 records use the Version 2 extended field set through `ElevatedToken`; all 4688 records include the Version 2 target identity, parent image, and mandatory-label fields; and 1102 correctly uses `UserData` rather than a fabricated `EventData` list.

Logon types are plausible: 761 Type 3, 317 Type 5, 13 Type 10, eight Type 7, and eight Type 2. Type 2/5/7 records use `IpAddress=-`; Type 3 and Type 10 records carry remote IPv4-mapped addresses where appropriate. Failure combinations are coherent, including bad-password `0xc000006d/0xc000006a/%%2313` and disabled-account `0xc000006d/0xc0000072/%%2307`.

The account/service storyline records also render credibly. Event 4697 at `2024-03-18T15:59:55.6913573Z` identifies `PSEXESVC`, `%SystemRoot%\PSEXESVC.exe`, type `0x10`, demand start, and `LocalSystem`. Event 4698 at `16:19:51.0911441Z` contains a well-formed escaped Task Scheduler XML definition.

### Process and session correlation

For every matched 4688/Sysmon Event 1 pair, Security hex PIDs convert to the Sysmon decimal PIDs, and parent identity, command line, image, and LogonID match exactly. The source timestamps are not copied: both positive and negative deltas occur, mostly within 20 ms.

All Sysmon process GUIDs match the braced GUID format. I checked dependent Event 3, 5, 7, 11, 13, and 22 records against visible process creations and found no case where a dependent record used a GUID and a creation for that same GUID appeared later in the window.

Sysmon Event 10 also has credible detail rather than a fixed placeholder: 538 records contain 67 distinct call traces, with zero-, one-, and two-separator stack depths and six plausible access-mask values. The seven Event 8 records use formatted start addresses, source/target GUIDs, source/target users, and plausible module/function combinations.

### Registry telemetry defect

The CBS family is the main authenticity failure. It is not merely high-volume registry telemetry; the names and actors are semantically weak.

Across the dataset, a single named KB is represented as dozens of unrelated package versions. For build 22621, KB5034122 appears with nine different revisions; build 20348 has 25; build 19041 has 11; and build 17763 has six. Almost every occurrence has a unique revision. This resembles independent random suffix generation, not installed-package identity.

The owning `Image` field compounds the problem. All 293 CBS writes are assigned to `services.exe`, `svchost.exe`, or `msiexec.exe`; none use the servicing workers expected to own direct CBS state transitions. Because this affects all nine Windows hosts and nearly 54% of Event 13 volume, it materially influenced the synthetic-confidence score.

### Network and SIEM usability

Both Zeek sensor families are clean JSONL with source-native field names. Core has 6,298 conn records and DMZ has 5,490. Protocol fan-out is internally consistent:

- DNS: 2,975 rows, all with matching conn UIDs/tuples and no pre-connection timestamps.
- HTTP: 2,206 rows, with valid multi-transaction reuse.
- SSL: 1,746 rows, all matched to connections and all response-bearing.
- SMTP: 67 rows, all matched.
- DHCP: 69 rows and 69 conn UID references, all present and `SF`.
- Files/PE/X.509/OCSP identifiers use plausible Zeek FUID shapes and coherent local correlation.

The firewall and IDS records are similarly ingestible. ASA connection IDs do not collide, build/teardown ordering is sound, and Snort alert headers, generator/signature/revision triplets, classifications, priorities, protocols, and endpoints are parseable.

### Collection-window handling

I did not treat pre-window sessions, processes, certificate observations, or the two unclosed ASA flows as synthetic. No visible initiator for any of these identifiers occurred later than its dependent event. Likewise, complete UID and process correlations were counted as realism evidence only because the values and timings are source-native and non-contradictory, not because completeness itself proves authenticity.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score effect |
|---|---|---:|---|
| `schema_or_format` | Sysmon Event 13 / CBS package identities | 52 KB5034122 records, 51 distinct versions | High: repeated impossible-looking package identity construction |
| `environment_or_collection_plausibility` | Sysmon Event 13 process ownership | 293 records across all 9 Windows hosts | High: CBS state writes attributed to implausible owners |
| `distribution_texture` | Sysmon Event 13 CBS state | 290 identical `DWORD (0x00000070)` writes | Medium: dominant repeated background family amplifies the identity defect |
| `weak_signal` | Sysmon Event 3 | 677/677 `Initiated=true` | Low: explainable by an outbound-only filter |
| `weak_signal` | All Sysmon | 4,362/4,362 `RuleName=-` | Very low: legal default configuration |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Sysmon, Zeek, eCAR, ASA, and Snort structures are highly accurate, but CBS package identities are not credible.
- **Temporal patterns:** 9 — Source-native precision, jitter, lifecycle ordering, and the Security-log reset are convincing.
- **Cross-source correlation:** 9 — Process, session, UID, tuple, certificate, DHCP, firewall, and IDS checks found no visible contradictions.
- **Behavioral realism:** 7 — Most activity is plausible, but CBS ownership by services/svchost/msiexec is a broad behavioral defect.
- **Environmental consistency:** 7 — Host roles and protocol use fit, while the fleet-wide fabricated-looking package inventory reduces confidence.

## Recommendations

- If this were synthetic, generate CBS package identities from a coherent per-OS servicing inventory. A named KB should have a defensible package version for each OS branch, not dozens of random low revision suffixes.
- Attribute direct `Component Based Servicing\Packages\...\CurrentState` changes to realistic servicing owners such as `TrustedInstaller.exe` or `TiWorker.exe`, with compatible parent processes and update-session timing.
- Reduce CBS registry volume unless an actual servicing interval is modeled. Preserve repeated `0x70` values only when backed by a coherent package transition and actor lifecycle.
- If Event 3 is intentionally outbound-only, retain that policy consistently; otherwise include a small source-native sample of `Initiated=false` server accepts on the Windows server hosts.
- Consider named Sysmon rules for selected high-value detections, while retaining `-` for unnamed baseline rules; this is polish rather than a correctness requirement.
