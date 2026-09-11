# Detection Engineer — Feature-Branch Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 99
**Synthetic-Confidence Score:** 96

## Executive Summary

The dataset contains sophisticated, mostly source-native telemetry with strong role-based volume and cross-source correlation. However, a repeated Sysmon timestamp defect creates impossible internal event chronology across seven of nine Sysmon hosts: 105 records have `EventData.UtcTime` ahead of the event header by as much as 7,564.947 seconds, including create/terminate pairs assigned the same false `UtcTime`.

## Evidence For Synthetic

- **[hard_contradiction] Sysmon event-internal timestamps conflict with their own event headers.** Across the nine `windows_event_sysmon.xml` files, 105 of 3,572 Sysmon records have `EventData.UtcTime` more than one second later than `System/TimeCreated`; the lead reaches 2 hours 6 minutes 4.947 seconds. This affects seven hosts and is concentrated in present Event IDs 1 and 5.
- **[hard_contradiction] One process can have creation and termination assigned the same Sysmon `UtcTime`.** Four hosts contain 14 matched ProcessGuid lifecycle pairs with different header times but exactly identical internal `UtcTime` values.
- **[contract_gap] Other sources establish that the Sysmon header time is the actual occurrence time.** On `WS-AJOHNSON-01`, PID 5572 `mstsc.exe /v:DC-01` appears in Sysmon Event 1 at header time `14:42:38.4289327Z`, Security 4688 at `14:42:38.5612214Z`, and eCAR PROCESS/CREATE at epoch time `14:42:38.546Z`. Yet the Sysmon Event 1 `UtcTime` is `15:55:17.726`, 72 minutes 39 seconds late.
- **[hard_contradiction] The corresponding PID 5572 termination is also internally impossible.** Sysmon Event 5 has header time `15:12:51.0435386Z`, while its `UtcTime` remains `15:55:17.726`, the same value as process creation. eCAR terminates PID 5572 at `15:12:50.985Z`. A SIEM normalizing Sysmon on `UtcTime` would place both lifecycle events after the process had already terminated according to two other telemetry views.
- **[distribution_texture] The error repeats in characteristic clusters rather than resembling clock skew.** Examples include five identical-time create/terminate pairs on `WS-AJOHNSON-01`, seven on `WS-MCHEN-01`, and isolated pairs on `WS-EBROOKS-01` and `WS-PPATEL-01`. Offsets vary from seconds to over two hours, ruling out a fixed timezone or clock-offset explanation.
- **[schema_or_format] The conflicting canonical timestamps make otherwise valid Sysmon XML unsafe for SIEM processing.** A parser using `System/TimeCreated` produces the intended sequence, while standard Sysmon mappings commonly using `EventData.UtcTime` produce materially different and impossible timelines.

## Evidence For Real

- Windows provider GUIDs, channels, Event ID versions, tasks, keyword masks, SIDs, hexadecimal PIDs, logon IDs, and insertion-string values are generally well formed. Representative Security 4624, 4625, 4688, 4697, 4720, 4768, 4769, 5140, 5145, and 5156 records have plausible field sets.
- The DC Security log models a credible Event 1102 clear at `17:41:41.8532026Z`: the provider changes to `Microsoft-Windows-Eventlog`, data is represented under `UserData/LogFileCleared`, and `EventRecordID` resets from 28,260,889 to 1 before subsequent records resume at 5, 6, and 8.
- Source volumes reflect system roles: DC-01 has 6,289 Security events dominated by firewall, Kerberos, and logon activity, while ordinary Windows hosts have roughly 293–561 Security records. The proxy and public web server also have substantially higher flow telemetry than ordinary endpoints.
- Zeek data shows varied connection outcomes rather than a success-only model. Core states include 5,330 `SF`, 1,500 `S0`, and smaller `RSTO`, `RSTR`, `REJ`, `S1`, `S2`, `S3`, and `OTH` populations; DMZ telemetry has similarly varied outcomes.
- All sampled Zeek protocol UIDs resolve to corresponding `conn.json` rows. Protocol timing is plausible: DNS records follow connection open by milliseconds, while HTTP and TLS offsets vary naturally.
- Linux RFC5424 syslog contains realistic facility/severity values, process identifiers, PAM session pairs, DHCP sequencing, kernel/UFW messages, queue health, package activity, and operational noise. Bash history includes role-specific work, natural command diversity, and even an ordinary typo (`uptiem`).
- eCAR process identities, parent PIDs, logon IDs, principals, paths, and flow tuples correlate closely with Security, Sysmon header timestamps, and network data.

## Detailed Analysis

The collection covers a six-hour window from approximately `2024-03-18T12:00Z` through `17:59Z`. I parsed all Windows XML files, all line-oriented JSON families, and representative RFC5424, ASA, Snort, proxy, web, and bash-history records.

Windows System metadata is otherwise unusually consistent. Security Event 5156 uses Version 1/Task 12810; 4688 uses Version 2/Task 13312; 4624 uses Version 2/Task 12544. Present Sysmon types use coherent versions: Event 1 and 3 Version 5, Event 5/7/10 Version 3, and Event 8/11/13 Version 2. Record IDs are unique within each file and timestamps are monotonically ordered by `System/TimeCreated`.

That consistency makes the Sysmon `UtcTime` failures especially decisive. Normal Sysmon records have header-to-`UtcTime` latency around 1–3 ms. The anomalous population instead contains:

- `WS-MCHEN-01`, PID 7724 `mmc.exe`: header `14:55:09.5039903Z`, internal `UtcTime` `17:01:14.451`, a 7,564.947-second lead.
- `WS-SMARTINEZ-01`, PID 7460 `OUTLOOK.EXE`: header `13:42:38.3695434Z`, internal `UtcTime` `15:05:15.252`, a 4,956.882-second lead.
- `WS-MCHEN-01`, PID 7704 `powershell.exe`: header `13:07:23.8093016Z`, internal `UtcTime` `14:22:50.997`, a 4,527.188-second lead.
- `WS-EBROOKS-01`, PID 4808 PowerShell: Event 1 header `17:09:35.2955636Z` and Event 5 header `17:09:49.5998685Z`, but both records say `UtcTime=17:38:57.653`.

The anomaly count by host is: DC-01 1, WS-AJOHNSON-01 28, WS-DRAMIREZ-01 15, WS-EBROOKS-01 5, WS-MCHEN-01 45, WS-PPATEL-01 5, and WS-SMARTINEZ-01 6. FILE-SRV-01 and MAIL-FIN-01 do not show the greater-than-one-second defect. Because the offsets vary by record and other sources agree with the Sysmon header, collection delay, timezone, and simple clock skew do not explain it.

The network families are substantially better. Core Zeek contains 6,980 connections, 1,870 DNS rows, 1,529 HTTP rows, and 102 TLS rows. DMZ Zeek contains 7,881 connections, 1,744 HTTP rows, and 2,151 TLS rows. Protocol UIDs were present in the corresponding connection sets, byte/packet fields were nonuniform, and durations showed thousands of distinct values. Certificate chains connect SSL `cert_chain_fuids` to x509 IDs, and repeated certificates retain fingerprints while receiving per-observation file identifiers.

Syslog and appliance formats are also convincing. ASA built/teardown messages use plausible connection IDs, zones, NAT annotations, ports, durations, and byte counts. Snort records have recognizable rule/classification/priority syntax. Proxy logs use combined-style timestamps and expose tunnel control bytes separately from tunneled byte totals. These strengths reduce the likelihood of a crude synthetic corpus but cannot overcome the repeated impossible Sysmon lifecycle timestamps.

## Synthetic Indicator Summary

| Category | Source family | Scope | Score impact |
|---|---|---:|---|
| hard_contradiction | Windows Sysmon Event IDs 1 and 5 | 105 records across 7/9 Sysmon hosts; maximum 7,564.947-second discrepancy | Dominant |
| hard_contradiction | Sysmon process lifecycle | 14 matched ProcessGuid create/terminate pairs share one false `UtcTime` | Very high |
| contract_gap | Sysmon vs Security/eCAR | Multiple process occurrences where two sources and Sysmon header agree but Sysmon `UtcTime` disagrees | High |
| distribution_texture | Sysmon timestamp clusters | Variable multi-minute/hour offsets and reused lifecycle timestamps | Moderate, corroborating |
| schema_or_format | SIEM timestamp normalization | Parser-dependent contradictory chronology | Moderate operational impact |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Most Windows, Zeek, eCAR, syslog, ASA, and proxy fields are source-shaped and parseable, but Sysmon’s primary payload timestamp is materially wrong.
- **Temporal patterns:** 3/10 — Network and baseline timing are varied, but 105 impossible Sysmon payload timestamps and identical create/terminate times are severe.
- **Cross-source correlation:** 7/10 — IDs, tuples, PIDs, and header times generally correlate well; that correlation directly exposes the Sysmon timestamp defect.
- **Behavioral realism:** 9/10 — Host-role activity, connection outcomes, process trees, administrative traffic, and Linux operational noise are convincing.
- **Environmental consistency:** 9/10 — Addressing, host roles, domain identities, services, proxy routing, and collection volumes are coherent.

## Recommendations

If synthetic, derive every Sysmon `EventData.UtcTime` from the individual event occurrence represented by `System/TimeCreated`, not from a parent action, session boundary, or later lifecycle anchor. Add validation requiring these two timestamps to remain within realistic provider latency and requiring Event ID 1 and Event ID 5 for the same ProcessGuid to have distinct, ordered `UtcTime` values. Cross-source tests should also assert that Security 4688, Sysmon Event 1, and eCAR PROCESS/CREATE timestamps converge on the same process creation, with the matching termination strictly later.
