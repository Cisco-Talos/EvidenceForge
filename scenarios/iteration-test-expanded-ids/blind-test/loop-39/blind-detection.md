# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 78  
**Synthetic-Confidence Score:** 42

## Executive Summary

Most of the 82,882 visible records are unusually strong at the schema and correlation level: Windows Security/Sysmon field sets, Event ID metadata, GUID/SID/hash formats, process lifecycles, and cross-source timing are internally coherent. The principal synthetic tell is systematic misuse of Windows Security Event 4648 network fields: all 31 events place the target server’s address in `IpAddress`, while their ephemeral `IpPort` values do not correspond to any matching observed connection tuple; this looks like a repeated generator or normalization contract error rather than ordinary collection loss.

## Evidence For Synthetic

- `[hard_contradiction]` All 31 Security Event 4648 records appear to populate `IpAddress` with the target server address, not the address of the computer from which the explicit-credential attempt was made. Examples include:
  - `WS-PPATEL-01` at `2024-03-18T13:55:18.0343351Z`: target `MAIL-EDGE-01`, `IpAddress=10.10.2.25`.
  - `WS-AJOHNSON-01` at `2024-03-18T14:51:30.5739449Z`: target `WS-SMARTINEZ-01`, `IpAddress=10.10.1.36`.
  - `WS-MCHEN-01` at `2024-03-18T14:50:31.2035884Z`: target `DC-01`, but `IpAddress=10.10.1.99`, which is the address associated elsewhere with `LT-MRIVERA-02`, not the emitting workstation or DC.
  - `FILE-SRV-01` at `2024-03-18T16:17:15.9883554Z`: target `DB-PROD-01`, `IpAddress=10.10.4.10`.
  This is source-native semantic misuse of the 4648 Network Information block.

- `[contract_gap]` None of the 31 Event 4648 source-host/target-address/`IpPort` combinations matches a Zeek connection anywhere in the six-hour dataset, and none has even a same source/destination tuple within ten seconds. For example, the `WS-PPATEL-01 → MAIL-EDGE-01` event above reports port `58446`, but no `10.10.1.32:58446 → 10.10.2.25` connection exists. Missing telemetry alone would not be evidence, but the 31/31 systematic result combined with the reversed address semantics indicates that these fields were assembled independently of the transport evidence.

- `[distribution_texture]` Security 4688 and Sysmon Event 1 pairing is nearly deterministic across the Windows fleet: 911 of 914 Security process creations have exact PID/image Sysmon partners. Median timestamp separation is approximately 5.5–7 ms per host, and most host maxima remain under 20 ms. This is a weak signal only—both providers observe the same underlying operation—but the extremely narrow delay distribution is cleaner than many production collection pipelines.

- `[weak_signal]` Every one of the 656 Sysmon Event 3 records has `Initiated=true`. An outbound-only Sysmon rule set can legitimately produce this, so it did not materially drive the verdict, but the dataset does not expose any `Initiated=false` example with which to test inbound network detection semantics.

## Evidence For Real

- The dataset is substantial and heterogeneous: approximately 82,882 records across 18 endpoint eCAR streams, nine Security logs, nine Sysmon logs, two Zeek sensors, proxy/web/syslog, ASA, and Snort sources. The visible window spans roughly six hours, from 12:00 to 18:00 UTC.

- Windows provider metadata is highly accurate across 17,887 XML events. Security events consistently use the Security channel, correct provider identities, expected versions such as 4624 v2, 4688 v2, and 5156 v1, and success/failure audit keywords appropriate to outcome. Sysmon records consistently use the Operational channel, Level 4, and plausible event versions.

- I parsed and checked representative records for Security IDs 1102, 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4800, 4801, and 5156, plus Sysmon IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22. Apart from the 4648 semantic defect, the field names and basic value types are convincingly source-native.

- Event 4624 semantics vary appropriately by logon type:
  - Interactive Type 2 events use `User32`, local workstation names, dash IP/port values, and `winlogon.exe`.
  - Service Type 5 events use `Advapi` and local service identities.
  - Network Type 3 events include IPv4-mapped IPv6 source addresses and distinguish Kerberos from NTLM, including NTLM `KeyLength=128`.
  - Remote interactive Type 10 events include remote workstation/IP/ephemeral port values.

- Logon lifecycle checks found no visible logoff preceding its matching logon. Only five of 747 Security 4634 events lacked a visible 4624 on the same host, an entirely reasonable bounded-window condition.

- Process lifecycle checks were similarly sound. Across Sysmon, no Event 5 termination preceded the matching visible Event 1 creation, no dependent process event preceded its matching visible creation, and no child process referenced a visible parent created later. Unmatched terminations are consistent with processes already running before collection began.

- Security/Sysmon process correlation is excellent without field disagreement. Representative example: `WS-PPATEL-01` created `C:\Windows\System32\spoolsv.exe` as PID 6048 at `12:05:54.5804402Z` in Event 4688 and at `12:05:54.5898044Z` in Sysmon Event 1, with aligned parent, user, command line, and process identity.

- Sysmon field shapes are credible:
  - Event 1 has the expected 22 fields, including process/parent GUIDs, hashes, logon data, and product metadata.
  - Event 10 correctly uses `SourceProcessGUID` and `TargetProcessGUID`.
  - Event 22 uses semicolon-terminated query results.
  - Event 7 contains signature and hash metadata.
  - Events 8, 11, and 13 have realistic source-native field sets.

- System binary hashes are stable where file versions match and differ coherently across OS builds. For example, `spoolsv.exe` uses one hash for version `10.0.19041.1`, another for `10.0.20348.1`, another for `10.0.22621.1`, and another for `10.0.17763.1`, consistently across hosts sharing each build. This is a particularly convincing implementation detail.

- Security EventRecordIDs are unique and monotonic within each file, with realistic gaps. On `DC-01`, Event 1102 at `2024-03-18T17:42:30.4513637Z` correctly uses the `Microsoft-Windows-Eventlog` provider and `LogFileCleared` UserData; subsequent Security record IDs reset to 1 and increase to 778, while filtered-out events leave gaps.

- The account and service records are internally coherent. On `DC-01`, account `svc_mhsync` retains the same SID ending `-4771` through 4720 creation, 4724 password reset, 4728 Domain Admins membership, 4738 change, and 4726 deletion. Event 4697 service records use plausible service type/start values, and Event 4698 contains a structurally credible Task Scheduler XML document.

- eCAR records use valid UUID-shaped identities, have no duplicate event IDs, and show no visible actor/process creation occurring after a dependent event. Process termination `objectID` values consistently join back to visible process creations when those creations fall within the window.

- Zeek UID relationships and JSON value types were consistent in the records sampled, with plausible protocol-specific connection states, packet accounting, and fan-out into DNS, HTTP, SSL, X.509, file, SMTP, DHCP, OCSP, and PE logs.

## Detailed Analysis

### Quantitative inventory

I counted 13,462 Windows Security events, 4,425 Sysmon events, 25,241 eCAR records, 20,312 Zeek JSON records, and 19,442 line-oriented proxy/web/syslog/firewall/IDS records. Security volume is dominated by 7,920 Event 5156 records, 1,102 Event 4624 records, 1,070 Event 4769 records, 914 Event 4688 records, 747 Event 4634 records, and 653 Event 4689 records. Sysmon contains 911 Event 1, 762 Event 22, 668 Event 5, 656 Event 3, 600 Event 13, 530 Event 10, 192 Event 7, 97 Event 11, and 9 Event 8 records.

### Windows Security schema and Event ID accuracy

All observed Security Event IDs had stable, appropriate field sets. Event 4624 contained the full v2 field set, including linked-logon, restricted-admin, virtual-account, elevated-token, and outbound identity fields. Event 4625 had correctly different failure fields (`Status`, `SubStatus`, `FailureReason`) rather than simply reusing the 4624 shape. Event 4688 used hexadecimal process IDs, token elevation resource strings, mandatory-label SIDs, and full subject/target sections. Event 5156 used device-style application paths, numeric protocol identifiers, resource-string directions, WFP layer fields, and remote identity SIDs.

Failure keyword behavior is convincing: 4625 and 4771 use `0x8010000000000000`, successes use `0x8020000000000000`, and 1102 uses `0x4020000000000000`. Event levels and versions also match expectations.

The major exception is Event 4648. Its `TargetServerName` and `TargetInfo` already identify the remote system, while `IpAddress` repeats that target’s IP. The Network Information address is supposed to describe the originating computer. The associated ephemeral port values also fail to join to any observed connection tuple, making the record actively misleading for detections that correlate explicit credential use with transport activity.

### Authentication and session correlation

Of 747 visible 4634 logoffs, only five lacked a matching visible 4624 on the same host; none had an impossible visible ordering. The unmatched cases are spread across hosts and fit pre-window sessions. Type 3 sessions often close quickly, while interactive and remote-interactive sessions persist longer.

Kerberos fields are diverse rather than fixed: 4768 includes AES256 (`0x12`), AES128 (`0x11`), and RC4 (`0x17`), multiple legitimate ticket option combinations, and pre-auth types 0, 2, and 15. Event 4769 similarly varies encryption and ticket options. IPv4-mapped IPv6 client addresses and ephemeral ports are consistently formatted.

Representative RDP record: `DC-01` Event 4624 at `2024-03-18T14:14:38.7687168Z` records `marcus.chen`, Type 10, source workstation `WS-MCHEN-01`, source `::ffff:10.10.1.31:65082`, Kerberos authentication, `winlogon.exe`, and a unique target logon ID. Its fields are suitable for normal SIEM RDP rules.

### Process and Sysmon integrity

Security 4688 and Sysmon Event 1 align closely:

| Host | Security 4688 | Sysmon 1 | Exact PID/image pairs |
|---|---:|---:|---:|
| DC-01 | 172 | 172 | 172 |
| FILE-SRV-01 | 101 | 101 | 101 |
| MAIL-FIN-01 | 98 | 98 | 98 |
| WS-AJOHNSON-01 | 126 | 126 | 126 |
| WS-DRAMIREZ-01 | 69 | 69 | 69 |
| WS-EBROOKS-01 | 74 | 74 | 74 |
| WS-MCHEN-01 | 121 | 120 | 120 |
| WS-PPATEL-01 | 80 | 78 | 78 |
| WS-SMARTINEZ-01 | 73 | 73 | 73 |

The three missing Sysmon partners are plausible source-observation gaps. No sampled pair contradicted process image, PID, user, or parent identity.

Sysmon ProcessGuids and parent GUIDs are valid brace-delimited UUID forms. Visible parent references never point forward in time. Event 5 and Security 4689 termination paths contain unmatched pre-window processes but no matching visible process terminated before creation.

Hashes have correct lengths and algorithm labels. More importantly, hash/version relationships behave like fleet binaries rather than per-event random values. Hosts on the same OS build share the same binary hash, while different builds have distinct hashes.

### eCAR structure and usefulness

All 25,241 eCAR records are valid JSON with unique event IDs. The dominant object/action families are `FLOW/CONNECT`, `PROCESS/CREATE`, `PROCESS/TERMINATE`, `USER_SESSION/LOGIN`, `USER_SESSION/LOGOUT`, plus file, module, registry, process-open, and remote-thread activity. Process creation `objectID` values are reused by terminations and dependent records, and no visible dependency precedes the corresponding visible process creation.

The eCAR properties use consistent canonical keys such as `image_path`, `command_line`, `logon_id`, `source_process_uuid`, and network tuple fields. The short hostname convention differs from Windows FQDNs but remains consistent and does not prevent correlation.

### Timing and source correlation

XML `SystemTime` values use seven fractional digits and UTC `Z`; Sysmon `UtcTime` values use its familiar millisecond display. eCAR uses integer epoch milliseconds, and Zeek uses fractional epoch seconds. No XML file contains a timestamp inversion.

The 4688/Event 1 delay distribution is very narrow. On most hosts the median is 5.5–7 ms and the maximum is below 20 ms, with a few larger outliers up to about 180 ms. This is possible for locally generated channels but looks cleaner than a pipeline where separate subscriptions, forwarders, or ingestion queues contribute latency. I therefore treated it only as a secondary texture signal.

### Detection-stack behavior

Most common SIEM content would work well:

- Windows process creation rules can join Security and Sysmon on host/PID/time.
- Logon/logoff rules can track target logon IDs.
- Kerberos detections receive correct encryption, status, service, client-address, and ticket-option fields.
- Sysmon process-access and remote-thread rules have correctly named source/target GUID and image fields.
- DNS, flow, and proxy detections receive typed addresses, ports, protocols, and timestamps.

Rules using Event 4648 Network Information would be wrong. A query interpreting `IpAddress` as the caller would attribute the credential use to the destination, and a tuple join on `IpAddress`/`IpPort` would fail in every visible case.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Windows Security 4648 | All 31 records | Target address is placed in the source-address field, producing wrong caller attribution. This was the main reason the dataset did not receive a clear Real verdict. |
| `contract_gap` | Security 4648 ↔ Zeek/eCAR flow | All 31 records | No reported address/port combination joins to a visible source-host/target transport tuple; the port appears independently generated. |
| `distribution_texture` | Security 4688 ↔ Sysmon 1 | Dataset-wide | Pairing delays are highly concentrated around 5–7 ms. Plausible locally, but cleaner than many forwarded production datasets. |
| `weak_signal` | Sysmon Event 3 | 656 records | Every record has `Initiated=true`; plausible under outbound-only filtering, so it had little score impact. |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Windows, Sysmon, Zeek, and eCAR formats are generally excellent; Event 4648 network-field semantics are the clear exception.
- **Temporal patterns:** 9/10 — No impossible process/session ordering was found, log clearing resets record IDs correctly, and timestamp representations are source appropriate.
- **Cross-source correlation:** 8/10 — Process and lifecycle correlations are strong, but Event 4648 cannot be joined to transport evidence using its reported network fields.
- **Behavioral realism:** 9/10 — Authentication, process, service, account, DNS, and network activity show credible diversity and lifecycle behavior.
- **Environmental consistency:** 9/10 — OS-version-specific binary metadata, host naming, service placement, authentication mechanisms, and network addressing are internally coherent.

## Recommendations

- If this were synthetic, correct the Event 4648 field contract first. Populate `IpAddress` and `IpPort` according to the source-native meaning for the credential-use mechanism—typically caller-side network information or source-native dash/loopback/zero values—not the target server’s address.

- Build Event 4648 and any resulting remote connection from one canonical transaction. When a real network attempt is represented, the caller, target, source port, destination service, timestamp, and process should join to the corresponding endpoint/network tuple. If the connection is not observable under the collection profile, avoid inventing an unrelated ephemeral port.

- Preserve the strong Security/Sysmon process correlation, but consider a more empirically shaped source-delay distribution if the intended collection path includes forwarding or centralized ingestion. This recommendation is lower priority because the current delays remain technically plausible.

- If the selected Sysmon configuration is intended to capture inbound connections, include credible `Initiated=false` Event 3 records. If it is deliberately outbound-only, no change is necessary.
