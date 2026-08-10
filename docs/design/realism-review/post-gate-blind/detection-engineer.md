# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 87
**Synthetic-Confidence Score:** 74

## Executive Summary

The corpus is unusually strong synthetic telemetry: identities, PIDs, logon IDs, Zeek UIDs, file
IDs, hashes, network tuples, and lifecycle ordering are coherent enough to support realistic
detection joins. It also contains convincing production texture—browser bursts with cache hits,
mistyped shell commands, incomplete bounded-window lifecycles, failed authentication, scanner
noise, and heterogeneous endpoint volumes.

The synthetic verdict rests primarily on a repeated Windows schema defect and firewall lifecycle
contradictions. All 29 Windows Security Event 4648 records use non-native XML field names
`NetworkAddress` and `NetworkPort` where the provider schema uses `IpAddress` and `IpPort`.
Separately, three ASA translations are torn down at connection creation while their owning
half-open TCP connections remain alive for another 30 seconds. Broad symmetric timing displacement
between paired Sysmon 1 and Security 4688 records adds generator-like texture.

## Evidence For Synthetic

- **schema_or_format — repeated non-native Event 4648 fields.** Every observed 4648 record uses
  `NetworkAddress` and `NetworkPort`. Native `Microsoft-Windows-Security-Auditing` 4648 XML uses
  `IpAddress` and `IpPort`; Network Address and Port are display labels. This affects 29 records
  across all seven Windows hosts.

- **contract_gap — NAT teardown precedes owning connection teardown.** Three ASA dynamic
  translations tear down at their build timestamp with duration zero, while the associated TCP
  connection remains for 30 seconds and closes with `SYN Timeout`. The other 701 translation pairs
  retain coherent lifecycles, making the exceptions look like an implementation edge case.

- **distribution_texture — paired local-provider timestamps have broad symmetric jitter.** All 510
  inspected Sysmon process-create records have matching Security 4688 records, but their timestamp
  displacement ranges from Security occurring 1.018293 seconds before Sysmon to 0.846788 seconds
  after it. Each Sysmon `UtcTime` remains within one millisecond of its own `SystemTime`. The
  bidirectional bounded displacement resembles independent per-source jitter.

- **distribution_texture — highly regular provider construction.** Within every Windows file,
  each EventID has exactly one EventData field layout, record IDs are unique and monotonic, and
  process-create identity agrees across Sysmon, Security, and eCAR without an image mismatch. None
  is evidence alone, but they reinforce the explicit schema and timing defects.

## Evidence For Real

- No visible Sysmon dependent references a process created later or terminated earlier; no eCAR
  process-owned evidence falls outside its visible actor lifetime.
- Windows 4624/4634/4672 relationships and lock/unlock behavior are well ordered.
- All Zeek DNS, HTTP, TLS, file, X.509, DHCP, and connection references examined join correctly;
  no packet/IP-byte lower-bound contradiction was found.
- Bounded-window incomplete lifecycles were not treated as synthetic evidence.
- Bash histories include ordinary investigation, repetition, typos, background jobs, and exits.
- Web, proxy, Zeek, and firewall traffic include credible success, cache, denial, reset, half-open,
  scanner, and failure texture.
- Endpoint and network source volumes differ plausibly by host role.

## Detailed Analysis

The Windows provider envelopes are mostly accurate: provider GUIDs, channels, event versions,
tasks, keyword values, hexadecimal PIDs, SIDs, logon types, and Sysmon field layouts are
recognizable. Process identities remain consistent across 4688, Sysmon 1, and eCAR CREATE records.
The recurring 4648 XML-name defect is therefore especially diagnostic.

Authentication and process rules are feasible and detection joins are strong. Domain users keep
stable SIDs across hosts. Cross-source process joins require a tolerance of at least two seconds
because same-process provider times can differ by just over one second. Network UIDs, tuples,
firewall connection IDs, endpoint FLOW, and 5156 records retain usable correlation. The three
premature xlate teardowns are exceptions that can break stateful NAT correlation.

No claim is based on sanitized-domain resolution, absent optional Sysmon event types, high
cross-source completeness, thin coverage, or easy narratability.

## Synthetic Indicator Summary

- **schema_or_format:** 29 Event 4648 records use display-label-derived XML names.
- **contract_gap:** Three ASA dynamic translations close 30 seconds before their connection.
- **distribution_texture:** Security 4688/Sysmon 1 timing uses broad bounded bidirectional jitter.
- **weak_signal:** Provider layouts and sequencing are exceptionally regular.
- **hard_contradiction:** No impossible process/authentication ordering was found.
- **environment_or_collection_plausibility:** Overall source volumes and asymmetry are credible.

## Realism Score by Category

- **Field format accuracy:** 6/10
- **Temporal patterns:** 7/10
- **Cross-source correlation:** 9/10
- **Behavioral realism:** 8/10
- **Environmental consistency:** 8/10

## Recommendations

Use native 4648 `IpAddress`/`IpPort` names, enforce NAT-lifetime containment, preserve the existing
identity and lifecycle joins, and derive same-host provider timing from a more natural source-clock
model.
