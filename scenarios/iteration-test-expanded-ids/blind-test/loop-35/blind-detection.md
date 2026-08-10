# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 78  
**Synthetic-Confidence Score:** 64

## Executive Summary

The collection is unusually strong in correlation integrity, timestamp coherence, and most Windows/Zeek field values, but it contains several repeatable source-native schema defects that would not normally be produced by the named providers. The strongest indicators are noncanonical Snort classification strings across all 227 alerts, a manifest-order defect across all 1,049 Security 4624 records, and missing required user fields in every Sysmon Event ID 8 version 2 record.

## Evidence For Synthetic

- `[schema_or_format]` All 227 records in `snort-core/snort_alert.log` and `snort-perimeter/snort_alert.log` place classtype identifiers such as `[Classification: policy-violation]`, `[Classification: potentially-bad-traffic]`, and `[Classification: icmp-event]` into Snort fast-alert output. Native Snort fast alerts normally render the human-readable description resolved from `classification.config`, not the hyphenated rule `classtype` identifier. Examples include the core alert at `03/18-12:07:23.166401` and perimeter alerts throughout the collection.
- `[schema_or_format]` Every one of the 1,049 Windows Security Event ID 4624 version 2 records serializes `ElevatedToken` before `TargetLinkedLogonId`. The Security-Auditing v2 manifest order is `VirtualAccount`, `TargetLinkedLogonId`, then `ElevatedToken`. The field names and values remain usable to name-based SIEM parsers, but the dataset-wide raw XML ordering is not faithful to the provider schema.
- `[schema_or_format]` All seven Sysmon Event ID 8 records declare version 2 but omit the version-2 `SourceUser` and `TargetUser` fields. Examples include `WS-AJOHNSON-01` at `2024-03-18T15:45:12.2225955Z`, where `ms-index-service.exe` creates a thread in `lsass.exe`, and `WS-PPATEL-01` at `2024-03-18T13:17:12.0391692Z`, where `MpCmdRun.exe` targets `MsMpEng.exe`. The associated identities are available elsewhere in the endpoint telemetry, so this is a renderer/schema omission rather than an unavoidable absence.
- `[weak_signal]` The defects above are invariant within their event families: 227/227 Snort records use identifier-style classifications, 1,049/1,049 4624 records share the same field-order defect, and 7/7 Sysmon 8 records omit the same two fields. That uniformity is more consistent with deterministic formatting behavior than occasional collector damage.

## Evidence For Real

- Windows System metadata is otherwise highly accurate. Security 4688 uses version 2, task 13312, and the expected 15-field payload; 4689 uses task 13313; 5156 uses version 1/task 12810 with numeric protocols and native WFP device paths. Sysmon Event IDs 1, 3, 5, 7, 10, 11, 13, and 22 have internally appropriate versions, tasks, and fields.
- The Security/Sysmon process correlation is excellent without impossible ordering. Of 923 Security 4688 records, 921 have a matching Sysmon Event 1 by host, PID, image, and timestamp within two seconds. The observed deltas range from Sysmon 25.708 ms before Security to 124.467 ms after it. The two Security-only creations are plausible collection omissions rather than contradictions.
- At `WS-AJOHNSON-01`, `SearchProtocolHost.exe` PID 5232 appears in Sysmon Event 1 at `2024-03-18T12:03:23.9480746Z` and Security 4688 at `12:03:23.9626791Z`, with matching image, parent PID 4628, and parent `SearchIndexer.exe`.
- No visible process-parent impossibilities were found. Among Sysmon process creations whose parent GUID was visible, no child preceded its parent creation and no child was created after the referenced parent’s termination. Process GUIDs were not reused.
- Session causality is coherent. No 4634 or 4672 record had a matching visible 4624 occurring later. Five 4634 records had no visible login, but each was a logout-only boundary case consistent with a session established before the six-hour window.
- Hash behavior is realistic. Within a host, the same image path never changed its Sysmon Event 1 or Event 7 hash set. Cross-host variation was concentrated in operating-system binaries, where differing builds are plausible; common third-party paths generally retained one hash set.
- Kerberos fields are detailed and internally typed: 4768 certificate pre-authentication records populate issuer, 32-hex-character serial, and 40-hex-character thumbprint values, while noncertificate pre-authentication leaves those fields empty.
- Zeek references are structurally sound. Across both sensors, every DNS, HTTP, SSL, and SMTP UID has a corresponding `conn.json` record with the same tuple, and no protocol record precedes its connection. All file `conn_uids` resolve, and all 697 referenced certificate FUIDs resolve to `x509.json`.
- A representative DNS transaction, UID `CkyYeTBueC0jvnClMR` at epoch `1710763210.733374`, has the same tuple in `zeek-core/conn.json` and `dns.json`; its 2.976 ms DNS RTT equals the connection duration.
- The SSH lifecycle from `10.10.1.31:61363` to `10.10.4.10:22` is credible: Zeek UID `CPsE2kOFtBcgGFQmlvj` begins at `12:00:13.509266`, followed by DB syslog connection, public-key acceptance, PAM session open, and logind session creation between `12:00:15.664867Z` and `12:00:18.424459Z`.
- The Security-log clear sequence is source-native and causally coherent: `cmd.exe /c wevtutil cl Security` at `17:42:28.1680121Z`, `wevtutil.exe` at `17:42:28.5455871Z`, Event 1102 at `17:42:29.6787301Z`, and a reset of `EventRecordID` to 1. Event 1102 correctly uses the Eventlog provider and `UserData/LogFileCleared` structure.
- Shell history includes realistic concurrent-session ordering. For example, `DB-PROD-01` history contains later epoch entries followed by earlier entries rather than a globally sorted narrative, consistent with separate shells appending history.

## Detailed Analysis

### Collection and parseability

All examined JSON records parsed successfully: 25,805 eCAR records plus the Zeek families. All Windows Security and Sysmon XML documents parsed successfully with provider namespaces intact. The principal source window is approximately `2024-03-18T12:00Z` through `18:00Z`; a small number of host process terminations extend beyond 18:00. I did not penalize process, session, or logoff records whose initiators were outside the bounded window.

The Windows collection contains 13,566 Security events and 4,621 Sysmon events. Major Security families include 1,049 logons, 715 logoffs, 923 process creations, 640 process terminations, 515 TGT requests, 1,119 TGS requests, and 8,059 WFP connection permits. Sysmon includes 921 process creations, 707 network connections, 652 process terminations, 583 process-access events, 602 registry modifications, and 792 DNS queries.

### Windows Security schema and Event ID fidelity

Most Event ID metadata and payload shapes agree with their declared versions. Examples include:

- 4625 version 0 with status, substatus, failure reason, logon type, process, workstation, and network fields.
- 4688 version 2 with token elevation, command line, target identity, parent image, and mandatory label.
- 4697 with service name, binary, type, start type, and service account.
- 4768/4769 with expected Kerberos ticket options, encryption types, IP fields, and certificate fields.
- 5156 with native `\device\harddiskvolume1\...` application paths, numeric protocols 6/17, direction resource identifiers, and WFP layer identifiers.

The repeatable 4624 serialization-order error is the notable exception. A parser that maps `Data` elements by `Name` will still ingest the event correctly, but a strict provider-schema comparison or position-based pipeline would observe a mismatch in every 4624 record.

Logon values themselves are plausible: types 2, 3, 5, 7, and 10 are present; remote IPs are represented as IPv4-mapped IPv6 where appropriate; local/service events use `-`; and logon IDs correlate with 4634 and 4672 without visible reverse causality.

### Sysmon schema and process telemetry

Events 1, 3, 5, 7, 10, 11, 13, and 22 have consistent native-looking payloads. `UtcTime` has millisecond precision, while XML `SystemTime` retains finer precision and occurs 0–0.999 ms later, a plausible formatting relationship. Process/image hashes remain stable within each host.

Event ID 8 is the clear schema exception. Each record declares version 2 and ends after `StartFunction`, omitting `SourceUser` and `TargetUser`. This matters operationally: detections for cross-user remote-thread creation or SYSTEM-to-user injection commonly consume those fields. The omission also contrasts with Event ID 10, where `SourceUser` and `TargetUser` are present.

The suspicious Event 8 at `WS-AJOHNSON-01` (`15:45:12.2225955Z`) is still correlatable by process GUID, PID, image, and target, but its absent identities reduce detection fidelity.

### Cross-source correlation

The collection exhibits strong, technically useful joins:

- Security 4688 and Sysmon 1 agree on host, process PID, image, parent PID/image, command line, and logon context for 921 records.
- Security 4689 and Sysmon 5 match for 639 of 640 Security terminations within two seconds; the single unmatched record is an isolated collection gap rather than a contradictory record.
- Visible 4624/4672 and 4624/4634 relationships preserve ordering.
- eCAR process and session identifiers do not show a visible dependent record whose matching creator/login occurs later.
- Zeek protocol logs preserve UID, tuple, and timestamp relationships across both core and DMZ sensors. File and certificate references resolve cleanly.

This completeness was not counted as synthetic evidence. It instead establishes that the dataset is usable for joins and rule testing despite the source-native format defects.

### Snort, proxy, firewall, and text formats

Cisco ASA messages have credible priority values, message IDs, connection IDs, NAT notation, directions, durations, byte counts, and teardown reasons. Proxy and web records are structurally parseable extended/combined-style logs.

Snort fast-alert records preserve the expected date, signature tuple, message, priority, protocol, and endpoints, but the classification text is noncanonical. The defect spans all five observed classification families and both sensors:

- `attempted-recon`
- `icmp-event`
- `misc-activity`
- `policy-violation`
- `potentially-bad-traffic`

A SIEM regex may still extract the string, but rules and dashboards expecting configured Snort classification descriptions would receive unexpected values.

Linux syslog is valid RFC 5424-style text with plausible priorities, structured SSH/PAM/logind ordering, and realistic facility/program combinations. Bash history uses epoch comment lines in the expected `HISTTIMEFORMAT` persistence style and shows credible cross-session append ordering.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `schema_or_format` | Snort fast alerts | Dataset-wide, 227/227 alerts | Highest-impact indicator: the formatter emits rule classtype slugs where native fast-alert output normally emits configured descriptions. |
| `schema_or_format` | Windows Security 4624 v2 | Dataset-wide, 1,049/1,049 events | Repeatable provider-manifest ordering mismatch, suggestive of deterministic template serialization. |
| `schema_or_format` | Sysmon Event ID 8 v2 | Repeated, 7/7 events | Required `SourceUser` and `TargetUser` fields are absent, reducing strict schema compliance and detection utility. |
| `weak_signal` | Multiple source families | Repeated invariants | The defects occur uniformly within each affected family rather than as sporadic collector corruption. |

## Realism Score by Category

- **Field format accuracy:** 6 — Most Windows, Zeek, ASA, proxy, and syslog fields are strong, but the Snort classification rendering, 4624 ordering, and Sysmon 8 omissions are concrete native-schema defects.
- **Temporal patterns:** 9 — Source timestamps, process lifecycles, session ordering, DNS/connection timing, and window-boundary cases are coherent.
- **Cross-source correlation:** 9 — Process, session, Zeek UID, file, and certificate relationships are highly usable and show no sampled impossible ordering.
- **Behavioral realism:** 8 — Process, authentication, SSH, Kerberos, service, firewall, and shell activity use plausible values and sequences.
- **Environmental consistency:** 8 — Host roles, paths, accounts, network locations, protocol placement, and collection volumes are broadly consistent with the visible environment.

## Recommendations

- If this were synthetic, render Snort fast alerts through an authentic classification configuration so `classtype` identifiers resolve to their human-readable classification descriptions exactly as the native formatter would emit them.
- Generate Security Event ID 4624 version 2 directly from the provider manifest order, placing `TargetLinkedLogonId` before `ElevatedToken`, and add strict ordered-field fixture tests rather than checking only field-name presence.
- Add `SourceUser` and `TargetUser` to every Sysmon Event ID 8 version 2 record. Validate all Sysmon events against version-specific manifests so field additions are tied to the declared event version.
- Exercise representative output through strict source-family parsers and schema fixtures, including a Snort fast-alert classifier, ordered Windows EventData comparison, and version-aware Sysmon validation.
