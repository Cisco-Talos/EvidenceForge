# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 24

## Executive Summary

The dataset is highly production-like from a detection-engineering perspective: the Windows and Sysmon event schemas are source-native, timestamp and identifier correlations survive detailed sampling, and every parsed JSON/XML source is structurally usable by a SIEM. The principal reservation is a conspicuous collection-profile asymmetry in which all 695 visible Sysmon Event 3 records are locally initiated even though Security 5156 documents thousands of inbound connections on the same Windows fleet; this looks curated, but it is not a hard contradiction and could result from an explicit Sysmon filter.

## Evidence For Synthetic

- [environment_or_collection_plausibility] Across all nine Windows Sysmon files, all 695 Event ID 3 records have `Initiated=true`. This includes server-class systems such as `DC-01`, `FILE-SRV-01`, and `MAIL-FIN-01`, while the corresponding Security logs contain 4,866 inbound 5156 records (`Direction=%%14592`, receive/accept layer `%%14610`). For example, `WS-PPATEL-01` records an inbound SMB flow from `10.10.2.26:52232` to `10.10.1.32:445` at `2024-03-18T14:03:59.5756345Z`, yet the complete Sysmon Event 3 population contains no `Initiated=false` observations. A deliberately outbound-only Sysmon rule could explain this, but the all-or-nothing asymmetry is the clearest curated-collection signal.
- [distribution_texture] Some fields are unusually categorical at dataset scale. All 8,295 Security 5156 events use `RemoteUserID=S-1-0-0` and `RemoteMachineID=S-1-0-0`, all 704 Security 4689 records have `Status=0x0`, and every one of the 695 Sysmon Event 3 rows has an empty source-port service name (`SourcePortName=-`). Each value is individually valid, but the absence of even rare exceptions weakly suggests a bounded generator or normalized export rather than unconstrained production collection.
- [weak_signal] Sysmon process-create `LogonGuid` is the all-zero GUID for 868 of 969 records, including all user processes on several workstations. This can be explained by sessions beginning before the six-hour collection window or by telemetry/session-correlation limitations, and non-zero GUIDs are correctly reused where present, so it is only a low-weight concern.

## Evidence For Real

- Windows Security metadata is notably accurate across the event families sampled. Event 4624 is Version 2/Task 12544; 4688 is Version 2/Task 13312; 5156 is Version 1/Task 12810; success and failure keywords separate correctly; and the 1102 record uses the `Microsoft-Windows-Eventlog` provider plus native `UserData/LogFileCleared` structure rather than an incorrect generic `EventData` block.
- Security event field sets match their event IDs. The 1,086 Event 4624 records carry the expected Version 2 fields through `ElevatedToken`; 4625 includes `Status`, `FailureReason`, and `SubStatus`; 4688 contains `NewProcessId`, `TokenElevationType`, `ParentProcessName`, and `MandatoryLabel`; and 4768/4769 use plausible ticket options, encryption types, IPv4-mapped addresses, and client ports.
- Sysmon schemas are similarly credible: Event 1 has the expected Version 5 process, hash, parent, logon, and integrity fields; Event 10 uses source/target process GUIDs, access masks, and call traces; Event 13 uses `EventType=SetValue`; and Event 22 has realistic status/result shapes, including `9003` failures and SRV-style results.
- Cross-source process correlation is strong without visible causal inversion. Security 4688 and Sysmon Event 1 match on PID, image, and sub-second timing for essentially the full population: for example, `WS-AJOHNSON-01` creates `GoogleUpdater.exe` as PID 5232 at Sysmon `2024-03-18 12:01:51.361`, Security records PID `0x1470` at `12:01:51.3668541Z`, and eCAR records the same PID/image at epoch millisecond `1710763312125`. No sampled pair differed by more than one second or disagreed on image.
- Process and session lifecycles contain no impossible visible ordering. eCAR actor references that also have a visible create never precede that create, visible process terminations never precede their matching creates, and no Security 4634 precedes a visible 4624 for the same Logon ID.
- Zeek JSON is natively shaped and fully parseable. `conn.json` uses conventional dotted tuple fields and state/history/accounting values; DNS rows use standard flags, response codes, answer arrays, and TTL arrays; and HTTP/SSL rows use credible optional-field variation rather than a single rigid shape.
- Zeek UID contracts hold under exhaustive checks. Every DNS, HTTP, and SSL UID resolves to a `conn.json` record in the same sensor directory, all four tuple fields agree, protocol timestamps are at or after connection open and no later than connection close, and no orphan or tuple-conflicting protocol records were found.
- Timestamp representations fit each source: Windows `SystemTime` uses UTC ISO-8601 with seven fractional digits, Sysmon `UtcTime` uses millisecond precision, eCAR uses integer epoch milliseconds, Zeek uses floating-point epoch seconds, RFC5424 syslog uses UTC timestamps, and proxy logs use Apache-style `+0000` timestamps.
- Source-specific texture is convincing. Security log record IDs are monotonic except for the correct reset to `1` immediately after the DC's Security audit log clear at `2024-03-18T17:41:49.0211714Z`; Sysmon module signatures vary between valid signed vendors and unavailable unsigned modules; Event 10 contains varied access masks and 65 distinct call traces; and Zeek files/HTTP/SSL records exhibit plausible optional-field diversity.

## Detailed Analysis

### Windows Security events

I parsed all Windows Security XML files and inspected the aggregate schemas and values for Event IDs 1102, 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4800, 4801, and 5156. Provider GUIDs, channels, levels, tasks, opcodes, keywords, and versions are internally consistent with the event families.

Logon semantics are detailed rather than generic. The 4624 population contains Types 2, 3, 5, 7, and 10 with fitting process/authentication combinations: Type 5 is consistently `services.exe`/`Advapi`/`Negotiate`; Types 2, 7, and 10 use `winlogon.exe`/`User32`; Type 3 separates Kerberos and `NtLmSsp`/NTLM, including `NTLM V2` key length 128. Remote addresses use Windows-style IPv4-mapped IPv6 presentation such as `::ffff:10.10.1.31`, while local/service logons use `-`. Failed logons have coherent status chains, including `0xc000006d` with `0xc000006a` for bad passwords and `0xc0000072` for disabled accounts.

Kerberos records are SIEM-usable and varied: 4768 includes encryption types `0x12`, `0x11`, and `0x17`, several plausible ticket-option masks, and pre-auth types 0, 2, and 15; 4769 has service principals, status, client network data, and Logon GUID fields. I found no impossible visible TGS-before-TGT ordering that could be established for the same identifier within the bounded window.

The log-clear sequence is especially persuasive. DC-01 records `wevtutil cl Security`, then Event 1102 at `2024-03-18T17:41:49.0211714Z` with native provider `{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}`, `UserData/LogFileCleared`, SYSTEM subject fields, and EventRecordID 1. Subsequent Security records restart their IDs rather than continuing the pre-clear sequence.

### Sysmon and Windows correlation

I parsed Events 1, 3, 5, 7, 8, 10, 11, 13, and 22. Their field names and value types align with common Sysmon XML. Process GUIDs have the expected brace-delimited GUID form; PIDs are decimal in Sysmon and correlate to hexadecimal Security PIDs; hashes contain correctly sized SHA1, MD5, SHA256, and IMPHASH values; integrity levels and signature states are credible.

The process-create contract is unusually strong. Across the nine Windows systems there are 972 Security 4688 and 969 Sysmon Event 1 records. The few unmatched Security events are compatible with source-local observation loss; every matched nearest-time pair agreed on PID and image within one second. The same process identity is then reflected in eCAR with a plausible independent collection delay. I also found no eCAR actor whose visible process creation occurred later than the dependent event.

The Sysmon network population is the one material concern. It is not malformed: destination service names such as `domain`, `kerberos`, `ldap`, `microsoft-ds`, `ms-wbt-server`, `ssh`, and `http-alt` match ports, and hostnames/addresses are coherent. Nevertheless, an enterprise-wide population of 695 rows with no `Initiated=false` record is hard to reconcile with the rich inbound Security 5156 coverage unless the Sysmon configuration deliberately filters inbound connections.

### eCAR and JSON ingestion

All eCAR lines parsed as JSON and all event IDs were unique. The records maintain stable top-level types (`timestamp_ms`, UUID-like `id`/`objectID`, hostname, object, action, properties) while optional actor/PID/principal fields vary appropriately between process-attributed and unattributed network observations. Object/action families include process create/terminate/open, module load, flow connect, user-session login/logout, registry modification, file activity, remote-thread creation, and service creation. No matching process termination precedes its visible create, and no visible actor is referenced before its own visible creation.

### Zeek and other sources

Both Zeek sensors are line-delimited JSON with conventional field types. I exhaustively joined DNS, HTTP, and SSL rows to conn rows by UID: there were no missing UIDs, tuple mismatches, protocol records before connection open, or protocol records after the recorded connection interval. DNS contains NOERROR and NXDOMAIN behavior, A and service-style answers, flags, variable RTTs, and answer omission on failures. HTTP and SSL have source-native optional fields, response file references, certificate-chain references, and SNI omission where appropriate.

The RFC5424 syslog, bash timestamp records, Apache-style web/proxy logs, Cisco ASA text, and Snort alerts are readily parseable and use appropriate timestamp conventions. They add believable parser heterogeneity rather than forcing every source into one normalized schema.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `environment_or_collection_plausibility` | Sysmon Event 3 versus Security 5156 | Dataset-wide across nine Windows hosts | Moderate: 695/695 Sysmon network events are initiated locally despite 4,866 inbound WFP events; explainable only by an explicit filter. |
| `distribution_texture` | Windows Security/Sysmon | Dataset-wide | Low: a few fields have no long-tail exceptions (`RemoteUserID`, 4689 status, source-port names). |
| `weak_signal` | Sysmon Event 1 | Broad but not universal | Low: 868/969 process creates use a zero Logon GUID, but the window and session visibility provide a plausible explanation. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Sysmon, eCAR, Zeek, syslog, proxy, firewall, and IDS records are parseable and closely follow source-native schemas.
- **Temporal patterns:** 9 — Source-specific precision is correct, correlated observations have plausible latency, and no impossible visible lifecycle ordering was found.
- **Cross-source correlation:** 9 — Process/PID/image joins and Zeek UID/tuple joins are exceptionally strong without a concrete contradiction.
- **Behavioral realism:** 8 — Event-value diversity is good, though several all-or-nothing field distributions look curated.
- **Environmental consistency:** 8 — Host roles and traffic are coherent, with the outbound-only Sysmon network profile as the main caveat.

## Recommendations

- If this were synthetic, model or emit a small, realistic population of Sysmon Event 3 records with `Initiated=false` on server endpoints, or otherwise make the outbound-only filtering assumption explicit in the collection profile. The population should correspond to already visible inbound 5156 traffic rather than inventing unrelated flows.
- If this were synthetic, introduce source-native long-tail variation where warranted: occasional non-zero WFP remote identities when IPsec/authenticated policy applies, non-success process-exit statuses for genuinely abnormal exits, and richer source-port service-name behavior only where Windows would resolve it.
- If this were synthetic, preserve non-zero Sysmon `LogonGuid` values for user processes when a visible session supplies a stable logon identity, while retaining zero GUIDs for pre-window, SYSTEM, or genuinely uncorrelatable contexts.
