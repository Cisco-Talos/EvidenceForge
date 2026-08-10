# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 86  
**Synthetic-Confidence Score:** 68

## Executive Summary

The dataset is technically strong: its XML and JSON parse cleanly, Windows and Sysmon schemas are largely source-accurate, and visible lifecycle/correlation checks reveal no impossible ordering. I nevertheless assess it as synthetic because Windows servicing telemetry shows a dataset-wide generated pattern, while failed proxy CONNECT transactions expose both questionable tunnel semantics and an unusually narrow timing distribution.

## Evidence For Synthetic

- `[distribution_texture]` The nine Windows hosts contain 316 Sysmon Event 13 writes to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\...\CurrentState`. Every write has `Details=DWORD (0x00000070)`, and the events are spread smoothly through every hour of the six-hour window: 71, 61, 45, 46, 56, and 37 events by hour.
- `[environment_or_collection_plausibility]` Those 316 CBS writes are attributed only to long-lived `svchost.exe` (111), `msiexec.exe` (103), and `services.exe` (102). Every Windows host has exactly one persistent ProcessGuid for each of these three actors. For example, `WS-PPATEL-01` records `msiexec.exe` PID 5264 updating randomly varied `Package_for_KB5034122`, `Package_for_RollupFix`, `Package_for_DotNetRollup`, and servicing-stack keys between 13:15:56 and 16:10:36. Normal component servicing is owned principally by the servicing stack, TrustedInstaller, and TiWorker in update bursts; a six-hour, fleet-wide stream evenly divided among persistent generic processes is a strong generated-baseline fingerprint.
- `[schema_or_format]` All 60 failed CONNECT decisions with tunnel fields—32 `proxy_action=deny`/HTTP 403 and 28 `proxy_action=auth-required`/HTTP 407—also report nonzero `tunnel_cs_bytes`, `tunnel_sc_bytes`, and `tunnel_duration_ms` despite `ssl_bump=terminate`. At `18/Mar/2024:12:03:27`, for example, a denied CONNECT to `analytics.statuspage.io:443` reports `tunnel_cs_bytes=328`, `tunnel_sc_bytes=523`, and `tunnel_duration_ms=460`. A policy denial or authentication challenge can exchange an HTTP error body, but it does not create an application tunnel; these metrics should be absent, zero, or explicitly named as control-connection bytes.
- `[distribution_texture]` The failed-proxy durations are conspicuously templated. All 28 authentication challenges fall between 456 and 479 ms, while 32 denied CONNECTs fall between 455 and 573 ms, with a 469.5 ms median. Real local proxy policy and authentication decisions normally exhibit broader operational variance and often complete much faster.
- `[weak_signal]` Eight `SearchProtocolHost.exe` launches on five workstations embed per-host SIDs unrelated to the domain SID consistently used in Security telemetry. For example, `WS-PPATEL-01` uses `S-1-5-21-856627621-127616577-549106447-1367` in its search pipe, while `priya.patel` is consistently `S-1-5-21-1537687973-2974994828-3875246326-1004`. These could represent local or stale profiles, so this is not independently dispositive, but the repeated one-off SID construction across endpoints looks generated.

## Evidence For Real

- All 13,555 Security events and 4,610 Sysmon events parse as valid XML. The inspected event IDs use credible providers, channels, versions, tasks, levels, opcodes, keywords, and source-specific data fields.
- Windows account-management telemetry is unusually well modeled. Events 4720, 4724, 4738, 4728, and 4726 preserve the SID for `svc_mhsync`, show the expected enablement transition from `OldUacValue=0x15` to `NewUacValue=0x10`, and use a valid Domain Admins SID ending in RID 512.
- The DC’s Security log-clearing record at `2024-03-18T17:42:29.6787301Z` is correctly represented as Event 1102 from `Microsoft-Windows-Eventlog`, with its subject fields inside the native `UserData/LogFileCleared` structure. `EventRecordID` resets to 1 and subsequent records continue from the reset rather than reusing the earlier high IDs.
- All 921 Sysmon Event 1 records that had a matching Security 4688 agreed on PID, image, command line, LogonId, and parent image. Provider timestamps were not bit-identical: offsets ranged from approximately -25.7 to +18 ms for the normal population, with two larger outliers, which is more plausible than a fixed copied timestamp.
- Across all Windows hosts, no Sysmon event for a visible ProcessGuid preceded that GUID’s Event 1, no dependent event followed a visible Event 5 termination, and no visible child process was created before a later visible parent creation. Likewise, no matching 4634, 4672, 4800, or 4801 visibly preceded its corresponding 4624.
- The 20,817 Zeek records are structurally convincing. Every DNS, HTTP, SSL, and SMTP UID resolved to a conn record on the same sensor with an identical tuple. TLS 1.2 records use TLS 1.2 cipher suites; TLS 1.3 records use `TLS_AES_*` or `TLS_CHACHA20_*`, and resumed sessions correctly omit certificate-chain FUIDs.
- Zeek certificate records preserve FUID, SHA-1 fingerprint, serial, validity, subject/issuer, SAN, and leaf/CA relationships. Observed leaf SANs matched SNI after normal case-insensitive comparison.
- Cisco ASA lifecycle behavior is strong: 5,089 connection IDs have visible build-then-teardown pairs, three builds remain open at the collection boundary, and no visible teardown precedes its matching build. NAT creation/removal records are likewise paired.
- The 25,792 eCAR records consistently use integer millisecond timestamps, UUID identifiers, typed object/action pairs, and structured properties. No visible actor reference preceded its process creation or continued after its visible termination, and actor PID/source UUID checks showed no contradictions.
- Linux RFC5424 syslog records use plausible priorities and facilities: CRON at PRI 78, sudo/authpriv at 85/86, and system daemons at 30. Sudo command, PAM-open, and PAM-close records share the same PID and preserve causal ordering.

## Detailed Analysis

### Windows Event and Sysmon Schema Fidelity

I sampled and programmatically grouped the Windows event schemas. Security 4624 uses Version 2 and includes the extended fields through `ElevatedToken`; 4688 uses Version 2 and represents process IDs in hexadecimal; 5156 uses numeric protocol values and the appropriate outbound/inbound ALE layers. Kerberos 4768/4769 records use plausible ticket-option and encryption-type values, including AES and RC4, while PKINIT records populate certificate issuer, serial, and thumbprint fields.

Sysmon schemas are also convincing. Event 1 uses Version 5 and the expected image metadata, hashes, LogonGuid, integrity, parent, and user fields. Events 3, 5, 7, 8, 10, 11, 13, and 22 use credible versions and native field names, including the capitalization differences between `ProcessGuid` and Event 10’s `SourceProcessGUID`/`TargetProcessGUID`. Hashes have valid MD5, SHA-1, SHA-256, and IMPHASH lengths, and no identical hash mapped to contradictory file metadata.

The main Windows weakness is not XML structure but the generated behavior represented by valid Event 13 structures. Fleet-wide CBS `CurrentState` activity is too continuous, too evenly distributed, and assigned to the same three generic long-lived processes on every endpoint. Only four TiWorker process creations occur, and none of the 316 sampled CBS writes is attributed to TiWorker.

### Process, Session, and Identity Correlation

Visible process and session causality is excellent. The assessment found no ProcessGuid used before its visible creation, no dependent event after visible termination, and no child whose matching parent was visibly created later. Security 4688 and Sysmon Event 1 agree field-for-field when both are present.

Logon lifecycles likewise contain no visible impossible ordering. The lower logout counts are compatible with a bounded window and were not scored negatively. Type 3, 5, 10, 2, and 7 logons use plausible source-address and process conventions; service and local interactive records generally use `-` where network address data is inapplicable.

The SearchProtocolHost SID mismatch is weaker. A search pipe may reference a local, stale, or otherwise unobserved profile, but five workstations independently use domain-shaped SIDs outside the organization’s otherwise stable domain SID. That merits reconciliation rather than treatment as a hard contradiction.

### Detection Usefulness

The logs would ingest successfully into a SIEM and support practical detections. Credential access is visible through the high-integrity `ms-index-service.exe` execution at `15:45:08.617`, Sysmon Event 10 access to LSASS with `GrantedAccess=0x1FFFFF` at `15:45:12.170`, and Event 8 remote-thread creation at `15:45:12.222`. Account creation, privilege assignment, service installation, scheduled-task creation, log clearing, and deletion are all represented with detection-relevant native fields.

The proxy log is parseable and rich, but its failure semantics could mislead rules that distinguish policy denials from successful tunnels. A detector summing `tunnel_*` fields would treat every 403/407 as tunneled traffic even though `ssl_bump=terminate` states that proxy processing stopped.

### Zeek, Firewall, and IDS Fidelity

Zeek conn/protocol fan-out is highly usable. DNS answers and TTL arrays have matching lengths, HTTP status/body semantics are generally correct, and TLS version/cipher combinations are valid. Certificate files, x509 rows, and SSL chain references correlate cleanly where the sensor observed all three.

ASA messages use credible facility/severity prefixes and message IDs. Built and teardown records preserve connection IDs and ordering, including realistic boundary-open connections. Snort alerts use plausible SID/revision, classification, priority, and protocol/port combinations for STUN, BitTorrent, ICMP, and DNS signatures.

### Linux and eCAR Sources

Linux syslog has native-looking RFC5424 timestamps, facilities, program names, PIDs, and PAM/sudo lifecycle text. Bash histories use standard epoch-marker lines and credible command syntax. eCAR adapts identities to endpoint-native representations without visible object-lifecycle inversions.

These strong areas substantially reduce the score from “confidently synthetic.” The verdict rests on repeated fleet-wide behavior and proxy semantics, not on completeness, narrative structure, or absent pre-window initiators.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---:|---|
| `distribution_texture` | Sysmon Event 13 / eCAR registry | 316 events across all 9 Windows hosts and every observed hour | High: fleet-wide servicing noise has a repeated generated shape |
| `environment_or_collection_plausibility` | Windows process/registry ownership | Exactly one persistent `msiexec.exe`, `services.exe`, and `svchost.exe` actor per host owns all CBS writes | High: process ownership and lifecycle are unlike normal servicing |
| `schema_or_format` | Proxy access logs | All 60 failed CONNECT records carrying tunnel fields | Medium-high: denial/authentication events are represented as nonzero tunnels |
| `distribution_texture` | Proxy access logs | Dataset-wide for CONNECT 403/407 | Medium: policy/auth durations collapse into narrow approximately 460–480 ms bands |
| `weak_signal` | Sysmon Event 1 / Security identity | 8 records on 5 workstations | Low: SearchProtocolHost pipe SIDs do not match the observed domain, but local/stale profiles remain possible |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Sysmon, Zeek, ASA, syslog, and eCAR formats are highly accurate; failed-proxy tunnel fields are the main semantic exception.
- **Temporal patterns:** 7 — Visible causal ordering and provider jitter are strong, but failed-proxy latency bands and fleet-wide servicing cadence are overly constrained.
- **Cross-source correlation:** 9 — Process, logon, UID, tuple, certificate, firewall, and endpoint references correlate without visible contradictions.
- **Behavioral realism:** 6 — The CBS activity model and proxy-failure behavior are strong synthetic fingerprints despite convincing attack and baseline events elsewhere.
- **Environmental consistency:** 7 — Host roles, users, addresses, and service placement are mostly coherent; persistent fleet-wide servicing actors and unexplained search SIDs reduce confidence.

## Recommendations

If this were synthetic, the following changes would improve it:

1. Model Windows component servicing as discrete update lifecycles. Use real package identities/build revisions, start TrustedInstaller/TiWorker/CBS-associated processes, cluster the registry writes within bounded maintenance bursts, and terminate the servicing processes afterward. Do not make one persistent `msiexec.exe` per host a six-hour CBS registry writer.
2. For HTTP 403 and 407 CONNECT outcomes with `ssl_bump=terminate`, omit or zero `tunnel_cs_bytes`, `tunnel_sc_bytes`, and `tunnel_duration_ms`. Preserve response/control bytes under explicitly named fields such as `connect_request_bytes` and `connect_response_bytes`.
3. Replace the narrow approximately 460–480 ms proxy rejection template with latency distributions appropriate to local ACL evaluation, authentication challenges, upstream errors, and genuine timeout classes.
4. Resolve SearchProtocolHost pipe SIDs from the same canonical local/domain account inventory used by Security events. If they intentionally represent stale or local profiles, include enough surrounding profile/account evidence to make that interpretation supportable.
5. Preserve the current Windows/Sysmon metadata fidelity, visible lifecycle ordering, Zeek tuple/FUID correlation, ASA state tracking, and source-native timestamp representations; these were the most convincing parts of the dataset.
