# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 94
**Synthetic-Confidence Score:** 71

## Executive Summary

The corpus is unusually strong in schema shape, timestamp conventions, process lifecycle integrity, and cross-source identity reuse. However, all 8,059 Windows Security Event ID 5156 records across nine hosts encode the local/remote tuple perspective opposite to the source-native `Direction` and filtering-layer values, including exact flows where Sysmon, eCAR, and Zeek independently establish the correct direction; that dataset-wide contradiction is a strong generator fingerprint.

## Evidence For Synthetic

- `[hard_contradiction]` Every Windows Security 5156 record has its endpoint perspective reversed relative to its source-native direction. Across all nine Security XML files, 4,700 events use `Direction=%%14592` and `LayerName=%%14610`—outbound/connect—while the recording host is the destination, and 3,359 use `Direction=%%14593` and `LayerName=%%14611`—inbound/receive-accept—while the recording host is the source.
- `[hard_contradiction]` At `2024-03-18T12:00:10.7787965Z`, `DC-01` records `10.10.1.31:61638 -> 10.10.2.10:53`, attributed to local `dns.exe`, as `%%14592/%%14610` outbound/connect. The matching `DC-01/ecar.json` row at `timestamp_ms=1710763210678` correctly calls the same tuple `INBOUND`, while `zeek-core/conn.json` and `dns.json` use UID `CkyYeTBueC0jvnClMR` with `10.10.1.31` as originator and `10.10.2.10` as responder.
- `[hard_contradiction]` The inverse case is equally explicit: at `2024-03-18T12:14:20.2979103Z`, `DC-01` Security 5156 records local `10.10.2.10:61421 -> 10.10.3.20:8080` as `%%14593/%%14611` inbound/receive-accept. Sysmon Event 3 at `12:14:20.4924000Z` has the same PID 2368 and tuple with `Initiated=true`; eCAR labels it `OUTBOUND`; and both Zeek sensors identify `10.10.2.10` as originator.
- `[schema_or_format]` Ninety-one non-200 proxy `CONNECT` records retain `tunnel_cs_bytes`, `tunnel_sc_bytes`, and `tunnel_duration_ms` despite `ssl_bump=terminate` and outcomes such as `proxy_action=deny`, `auth-required`, or `gateway-error`. For example, the denied `api.snapcraft.io:443` request at `15:38:01` reports HTTP 403 plus nonzero tunnel counters. These custom fields could cause rules to infer that a tunnel was established when the same record says it was terminated.
- `[weak_signal]` The `DC-01` 4771 failure for `aisha.johnson` at `2024-03-18T14:58:36.4889191Z` uses `IpAddress=-` and `IpPort=-`, while the immediately related 4776 names workstation `LT-MRIVERA-02`. Other 4771 records preserve client address and port, making this a localized correlation gap rather than a general schema failure.

## Evidence For Real

- Windows provider metadata and event shapes are largely source-native: Security 4624 uses version 2/task 12544, 4688 uses version 2/task 13312, 5156 uses version 1/task 12810, and Sysmon event versions and tasks match the present event types. Security and Sysmon use the expected decimal-versus-hex PID conventions.
- Process correlation is excellent without visible lifecycle impossibilities. On `DC-01`, the Veeam process appears as Sysmon Event 1 at `12:00:33.7470159Z` with PID 3912, Security 4688 at `12:00:33.7566492Z` with `NewProcessId=0xf48`, and eCAR at `timestamp_ms=1710763234759` with PID 3912 and the same image and command line.
- No Sysmon ProcessGuid had a visible Event 5 before its Event 1. Across eCAR records on all 18 hosts, no event referred to a visibly later process creation or to an actor after its visible termination.
- eCAR session lifecycles are coherent: 792 object IDs have ordered `LOGIN -> LOGOUT`, 378 have login-only records, and 15 have logout-only records. The latter two patterns are compatible with the bounded collection window.
- Security logon lifecycles preserve identifiers and order. Network logons overwhelmingly have matching 4624/4634 pairs; repeated Type 7 unlocks correctly reuse the existing interactive Type 2 LogonID rather than inventing a new session.
- Zeek records use appropriate JSON types and source-native structures. DNS rows share UIDs and tuples with `conn.json`; TLS 1.2 non-resumed sessions carry certificate-chain FUIDs, resumed sessions omit them, and TLS 1.3 rows appropriately lack passively unavailable certificate chains.
- Firewall lifecycle texture is convincing: 4,248 TCP builds have 4,245 teardowns, leaving three connections open at the window boundary; 844 UDP builds have 844 teardowns; and dynamic translations pair cleanly without requiring every TCP connection to terminate in-window.
- Timestamp precision varies appropriately by source: Windows SystemTime has seven fractional digits, Sysmon `UtcTime` uses milliseconds, Zeek uses fractional epoch seconds, RFC 5424 syslog uses microseconds, and ASA records use whole seconds.
- Syslog priority values, process names, PAM sequences, SSH session ordering, and application-specific truncation such as `unattended-upgr` are source-plausible.

## Detailed Analysis

### Windows Security schema and event semantics

I parsed the Security XML across nine Windows hosts and reviewed all present IDs: 1102, 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4800, 4801, and 5156. Provider GUIDs, version/task/level/opcode/keyword combinations, field names, SID syntax, hexadecimal PID representation, logon types, and account-management shapes were generally convincing. Event 1102 correctly uses the Eventlog provider, source-specific `UserData/LogFileCleared`, and a reset EventRecordID.

The decisive defect is Event 5156. Host addresses were independently recoverable from each host’s Sysmon Event 3 `SourceHostname`/`SourceIp` values. Relative to those local addresses, every one of 8,059 Security 5156 records is inverted:

- `%%14592` plus `%%14610` appears 4,700 times with the local host in `DestAddress`.
- `%%14593` plus `%%14611` appears 3,359 times with the local host in `SourceAddress`.

The direction and layer fields agree with each other but disagree with the tuple and observing host. This is not missing context, a pre-window initiator, or a completeness artifact; it is a source-native contradiction visible inside each record and confirmed by sibling sources.

The authentication schemas were otherwise strong. Logon types 2, 3, 5, 7, and 10 use plausible process and address conventions. The isolated 4771 at `14:58:36.4889191Z` with absent client endpoint is weaker than the 5156 issue because unavailable fields are possible, but its adjacent 4776 workstation attribution makes the omission worth correcting.

### Sysmon fidelity

The corpus contains Sysmon IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22. Their provider metadata, field casing, versions, tasks, PID representations, hashes, registry detail formats, DNS statuses, and process-access structures are internally consistent. Sampled Event 10 rows include appropriate source and target GUIDs, hexadecimal GrantedAccess, thread IDs, users, and Windows-style call traces; Event 11 CreationUtcTime precedes its event time by a plausible small amount.

Visible lifecycle analysis found no Event 5 preceding Event 1 for the same ProcessGuid and no duplicate create/terminate transitions. Create/terminate incompleteness is compatible with the bounded window and was not scored negatively.

Sysmon Event 3 is particularly useful because it exposes the 5156 defect rather than sharing it. For the PID 2368 connection from `DC-01` to the proxy, Sysmon records `Initiated=true`, local source `10.10.2.10:61421`, and destination `10.10.3.20:8080`, while Security 5156 calls the same flow inbound.

### eCAR structure and lifecycle

All eCAR lines parsed as JSON. Top-level UUIDs are well formed and record IDs are unique. Objects and actions are consistently structured across `PROCESS`, `FLOW`, `USER_SESSION`, `MODULE`, `REGISTRY`, `FILE`, `THREAD`, and `SERVICE`.

Process ownership is notably coherent: for every actorID with a visible process creation, creation precedes dependent activity; no dependent record occurs after that actor’s visible termination. Session object IDs likewise preserve login/logout identity. The eCAR network direction on destination hosts is source-relative and correct, which further isolates the Windows 5156 inversion to that source family.

### Network and proxy detection utility

Zeek connection, DNS, HTTP, SSL, X.509, file, DHCP, SMTP, and OCSP rows are structurally useful for SIEM rules. UID reuse ties parser views to their connection, and byte, packet, state, and history fields are credible. The same connection appearing on core and DMZ sensors with distinct sensor-local UIDs is plausible rather than suspicious.

ASA built/teardown and NAT lifecycle records are balanced while still permitting active connections at the collection boundary. Snort alert lines use recognizable timestamp, GID:SID:REV, classification, priority, protocol, and tuple syntax.

The proxy access format is parseable and unusually informative. Its non-200 CONNECT rows, however, use successful-tunnel-looking counters while simultaneously declaring termination. Because these are custom extension fields rather than a fixed vendor schema, I treat this as a moderate format/semantic weakness rather than an impossibility. It can still produce false positives in detections that use `tunnel_duration_ms` or `tunnel_*_bytes` as evidence of a completed tunnel.

### Timing, correlation, and bounded-window handling

I found no visible process, user-session, or firewall teardown that precedes its matching visible initiator. Login-only, logout-only, create-only, and terminate-only objects were not penalized because their other lifecycle endpoint can legitimately fall outside the six-hour window.

Cross-source timing generally includes plausible sensor latency rather than exact timestamp cloning. The Veeam example differs by milliseconds between Security and Sysmon and approximately one second at eCAR. DNS and protocol parser rows appropriately share connection timing and UID where they represent views of the same packet stream. Complete correlation was treated as positive or neutral, not as synthetic evidence.

### Distribution and environment

The corpus includes workstation, domain-controller, file-server, mail, proxy, application, database, and web roles with source families appropriate to their operating systems. Windows and Linux path syntax stays separated, service accounts appear in plausible host roles, and source volumes are role-sensitive rather than uniformly replicated.

Timing and vocabulary have reasonable variation: system traffic, user activity, failed authentication, external scanning, proxy browsing, background maintenance, service sessions, and source-local noise coexist. I found no valid narrative-based reason to adjust the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `hard_contradiction` | Windows Security 5156; contradicted by Sysmon, eCAR, and Zeek | Dataset-wide: 8,059/8,059 records across nine hosts | Primary driver. Direction/layer semantics are opposite to the observing host and tuple. |
| `schema_or_format` | Proxy access | Repeated: 91 failed or denied CONNECT records | Moderate. Nonzero `tunnel_*` fields coexist with explicit termination and can mislead tunnel detections. |
| `weak_signal` | Windows Security 4771/4776 | One event sequence | Low. Client endpoint disappears from one Kerberos failure despite adjacent workstation attribution. |

## Realism Score by Category

- **Field format accuracy:** 6 — Most Windows, Sysmon, Zeek, eCAR, syslog, and appliance formats are strong, but the dataset-wide 5156 direction semantics are materially wrong.
- **Temporal patterns:** 9 — Sampled lifecycles and dependent events preserve visible ordering, with boundary-only orphans treated appropriately.
- **Cross-source correlation:** 7 — Process, session, UID, and firewall correlations are excellent, but sibling sources expose the universal 5156 inversion.
- **Behavioral realism:** 8 — Host activity, authentication, process, network, and background-noise mixes are varied and operationally plausible.
- **Environmental consistency:** 9 — Host roles, OS-native paths, source-family placement, and telemetry volumes are broadly coherent.

## Recommendations

- If this were synthetic, derive Windows 5156 `Direction`, `LayerName`, and `LayerRTID` from the recording host’s local endpoint, not from a globally reused or destination-relative connection direction. For a local originator, emit outbound/connect; for a local responder, emit inbound/receive-accept. Add assertions against the rendered SourceAddress and DestAddress for both observations of a bidirectional modeled flow.
- Add a cross-source contract test using the `10.10.2.10:61421 -> 10.10.3.20:8080` pattern: Security 5156, Sysmon Event 3, eCAR FLOW, and Zeek conn should agree on originator/responder semantics even though each source uses different field names.
- For non-successful proxy CONNECT results, omit `tunnel_*` fields unless an actual tunnel was established. If they represent attempted backend/control-channel bytes, rename them to make that scope explicit so detections cannot confuse a 403, 407, 502, 503, or 504 transaction with a completed tunnel.
- Preserve a client address and port in 4771 whenever the modeled Kerberos request has a known remote workstation. If a field is intentionally unavailable, keep that unavailability consistent with sibling authentication evidence or document it through the collection profile.
