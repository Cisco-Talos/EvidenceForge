# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 70

## Executive Summary

The dataset is technically sophisticated and largely SIEM-usable, with strong Windows schemas, coherent process correlations, valid Zeek relationships, and convincing network lifecycles. However, repeated contradictions between Security and Sysmon process integrity, systematic RDP LogonGuid discontinuities, and fleet-wide Linux telemetry templates are difficult to reconcile with independent production hosts. These concrete defects outweigh the substantial realistic detail.

## Evidence For Synthetic

- `[hard_contradiction]` Five identical process-creation events disagree on integrity level between Security 4688 and Sysmon Event 1. For example, on `DC-01` at `2024-03-18T16:10:42`, PID `5512` (`userinit.exe`) is `S-1-16-8192`/Medium with `TokenElevationType=%%1938` in Security, but `IntegrityLevel=High` in Sysmon. Equivalent contradictions occur twice on `DC-01`, twice on `MAIL-FIN-01`, and once on `FILE-SRV-01`; PID, image, command line, parent, LogonId, and timestamps otherwise identify the same process unambiguously.
- `[schema_or_format]` All seven Security 4688 events labeled High integrity (`S-1-16-12288`) use `TokenElevationType=%%1936`—TokenElevationTypeDefault—rather than Full (`%%1937`). These include `mmc.exe` launched from Medium-integrity `explorer.exe` on `WS-PPATEL-01` at `16:17:14`, several similar `mmc.exe` launches on `WS-AJOHNSON-01`, and PID `6200` at `15:44:39`, whose Medium-integrity PowerShell parent creates a High-integrity `ms-index-service.exe`. The consistent absence of Full-token semantics across this elevation pattern is source-native implausibility.
- `[contract_gap]` All 15 visible RDP Type 10 sessions exhibit the same LogonGuid discontinuity. Their Security 4624 events carry nonzero GUIDs, but the corresponding Sysmon Event 1 records for `userinit.exe` and `explorer.exe` use the zero GUID; later processes under the same LogonId switch to the Security GUID. This affects 30 process records across `DC-01`, `DC-02`, `FILE-SRV-01`, `MAIL-FIN-01`, and `WS-AJOHNSON-01`. For example, the `WS-AJOHNSON-01` session at `15:01:08.9426803Z` has LogonGuid `{11a86a48-4672-48ca-9f42-69aba50171fe}`, while its `userinit.exe` and `explorer.exe` records are zero-GUID; PowerShell PID `6164` later uses the nonzero GUID.
- `[distribution_texture]` Linux syslog repeatedly uses identical hardware-specific `irqbalance` messages across unrelated hosts. The exact mapping `IRQ 181 ... CPU 0 (mlx5_comp2)` appears on ten hosts, while identical mappings for IRQs `16`, `24`, `32`, `64`, `86`, `122`, `137`, and `154` recur across servers and workstations. This looks like a shared message pool rather than independently observed hardware topology.
- `[environment_or_collection_plausibility]` The same snap inventory appears across nearly every Linux role: `microk8s`, `lxd`, `core20`, `core22`, and `snapd-desktop-integration` generate refresh/hook activity on application, file, monitoring, mail-edge, mail-clinical, proxy, external-web, laptop, and workstation systems. A standardized image could explain some overlap, but deploying both MicroK8s and desktop-integration snaps so broadly—especially across mail, proxy, and file-server roles—is implausibly homogeneous.
- `[distribution_texture]` All 110 RFC 5424 `CRON` timestamps are quantized to milliseconds and padded with three zero microsecond digits, while essentially none of the thousands of non-CRON messages share that precision pattern. Since the timestamp is in the common syslog header rather than the message body, this application-conditioned precision is a generator-like artifact.
- `[contract_gap]` Twenty-six established, non-resumed TLS 1.2 records show certificate-bearing `ssl_history` values such as `CSXKNGIFIFD` but omit `cert_chain_fuids`, despite zero `missed_bytes` in the associated connections and successful extraction for other connections to the same endpoints. One example is UID `CmrZMDmvFtD85wkeEGQ` at `12:05:06.851633` in `zeek-core/ssl.json`.

## Evidence For Real

- The Windows XML is structurally valid and source-native metadata is unusually accurate. Security events use appropriate versions, tasks, keywords, and field sets—for example, 4624 Version 2/Task 12544, 4688 Version 2/Task 13312, 5156 Version 1/Task 12810, and failure events with audit-failure keywords.
- The `DC-01` Security-log clear at `17:42:33.1802494Z` is rendered correctly as Event 1102 from `Microsoft-Windows-Eventlog`, with `LogFileCleared` under `UserData`, audit-clear keywords, EventRecordID reset to `1`, and the following event numbered `2`.
- Of the matched Security 4688/Sysmon Event 1 pairs, 969 agree on PID, image, command line, parent PID, parent image, and LogonId. Sysmon records precede Security records by a plausible 35–637 ms, with a median near 130 ms.
- SID assignment is stable across the corpus. Each named user and computer account maps to one domain SID, and well-known identities use appropriate values such as `S-1-5-18`, `S-1-5-20`, and `S-1-5-7`.
- Logon lifecycle integrity is strong: no visible 4634 occurs before a visible initiating 4624 for the same identifier, all 4672 records have a prior matching 4624, and paired logoffs preserve SID, username, and domain. The Type 7 unlock followed by a Type 2 logoff on `WS-EBROOKS-01` is consistent with reuse of a pre-existing interactive session.
- Zeek correlation is excellent without simply duplicating sensor output. All DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file UIDs resolve to same-sensor `conn.json` entries with matching tuples and no protocol timestamp before connection start. Sensors assign different UIDs and show small clock offsets when observing the same tuple.
- TLS versions and ciphers are compatible, every referenced certificate FUID resolves, observed certificates are within validity windows, and repeated endpoints retain stable leaf fingerprints.
- All 15 RDP Type 10 logons have a unique matching TCP/3389 connection with the same source IP and port. Each connection begins 5.6–7.3 seconds before authentication and has `SF` state with a substantive duration.
- The ASA log contains 7,403 Built connection records and 7,401 corresponding Teardown records with no orphan or reversed teardown; the two remaining connections are legitimately open at the collection boundary.
- DHCP renewal intervals include per-client jitter and occasional skipped observations rather than exact periodic repetition. For example, the one-hour leases for `WS-LNGUYEN-01` renew around 1,756–1,989 seconds, while one `WS-DRAMIREZ-01` gap spans two renewal periods.
- File hashes are stable for each identical path and version, including across hosts. Zeek packet accounting also preserves minimum protocol overhead and realistic variable TCP header overhead.
- Linux telemetry contains some organic texture, including pre-window SSH session closures, host-specific service activity, differing application mixes, and a literal `grroups` typo in one shell history.

## Detailed Analysis

### Corpus and Parsing

I examined 18,232 Security events, 11,542 Sysmon events, 32,991 eCAR records, 33,250 Zeek records, 19,376 ASA messages, 3,869 RFC 5424 syslog entries, 2,524 proxy records, 185 Snort alerts, and 212 timestamped shell-history commands. Every XML document parsed successfully, and every JSON line decoded successfully.

The sampled Windows records included 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4728, 4768, 4769, 4771, 4776, 5140, 5145, and 5156, plus Sysmon Events 1, 3, 5, 7, 8, 10, 11, 13, and 22.

### Windows Schema and Event Semantics

The base schemas are highly accurate. For example:

- `DC-01` Event 4769 at `12:00:04.2912139Z` has the expected target, service, ticket options, encryption type, mapped IPv4 address, port, status, LogonGuid, and transmitted-services fields.
- Event 4624 at `12:06:21.9825293Z` records an NTLM Type 3 logon for `lina.nguyen`, followed 56 ms later by Event 5140 using the same LogonId, source address, and source port.
- Event 4768 at `12:06:49.8449384Z` correctly represents certificate preauthentication with `PreAuthType=15` and populated issuer, serial, and thumbprint.
- Event 4771 at `12:16:09.6560211Z` uses failure status `0x12` and audit-failure keywords.
- Event 4697 at `15:59:34.1567707Z` uses the expected service-install fields for `PSEXESVC`.
- Events 4720 and 4728 at `16:14:53` and `16:14:57` use coherent domain SIDs, including Domain Admins RID 512.
- Event 4698 at `16:20:07.6325399Z` contains a plausible embedded Task Scheduler 1.4 document.

The principal defect is token identity. Five matched process records have contradictory integrity levels between Security and Sysmon. These are not fuzzy joins: the process ID, executable, parent, user, LogonId, command, and sub-second timestamps agree. In addition, the corpus never uses `%%1937` for the seven High-integrity 4688 events, even when a Medium parent launches an elevated MMC process.

### Session and Process Correlation

No process-dependent Sysmon record refers to a process GUID whose visible Event 1 occurs later. Security 4689 and Sysmon Event 5 terminations similarly show no future-created PID/image or GUID relationships.

The RDP transport family is particularly strong. Every Type 10 logon has a prior successful TCP/3389 interval. However, each session gives its initial `userinit.exe` and `explorer.exe` a zero Sysmon LogonGuid despite the preceding 4624 having a nonzero GUID. Later children adopt the nonzero value, creating a repeated identity discontinuity within the same LogonId.

### Zeek, Proxy, Firewall, and IDS

Across 19,833 Zeek connections, connection UIDs are unique per sensor. Every protocol UID tested resolves to its connection, protocol tuples match exactly, and protocol timestamps fall within their connection interval. File FUIDs are unique, and all `conn_uids` references resolve.

Packet counts and byte fields are internally credible: no IP-byte count is smaller than payload bytes, UDP overhead is consistent with IPv4/UDP framing, and TCP overhead varies with header options. TLS 1.3 exclusively uses TLS 1.3 cipher naming, while TLS 1.2 avoids TLS 1.3-only suites.

The first proxy transaction illustrates good layered semantics: the client-to-proxy CONNECT at approximately `12:03:11` appears in Zeek HTTP and proxy access logs, while tunnel byte counts are separated from CONNECT control-message bytes. ASA connection IDs have orderly Built/Teardown lifecycles, and host-firewall UFW blocks can coexist with ASA Built records because the perimeter accepted the packet before the endpoint rejected it.

The limited TLS defect involves non-resumed TLS 1.2 rows that record an `X` certificate stage but omit the certificate reference. This is a minority condition, but it is difficult to explain for repeated endpoints when packet-loss counters remain zero.

### eCAR and Linux Telemetry

All eCAR event IDs are valid UUIDs, top-level timestamps are sorted, and no visible process reference points to a later process creation. Flow direction is also correct for every host tested: outbound records use the host as `src_ip`, and inbound records use it as `dst_ip`.

Linux SSH sequences are coherent. For example, `DB-PROD-01` records public-key acceptance for `marcus.chen` from `10.10.1.31:58362` at `12:33:51.872739Z`, PAM session opening 164 ms later, and session closure at `13:01:07.437557Z`. Public-key fingerprints and numeric UIDs remain stable for the same users across hosts.

The Linux baseline is nevertheless over-shared. Ten systems use the same small collection of IRQ numbers, device names, CPU assignments, and affinity messages. The snap activity similarly implies near-universal deployment of MicroK8s, LXD, and desktop integration across unlike roles. This is stronger than ordinary standardized-image behavior because it combines software-role and hardware-topology repetition.

The syslog timestamps otherwise have valid RFC 5424 structure and six fractional digits. The exception is CRON: all 110 records have millisecond-only values padded to microseconds, while nearly all other applications use genuine six-digit variation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `hard_contradiction` | Windows Security/Sysmon | 5 processes on 3 hosts | The same process is simultaneously Medium in 4688 and High in Sysmon Event 1. |
| `schema_or_format` | Windows Security 4688 | 7 High-integrity processes | Elevated children consistently use TokenElevationTypeDefault; TokenElevationTypeFull never appears. |
| `contract_gap` | Windows Security/Sysmon RDP | 30 processes in all 15 Type 10 sessions | Initial session processes use zero LogonGuid, then later children switch to the session's nonzero GUID. |
| `distribution_texture` | Linux syslog/irqbalance | Up to 10 hosts | Hardware-specific IRQ, CPU, and device mappings repeat across unrelated machines. |
| `environment_or_collection_plausibility` | Linux syslog/snapd | 8–10 hosts and many roles | MicroK8s, LXD, core snaps, and desktop integration appear across mail, proxy, file, application, monitoring, and endpoint roles. |
| `distribution_texture` | RFC 5424 syslog | All 110 CRON records | CRON alone is perfectly millisecond-quantized inside a microsecond-precision stream. |
| `contract_gap` | Zeek SSL/X.509 | 26 TLS 1.2 sessions | Certificate-bearing SSL histories omit certificate references without visible packet loss. |

## Realism Score by Category

- **Field format accuracy:** 8 — Event schemas and field types are excellent, but token-elevation semantics and a minority of TLS certificate relationships are defective.
- **Temporal patterns:** 8 — Lifecycle ordering and sensor timing are strong; CRON precision and some family-level timing patterns remain synthetic-looking.
- **Cross-source correlation:** 7 — Most correlations are exact and causally sound, but integrity and RDP LogonGuid contradictions are substantive.
- **Behavioral realism:** 7 — User, service, SSH, mail, browser, and file activity is varied, while Linux background behavior reuses conspicuous pools.
- **Environmental consistency:** 6 — Host addressing and service roles are coherent, but shared snap inventories and identical IRQ topology across unlike systems reduce credibility.

## Recommendations

- If this were synthetic, derive integrity level and token-elevation type once per process and render that same value into Security 4688, Sysmon Event 1, and eCAR. Add an invariant test mapping `S-1-16-4096/8192/12288/16384` to Low/Medium/High/System.
- If this were synthetic, model UAC-linked tokens explicitly. A High-integrity process launched from a Medium, limited-token desktop should normally use TokenElevationTypeFull unless a concrete alternate token-acquisition path is represented.
- If this were synthetic, propagate the RDP session LogonGuid to `userinit.exe` and `explorer.exe` before emitting their process records. If the GUID is genuinely unavailable, model availability consistently rather than switching values within the same LogonId.
- If this were synthetic, make Linux background software inventory role-aware. Avoid assigning MicroK8s, LXD, and desktop-integration snaps to mail, proxy, file, and monitoring servers without role-specific justification.
- If this were synthetic, generate IRQ telemetry from a per-host hardware model. IRQ numbers, interface names, storage devices, NUMA nodes, and CPU affinities should remain internally stable but differ across hardware classes and hosts.
- If this were synthetic, preserve one collector-derived timestamp precision for RFC 5424 headers. Do not quantize only CRON records to milliseconds.
- If this were synthetic, ensure a TLS 1.2 history indicating an observed certificate carries `cert_chain_fuids`, or model an explicit parser/capture failure consistent with connection loss fields.
