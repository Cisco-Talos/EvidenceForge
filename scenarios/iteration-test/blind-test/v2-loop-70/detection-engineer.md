# Detection Engineer — Authenticity Assessment

## Verdict

- **Assessment:** Real
- **Verdict Confidence:** 72/100
- **Synthetic-Confidence Score:** 34/100

## Executive Summary

The telemetry is mostly indistinguishable from sanitized production data. I reviewed well over 20
individual records across Windows Security, Sysmon, eCAR, RFC 5424 syslog, bash history, Zeek
connection/DNS/HTTP/TLS/X.509/file/SMB/SMTP logs, Cisco ASA, Snort, proxy, and web access data.
The strongest observations are source-native schema fidelity, coherent stateful lifecycles, and
small but realistic timing and collection differences between sources.

I found no hard contradiction: no impossible event ordering, identity collision, protocol-field
conflict, or source-native schema failure that by itself identifies generation. The strongest
synthetic-looking feature is the unusually bounded distribution of Sysmon Event 10 `CallTrace`
values: all 713 inspected Event 10 records contain only one to three frames, with a small set of
repeated system-DLL patterns. A smaller collection-model concern is that 19 of 972 Sysmon Event 1
records use `Hashes=-`, including persistent or well-known binaries, while almost all neighboring
process creates contain four algorithms. Linux daemon noise is also somewhat template-dense across
hosts. These are concrete artifacts, but each remains possible in a real collection and does not
outweigh the extensive source-native detail.

The score of 34 falls in the “mostly realistic” band. This is a probabilistic authenticity verdict,
not a finding that the data is proven real.

## Evidence For Synthetic

- **distribution_texture — bounded Sysmon access stacks (moderate):** Across 713 Sysmon Event 10
  records on ten Windows hosts, every `CallTrace` has one, two, or three frames: 149 have one frame,
  20 have two, and 544 have three. There are no deeper stacks. Repeated families such as
  `ntdll.dll|KERNELBASE.dll|advapi32.dll`,
  `ntdll.dll|KERNELBASE.dll|sechost.dll`, and one-frame `ntdll.dll` dominate. The hard three-frame
  ceiling across hundreds of unrelated process accesses is more regular than expected from varied
  production call stacks. A particularly visible example is
  `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml` at
  `2024-03-18T15:45:08.1893444Z` (record 31186):
  `ms-index-service.exe` opens `lsass.exe` with `GrantedAccess=0x1FFFFF`, but the trace is only
  `ntdll.dll+9C199|KERNELBASE.dll+2D6AD|wbemcomn.dll+15398`. The immediately preceding access to
  `winlogon.exe` at `15:45:07.7083784Z` is likewise exactly three frames.

- **contract_gap — selective missing Sysmon hashes (low to moderate):** Nineteen of 972 Event 1
  process-create records have `Hashes=-`, despite the same channels normally reporting MD5, SHA1,
  SHA256, and IMPHASH. At `2024-03-18T15:45:04.4711687Z`, record 31184 on WS-AJOHNSON-01 creates
  `C:\Windows\System32\ms-index-service.exe` with a credential-dumping command line and
  `Hashes=-`. DC-01 record 3292070 at `2024-03-18T15:59:51.7751657Z` creates
  `C:\Windows\PSEXESVC.exe`, also with `Hashes=-`, although its file creation was recorded at
  `15:59:44.9876438Z`. Other missing-hash cases include `MonitoringHost.exe`, `curl.exe`,
  `vpnagent.exe`, `runas.exe`, Veeam, and installer processes. Hash acquisition can fail in real
  Sysmon, so this is not a contradiction; the selective concentration around uncommon or
  storyline-relevant binaries is the synthetic-looking part.

- **distribution_texture / environment_or_collection_plausibility — repeated Linux daemon prose
  (low):** The Linux hosts contain large volumes of a small family of highly specific `irqbalance`
  and `snapd` messages. APP-INT-01 alone has 55 `irqbalance` and 40 `snapd` records in six hours;
  WEB-EXT-01 has 106 and 107 respectively, with the same message families appearing environment-wide.
  Concrete APP-INT-01 examples are `2024-03-18T12:03:14.498946Z`,
  `NUMA node 0: balancing pass complete, 2 IRQs moved`, and
  `2024-03-18T12:27:16.110589Z`,
  `stateengine.go:150: state ensure starting change 3443`. Verbose service logging is possible, but
  the broad deployment and repeated vocabulary have a catalog-driven texture.

- **weak_signal — concentrated recurring Internet scanners (low):** WEB-EXT-01 records 855 UFW
  blocks, all TCP, from only 13 source IPs; four sources account for 756 records. For example,
  `2024-03-18T12:00:35.514403Z` blocks `185.220.88.13:7685 -> 10.10.3.10:445`. Repeated scanners
  are entirely plausible on an exposed host, and sanitization may compress source diversity, so
  this contributes little weight.

## Evidence For Real

- **Windows event contracts are accurate and internally coherent.** DC-01 Security Event 4624 at
  `2024-03-18T12:00:58.2956717Z` uses version 2, task 12544, `LogonType=5`,
  `TargetLogonId=0x3e5`, and `services.exe`; Event 4672 follows at
  `12:00:58.3002675Z` for the same logon ID. Event 5156 at
  `12:01:41.9658147Z` has plausible WFP fields (`Direction=%%14593`, layer ID 48), PID 2336
  `lsass.exe`, and a UDP Kerberos tuple to DC-02. Event 4769 at
  `12:01:52.7507898Z` correctly uses AES256 ticket type `0x12`, a machine account, and mapped IPv4
  address `::ffff:10.10.2.11`.

- **Stateful Windows lifecycles survive broad consistency checks.** Across all Windows Security
  files, no visible 4672, 4634, 4779, 4800, or 4801 event precedes its corresponding 4624 for the
  same logon ID. No file-handle close or access precedes its visible open. FILE-SRV-01 shows a
  particularly credible sequence for `Team\project-plan-final.txt`: Event 5145 at
  `2024-03-18T12:04:06.9383901Z`, 4656 at `12:04:06.9774461Z`, 4663 at
  `12:04:07.0026254Z`, and 4658 at `12:04:07.0448424Z`, retaining handle `0xd160806b` and the
  same user/path.

- **The Security-log clearing behavior is source-native rather than cosmetic.** DC-01 records
  Event 1102 at `2024-03-18T17:42:34.7208375Z` from
  `Microsoft-Windows-Eventlog`, using the expected `LogFileCleared` user-data structure. The
  Security EventRecordID then resets from the prior high sequence to 1 and advances normally; a
  later 4726 at `17:49:35.4547944Z` is record 364. This is an unusually strong collection-level
  detail.

- **Sysmon identity and lifecycle behavior is convincing.** Process GUIDs remain stable across
  Event 1 creation, Event 3 network, Event 7 image load, Event 10 access, and Event 5 termination.
  The GUID time component tracks process start time, while the machine prefix remains host-stable.
  Automated ordering checks found no visible process termination or dependent record before its
  matching process create. OS-build metadata and hashes also vary coherently: hosts on builds
  17763, 19041, 20348, and 22621 carry different Microsoft binary versions/hashes, while the same
  Office build shares the same image hash across hosts.

- **Zeek transaction structure is detailed and protocol-consistent.** UID
  `CDB5kjv4G7HL9IhsHwc` begins with a TCP connection at epoch `1710763267.118189` and carries three
  HTTP transactions at depths 1–3. They include a 200 HTML response of 25,468 bytes, a 304 with
  zero response body, and a 200 WebP response of 349,053 bytes; the corresponding file records use
  the same UID and exact FUIDs/sizes. Across the core, database, and DMZ sensors, I found no DNS,
  HTTP, TLS, SMTP, or SMB child record whose UID was missing from or preceded its connection.

- **Packet loss is represented coherently instead of making every source perfect.** Zeek UID
  `CYoXqLMhe5YTxQD7al` has `missed_bytes=1456`; its HTML response declares 12,295 bytes while the
  associated file record at epoch `1710781797.062671` has `seen_bytes=12267`,
  `total_bytes=12295`, and `missing_bytes=28`. Other file objects on that same connection are
  complete. This selective, internally consistent loss is strongly production-like.

- **Multipart HTTP accounting is plausible.** At epoch `1710779287.567850`, UID
  `CDa3HtyEZd4qcLZZYaA` POSTs 1,573,258 request bytes. Its two originating file records contain a
  50-byte JSON part and a 1,572,864-byte gzip file named `mhs-support-48217.tar.gz`; the 344-byte
  difference is plausible multipart framing. The connection remains open for 20.878448 seconds and
  carries realistic packet/byte overhead.

- **Linux session evidence has complete, source-native timing.** APP-INT-01 records SSH connection
  `10.10.1.21:50093 -> 10.10.2.30:22` at `2024-03-18T13:30:40.093339Z`, successful password
  authentication at `13:30:48.924380Z`, PAM open at `13:30:48.980679Z`, and logind session 376761
  at `13:30:49.587744Z`. The same sshd PID closes PAM at `14:03:27.069563Z`; logind removes session
  376761 at `14:03:28.080388Z`. Failed SSH attempts also use the normal connection, invalid-user,
  failed-password, preauth-close progression.

- **Firewall records preserve device-native semantics.** In `fw-perimeter/cisco_asa.log`, connection
  1681558 is built inbound at `Mar 18 12:00:35` from outside
  `185.220.88.13/7685` to DMZ `10.10.3.10/445`, including the public NAT address
  `203.14.220.10/445`; it is torn down at `12:01:05` with duration `0:00:30`, zero bytes, and
  reason `SYN Timeout`. Connection 1681561 uses matching build/teardown tuple, duration, byte count,
  and `TCP FINs` semantics.

- **Timestamp precision varies naturally by producer.** Windows XML uses seven fractional digits,
  Sysmon's embedded `UtcTime` uses milliseconds, eCAR uses epoch milliseconds, Zeek uses fractional
  epoch seconds, RFC 5424 syslog uses microseconds, and ASA/access records use seconds. Correlated
  events show small directional collection delays rather than identical timestamps.

## Detailed Analysis

I parsed the XML/JSON structures and sampled every observed Windows Security Event ID and every
observed Sysmon event family, then checked state relationships at scale. Representative Security
IDs included 1102, 4624, 4625, 4634, 4648, 4656, 4658, 4663, 4672, 4688, 4697, 4698, 4720, 4724,
4726, 4728, 4738, 4768, 4769, 4771, 4776, 4779, 4800, 4801, 5140, 5145, and 5156. Representative
Sysmon IDs included 1, 3, 5, 7, 8, 10, 11, 13, and 22. Versions, tasks, providers, field names,
GUID capitalization differences between event versions, SID/logon-ID conventions, registry
targets, address formats, and process metadata were credible.

The most important Windows sequence is coherent across independent record types. DC-01 records a
PSEXESVC drop at `15:59:44.9876438Z`, service-install activity, process start at
`15:59:51.7751657Z`, and subsequent command execution. Later, account creation/modification and
Domain Admins membership appear as 4720 at `16:15:11.9587961Z`, 4724 at
`16:15:12.9346763Z`, 4738 at `16:15:14.4632282Z`, and 4728 at
`16:15:17.3924203Z`. Task creation follows as 4698 at `16:20:05.8737054Z`. At
`17:42:23.800Z`, the eCAR chain creates `wevtutil` from `cmd.exe /c wevtutil cl Security`; the
Security clear arrives at `17:42:34.7208375Z`, and the eCAR termination follows at
`17:42:34.789Z`. Account deletion is later reflected by 4726 at `17:49:35.4547944Z`. The timing is
not perfectly simultaneous, but it is causally ordered and source-plausible.

Network evidence similarly preserves protocol state. DNS answers link to their connection UIDs;
HTTP files link by FUID; TLS 1.2 sessions carry certificate-chain/X.509/file relationships while
TLS 1.3 records generally omit visible certificate chains, consistent with encrypted handshake
content; SMB mappings precede file open/read/write records; and connection packet/IP-byte totals
include plausible transport overhead. A STARTTLS-capable SMTP session without a Zeek SSL companion
was observed, but one missing companion can result from an incomplete handshake or collection gap
and is not treated as synthetic.

The main reason the score is not in the 0–20 range is distribution texture rather than broken
semantics. Event 10 stacks appear drawn from a shallow vocabulary, missing-hash decisions cluster
around a narrow subset of binaries, and Linux service noise repeats a conspicuous common catalog.
None creates an impossible record. Conversely, complete cross-source matches were treated as
corroboration only, not as a synthetic indicator, and absent source/event coverage was not
penalized.

## Synthetic Indicator Summary

| Category | Finding | Weight |
|---|---|---:|
| hard_contradiction | None found after lifecycle, identity, tuple, and protocol checks | 0 |
| contract_gap | 19/972 Sysmon Event 1 records have `Hashes=-`, selectively affecting several persistent or scenario-relevant binaries | Low–moderate |
| distribution_texture | All 713 Sysmon Event 10 call traces are capped at three frames and reuse a small module-pattern vocabulary | Moderate |
| distribution_texture | Repeated `irqbalance`/`snapd` message families occur at high volume across the Linux fleet | Low |
| schema_or_format | No material source-native schema or serialization defect found | 0 |
| environment_or_collection_plausibility | Fleet-wide verbose Linux daemon noise is somewhat over-consistent | Low |
| weak_signal | Four recurring source IPs dominate the WEB-EXT UFW scan blocks | Very low |

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 9/10 | Windows XML, Sysmon versions/fields, Zeek JSON, RFC 5424, ASA, Snort, proxy, and web formats are source-native; the main blemish is selective missing hash data. |
| Temporal patterns | 9/10 | Session, process, file, transport, service, task, and log-clear sequences are ordered with realistic producer-specific delays and timestamp precision. |
| Cross-source correlation | 9/10 | GUIDs, PIDs, logon IDs, tuples, UIDs, FUIDs, handles, byte counts, and lifecycle relationships agree without requiring identical timestamps. |
| Behavioral realism | 8/10 | User, service, administrative, attack, web, mail, DNS, TLS, SMB, and Internet-noise behaviors are varied; several Sysmon/syslog distributions remain visibly bounded. |
| Environmental consistency | 8/10 | Roles, OS builds, services, domain identities, network zones, and NAT behavior are coherent; Linux daemon-noise symmetry is the principal concern. |

## Recommendations

- If this is synthetic, expand Sysmon Event 10 stack generation beyond a fixed one-to-three-frame
  grammar. Include process-specific frames, variable unwind depth, occasional unknown/unresolved
  frames, and depth distributions conditioned on access path and operating-system build.

- Model Sysmon hash failure from collection mechanics rather than binary importance. Missing hashes
  should follow defensible causes such as access failure, deletion race, file type, exclusion, size,
  or timeout, and should not disproportionately select uncommon or narrative-critical binaries.

- Increase Linux daemon diversity by conditioning enabled services, log levels, IRQ devices, snap
  inventory, and message cadence on each host's role and configuration. Preserve the strong RFC
  5424 formatting and session lifecycle behavior.

- Preserve the current Windows Security contracts, EventRecordID reset after 1102, Zeek loss/file
  accounting, TLS-version behavior, SMB lifecycle, SSH/PAM/logind sequencing, NAT semantics, and
  producer-specific timestamp precision. Those details materially reduce synthetic appearance.

- For a follow-up blind review, add a longer capture window. Six hours is sufficient to validate
  event contracts but gives limited evidence about day/night cycles, weekly maintenance, long-lived
  sessions, scanner churn, and natural drift in background distributions.
