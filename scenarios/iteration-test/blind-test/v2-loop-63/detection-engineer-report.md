# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 84  
**Synthetic-Confidence Score:** 71

## Executive Summary

The dataset is likely synthetic, although most individual records are impressively source-native and would parse successfully in a SIEM. The decisive evidence is a combination of a cross-host identity contradiction in Windows Event 4648, repeated missing process children after successful wrapper executions, inconsistent Zeek file-analyzer metadata, and repeated Linux service-message texture. Strong lifecycle, timing, and network correlations keep the synthetic-confidence score below the “confidently synthetic” tier.

## Evidence For Synthetic

- `[hard_contradiction]` At `2024-03-18T14:50:21.5760166Z`, WS-MCHEN-01 Event 4648 identifies local process `C:\Windows\System32\runas.exe`, PID `0x2124`, but records `IpAddress=10.10.1.99`. WS-MCHEN-01 consistently uses `10.10.1.31`, while `10.10.1.99` belongs to LT-MRIVERA-02. Other Event 4648 records on WS-MCHEN-01 correctly use `10.10.1.31`, making this a specific cross-host ownership leak rather than a general interpretation issue. See [WS-MCHEN-01 Security XML](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-63/review-data/WS-MCHEN-01.meridianhcs.local/windows_event_security.xml:15495>).

- `[contract_gap]` All three visible successful `runas.exe /netonly` executions produce Type 9 logons and Event 4648 records but never create their quoted `cmd.exe` child in Security 4688, Sysmon Event 1, or eCAR. Examples occur at `13:31:18.024Z` and `14:50:18.429Z` on WS-MCHEN-01 and `15:30:06.252Z` on WS-PPATEL-01. The wrapper processes terminate inside the window, so this is not explained by the slice boundary.

- `[contract_gap]` The same incomplete wrapper modeling occurs at `2024-03-18T16:00:01.043Z` on DC-01: PSEXESVC launches `cmd.exe /c whoami && hostname`, but neither `whoami.exe` nor `hostname.exe` appears as a child. In contrast, later `cmd.exe /c net ...` activity correctly creates `net.exe` children, showing that child-process collection is present and capable of representing these relationships.

- `[schema_or_format]` In `zeek-core/files.json`, 87 SMB file records contain `md5`, `sha1`, and `sha256` values while declaring only `analyzers:["MIME"]`. One example is FUID `Fop8BNCiKLAKuJaJtM` at `2024-03-18T12:04:06.791175Z`, which has all three hashes but no corresponding hash analyzers in the analyzer set. See [files.json](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-63/review-data/zeek-core/files.json:2>).

- `[contract_gap]` Three PE files have records in `pe.json`, but their corresponding `files.json` entries do not include `PE` in `analyzers`. For example, FUID `FWAJpACCLhSB7rXrG1` at `2024-03-18T17:30:34.736523Z` has a PE record but lists only `["SHA1"]` in the file record. See [files.json](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-63/review-data/zeek-core/files.json:533>) and [pe.json](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-63/review-data/zeek-core/pe.json:1>).

- `[contract_gap]` Ten Windows-host eCAR FILE records attribute server-side file activity directly to a remote Linux `/usr/bin/smbclient` process and Linux PID. At `2024-03-18T16:35:20.514Z`, FILE-SRV-01 records a Windows-path read with `source_pid=3406417` and `source_image_path=/usr/bin/smbclient`; the corresponding native Windows 4656/4663 records identify the local server process as PID `0x4`, `System`. Unless eCAR explicitly defines these fields as remote-origin enrichment, common detection logic would interpret an impossible Linux process on a Windows host. See [FILE-SRV eCAR](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-63/review-data/FILE-SRV-01.meridianhcs.local/ecar.json:1031>) and [Security XML](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-63/review-data/FILE-SRV-01.meridianhcs.local/windows_event_security.xml:39138>).

- `[distribution_texture]` Linux service noise repeatedly draws from small shared message pools across unrelated hosts. Across 11 Linux hosts, 492 `irqbalance` messages collapse to 31 normalized templates; across 10 hosts, 470 `snapd` messages collapse to 21 templates. On LOG-MON-01, these two services account for 189 of 304 syslog records, with similarly high shares on WEB-EXT-01 and FILE-LNX-01.

- `[weak_signal]` All 18 visible RDP Type 10 logons occur only 4.599–6.325 seconds after their matching inbound TCP/3389 eCAR flow. The ordering is correct, but the narrow delay range across multiple systems suggests a shared timing recipe.

## Evidence For Real

- Windows Security records closely follow native event schemas. Representative checks across 26 Event IDs found appropriate versions, tasks, levels, opcodes, keywords, and field names—for example, 4624 version 2/task 12544, 4688 version 2/task 13312, and 5156 version 1/task 12810.

- Sysmon records preserve source-specific schema details, including the real capitalization difference between Event 10 `SourceProcessGUID` and Event 8 `SourceProcessGuid`. Timestamps use seven-digit XML precision while `UtcTime` uses milliseconds.

- Approximately 1,024 Security 4688 and Sysmon Event 1 process creations agree on PID, executable, command line, and parent PID. Only a handful lacked a counterpart, with no contradictory counterpart found.

- No visible eCAR process reference or Sysmon ProcessGuid dependency preceded the matching visible process creation. Logon and process termination ordering was also coherent after accounting for pre-window state and Windows lock/unlock LogonID reuse.

- DC-01’s Security EventRecordID reset is causally justified. `cmd.exe` and `wevtutil.exe` execute `wevtutil cl Security` at approximately `17:42:22Z`; Event 1102 appears at `17:42:26.1855251Z` with EventRecordID 1, followed by normally increasing IDs. See [DC-01 eCAR](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-63/review-data/DC-01.meridianhcs.local/ecar.json:5321>) and [Event 1102](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/blind-test/v2-loop-63/review-data/DC-01.meridianhcs.local/windows_event_security.xml:263724>).

- Every inspected Zeek DNS, HTTP, SSL, DHCP, SMB, and file UID had a matching same-sensor `conn.log` UID and tuple. Protocol child timestamps did not precede their connections, and no UIDs were duplicated across sensors.

- The 48 DHCP records form plausible REQUEST/ACK renewals. One-, two-, and four-hour leases renew near T/2 with jitter rather than at a single fixed cadence.

- ASA lifecycle counts look naturally bounded by the collection window: 6,645 TCP builds versus 6,643 teardowns, 1,068 UDP builds and teardowns, and balanced translation creation/deletion. The two unmatched TCP sessions are consistent with connections still open at cutoff.

- Linux SSH/PAM/logind sequences contain coherent accepted-password/key events, session opens, shell activity, and closes with stable host PIDs. UFW records also show varied source fingerprints, TTLs, TCP windows, and kernel monotonic times tracking wall-clock progression.

## Detailed Analysis

### Corpus integrity and parseability

The corpus covers approximately six hours, from `2024-03-18T12:00Z` through `18:00Z`, and contains Windows Security XML, Sysmon XML, eCAR JSON, Linux RFC 5424 syslog, Zeek JSON, ASA messages, Snort alerts, proxy logs, and web access logs. All inspected XML and JSON files parsed successfully, and the sampled syslog lines matched their expected RFC 5424 structure.

The source volumes are credible for a monitored mixed environment: the core Zeek sensor contains 11,553 connections, 3,013 DNS transactions, 1,812 HTTP records, and 337 SSL records; the DMZ sensor contains 8,663 connections, 2,082 HTTP records, and 2,382 SSL records. These volumes do not show a simple one-record-per-scripted-action profile.

### Windows Security and Sysmon schemas

I sampled records from Events 1102, 4624, 4625, 4634, 4648, 4656, 4663, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4779, 4800, 4801, 5140, 5145, and 5156. Field names, versions, task values, success/failure keywords, hexadecimal access masks, SIDs, GUIDs, and process-path conventions were generally accurate.

Security 4688 records normally trail their corresponding Sysmon Event 1 by roughly 35–650 milliseconds, with variation rather than a fixed offset. Sysmon’s XML `SystemTime` and event-data `UtcTime` typically differ by fractions of a millisecond to a few milliseconds, with no systematic inversion.

The Event 4648 IP inconsistency is therefore conspicuous because it appears inside an otherwise disciplined implementation. The same host’s 13:31 Event 4648 uses `10.10.1.31`, whereas its 14:50 event suddenly uses another workstation’s stable address, `10.10.1.99`.

### Process and authentication lifecycles

Ordinary process lineage is strong. Security 4688, Sysmon Event 1, and eCAR PROCESS CREATE records generally agree, while eCAR PROCESS TERMINATE and Sysmon Event 5 close the same identities in sensible order.

The wrapper-execution exceptions are systematic enough to matter. Successful `runas /netonly` activity has Type 9 logon and explicit-credential evidence, then terminates without ever creating the requested command. The PSEXESVC `cmd.exe /c whoami && hostname` chain has the same problem. Since nearby `cmd /c net ...` records do create `net.exe`, this cannot be dismissed as wholesale child-process collection loss.

Authentication lifecycle checks otherwise passed. Type 3 logons generally have matching logoffs, Type 10 sessions are preceded by inbound RDP transport, and Type 7 unlock events legitimately reuse existing interactive session identifiers rather than creating contradictory sessions.

### Zeek and network-source correlation

UID and tuple integrity is excellent. DNS, HTTP, SSL, DHCP, SMB, and file records correlate to the correct sensor-local connection, and child protocol timestamps follow the connection start. TCP and UDP protocol numbers, byte accounting, duration values, DNS response codes, TTLs, SSL certificate references, and DHCP request/ack semantics were internally coherent.

The `files.log` analyzer metadata is the notable exception. Hash fields and PE child records represent analyzers that necessarily ran, yet the analyzer sets omit their names. This would not stop JSON ingestion, but it can break detections or validation rules that use `files.analyzers` to determine which analysis was performed.

ASA, proxy, Snort, and web formats were broadly plausible. ASA build/teardown and translation lifecycles balance naturally, proxy CONNECT records contain reasonable tunnel fields, and web logs show varied methods, user agents, status codes, and response sizes.

### eCAR semantics

eCAR process identities are stable, and visible actor/source/target UUID references do not point forward to processes created later. The ambiguity is specifically in remote SMB file attribution: host-scoped Windows FILE records receive the remote client’s PID and executable as `source_*`, while native Windows auditing identifies local `System`.

A cross-host UUID can be valuable enrichment, but it should occupy clearly remote fields such as `remote_process_uuid`, `client_pid`, or `origin_process`. Overloading ordinary source-process fields produces misleading host-local semantics for SIEM rules.

### Linux distribution and environmental texture

The Linux records have convincing syntax, UID conventions, PAM sequences, SSH outcomes, sudo records, kernel timestamps, and facility/severity values. However, the frequency and reuse of `irqbalance` and `snapd` status messages are difficult to explain across nearly every server without a shared verbose collection configuration.

The weakness is not simply repetition: operational logs naturally repeat. It is the combination of high per-host volume, deployment across unrelated host roles, and a small normalized vocabulary dominating some hosts’ six-hour output. That resembles a finite generator pool more than ordinary default service logging.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `hard_contradiction` | Windows Security 4648 | One explicit-credential event | Local runas process inherits another workstation’s IP address; strongest ownership contradiction. |
| `contract_gap` | Security, Sysmon, eCAR | Three runas chains plus one PSEXESVC shell chain | Successful wrappers omit required executable children despite child-process telemetry working elsewhere. |
| `schema_or_format` | Zeek files | 87 hashed SMB files | Hash values exist without corresponding hash analyzers in `analyzers`. |
| `contract_gap` | Zeek files/PE | Three executable files | PE records exist while the parent file metadata says the PE analyzer did not run. |
| `contract_gap` | eCAR and Windows Security | Ten Windows SMB file records | Remote Linux process identity is placed in host-scoped Windows source-process fields. |
| `distribution_texture` | Linux syslog | 10–11 hosts, 962 messages | A small common `irqbalance`/`snapd` vocabulary appears at unusually high volume across unrelated roles. |
| `weak_signal` | RDP/eCAR | 18 sessions | Correct but unusually narrow transport-to-authentication timing range. |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Sysmon, Zeek, ASA, and syslog records are mostly source-native; Zeek analyzer metadata and eCAR process semantics are the primary exceptions.
- **Temporal patterns:** 8 — Causal ordering and lifecycle timing are strong, although RDP delays occupy a narrow shared range.
- **Cross-source correlation:** 7 — Most process, session, UID, and network relationships agree, but the Event 4648 IP leak and SMB actor attribution are material contradictions.
- **Behavioral realism:** 7 — Authentication, DHCP, firewall, and user activity are varied; successful wrapper commands without their executable children reduce credibility.
- **Environmental consistency:** 8 — Host roles, addressing, traffic volumes, and service placement are coherent, with Linux service-noise distribution as the main weakness.

## Recommendations

If this were synthetic, the following changes would improve it:

- Derive Event 4648 `IpAddress` from the canonical host executing the identified process, and add a validator requiring local-process network addresses to belong to that host unless the event explicitly models remote execution.

- Materialize the child process after successful `runas /netonly` operations. Emit the same child identity consistently through Security 4688, Sysmon Event 1, eCAR PROCESS CREATE, and termination telemetry.

- Parse executable commands inside `cmd.exe /c` wrappers and emit external programs such as `whoami.exe`, `hostname.exe`, and `net.exe`. Built-in shell commands may remain wrapper-only.

- Populate Zeek `files.analyzers` from the analyzers that actually produced the record. Hash fields should imply their matching hash analyzers, and an emitted `pe.log` record should imply the `PE` analyzer.

- Separate remote SMB-client attribution from the server’s local source process in eCAR. Preserve the remote UUID and PID in explicitly named client/origin fields while retaining Windows `System` as the server-side process.

- Reduce default `irqbalance` and `snapd` chatter and vary it by host role, package state, logging level, and maintenance activity. Introduce a broader low-frequency message tail instead of drawing most records from a small common pool.

- If modeling RDP timing, widen the transport-to-authentication distribution using connection latency, authentication mechanism, DC lookup timing, and host load while preserving transport-before-authentication ordering.
