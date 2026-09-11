# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 83  
**Synthetic-Confidence Score:** 66

## Executive Summary

The dataset is exceptionally strong at schema fidelity, lifecycle correlation, and source-native formatting; most records would parse and behave correctly in a SIEM. My synthetic verdict is driven instead by several measurable distribution fingerprints, especially the randomized TCP-window behavior of recurring scanner identities, artificial-looking Nikto test identifiers, and zero variance across 825 Windows process exit statuses. These defects outweigh the otherwise convincing Windows, Zeek, eCAR, mail, firewall, and Linux telemetry.

## Evidence For Synthetic

- `[distribution_texture]` In `WEB-EXT-01.meridianhcs.local/syslog.log`, 918 UFW blocks use only three TCP window sizes: `65535` 314 times, `14600` 305 times, and `1024` 299 times. Each dominant scanner IP independently rotates through the same near-uniform three-value pool. For example, `185.220.163.140` retains `TTL=113` and `LEN=52` but changes from `WINDOW=65535` at `12:00:36.141250Z`, to `14600` at `12:00:53.947383Z`, to `1024` at `12:06:41.032450Z`. A persistent source stack or scan tool would normally have a much more stable TCP fingerprint.

- `[distribution_texture]` The same UFW data contains 918 blocked packets from only 11 source IPs, with seven addresses responsible for 911 records. A targeted campaign could explain the small population, but all dominant identities share the same window-value pool and common destination-port vocabulary, making the population look generated rather than independently sourced.

- `[distribution_texture]` In `WEB-EXT-01.meridianhcs.local/web_access.log`, the apparent Nikto scan from `185.70.41.45` contains 344 `Test:` values. Every value is unique, every value falls between `100000` and `999999`, and none is zero-prefixed. Examples include `Test:227380`, `Test:745925`, `Test:693857`, `Test:204230`, and `Test:419421`. Nikto’s token is intended to identify a scanner test; this full-range, non-zero-leading, non-repeating pattern resembles random integer generation rather than identifiers drawn from a scanner test database.

- `[distribution_texture]` All 825 Security Event ID 4689 records have `Status=0x0`, despite spanning 71 process images and ten hosts. The population includes `powershell.exe`, `cmd.exe`, `net.exe`, `dsquery.exe`, `gpupdate.exe`, browsers, update agents, Exchange processes, and short-lived administrative utilities. Zero exit-status variance across that population is implausibly clean.

- `[distribution_texture]` All 2,538 Zeek `ssl.json` records have `established=true`. Failed TCP attempts exist elsewhere in `conn.json`, so this is not a claim that all network traffic succeeded; nevertheless, seeing no TLS negotiation or certificate failure in a six-hour enterprise sample is a weak but measurable lack of long-tail behavior.

- `[weak_signal]` There are 1,502 otherwise identical `conn` observations and 1,348 otherwise identical HTTP observations duplicated between `zeek-dmz` and `zeek-core`. Core timestamps trail DMZ by a very narrow band: 111.212–117.187 ms for connections, with a 114.087 ms median, and 110.051–118.199 ms for HTTP, with a 114.251 ms median. Overlapping sensors and clock skew can explain duplication, but the tightly bounded per-record jitter looks modeled rather than like a slowly drifting clock offset.

- `[contract_gap]` eCAR file operations use two actor-linkage shapes. Ninety of 149 `FILE/READ` records contain top-level `actorID` and `pid`, while 59 omit both even though `properties.source_process_uuid` and `properties.src_pid` are populated; 11 of 116 writes and the sole rename behave similarly. Remote target-side semantics may explain the omission, but generic eCAR detections querying top-level actor fields would silently miss those operations.

## Evidence For Real

- All Windows XML documents, Zeek/eCAR JSON lines, RFC 5424 syslog records, ASA messages, Snort fast-alert records, proxy rows, and web-access rows parsed successfully. I found no malformed record in these families.

- Windows event metadata is unusually accurate. Security Event IDs use appropriate versions, tasks, keywords, and field sets: 4624 v2/task 12544, 4688 v2/task 13312, 5156 v1/task 12810, and 1102 under `Microsoft-Windows-Eventlog` with task 104 and `0x4020000000000000`.

- Sysmon versions and case-sensitive field names are correct, including Event 1 v5, Event 3 v5, Event 5 v3, Event 8 v2, Event 10 v3 with `SourceProcessGUID`/`TargetProcessGUID`, Event 11 v2 with `TargetFilename`, Event 13 v2, and Event 22 v5.

- Of 970 Sysmon Event 1 process creations, 969 matched a Security 4688 by host, PID, image, command line, and parent image within ten seconds. There were no command-line or parent-image mismatches. The single unmatched Google Drive process is consistent with selective collection rather than a systemic correlation defect.

- No Sysmon event referenced a process GUID whose visible creation occurred later. No paired process termination preceded its visible creation, and no paired Windows logoff preceded its visible logon.

- Binary identity is stable. Across 254 host/image combinations for Sysmon Event 1 and 83 host/module combinations for Event 7, no image changed hashes on the same host.

- Zeek correlation is strong without obvious semantic breakage: all application UIDs had a same-sensor `conn` record, no application timestamp preceded its connection timestamp, all referenced certificate FUIDs resolved to `x509` records, and IP-byte accounting was valid for every connection.

- Packet-loss effects are modeled coherently. UID `CmrZMDmvFtD85wkeEGQ` has `missed_bytes=380`; its two certificate files have 12 and 15 missing bytes, no X.509 parse records, and no `cert_chain_fuids` in the corresponding SSL record. That is convincing source-native behavior.

- SMTP STARTTLS is handled realistically. Submission records such as UID `CkfvDCvr2HjYKKMbHY` show `tls=true`, a `220 ... Ready for TLS` reply, and empty post-encryption envelope fields, while unencrypted mail hops expose sender, recipient, subject, message ID, and file FUIDs.

- The ASA lifecycle is coherent: 7,403 visible built connections and 7,401 teardowns, with no teardown preceding a visible build for the same connection ID. Message IDs and formats for 302013/302014, 302015/302016, 305011/305012, 106023, and 302020/302021 are structurally correct.

- Linux syslog shows source-appropriate PRI values and applications, including `<78>` CRON, `<85>/<86>` sudo/SSHD, DHCP request/ACK/bind sequences, Samba open/read/close sequences, and host-specific service mixes.

## Detailed Analysis

**Scope and sampling.** The visible window is approximately `2024-03-18T12:00:00Z` through `17:59:56Z`. I parsed every structured record and manually inspected representative examples from more than 20 event types, including Security 1102, 4624, 4625, 4634, 4648, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4779, 4800, 4801, 5140, 5145, and 5156, plus all present Sysmon types.

**Windows Security events.** The major populations were 802 Event 4624 logons, 383 Event 4634 logoffs, 419 Event 4672 privilege assignments, 976 Event 4688 process creations, 825 Event 4689 terminations, 749 Event 4768 TGT requests, 2,072 Event 4769 service-ticket requests, and 11,605 Event 5156 connections.

The field semantics generally hold. At `12:06:21.9825293Z`, DC-01 records a Type 3 NTLM logon for `lina.nguyen` from `::ffff:10.10.1.21:33757`, using `NtLmSsp`, `NTLM V2`, and a 128-bit key. At `12:52:43.5692401Z`, MAIL-FIN-01 records a Type 10 RDP logon for `aisha.johnson` from `WS-AJOHNSON-01`/`10.10.1.35:62602`, with `User32`, `Negotiate`, and `winlogon.exe`.

Lock/unlock behavior also preserves the existing session LUID. On WS-EBROOKS-01, Event 4800 locks LUID `0xa370ec7` at `12:30:49.3843994Z`; Event 4624 Type 7 reuses that LUID at `12:42:29.7188314Z`; Event 4801 follows at `12:42:30.2781875Z`. That explains apparent pre-logon references without violating bounded-window causality.

At `17:42:33.1802494Z`, DC-01 records Event 1102 with the correct Eventlog provider, `UserData/LogFileCleared` payload, and `EventRecordID=1`; the next retained Security event has record ID 2. This is a convincing log-clear reset.

The significant Windows defect is Event 4689: every one of 825 terminations has `Status=0x0`. Schema and correlation are correct, but the value distribution is not production-like.

**Sysmon and eCAR.** Sysmon contains 970 process creates, 7,435 network events, 839 process terminations, 149 image loads, seven remote-thread creations, 741 process accesses, 27 file creations, 140 registry value sets, and 1,234 DNS-query events. Field naming, event versions, GUID formatting, hash formatting, and timestamp precision are accurate.

The PSEXESVC sequence on DC-01 is especially coherent. Sysmon Event 11 records `C:\Windows\PSEXESVC.exe` at `15:59:33.8502323Z`; Security 4697 records service `PSEXESVC`, type `0x10`, demand start `3`, and `LocalSystem` at `15:59:34.1567707Z`; Sysmon Event 1 creates PID 5560 under `services.exe` at `15:59:34.7350125Z`. eCAR independently renders the file, service, process, module, and child-command lifecycle with stable actor/object identifiers.

Across all visible Sysmon GUID consumers—including network connections, image loads, process access, file creation, registry modification, and DNS—none referenced a process whose visible Event 1 occurred later. eCAR likewise had no duplicate event IDs, no termination-before-creation for paired process object IDs, and no actor object visibly created after first use.

The eCAR remote-file shape is less consistent for detection content. For example, the DC-02 `FILE/READ` at epoch-ms `1710764257012` contains `properties.source_process_uuid` and `src_pid=6644` but lacks equivalent top-level `actorID` and `pid`. This is parseable but requires special-case query logic.

**Network telemetry.** Zeek contains 19,833 connections, 3,895 DNS records, 3,424 HTTP records, 2,538 SSL records, 1,928 files, 1,074 X.509 records, 82 OCSP records, 46 SMTP transactions, and 371 SMB mapping/file records. JSON schemas are stable, source files are time ordered, application UIDs join successfully, and byte/packet arithmetic is valid.

DNS cadence is mostly plausible. Repeated internal A lookups tend to occur near the configured 300-second TTL; for example, DC-02 querying DC-01 has a median interval of 291 seconds. Certificate chains, resumed TLS sessions, missing-packet effects, MIME types, PE metadata, and SMTP visibility all display convincing source-native nuance.

The cross-sensor copies show a consistent roughly 114 ms DMZ-to-core relationship. This could represent a sensor clock offset, but the 8 ms-wide randomized envelope across thousands of paired records is a synthetic-looking collection texture. The fact that identities differ while tuples, application fields, and traffic totals remain stable is otherwise appropriate for separate Zeek instances.

**Firewall, IDS, proxy, web, and syslog.** All 19,376 ASA lines and 185 Snort alerts match their expected textual forms. ASA connection IDs are lifecycle-consistent, NAT build/destroy messages are paired, and SYN timeouts carry zero bytes as expected. Proxy and web logs use valid combined-style syntax and include realistic status diversity: proxy responses include 200, 206, 301, 302, 304, 403, 407, 502, 503, and 504; web responses include 200, 206, 301, 302, 304, 401, 403, 404, 429, and 500.

The scanner simulation is where realism degrades sharply. UFW packet fields show stable TTL and IP length per source but randomly rotate exactly three TCP-window values. Separately, Nikto test identifiers appear randomly allocated across a six-digit range. Both patterns would survive normal SIEM parsing but are conspicuous to detection logic that groups activity by scanner fingerprint or user-agent test ID.

**Balance of evidence.** I found no impossible visible ordering, invalid SID/GUID, broken Zeek reference, malformed source file, or incorrect major Windows event signature. The synthetic verdict therefore does not rest on attack narratability or complete source coverage. It rests on repeated, measurable RNG-like behavior across edge scanning telemetry and Windows process outcomes.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `distribution_texture` | Linux UFW/kernel | 918 records; seven IPs account for 911 | Same three TCP windows are near-uniformly resampled for every dominant source identity, breaking stable scanner fingerprint behavior. |
| `distribution_texture` | Web access/Nikto | 344 user-agent test values | All identifiers are unique, non-zero-leading six-digit values, indicating random-number generation rather than scanner test metadata. |
| `distribution_texture` | Windows Security 4689 | 825 records, 71 images, ten hosts | Every process exit has `Status=0x0`; the complete absence of nonzero outcomes is implausibly smooth. |
| `contract_gap` | eCAR file operations | 71 file operations | Available source-process identity is relegated to properties while top-level actor fields are omitted, creating inconsistent query behavior. |
| `distribution_texture` | Zeek SSL | 2,538 records | No `established=false` outcome appears anywhere in the SSL population. |
| `weak_signal` | Zeek core/DMZ | 1,502 conn and 1,348 HTTP pairs | A tightly bounded ~114 ms per-record sensor offset looks modeled, though real clock skew remains a credible explanation. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows/Sysmon metadata, Zeek fields, eCAR JSON, RFC 5424 syslog, ASA, Snort, and access-log structures are highly accurate.
- **Temporal patterns:** 7 — Lifecycle ordering is strong, but the narrow cross-sensor delay envelope and some zero-variance outcomes look engineered.
- **Cross-source correlation:** 9 — Process, session, file, service, network, mail, certificate, and firewall relationships are consistently joinable without impossible ordering.
- **Behavioral realism:** 6 — Host and application activity is varied, but scanner fingerprint randomization and all-zero process exits are strong behavioral tells.
- **Environmental consistency:** 8 — Host roles, paths, software versions, authentication protocols, source volumes, and service mixes are largely coherent and heterogeneous.

## Recommendations

- If this were synthetic, preserve a persistent TCP/IP fingerprint for each scanner identity. Assign window size, initial TTL, packet length, TCP options, and scan-tool profile per source or campaign instead of independently selecting from a global three-value pool.

- If this were synthetic, derive Nikto `Test:` identifiers from a real test catalog and bind each identifier to the corresponding method, URI, and expected check. Include the zero-padding and legitimate reuse patterns produced by the selected Nikto version.

- If this were synthetic, generate Security 4689 exit status from process outcome. Failed commands, interrupted updates, authentication utilities, scanners, and administrative tools should produce a small but meaningful nonzero tail.

- If this were synthetic, introduce a bounded population of failed TLS negotiations—protocol alerts, certificate failures, client aborts, or unsupported ciphers—while preserving the existing distinction between pre-TLS connection failures and SSL analyzer records.

- If this were synthetic, model each Zeek sensor’s clock as a slowly drifting offset with occasional synchronization corrections. Avoid independently jittering every duplicate observation inside a narrow fixed band.

- If this were synthetic, formalize eCAR remote-file actor semantics. Either populate top-level `actorID`/`pid` consistently or expose explicit `remote_actor_id`, `remote_pid`, and `actor_host` fields so rules do not need to infer ownership from nested properties.

