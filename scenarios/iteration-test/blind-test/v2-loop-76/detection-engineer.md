# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 64

## Executive Summary

The telemetry is unusually sophisticated: schemas, timestamps, process lifecycles, Windows/Zeek correlations, and firewall accounting are overwhelmingly coherent. However, several repeated source-native defects—especially selective Sysmon metadata loss, collapsed Windows version values, a modern-host/legacy-event-version mismatch, and inconsistent Zeek PE analyzer bookkeeping—make synthetic generation more likely than sanitized production data.

## Evidence For Synthetic

- `[schema_or_format]` Sysmon Event 1 selectively loses every file-derived field for 22 executions, including standard Windows binaries. For example, `WS-PPATEL-01.../windows_event_sysmon.xml` at `2024-03-18T14:59:58.9154364Z` records `C:\Windows\System32\curl.exe`, and at `15:09:10.8001735Z` records `runas.exe`, but both have `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, and `Hashes` equal to `-`. The other 970 Event 1 records contain four correctly formatted hashes, so this looks like an incomplete executable catalog rather than an unconfigured collector.
- `[schema_or_format]` The same metadata hole affects well-known signed software: `MonitoringHost.exe`, `Veeam.Backup.Service.exe`, `PSEXESVC.exe`, Thunderbird, and several updater binaries. Separately, 29 Sysmon Event 7 records report `Signed=true` and `SignatureStatus=Valid` while all version-resource fields are `-`, including Office `mso.dll` and `OLMAPI32.DLL`, Defender `MpClient.dll`, and Edge `msedge_elf.dll`.
- `[distribution_texture]` Of 992 Sysmon Event 1 records, 800 use only four pristine base-build versions: `10.0.17763.1`, `10.0.19041.1`, `10.0.20348.1`, or `10.0.22621.1`. Every sampled Windows component on the Server 2019/2022 and Windows 10/11 hosts collapses to its base build even though the environment contains contemporaneous Defender and third-party software, creating a repeated low-entropy servicing fingerprint.
- `[schema_or_format]` `DC-01.../windows_event_security.xml` records scheduled-task creation Event 4698 at `2024-03-18T16:20:16.0143618Z` as Version 0 with only the legacy fields. The same host’s system binaries identify build 20348, on which the newer Event 4698 version and its client/parent process fields would ordinarily be available.
- `[contract_gap]` All 15 Zeek PE records contradict their companion `files.json` analyzer inventory. For example, FUID `Fzhk0yAe7DBT5s63VhL` appears in `zeek-core/pe.json` at `1710765797.009332`, but its `zeek-core/files.json` record lists only `analyzers:["SHA1"]`; every PE-associated file in `zeek-core` and `zeek-dmz` omits the `PE` analyzer. In contrast, X.509 file records correctly list `X509`.

## Evidence For Real

- All 18,939 Windows Security events and 11,839 Sysmon events parsed successfully. Event field sets, provider GUIDs, channels, tasks, levels, opcodes, keywords, and capitalization were otherwise highly accurate across more than 25 Security event types and eight Sysmon types.
- Security 4688 and Sysmon Event 1 produced 991 timestamp-proximate process-create pairs with zero PID, image, command-line, parent PID, parent image, user, or LogonID mismatches. Sysmon’s encoded creation time inside every visible ProcessGuid also matched the event creation second.
- No Sysmon ProcessGuid was visibly created twice, referenced before its visible creation, or used after its visible Event 5 termination. eCAR likewise had no duplicate event IDs, visible terminate-before-create relationships, PID mismatches within process identities, or actor references after termination.
- Windows logon semantics were strong: 4624/4634 LogonIDs aligned, 4672 followed its associated successful logon, NTLM used `NtLmSsp`, `NTLM V2`, and 128-bit keys, and Kerberos used the expected IPv4-mapped address representation and encryption-type codes.
- Sysmon `UtcTime` always preceded its XML `SystemTime`; typical rendering delay averaged approximately 2–3 ms, with a realistic long tail rather than one fixed offset.
- All 7,730 matched Security 5156/Sysmon Event 3 pairs agreed on endpoints, ports, protocol, and inbound/outbound semantics.
- Every Zeek DNS, HTTP, SSL, SMB, and SMTP UID matched a `conn.json` UID with consistent endpoints and nonnegative timestamps. Connection states, histories, byte/packet accounting, and protocol-specific field types were diverse and internally valid.
- ASA accounting closely follows actual flow totals. The connection built at `Mar 18 12:00:10` for `10.10.1.31:57153 → 10.10.3.20:8080` tears down after `0:01:45` with `3,793,206` bytes, exactly matching the corresponding Zeek IP-byte totals of `3,723,000 + 70,206`.
- The DC-01 Security log clear is rendered realistically: `wevtutil cl Security` is followed by Event 1102 from `Microsoft-Windows-Eventlog`, EventRecordID resets to 1, and subsequent records continue from the new sequence.
- Linux SSH telemetry contains coherent connection, authentication, PAM, logind, process, session, and shell-command timing. RFC5424 PRI values also match the message facilities and severities.

## Detailed Analysis

### Windows Event Schema and Semantics

I parsed every Windows XML record and examined representative records from Events 1102, 4624, 4625, 4634, 4648, 4656, 4658, 4663, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4779, 4800, 4801, 5140, 5145, and 5156.

Most metadata is precise. Examples include Security 4688 Version 2/Task 13312, 5156 Version 1/Task 12810, and appropriate success-versus-failure keywords. SIDs, LUIDs, hexadecimal PIDs, access masks, service types, UAC values, and mapped IPv4 addresses are properly shaped.

The account lifecycle on DC-01 is causally coherent: `svc_dirsync` is created at `16:14:43.9308110Z`, receives a password reset at `16:14:44.9115084Z`, changes state at `16:14:46.6668506Z`, joins Domain Admins at `16:14:53.7459768Z`, and is deleted at `17:50:06.6087566Z`.

Event 4698 is the material schema exception. DC-01 behaves as a Server 2022-class host elsewhere, yet the task-creation record is rendered with the old Version 0 field contract and omits the modern client-process provenance fields.

### Sysmon Accuracy

Sysmon’s field names and event versions are generally excellent, including the otherwise easy-to-miss `SourceProcessGUID` capitalization in Event 10 versus `SourceProcessGuid` in Event 8.

ProcessGuid construction is source-faithful: each host has a stable machine component, and all 992 visible Event 1 GUIDs encode the exact process-creation epoch second. Hash strings use valid lengths and the expected `SHA1,MD5,SHA256,IMPHASH` ordering.

The principal defect is selective metadata completeness. Hashing demonstrably works across the dataset, yet executions of `curl.exe` and `runas.exe` from System32 have no hashes or PE version resources. This is difficult to explain as ordinary file access failure because the executables necessarily existed and were readable enough to execute, and the pattern repeats by image rather than appearing as sporadic collection loss.

ImageLoad events have a related artifact: signed Office, Defender, Edge, and Power BI modules receive valid signature results and four hashes but no version-resource metadata. That combination is structurally possible, but its repetition across known versioned binaries suggests catalog-driven enrichment.

### Process and Session Correlation

Of 997 Security 4688 events, 991 matched Sysmon Event 1 within two seconds. All matched values agreed on process and parent identity, command line, user, and logon context. The usual ordering was Sysmon first and Security second, with plausible subsecond variation.

Likewise, 841 Security 4689 terminations matched Sysmon Event 5 without image mismatches. No visible Sysmon event referenced a process after its Event 5 termination.

Logon lifecycle testing found no impossible same-LUID ordering. The apparent WS-MCHEN lock-before-4624 sequence is valid: the later 4624 is LogonType 7 for the already-existing session, followed by Event 4801 unlock.

### Network-Aware Windows Events

Security 5156 fields are consistently native-looking. `%%14592` inbound events use receive/accept layer values, while `%%14593` outbound events use connect-layer values. Filter runtime IDs are stable for repeated application/protocol/direction combinations rather than being randomized per record.

For 7,730 flows represented in both Security 5156 and Sysmon Event 3, endpoint tuples and direction semantics matched without contradiction. Examples include inbound DNS and Kerberos on the domain controllers and outbound DNS/browser traffic on workstations.

### Zeek and Perimeter Formats

The Zeek corpus contains 19,728 connection records, 3,800 DNS records, 3,297 HTTP records, and 2,487 TLS records. All parsed as JSON, UIDs were unique within each connection log, child records used matching endpoints, and no application-layer record visibly preceded its connection.

Connection-state and history distributions have substantial variety, including `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, partial-close states, and dozens of history strings. IP byte totals meet the expected packet/header lower bounds, and S0 connections contain no responder payload.

X.509 references are especially strong: every certificate FUID resolves to `files.json`, and each X.509 fingerprint matches the file’s SHA-1. The PE bookkeeping is the notable exception: every PE record exists despite the associated file claiming only SHA-1 analysis.

ASA and Snort formats use credible native message IDs, PRI/severity combinations, NAT wording, connection IDs, teardown reasons, and alert layouts. The ASA/Zeek byte-level agreement provides strong evidence of a coherent underlying event model.

### eCAR, Linux, and Application Logs

All 33,687 eCAR records parsed. Event IDs were globally unique, process identities remained stable between CREATE and TERMINATE, and there were no visible post-termination actor references.

Linux syslog uses valid RFC5424 structure and source-appropriate facilities. SSH session sequences preserve PID, address, port, user, PAM, and logind relationships. Bash histories use standard `#<epoch>` timing records and correspond to eCAR process activity.

Proxy and web records are mechanically parseable and show credible CONNECT/inspection relationships, byte scopes, tunnel identifiers, conditional responses, referrers, and user-agent diversity.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `schema_or_format` | Sysmon Event 1 | 22 process starts across multiple hosts | Standard and signed executables selectively lose all hashes and PE metadata despite an otherwise active four-hash configuration. |
| `distribution_texture` | Sysmon Event 1 | 800 of 992 records | Windows component versions collapse to four pristine `.1` builds across several OS generations. |
| `schema_or_format` | Sysmon Event 7 | 29 of 126 records | Validly signed, hashed Microsoft modules repeatedly lack all version-resource metadata. |
| `schema_or_format` | Windows Security 4698 | One high-value record on DC-01 | A modern build emits the legacy Version 0 task-creation contract. |
| `contract_gap` | Zeek Files/PE | All 15 PE records | PE output exists while the companion file analyzer set omits `PE`. |

## Realism Score by Category

- **Field format accuracy:** 7 — Most schemas are highly accurate, but the Sysmon metadata gaps and legacy Event 4698 contract are meaningful defects.
- **Temporal patterns:** 9 — Precision, ordering, clock offsets, log clearing, and lifecycle timing are consistently plausible.
- **Cross-source correlation:** 9 — Process, flow, UID, hash, and firewall correlations are exceptionally coherent, with the PE analyzer inventory as the main exception.
- **Behavioral realism:** 8 — Logon, process, network, service, and user-session behaviors are varied and largely source-appropriate.
- **Environmental consistency:** 6 — The pristine Windows version pool conflicts with the otherwise current, actively maintained software environment.

## Recommendations

- If this were synthetic, populate process hashes independently of optional product metadata. At minimum, all executions of readable System32 binaries such as `curl.exe` and `runas.exe` should receive the configured hashes even when descriptive metadata is unavailable.
- If this were synthetic, derive `FileVersion`, `Description`, `Product`, `Company`, and `OriginalFileName` from per-binary PE resources. Include realistic serviced Windows revisions instead of mapping every system component to the OS’s pristine base build.
- If this were synthetic, select Windows event versions from the host build. Server 2022 task creation should use the contemporary Event 4698 contract and populate its client/parent process fields.
- If this were synthetic, make Zeek `files.log.analyzers` reflect every attached analyzer. A FUID that produces `pe.log` should include `PE`, just as certificate FUIDs correctly include `X509`.
- If this were synthetic, add validation fixtures specifically for known signed/versioned binaries and for bidirectional Zeek analyzer-to-output integrity; these would catch the highest-impact defects found here.