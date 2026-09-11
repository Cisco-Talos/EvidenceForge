# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 71

## Executive Summary

The dataset is highly parseable and unusually strong in Windows event schemas, lifecycle ordering, and cross-source identifier reuse, but several source-native value patterns are difficult to reconcile with a real mixed-build Windows estate. The deciding evidence is the combination of incompatible PE versions/hashes across hosts, systematic Sysmon metadata and hash placeholders for readable inbox executables, and near-identical PID-allocation rates across every Linux host.

## Evidence For Synthetic

- [environment_or_collection_plausibility] Sysmon Event 1 reports mutually inconsistent Windows component builds on the same hosts. On `DC-01.meridianhcs.local`, record 3289565 at `2024-03-18T12:48:34.4902025Z` identifies `winlogon.exe` as `10.0.20348.1`, while record 3289567 1.5 seconds later identifies `C:\Windows\explorer.exe` as `10.0.19041.1`. `FILE-SRV-01` similarly pairs `winlogon.exe` `10.0.17763.1` at record 1644441 with the same `explorer.exe` `10.0.19041.1` at record 1644443. The explorer SHA-256, `EA980949D49A837FB13FD9306217AB3A52A384685EB710C9135AE9EDF011FEB5`, is identical across those server builds and all workstation build families.
- [environment_or_collection_plausibility] The mixed-build defect extends beyond Explorer. `WS-MCHEN-01` record 525309 reports `winlogon.exe` `10.0.22621.1`, but record 525219 reports inbox `mstsc.exe` `10.0.19041.1`, record 525311 reports `explorer.exe` `10.0.19041.1`, and record 525444 reports `gpresult.exe` `10.0.20348.1`. `WS-PPATEL-01` likewise combines `winlogon.exe` `10.0.22621.1` at record 739695 with `gpupdate.exe` `10.0.19041.1` at record 740024. This looks like executable metadata selected by image name rather than from a coherent host image.
- [schema_or_format] Of 993 Sysmon Event 1 records, 716 carry `-` simultaneously for `FileVersion`, `Description`, `Product`, `Company`, and `OriginalFileName`, including repeatedly executed Microsoft inbox binaries such as `taskhostw.exe`, `svchost.exe`, `dllhost.exe`, `cmd.exe`, and `WmiPrvSE.exe`. For example, `DC-01` record 3288909 at `2024-03-18T12:06:11.5937025Z` gives all five fields as `-` for `C:\Windows\System32\taskhostw.exe` while successfully supplying four hashes. The stable all-or-nothing placeholder pattern is not consistent with normal PE-resource extraction from these signed Windows binaries.
- [schema_or_format] Hash collection is also selectively absent despite a host-wide four-algorithm hash format being present on neighboring Event 1 records. `WS-MCHEN-01` records 525353 and 525481 show `Hashes: -` for inbox `runas.exe`; `WS-PPATEL-01` records 739971 and 740267 do the same; and `WS-AJOHNSON-01` records 31641 and 31642 do so for inbox `curl.exe`. At `13:55:00.6046516Z`, immediately after the first hashless `runas.exe`, `WS-MCHEN-01` record 525354 supplies SHA-1, MD5, SHA-256, and IMPHASH for `sublime_text.exe`, making a disabled hash configuration an implausible explanation. Twenty-two of 993 process-create rows use `Hashes: -`, including these readable operating-system files.
- [distribution_texture] Linux eCAR process IDs advance at almost the same hidden churn rate on all 11 Linux hosts. Linear fits of visible `PROCESS/CREATE` PID against `timestamp_ms` produce slopes of 2.03-2.47 PIDs/second and R-squared values of 0.960-0.991 on every host despite very different roles and visible process counts. Examples include `APP-INT-01` moving from PID 1,889,059 at `timestamp_ms=1710763201076` to 1,938,227 at `1710783640671`, `DB-PROD-01` moving from 838,912 to 890,736, and `WS-OHADDAD-01` moving from 3,369,936 to 3,418,402; every host advances by roughly 39,000-52,000 PIDs during the slice.
- [weak_signal] A few Sysmon Event 13 actor/value combinations are operationally odd. `DC-01` record 3291358 at `2024-03-18T15:07:34.1728102Z` and `FILE-SRV-01` record 1644721 at `2024-03-18T15:00:04.6632504Z` show `svchost.exe` as `NT AUTHORITY\NETWORK SERVICE` setting `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` to `explorer.exe`; `FILE-SRV-01` record 1645116 shows the same principal setting the Sysmon Operational channel's `Enabled` value. Impersonation or custom ACLs could explain these, so I treated them only as supporting evidence.

## Evidence For Real

- Windows XML is well formed and its event-specific schemas are strong. Security events use credible provider GUIDs, versions, tasks, levels, keywords, channels, and ordered `EventData` fields for 4624/4625, 4634, 4648, 4672, 4688/4689, 4697/4698, 4720/4724/4726/4728/4738, 4768/4769/4771/4776/4779, 4800/4801, 5140/5145, 5156, and 1102. Sysmon event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22 likewise use plausible schema versions and field names.
- Authentication values have credible source-native detail: IPv4-mapped IPv6 addresses, hexadecimal logon IDs and process IDs, valid domain SIDs, NTLM V2 key lengths, Kerberos encryption types `0x11`, `0x12`, and `0x17`, and coherent logon-type/process/package combinations. Across 855 visible 4624 events and 412 visible 4634 events, I found no logout preceding a visible login for the same logon ID; 405 logoff IDs have a matching earlier login, while the seven unmatched logoffs are compatible with pre-window sessions.
- Process correlation is strong rather than merely cosmetically similar. I matched 992 of 996 Security 4688 records to Sysmon Event 1 by host, PID, image, and a one-second window; all 992 matched on user, parent PID, and parent image. I matched 824 of 826 Security 4689 records to Sysmon Event 5 under the same constraints. No Sysmon dependent event for a visible ProcessGuid occurred before its Event 1 or after its Event 5, and no visible child was created after its exact ParentProcessGuid had terminated.
- The remote-service sequence on `DC-01` is operationally useful for detections: Security 4624 record 28256178 at `16:00:23.8201875Z` records an NTLM Type 3 logon for `aisha.johnson`; Sysmon 11 record 3292033 at `16:00:25.5411566Z` records `C:\Windows\PSEXESVC.exe`; Security 4697 record 28256180 creates `PSEXESVC`; Sysmon 1 records 3292035-3292036 create `PSEXESVC.exe` and child `cmd.exe`; and the matching Event 5/4689 terminations follow. The event IDs, principals, paths, parentage, and ordering are detection-ready.
- Account and log-clearing telemetry is source-native. `DC-01` records 28256808-28256820 show 4720, 4724, 4738, and 4728 for `svc_dirsync` with one stable SID. Sysmon records the `wevtutil cl Security` process before Security 1102 at `2024-03-18T17:41:44.7309750Z`; that event correctly uses provider `Microsoft-Windows-Eventlog`, Task 104, `UserData/LogFileCleared`, and EventRecordID 1, after which the Security channel continues from the reset record sequence.
- Zeek correlation is excellent and internally causal. Across `zeek-core`, `zeek-db`, and `zeek-dmz`, every DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file row with a UID has a corresponding `conn.json` UID; the tuples agree and the protocol timestamp remains within the connection interval. All 1,232 certificate-chain FUID references resolve to an `x509.json` ID. As a concrete example, UID `Cbu965jUqo2oszG1N` starts in `zeek-core/conn.json` at `1710763206.376332`, carries HTTP transactions at `1710763206.435332` and `1710763208.041405`, and links to matching file records including FUID `Fpyj89nhfkoQGT0c37`.
- eCAR identities and lifecycles are consistent. The 34,056 eCAR rows use unique event IDs, and I found no event whose visible actor process was created later or had already terminated. Process and session object IDs also had no visible terminate/logout-before-create/login inversion.
- Bash histories contain credible shell-native texture rather than polished transcripts: timestamps use Bash's `#<epoch>` form, commands include redirections and pipelines, and there are normal mistakes and session-order artifacts such as `lmsod` in `MAIL-EDGE-01` and non-monotonic merged history entries on `WS-LNGUYEN-01`.

## Detailed Analysis

### Parsing and sample coverage

I parsed all records in the supplied directory: 18,699 Security XML events, 11,768 Sysmon XML events, 34,056 eCAR JSON lines, and 34,694 Zeek JSON lines, plus the timestamped Bash histories. I then inspected representative records from every Windows event ID present, every eCAR object/action family, and each Zeek protocol family; the focused checks included substantially more than the requested 10-20 records.

All XML documents and JSON lines parsed successfully. Windows timestamps use seven fractional digits in `SystemTime`, Sysmon `UtcTime` uses millisecond precision, Zeek uses epoch floats, and eCAR uses integer epoch milliseconds. The files are chronologically sorted by their native event times; the one Security EventRecordID drop is the correct reset caused by visible Event 1102, not an ordering defect.

### Windows Security and Sysmon fidelity

The event-ID metadata and field ordering are unusually accurate. Security 4624 is Version 2 with Task 12544 and includes the extended linked-logon/elevation fields; 4688 is Version 2 with Task 13312 and correctly uses hexadecimal PIDs; 5156 is Version 1 with paired direction/layer values (`%%14592`/`%%14610` for inbound and `%%14593`/`%%14611` for outbound). Failure events use audit-failure keywords while successful events use audit-success keywords. Sysmon metadata is likewise internally consistent: Event 1 and 3 are Version 5, Event 5 and 10 are Version 3, Event 8/11/13 are Version 2, and Event 22 is Version 5.

The principal weakness is not schema shape but PE-derived values. The dataset supplies a coherent PE metadata tuple for some images—`winlogon.exe`, PowerShell, browsers, Office, and selected tools—but substitutes a five-field `-` tuple for 72.1% of process creations, including core Windows binaries that contain version resources. Separately, the exact `explorer.exe` 10.0.19041.1 hash is reused on hosts whose adjacent inbox executables establish 17763, 20348, and 22621 build families. Those patterns would make hash allowlists, software-inventory detections, and build-aware vulnerability rules behave unlike they would against a real fleet.

Hash behavior is similarly inconsistent with a per-host Sysmon configuration. Most Event 1 rows present all four configured algorithms, including the blank-metadata `cmd.exe` record 3292036 at `16:00:28.7306281Z`; however, `runas.exe`, `curl.exe`, `PSEXESVC.exe`, and several service executables return only `-`. A real hash failure is possible, but repeated failures on installed inbox files across hosts, surrounded by successful four-hash events, create a recognizable source-native fingerprint.

### Authentication, event correlation, and detection usefulness

The authentication model passed the important visible-order tests. No 4672 occurred before a later visible 4624 for the same logon ID without an earlier login, and no 4634 preceded its matching visible 4624. Service logons, network logons, interactive/unlock sessions, RDP Type 10 sessions, and NewCredentials Type 9 sessions use plausible package/process combinations. The Type 9 event on `WS-AJOHNSON-01` at record 131015, for example, keeps `aisha.johnson` as the local target and places `marcus.chen` in `TargetOutboundUserName`, which is the correct semantic distinction for `/netonly` behavior.

Detection pivots are preserved across sources. Security 4688 and Sysmon 1 agree on process identity and parentage, Sysmon 3 uses the same ProcessGuid/PID/image as the initiating process, and eCAR actor IDs consistently reference the corresponding visible process object when one exists. The dataset would support stable detections for remote service creation, explicit credentials, account creation/group addition, Security-log clearing, suspicious process access, remote thread creation, registry persistence, and DNS/network pivots.

### Zeek and protocol schemas

The sampled Zeek field names and types are credible for JSON output. Connection rows include normal combinations of `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `OTH`, and partial-close states; packet and byte counts are not constant; DNS uses transaction IDs, rcode names, answer arrays, and TTL arrays; HTTP carries transaction depth, referrers, MIME types, and file references; SSL links certificate chains; and SMB separates mappings from file actions. Protocol rows do not exhibit impossible visible ordering against their connection UID.

Ten HTTP response FUID references do not appear in the corresponding visible `files.json` files, but I did not treat that as synthetic evidence. Selective file logging or collection loss can produce that result, and the dataset does not establish a collection contract that requires every file-analysis row.

### Distribution and environmental consistency

Event timing generally has useful entropy: Windows process-start intervals vary widely, cross-source timestamp offsets range over hundreds of milliseconds, and Zeek includes failed, reset, partial, and lossy connections. The Linux PID process is the exception. All 11 Linux hosts exhibit a highly linear PID/time relationship and nearly the same two-to-two-and-a-half PID-per-second slope, even though the hosts span workstations, mail, database, proxy, web, logging, and file roles. That repeated cross-host rate is a much stronger synthetic indicator than any single large PID.

The registry actor anomalies were not decisive because service impersonation and custom ACLs can produce surprising principals. They nevertheless warrant replay validation because repeated `NETWORK SERVICE` writes to Winlogon and logging-control keys would be unusual in production and can distort registry-focused detections.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `environment_or_collection_plausibility` | Sysmon Event 1 | Repeated across servers and workstations | Inbox PE build versions and exact hashes are incompatible with the build family established by adjacent Windows components on the same host. |
| `schema_or_format` | Sysmon Event 1 | Dataset-wide: 716/993 process creates | Five PE metadata fields collapse to `-` for many signed Microsoft binaries even when hashes are successfully emitted. |
| `schema_or_format` | Sysmon Event 1 | Repeated on multiple hosts: 22/993 process creates | Hashes disappear for readable inbox executables despite four-algorithm hashing working on neighboring records. |
| `distribution_texture` | Linux eCAR process telemetry | All 11 Linux hosts | PID advancement has nearly identical slopes and very high linear fit across unrelated host roles. |
| `weak_signal` | Sysmon Event 13 | A few records on three hosts | Low-privilege service principals appear to set privileged Winlogon or logging-control values; possible, but operationally odd. |

## Realism Score by Category

- **Field format accuracy:** 7 — Event schemas and primitive formats are strong, but PE metadata and hash placeholders are source-native weaknesses.
- **Temporal patterns:** 7 — Visible lifecycle ordering and timestamp precision are credible, offset by the repeated Linux PID/time slope.
- **Cross-source correlation:** 9 — Process, session, UID, tuple, file, and certificate pivots are consistently usable without visible causal inversions.
- **Behavioral realism:** 8 — Authentication, remote administration, process trees, and cleanup actions use plausible event semantics and ordering.
- **Environmental consistency:** 5 — Mixed Windows component builds and identical cross-build hashes substantially weaken the host model.

## Recommendations

- If this were synthetic, derive every PE metadata tuple and hash from a host-specific OS/build inventory. An inbox image on a 17763, 20348, or 22621 host should carry a compatible file version and hash, including a plausible patch-level UBR where that binary would have been serviced.
- Apply Sysmon's hash-algorithm configuration consistently to every process-create event. Model `Hashes: -` only as a rare, explicit collection failure with a plausible reason; do not leave readable `runas.exe`, `curl.exe`, `PSEXESVC.exe`, or installed service binaries hashless while adjacent processes receive four hashes.
- Populate PE version resources for Microsoft inbox binaries instead of using a five-field placeholder tuple. At minimum, keep `FileVersion`, `Description`, `Product`, `Company`, and `OriginalFileName` internally consistent with image path and host build.
- Make Linux PID allocation depend on host-specific uptime and workload-derived fork rates. Vary the slope materially by host role, include quieter intervals and burstier churn, and avoid giving every independent endpoint the same near-linear 2.0-2.5 PID-per-second trajectory.
- Validate privileged registry writes against the effective token or modeled impersonation context. If `NETWORK SERVICE` is intended to modify Winlogon or event-channel configuration, emit evidence that makes the service/impersonation path credible; otherwise assign the operation to the actual authorized principal.
