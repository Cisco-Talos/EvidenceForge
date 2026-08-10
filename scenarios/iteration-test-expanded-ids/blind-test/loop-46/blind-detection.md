# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 24

## Executive Summary

The dataset is strongly production-like from a detection-engineering perspective: the Windows and Sysmon schemas are source-native, identifiers and lifecycle ordering survive focused checks, and Zeek protocol records correlate to valid connection tuples without contradictions. The only scored synthetic signal is a low-impact concentration of repeated Windows OpenSSH launch forms; it is operationally possible, but the small command vocabulary is more regular than I would normally expect across a six-hour enterprise slice.

## Evidence For Synthetic

- `[distribution_texture]` Windows OpenSSH launches are unusually prominent and repetitive: 74 of 834 sampled Sysmon Event ID 1 records use `C:\Windows\System32\OpenSSH\ssh.exe`, but there are only 14 distinct host/user/command patterns. Examples include 14 instances of `ssh.exe marcus.chen@WEB-EXT-01.meridianhcs.local` on `WS-MCHEN-01`, nine of `ssh.exe aisha.johnson@WEB-EXT-01.meridianhcs.local`, and eight of `ssh.exe aisha.johnson@PROXY-01.meridianhcs.local` on `WS-AJOHNSON-01`. This is a weak dataset-level repetition signal, not a contradiction; legitimate administrators can repeatedly use fixed destinations.
- `[weak_signal]` Sysmon DNS Event ID 22 is concentrated on the domain controller name: 304 of 774 records contain `QueryName=DC-01.meridianhcs.local`, `QueryStatus=0`, and `QueryResults=10.10.2.10;`. The concentration is noticeable, but repeated DC discovery is expected in an Active Directory environment and does not independently imply synthesis.

## Evidence For Real

- Windows Security event schemas are internally precise. For example, all 4624 records use the Version 2 field layout through `ElevatedToken`; 4688 uses the Version 2 layout including `TargetLogonId`, `ParentProcessName`, and `MandatoryLabel`; 5156 uses the expected numeric protocol, localized direction/layer tokens, device-form application paths, and decimal process identifiers.
- On `WS-MCHEN-01`, Security 4688 at `2024-03-18T12:01:24.0208605Z` records `NewProcessId=0x1c60`, Outlook, parent PID `0x1c4c`, logon ID `0x6c07e4a`, and the quoted Outlook command. Sysmon Event ID 1 at `2024-03-18T12:01:24.0303607Z` independently records PID `7264`, the same image, command line, logon ID, parent PID `7244`, and `C:\Windows\explorer.exe` parent, with a correctly formed ProcessGuid.
- Windows lifecycle ordering passed targeted contradiction checks. Across all nine Windows Security files, no 4689 termination was followed by a later 4688 creation for the same PID/image identity, and no 4634 was followed by a later 4624 initiator for the same logon ID/SID/type. Across all nine Sysmon files, no Event ID 5 termination or dependent process event preceded a later Event ID 1 creation for the same ProcessGuid.
- The `DC-01` Security log models Event ID 1102 realistically at `2024-03-18T17:42:15.6063384Z`: provider `Microsoft-Windows-Eventlog`, Level 4, Task 104, Keywords `0x4020000000000000`, correctly namespaced `LogFileCleared` UserData, and `EventRecordID=1`. Later records continue from the reset sequence rather than the pre-clear value near 28 million.
- Zeek relationships are coherent. Every reviewed `dns`, `http`, `ssl`, and `smtp` UID has a corresponding `conn` record in the same sensor dataset; all origin/response tuples agree, and protocol timestamps remain within the visible connection interval. Every `files` `conn_uids` reference also resolves without a tuple-time contradiction.
- The first core DNS transaction is a representative source-native example: UID `C4nqcoZQlQsuoDgb6L` at `1710763204.886553` uses UDP `10.10.1.21:55355` to `10.10.2.10:53`; its `conn` row has service `dns`, state `SF`, history `Dd`, and one request/response packet, while its DNS row has matching tuple/UID, transaction ID `63944`, A query `DC-01.meridianhcs.local`, `NOERROR`, and answer `10.10.2.10`.
- eCAR NDJSON is structurally stable across 24,370 parsed records. Event IDs and object IDs are valid UUIDs, no event ID is duplicated, and shared object IDs express forward lifecycle transitions without a visible terminate/logout followed by a later create/login for the same identity.
- Collection is not artificially all-or-nothing. For example, `FILE-SRV-01` has 69 Security 4688 records but 67 Sysmon Event ID 1 records; the unmatched Security records at `2024-03-18T17:17:47.627052Z` and another point look like ordinary source-local collection differences rather than contradictory telemetry.

## Detailed Analysis

### Windows Security schema and metadata

I parsed the Security XML rather than treating it as text. The DC alone contains 7,514 events spanning 5156, 4689, 4624, 4776, 4625, 4634, 4688, 4672, 4768, 4769, 4771, 4697, 4720, 4724, 4728, 4738, 4698, 4648, 1102, and 4726. Provider, Version, Level, Task, Opcode, Keywords, and EventData field sets are stable for each event/version combination. Examples include 4625 failures with `Status=0xc000006d`, `SubStatus=0xc000006a`, `FailureReason=%%2313`, and failure-audit Keywords `0x8010000000000000`; successful events use `0x8020000000000000`.

Source-native value forms also hold up. Process identifiers in 4688/4689 are hexadecimal while 5156 process IDs are decimal. Outbound 5156 events use `Direction=%%14593` and `LayerName=%%14611`, while destination-side inbound observations use `%%14592` and `%%14610`. IPv4-mapped addresses such as `::ffff:10.10.1.99` occur in network-logon records, while local/service logons use `IpAddress=-` and `IpPort=-`.

Kerberos records show plausible field variety rather than a single template: 4769 events include AES128 `0x11`, AES256 `0x12`, and RC4 `0x17`, several ticket-option masks, IPv4-mapped client addresses, and service names tied to hosts. Account-management events are unusually well formed: the `svc_mhsync` sequence uses one SID ending in `-8196` across 4720, 4724, 4728, 4738, and 4726, with Domain Admins SID ending in `-512` and source-native UAC localization tokens.

### Sysmon and process correlation

Sysmon event layouts match their versions: Event ID 1 Version 5 includes file metadata, hashes, LogonGuid/LogonId, terminal session, integrity, and parent identity; Event ID 3 Version 5 uses boolean IPv6/Initiated fields and decimal ports; Event IDs 5, 7, 8, 10, 11, 13, and 22 use the expected source-native field names. GUIDs use braced hexadecimal format, hash strings have correctly sized SHA1/MD5/SHA256/IMPHASH components, and registry/DNS status values use credible native representations such as `DWORD (0x00000001)` and DNS status `9003`.

All XML files are timestamp-sorted. EventRecordID values are unique and monotonic within each channel, allowing gaps that are normal when only selected events are exported. The sole intentional Security-channel reset follows DC Event ID 1102. ProcessGuid checks found no visible dependent event whose exact same-identity creation occurs later, satisfying the bounded-window rule rather than penalizing processes that legitimately began before capture.

### Zeek, eCAR, and ingest utility

All Zeek JSON lines parsed. Core counts include 6,106 connections, 2,194 DNS records, 955 HTTP records, 113 SSL records, 66 SMTP records, and 338 file records; DMZ counts include 5,279 connections, 751 DNS, 1,142 HTTP, 1,655 SSL, and 561 file records. UIDs, four-tuples, service labels, and timestamps are usable for direct SIEM joins. STARTTLS is represented sensibly: core SSL records can attach to connections whose service is `smtp`, while ordinary TLS attaches to `ssl`.

All 24,370 eCAR lines parsed as JSON objects with millisecond epoch timestamps, unique record UUIDs, UUID object identities, hostname, object/action vocabulary, and typed object-specific properties. The vocabulary includes process create/terminate/open, flow connect, user-session login/logout, file create/read/write, module load, registry modify, remote-thread creation, and service creation. This would support straightforward rule logic without schema repair.

The dataset is especially convincing where the sources are not perfectly coextensive: a few Security 4688 events lack nearby Sysmon Event ID 1 companions, while every actual matched pair agrees on PID, image, command, parent, and logon identity. I treated complete matches elsewhere as neutral and these sparse gaps only as evidence that ingestion behavior is plausible, not as a requirement.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Windows Security / Sysmon process telemetry | Repeated across four Windows hosts; strongest on two users | The 74 `ssh.exe` launches collapse to 14 exact host/user/command patterns. This modestly raises synthetic confidence because of the narrow repeated command vocabulary, but no field or lifecycle contradiction accompanies it. |
| `weak_signal` | Sysmon DNS Event ID 22 | Dataset-wide but AD-specific | The exact successful DC lookup accounts for 304/774 DNS events. Its environment explains much of the concentration, so it has little independent weight. |

No `hard_contradiction`, `contract_gap`, or material `schema_or_format` indicator was found.

## Realism Score by Category

- **Field format accuracy:** 10 — Windows, Sysmon, Zeek, syslog, and eCAR records use credible native field names, types, tokens, and identifier formats.
- **Temporal patterns:** 9 — Visible lifecycle ordering and channel record sequencing are coherent; the repeated SSH launch family is the only notable texture concern.
- **Cross-source correlation:** 10 — Tested Windows/Sysmon process pairs and all Zeek UID/tuple relationships agree without impossible visible ordering.
- **Behavioral realism:** 8 — Activity is varied and role-compatible overall, though 74 Windows OpenSSH launches use a comparatively small command pool.
- **Environmental consistency:** 9 — OS-build-specific binary versions, Windows/Linux path forms, AD identities, server roles, and the Security-log clear/reset behavior remain consistent.

## Recommendations

- If this were synthetic, broaden the Windows remote-administration command distribution. Preserve the legitimate repeated destinations, but vary options, aliases/FQDN use, jump-host behavior, session duration, and the ratio of persistent sessions to repeated fresh `ssh.exe` launches so 74 launches do not collapse to 14 exact host/user/command forms.
- If this were synthetic, review the source of the 304 identical successful `DC-01.meridianhcs.local` Event ID 22 results. Retain frequent AD discovery, but ensure the observed query mix reflects resolver caching and the wider SRV/PTR/host lookup vocabulary already present rather than emitting a fresh identical A-query for every dependent operation.
