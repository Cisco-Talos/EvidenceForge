# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 69

## Executive Summary

The collection is highly usable for detections: the XML and JSON parse cleanly, Windows event metadata is mostly source-accurate, and process, session, and Zeek UID correlations are unusually strong without visible causal inversions. I nevertheless assess it as synthetic because repeated source-native defects occur across otherwise independent records, especially empty Windows Security fields where native audit XML normally carries explicit sentinel values, remote Type 3 logons whose workstation attribution collapses to the receiving host, and smaller repeated Zeek/eCAR semantic artifacts.

## Evidence For Synthetic

- [schema_or_format] Windows Security Event 4768 uses empty XML elements for `CertIssuerName`, `CertSerialNumber`, and `CertThumbprint` in 805 of 826 records. For example, the 2024-03-18 12:04:40.5965100Z record in `DC-02.meridianhcs.local/windows_event_security.xml` has password pre-auth (`PreAuthType=2`) but serializes all three unavailable certificate fields as empty strings rather than the source-native `-` placeholders normally exposed by this event schema.
- [schema_or_format] The same empty-value behavior affects a coherent block of 157 Event 4624 Type 3 logons: `SubjectUserSid`, `SubjectUserName`, `SubjectLogonId`, `LogonGuid`, `LogonProcessName`, and `LmPackageName` are all empty. At 2024-03-18 12:06:14.2778580Z on DC-01, for example, the event has a remote address of `::ffff:10.10.2.27`, target `aisha.johnson`, and `AuthenticationPackageName=Negotiate`, yet the subject and logon-process fields are zero-length XML values. This repeated all-or-nothing field family looks like a renderer/template path, not organic Windows audit output.
- [contract_gap] Those same remote Type 3 records repeatedly identify the receiving computer as `WorkstationName` instead of the remote source. DC-01 has 50 such events labeled `WorkstationName=DC-01`, DC-02 has 29 labeled `DC-02`, and FILE-SRV-01 has 78 labeled `FILE-SRV-01`, even though their `IpAddress` values are remote. At 2024-03-18 12:04:06.0673355Z on FILE-SRV-01, the source is `::ffff:10.10.2.11` but `WorkstationName=FILE-SRV-01`; at 12:04:52.3806918Z the source changes to `::ffff:10.10.1.31` while the workstation remains the receiver. This degrades source attribution for logon detections and is inconsistent with the otherwise modeled source-host identities.
- [schema_or_format] Zeek DNS rows set `rejected=false` even for explicit `rcode=5`, `rcode_name=REFUSED` responses. This occurs five times across `zeek-core/dns.json` and `zeek-dmz/dns.json`; the first core example is 2024-03-18 12:00:59.306480Z for `node-fb1ce1g9.bit`. NXDOMAIN and SERVFAIL need not imply rejection, but REFUSED paired with a false rejection flag is a source-semantic mismatch.
- [distribution_texture] eCAR contains 17 groups of records that are byte-for-byte identical after removing only the unique top-level `id`, spread across eight hosts. Examples include two DC-01 `PROCESS/OPEN` rows at `timestamp_ms=1710784721251` with the same actor, target LSASS object, PID/TID, access mask, and call trace (lines 5569-5570), plus repeated groups on DC-02, FILE-SRV-01, MAIL-FIN-01, and several workstations. Real duplicate ingestion usually preserves the same source identity; assigning new IDs to otherwise identical millisecond-resolution payloads across hosts suggests duplicated materialization.
- [environment_or_collection_plausibility] All 927 Sysmon Event 3 records have `Initiated=true`, despite extensive inbound traffic visible on Windows servers in Security Event 5156 and eCAR. A deliberately outbound-only Sysmon rule could explain this, so it is not decisive, but the direction distribution is unusually absolute for a mixed server/workstation estate.
- [weak_signal] Every one of the 965 matched Sysmon Event 1/Security Event 4688 process pairs places Sysmon first, with the Security event 35-645 ms later; eCAR process creation is also always after Sysmon in the matched samples. A stable endpoint collection pipeline can impose ordering, so this is only a weak signal, but the invariant ordering across all hosts adds to the generated texture.

## Evidence For Real

- Windows provider metadata is largely convincing. Event IDs use plausible `Version`, `Task`, `Level`, `Opcode`, `Keywords`, channel, provider GUID, and per-host record IDs. The Security log clear at 2024-03-18 17:41:55.9392730Z on DC-01 correctly uses the Eventlog provider, Event 1102 `UserData/LogFileCleared` shape, and resets `EventRecordID` to 1 before subsequent records continue from 2.
- Windows value formats are detection-ready: domain and well-known SIDs are syntactically valid, process IDs are hexadecimal in Security events and decimal in Sysmon, logon IDs have expected hexadecimal forms, mapped IPv4 addresses use `::ffff:`, and Sysmon GUIDs, hashes, integrity levels, signature fields, DNS statuses, and service-port names are well formed.
- Event semantics show meaningful variety rather than a single template. Event 4624 includes Types 2, 3, 5, 7, 9, and 10; Kerberos events vary ticket options, AES/RC4 encryption types, and pre-auth types; Event 4625 status/substatus/failure-reason combinations agree for bad passwords and disabled accounts.
- Process correlation is strong and technically correct. Across ten Windows hosts, all 965 Sysmon Event 1 records match a Security Event 4688 by host, PID, image, command line, and nearby timestamp; no image or command-line mismatches were found. Sysmon Event 5 and Security Event 4689 terminations never precede a visible matching create.
- Session lifecycle ordering is sound within the bounded window. Event 4634 never precedes a visible Event 4624 for the same host and logon ID. The small number of unmatched logoffs and process terminations are consistent with state that began before the six-hour window rather than evidence of impossible causality.
- Zeek JSON is structurally convincing. All reviewed lines parse; all DNS, HTTP, SSL, SMTP, SMB, and file UIDs/FUID references examined resolve to a corresponding `conn.json` row in the same sensor directory; no companion protocol timestamp precedes its matching connection open. Field names, scalar/array types, TLS versions/ciphers, certificate chains, file hashes, and connection tuple formats are generally Zeek-like.
- Linux RFC 5424 syslog is syntactically strong: PRI values align with authpriv/cron/daemon/kernel facilities, timestamps carry UTC precision, and SSH/PAM, systemd-logind, sudo, cron, Samba audit, unattended-upgrade, snapd, rsyslog, and UFW messages have plausible native vocabulary and process attribution.
- Proxy, web, Snort, and ASA text records use recognizable source formats. HTTP status/byte placeholders, CONNECT control-versus-tunnel accounting, Snort fast-alert syntax, and ASA build/teardown/NAT connection IDs are suitable for ordinary SIEM parsing and correlation.

## Detailed Analysis

### Data shape and parseability

I reviewed the available Windows Security, Sysmon, eCAR, Zeek, RFC 5424 syslog, proxy, web, Snort, and ASA sources over the apparent 2024-03-18 12:00-18:00 UTC window. All XML documents parsed as namespaced Windows event collections, and every sampled/aggregated JSON line parsed successfully. The Windows Security population contained 18,566 events across ten hosts, dominated by 11,672 Event 5156 rows but including authentication, process, object access, service/task, account-management, Kerberos, share, lock/unlock, and audit-clear events. Sysmon contained 5,853 events across IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22.

### Windows schema and event semantics

The `System` sections are mostly accurate enough for native-event detections. Event 4624 is consistently Version 2/Task 12544, Event 4688 is Version 2/Task 13312, Event 4768 is Task 14339, Event 4769 is Task 14337, and Sysmon events use the Operational channel with the normal provider GUID. Field sets are stable per version and use expected native names, including `NewProcessId` versus Sysmon `ProcessId`, `TargetLogonId`, `MandatoryLabel`, `ProcessGuid`, and `ParentProcessGuid`.

The major exception is absent-value serialization. Empty certificate fields appear in 805 ordinary Event 4768 records, while the 21 certificate-preauthentication records populate them. A native Windows export normally preserves the event's explicit unavailable marker; zero-length `<Data>` values change downstream semantics because SIEM mappings commonly distinguish null, empty, and `-`. The exact same style appears as a six-field block in 157 Type 3 Event 4624 records, suggesting a shared construction path. Four Event 4688 records also have empty subject identifiers, 15 have empty `ParentProcessName`, and four Event 4624 records have empty `TargetUserSid`, showing that the artifact is not confined to one certificate field.

The Type 3 source-attribution issue is more operationally important than formatting alone. The 157 affected records are concentrated on DC-01, DC-02, and FILE-SRV-01 and consistently use the destination computer as `WorkstationName` while carrying a different remote `IpAddress`. A rule grouping failed/successful network logons by workstation would misattribute those accesses to the target. Other Type 3 events do carry plausible source workstation names or `-`, so this appears to be one event-family path diverging from the rest.

Failure semantics are otherwise good. Event 4625 uses `0xc000006d/0xc000006a/%%2313` for bad passwords and `0xc000006d/0xc0000072/%%2307` for disabled accounts. Event 4771 uses Kerberos status `0x18` with pre-auth type 2, and Event 4776 failures use `0xc000006a`. Kerberos service and krbtgt SIDs use internally consistent domain SIDs and expected object RIDs.

### Process and session correlation

I matched all 965 Sysmon Event 1 rows to Security Event 4688 by host, PID, image, command line, and timestamp. Images and command lines agreed exactly, while the two sources retained their native PID representations. This would make process detections and enrichment work well. Security had 972 creates versus 800 terminations, and Sysmon had 965 creates versus 804 terminations; visible terminations did not precede visible creates. Unmatched terminations were few per host and are plausible pre-window processes.

The matched source timestamps are consistently ordered: Sysmon leads Security by 35-645 ms, and matched eCAR process creates always follow Sysmon. This may represent a stable collection pipeline and is not scored as a contradiction, but the lack of even one reversal across 965 processes is unusually controlled. More concerning is eCAR duplication: 17 semantic duplicate groups retain separate unique event IDs, including identical process-open payloads at identical millisecond timestamps. The low absolute rate prevents this from being decisive, but its recurrence on eight hosts makes it more than a one-off ingestion accident.

Authentication lifecycle checks were similarly sound. No visible Event 4634 preceded a visible 4624 for the same host/logon ID. The dataset contains plausible mixes of service, network, interactive, unlock, new-credentials, and remote-interactive sessions. The bounded window explains visible logoffs without a visible start and sessions without an in-window end.

### Zeek and other source schemas

Zeek tuple and UID integrity is strong without visible temporal inversion. The core sensor had 11,340 connection records, the DMZ sensor 8,534, and the database sensor 431. Every checked UID-bearing DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file record resolved to its local sensor's `conn.json`, and protocol timestamps followed connection timestamps. TLS rows use realistic `TLSv12`/`TLSv13` labels, cipher names, SNI, resume/established booleans, histories, and certificate FUID chains; X.509 records use plausible versions, validity epochs, key metadata, SAN arrays, and CA/host/client flags.

The concrete Zeek defect is the five REFUSED DNS replies with `rejected=false`. For the 12:00:59 query, both core and DMZ observations agree on transaction ID 28602 and rcode REFUSED but retain the false rejection flag. The two-sensor agreement supports correlation but also reproduces the same semantic defect. NXDOMAIN and SERVFAIL rows remaining false are not by themselves problematic; the REFUSED cases are.

Text formats are generally SIEM-ready. RFC 5424 syslog contains correct framing and plausible native messages; proxy and web records follow combined-style formats; Snort alert lines and ASA build/teardown messages are parseable and carry coherent tuples. I found no malformed timestamp, invalid IP, broken GUID, or impossible visible connection/auth/process ordering in these samples.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `schema_or_format` | Windows Security 4768/4624 | Dataset-wide family defect: 805 certificate-field triplets and 157 six-field logon blocks | High: repeated zero-length native fields look like a renderer path and alter SIEM null/sentinel handling. |
| `contract_gap` | Windows Security 4624 | 157 remote Type 3 events on three servers | High: receiver hostname is emitted as workstation despite a different remote source IP, degrading source attribution. |
| `schema_or_format` | Zeek DNS | Five REFUSED responses across core/DMZ | Medium: `rcode=REFUSED` conflicts with `rejected=false` and is duplicated across sensor views. |
| `distribution_texture` | eCAR | 17 exact semantic duplicate groups across eight hosts | Medium: new event IDs wrap otherwise identical same-millisecond payloads on multiple systems. |
| `environment_or_collection_plausibility` | Sysmon Event 3 | All 927 records | Low: every connection is `Initiated=true`; an outbound-only filter is possible but unusually absolute. |
| `weak_signal` | Security/Sysmon/eCAR process telemetry | All 965 matched process creates | Low: fixed cross-source ordering is controlled, though a consistent collection pipeline could explain it. |

## Realism Score by Category

- **Field format accuracy:** 6/10 — Most native schemas and value types are correct, but repeated empty Windows fields and the Zeek REFUSED flag are conspicuous source-format defects.
- **Temporal patterns:** 8/10 — Timestamps have appropriate precision and no visible causal inversions; only invariant process-source ordering and duplicate same-millisecond eCAR payloads reduce realism.
- **Cross-source correlation:** 9/10 — Process, session, tuple, UID, and FUID pivots work extremely well, with no scored penalty for completeness itself.
- **Behavioral realism:** 8/10 — Authentication, process, service, DNS, TLS, Linux, and network behavior is varied and technically plausible in the sampled records.
- **Environmental consistency:** 7/10 — Host roles and source mixes mostly agree, but target-as-workstation attribution and the all-outbound Sysmon direction profile weaken collection plausibility.

## Recommendations

If this were synthetic, I would first serialize unavailable Windows EventData exactly as the provider does for each event/version, using `-` or the documented sentinel rather than zero-length XML, and add schema tests covering the ordinary versus certificate-authenticated 4768 paths. I would then correct the shared Type 3 logon construction path so `WorkstationName`, remote address, logon process, subject placeholders, and authentication package are source-native and derived from the actual initiator rather than the receiver.

For Zeek, make `rejected` consistent with REFUSED response semantics and verify that the corrected response remains consistent across duplicated sensor visibility. For eCAR, deduplicate canonical process-open observations before assigning record IDs, or preserve a real source identity that explains retransmission/duplicate ingestion. Finally, review the Sysmon Event 3 selection policy: if inbound connections are intentionally excluded, represent that as an explicit collection profile; otherwise emit realistic `Initiated=false` server-side observations for eligible visible inbound traffic.
