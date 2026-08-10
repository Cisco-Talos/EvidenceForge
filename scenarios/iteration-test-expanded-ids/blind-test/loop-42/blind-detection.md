# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 82  
**Synthetic-Confidence Score:** 43

## Executive Summary

The dataset is highly convincing across Windows event schemas, process/session correlation, Zeek protocol relationships, and endpoint lifecycle ordering. Two concrete source-native defects prevent a real verdict: Security Event 1102 lacks its required subject fields, and 132 ICMP Zeek JSON records encode an unset `history` value as the literal ASCII placeholder `"-"`.

## Evidence For Synthetic

- `[schema_or_format]` `DC-01.meridianhcs.local/windows_event_security.xml` contains Event 1102 at `2024-03-18T17:42:15.8336571Z` with an empty `EventData` element. A native 1102 record should contain `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, and `SubjectLogonId`.
- `[schema_or_format]` Both Zeek sensors serialize ICMP `conn.json` records with `"history":"-"`: 78 records in `zeek-core/conn.json` and 54 in `zeek-dmz/conn.json`. The hyphen is an ASCII-log unset marker, not a valid Zeek connection-history code; JSON output should omit the unset optional field rather than store `"-"` as data.
- `[weak_signal]` Some eCAR property sets expose synonymous fields such as `src_pid` and `source_pid` simultaneously. The values agree, so this is not a contradiction, but the duplication looks more like a compatibility/enrichment layer than a single native sensor schema.

## Evidence For Real

- Windows event IDs use credible provider metadata, versions, tasks, keywords, and event-specific field sets. Examples include Security 4624 v2, 4688 v2, 5156 v1, Sysmon 1 v5, Sysmon 10 v3, and Sysmon 22 v5.
- All 900 sampled Sysmon Event 1 records use complete, correctly typed process-creation fields. Corresponding Security 4688 records agree on PID, image, and command line; only one of 901 Security process creations lacked a Sysmon companion.
- Executable hashes are stable where they should be. No host showed multiple hashes for the same image/version, and identical OS binaries with identical versions retained the same hashes across hosts. OS build metadata also varied coherently: `10.0.17763.1`, `10.0.19041.1`, `10.0.20348.1`, and `10.0.22621.1`.
- Visible Sysmon process GUIDs consistently map to one PID and image. No dependent event referenced a same-GUID process whose visible creation occurred later.
- Visible 4624/4634 pairs preserve username and logon type, and no same-ID session initiator appeared after a dependent event. Pre-window processes and sessions were not penalized.
- Zeek `dns`, `http`, `smtp`, and `ssl` records all resolve to a local `conn.json` UID with matching tuples. UIDs are sensor-local, unique, and differ appropriately between core and DMZ views.
- The DC Security log-clearing sequence is causally convincing: `cmd.exe /c wevtutil cl Security` at `17:42:13.2299517Z`, `wevtutil.exe` at `17:42:13.6308064Z`, Event 1102 at `17:42:15.8336571Z`, and an EventRecordID reset to `1`.
- SSH evidence has credible source-native timing. For `10.10.1.21:53725 → 10.10.2.30:22`, Zeek observes the connection at `12:03:05.317510Z`, eCAR records destination `sshd` creation and inbound flow at `12:03:06.971–07.312Z`, syslog records authentication at `12:03:09.706254Z`, and the eCAR session login follows at `12:03:10.110Z`.
- Record density and source-family composition vary substantially by role: the DC is authentication/network-heavy, workstations emphasize processes and modules, and Linux servers carry syslog and SSH evidence.

## Detailed Analysis

### Windows Event Schema and Event-ID Fidelity

The common Security events are structurally accurate. Event 4624 contains the expected 28 fields, including `TargetLogonId`, `LogonType`, authentication package, process information, source address/port, linked-logon fields, and elevation flags. Network logons use type 3 with realistic Kerberos or NTLM combinations; local interactive, service, unlock, and RDP activity use types 2, 5, 7, and 10 respectively.

Event 4688 v2 includes `NewProcessId`, `NewProcessName`, creator `ProcessId`, `CommandLine`, target fields, `ParentProcessName`, and `MandatoryLabel`. Event 4689 uses the expected subject, status, PID, and image fields. Rare records—including 4697, 4698, 4720, 4724, 4726, 4728, and 4738—also have credible event-specific structures.

The clear exception is Event 1102. Its provider metadata and placement are plausible, but its actor payload is absent. This would break detections and investigations that identify who cleared the Security log.

### Sysmon Fidelity

Sysmon field names and capitalization are accurate, including the distinct `ProcessGuid` spelling on Event 1 and `SourceProcessGUID`/`TargetProcessGUID` spelling on Event 10. Event-specific versions, tasks, levels, and keyword masks are internally consistent.

Process metadata is unusually strong. For example, Windows binaries carry host-build-appropriate versions, descriptions, products, companies, and original filenames. Hashes are correctly formatted as `SHA1`, `MD5`, `SHA256`, and `IMPHASH`, remain stable across repeated executions, and remain stable across hosts sharing the same binary version.

Sysmon timestamps use seven-digit `SystemTime` precision and millisecond `UtcTime` precision, with the latter matching the truncated provider timestamp. Process GUID ownership and visible lifecycle ordering are coherent.

### Windows Cross-Source Correlation

Across the nine Windows hosts, Security 4688 and Sysmon Event 1 pairs agree on process ID, path, and command line. Their timing is generally within roughly 20 milliseconds, with one larger but still plausible 133-millisecond offset. This correlation is operationally useful and does not create a contradiction.

Visible logon/logoff pairs preserve identity and type. Type 7 unlock records correctly reuse existing interactive LogonIDs after lock events; they were not misclassified as new session initiators. Sessions or processes whose initiators predate the window were treated as bounded-window state.

The log-clearing sequence is especially credible. EventRecordIDs increase before the clear, reset at the 1102 record, and resume increasing afterward. The missing 1102 subject payload is therefore a localized rendering/schema problem rather than a broader causal failure.

### Zeek Schema and Protocol Correlation

The standard JSON types are mostly correct: timestamps and durations are numeric, ports are integers, flags are booleans, answers and certificate chains are arrays, and optional fields are normally omitted. DNS response codes, query types, RTTs, answers, and TTLs are coherent. TLS versions, cipher names, certificate chains, fingerprints, validity periods, and SAN fields are plausible.

Every examined DNS, HTTP, SMTP, and SSL UID has a corresponding connection record with the same tuple, and no protocol record visibly precedes its connection beyond the allowed tolerance. Certificate FUIDs and fingerprints remain internally stable.

The ICMP history representation is the repeated defect. `history:"-"` appears exclusively on successful ICMP records, making it look like the generator copied Zeek’s ASCII unset marker into JSON. Other unset JSON fields are omitted, so the dataset’s own encoding convention reinforces the inconsistency.

### eCAR, Syslog, and Lifecycle Behavior

eCAR record IDs are unique, object IDs are reused appropriately for object lifecycle, and no process object has a visible termination followed by its creation. Actor references with visible creators never point forward in time; missing creators occur at window boundaries and were not treated as defects.

Linux SSH syslog follows credible phases: connection, authentication, PAM session opening, and systemd-logind session creation. The related eCAR flow and session records preserve the source tuple and order correctly. Source-native timestamps differ rather than being mechanically identical.

The duplicate eCAR property aliases are syntactically usable and internally consistent. They are a schema-maintenance concern, not enough by themselves to classify the dataset as synthetic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score effect |
|---|---|---:|---|
| `schema_or_format` | Windows Security Event 1102 | One event | High per-record impact because required actor fields are absent from a critical audit record |
| `schema_or_format` | Zeek `conn.json` ICMP | 132 records across both sensors | Moderate impact because an ASCII unset marker is repeatedly serialized as JSON data |
| `weak_signal` | eCAR properties | Repeated across several object families | Low impact; redundant aliases agree and remain parseable |

## Realism Score by Category

- **Field format accuracy:** 8 — Most Windows, Sysmon, Zeek, and eCAR fields are source-appropriate; Event 1102 and ICMP `history` are notable exceptions.
- **Temporal patterns:** 9 — Provider timing, visible lifecycle order, SSH phases, and the audit-log reset sequence are credible.
- **Cross-source correlation:** 9 — Process, session, UID, tuple, and file/certificate references correlate without visible contradictions.
- **Behavioral realism:** 8 — Host activity, authentication modes, process trees, service events, and protocol behavior are operationally plausible.
- **Environmental consistency:** 9 — Host roles, OS build metadata, identities, domains, binary versions, and network placement remain coherent.

## Recommendations

- If this were synthetic, populate the native Event 1102 subject fields even when the clearing process runs as `SYSTEM`: `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, and `SubjectLogonId`.
- Serialize Zeek JSON through source-native unset-field rules. For ICMP connections with no history, omit `history`; do not emit the ASCII placeholder `"-"` as a JSON string.
- Normalize eCAR process-reference properties to one documented naming convention, or explicitly version the compatibility aliases so detection pipelines do not need to guess which field is canonical.
- Preserve the current bounded-window lifecycle handling, OS-aware binary metadata, hash stability, and source-native timestamp relationships; these are among the dataset’s strongest realism properties.
