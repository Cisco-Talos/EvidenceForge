# Detection Engineer — Authenticity Assessment

## Verdict

- **Assessment:** Synthetic
- **Verdict Confidence:** 88%
- **Synthetic-Confidence Score:** 78/100

## Executive Summary

This dataset is a strong synthetic construction with unusually good schema discipline and
cross-source state management. Most Windows Security, Sysmon, eCAR, and Zeek records are
individually credible, and the major correlation keys remain coherent under scrutiny. The verdict
does not rest on sanitization, file times, absent optional Sysmon event types, thin source coverage,
or the mere completeness of correlations.

The highest-confidence synthetic indicator is a source-native content contradiction. At
2024-03-18 12:17:58 UTC, an HTTP proxy transaction for
`http://receiver.citrix.com/windows/CitrixWorkspaceApp.exe` returns `403 Forbidden` with a
1,474-byte body, yet both Zeek views classify that body as `application/x-msdownload`, hash it as
SHA-1 `e1d509be5fd0b0af1e10a840a594da5b8ff4b013`, and parse it as a complete AMD64 PE containing
five named sections, an import table, resources, relocations, and a certificate table. That is not
merely unlikely application behavior; the HTTP outcome, body size, MIME attribution, and parsed PE
structure conflict as one rendered artifact.

A second strong indicator appears in the credential-access sequence on `WS-AJOHNSON-01`. The
process `ms-index-service.exe` runs the unmistakable Mimikatz-style command
`"privilege::debug" "sekurlsa::logonpasswords" exit`, opens LSASS with `0x1FFFFF`, and then receives
a Sysmon Event ID 8 remote-thread companion into LSASS. The event resolves the remote thread's
entry point as `ntdll.dll!NtCreateThreadEx`. `NtCreateThreadEx` is the API used to create a thread,
not a credible payload thread procedure. Moreover, ordinary `sekurlsa::logonpasswords` memory
reading does not require a remote thread in LSASS. The sequence looks like two detection concepts—
credential dumping and process injection—were composed mechanically.

The remaining data is substantially more realistic. Windows schemas, WFP direction/layer values,
process identities, logon IDs, Zeek UIDs, TLS cipher/version pairings, file/certificate links, and
multi-sensor clock behavior are all convincing. Those strengths keep the synthetic-confidence score
below the very-high range despite the two decisive defects.

## Evidence For Synthetic with category labels

### [Cross-source content semantics] A forbidden proxy body is rendered as a complete signed-style PE

- In `zeek-core/http.json`, UID `COlIOJs83bE0vOhuj7` is a `GET` for
  `http://receiver.citrix.com/windows/CitrixWorkspaceApp.exe`. The response is `403 Forbidden`, with
  `response_body_len: 1474`, while `resp_mime_types` is `application/x-msdownload` and the response
  FUID is `FdrZuTbRdsEwITdHdU`.
- `zeek-core/files.json` records that FUID as a fully observed file: `seen_bytes: 1474`,
  `total_bytes: 1474`, `missing_bytes: 0`, `timedout: false`, SHA-1
  `e1d509be5fd0b0af1e10a840a594da5b8ff4b013`.
- `zeek-core/pe.json` then parses the same FUID as `AMD64`, `WINDOWS_GUI`, 64-bit, with ASLR, DEP,
  SEH, an import table, a certificate table, and five sections: `.text`, `.idata`, `.data`, `.rsrc`,
  and `.reloc`.
- The independent DMZ observation repeats the same semantic result under different local IDs:
  HTTP UID `CWXb63EgGgzteddOCg`, FUID `F3BPg8m9rzrtUQwDRp`, the same 403 status, 1,474-byte size,
  SHA-1, and PE attributes.
- A small HTML or policy body is credible for a 403. A complete five-section, certificate-bearing
  64-bit Citrix installer in a 1,474-byte forbidden response is not. The duplicate observation shows
  that this is canonical event content propagated consistently, not a one-sensor parse accident.

### [Companion-event semantics] Credential reading is mechanically expanded into LSASS injection

- `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml`, EventRecordID `31156`, creates PID
  `6092`, image `C:\Windows\System32\ms-index-service.exe`, command line
  `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`, integrity `High`, under
  `explorer.exe` in logon ID `0x26db80d`.
- EventRecordID `31161` records the process opening LSASS PID `4292` with
  `GrantedAccess: 0x1FFFFF`. That is a coherent credential-access signal.
- EventRecordID `31162`, only about 67 ms later, adds a remote thread into the same LSASS process.
  It reports `StartModule: C:\Windows\System32\ntdll.dll` and
  `StartFunction: NtCreateThreadEx`.
- The eCAR records repeat the same construction: PROCESS `OPEN` at timestamp `1710776724916` and
  THREAD `REMOTE_CREATE` at `1710776724932`, sharing source process UUID
  `a0b28408-ea99-4cc8-8bac-25db17b4a539` and LSASS target UUID
  `a786f21e-ee7c-46ed-8bcc-877aa7f92f81`.
- `NtCreateThreadEx` is a creation primitive, not a plausible remote thread start routine. Standard
  `sekurlsa::logonpasswords` behavior is memory access, not a requirement to launch a remote thread
  inside LSASS. This is concrete over-generation of a detection companion, not a complaint that the
  attack is too linear or too well correlated.

### [Call-stack semantics] The malicious LSASS-open stack is poorly coupled to the visible process

- Sysmon EventRecordID `31161` assigns the full-access LSASS open a call trace ending in
  `C:\Windows\SYSTEM32\wbemcomn.dll+15398`.
- The process is a standalone renamed credential-dumping executable launched by `explorer.exe`; the
  adjacent eCAR MODULE records identify `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `msvcrt.dll`,
  `ucrtbase.dll`, `advapi32.dll`, `sechost.dll`, and `rpcrt4.dll` for PID `6092`, but do not establish
  a WMI execution path. Module telemetry may be filtered, so omission alone is not dispositive.
  Nevertheless, pairing a WMI common-library frame with this direct LSASS access, and then resolving
  the injected thread to the creation API itself, is a coherent family of source-native semantic
  weaknesses rather than an isolated cosmetic oddity.

### [Timing distribution] Cross-source process timestamps follow a rigid one-sided hierarchy

- Across 944 process creations simultaneously visible as Security 4688, Sysmon 1, and eCAR PROCESS
  CREATE, every eCAR record occurs after the corresponding Sysmon event; none occur before it. The
  eCAR-minus-Sysmon delay spans approximately 2–887 ms.
- For the matched Security/Sysmon pairs, Sysmon is always earlier than Security by approximately
  35–648 ms. No matched pair reverses that ordering.
- A consistent source-latency direction is plausible, so this is not an impossibility. The concern is
  the perfect one-sidedness across hundreds of heterogeneous processes and ten Windows hosts,
  combined with tightly bounded sub-second offsets. It resembles an explicit source-ordering rule
  more than independently buffered endpoint channels. This is a supporting, lower-weight indicator.

## Evidence For Real

### Windows schema and value fidelity

- Security XML uses the correct providers and channels. Ordinary audit records use
  `Microsoft-Windows-Security-Auditing`; the Security-log clear record, Event ID 1102 on `DC-01`,
  correctly switches to `Microsoft-Windows-Eventlog`, uses `UserData/LogFileCleared`, and resets
  `EventRecordID` to `1`.
- Sysmon event versions and field shapes are credible: Event ID 1 uses version 5 and includes
  ProcessGuid, LogonGuid, hashes, parent identity, and integrity; Event ID 3 uses version 5 and the
  expected initiated/IP/port fields; Event IDs 7, 8, 10, 11, 13, and 22 use appropriate field sets.
- Security 5156 records preserve WFP semantics. Inbound records use Direction `%%14592`, LayerName
  `%%14610`, and LayerRTID `44`; outbound records use `%%14593`, `%%14611`, and `48`. FilterRTIDs
  recur by functional category rather than changing randomly per event. For example, DC-01 has only
  13 FilterRTIDs over 4,126 records, while applications and direction vary coherently.
- Process IDs, thread IDs, SIDs, hexadecimal logon IDs, privilege message tokens, and provider GUIDs
  are syntactically credible. Non-system TargetLogonIds do not collide across hosts.

### Process and session correlations

- In 944 three-source process-creation matches, Security `NewProcessName`, Security `CommandLine`,
  Sysmon `Image`, Sysmon `CommandLine`, Sysmon `ParentProcessId`, and the corresponding eCAR process
  fields agree. The observed few missing source records occur at source boundaries and do not create
  contradictory identities.
- No eCAR dependent record referencing a visibly created process occurs before that process's CREATE
  or after its TERMINATE. No process has a visible TERMINATE before its CREATE.
- No Windows logon ID with both visible endpoints has a 4634 before its matching 4624. Privileged
  logons, RDP disconnects, and lock/unlock events reuse the correct host-local logon identifiers.
- eCAR target-process UUIDs remain stable for repeated access to the same target PID and agree with
  the target's visible PROCESS CREATE UUID when that creation exists in the window.

### Zeek schema and protocol correlations

- All DNS, HTTP, SSL, SMB, and SMTP UIDs checked are present in the same sensor's `conn.json`; all
  file `conn_uids` resolve locally; and all SSL certificate-chain FUIDs resolve to both file and X.509
  records. This completeness is treated as neutral for classification, but the absence of semantic
  contradictions in the linked tuples and timestamps is affirmative quality evidence.
- TLS versions and cipher suites are correctly coupled across 2,429 SSL records: TLS 1.3 uses only
  AES-GCM or ChaCha20 TLS 1.3 suites, and TLS 1.2 records do not use TLS 1.3-only suites.
- Certificate SHA-1 fingerprints equal the linked file SHA-1 values. Repeated certificates retain
  serials, fingerprints, validity windows, chain depth, and byte sizes across connections and sensors.
- HTTP error responses usually carry credible error-body types (`text/html`, occasionally JSON),
  including 403, 407, 502, 503, and 504 responses. This makes the exceptional 403/PE contradiction
  more probative, not less.

### Independent multi-sensor behavior

- The three Zeek sensors share no UIDs, even when they observe the same five-tuple. This is realistic
  for independently operating Zeek instances.
- Matched observations have stable sensor-specific clock offsets rather than identical timestamps:
  4,071 core/DMZ pairs differ by about -114 ms on average, 137 core/database pairs by about +64 ms,
  and 282 database/DMZ pairs by about -179 ms. Packet and byte values are usually close but not
  universally identical, reflecting observation-point differences.
- Connection state remains consistent across matching sensor observations while duration, missed
  bytes, history, and packet accounting can differ. That is substantially more realistic than simple
  row duplication.

### Detection usefulness

- High-value pivots are available without invented analyst-only labels: process GUIDs, logon IDs,
  target process IDs, eCAR actor/object relationships, Zeek UIDs/FUIDs, SMB handles, certificate
  fingerprints, and network tuples.
- Benign access to LSASS from Defender, services, CSRSS, and service hosts uses varied access masks
  and call traces, giving the malicious `0x1FFFFF` access meaningful context.
- Authentication events include successes and failures with plausible status codes, encryption
  types, IPv4-mapped addresses, ticket options, and host-local session lifecycles.

## Detailed Analysis

The Windows event layer is the strongest part of the dataset. Event headers are not generic wrappers:
provider, channel, task, version, level, keywords, execution IDs, and EventData names vary by source
and event ID. The Event ID 1102 handling is especially persuasive because it uses the different
Eventlog provider and UserData schema expected for a log-clear event, and its record-ID reset explains
the only backward EventRecordID transition on DC-01 without creating a timestamp inversion.

Process telemetry is also internally disciplined. Security, Sysmon, and eCAR agree on PID, image,
command line, and parent identity for the large matched population. Sysmon ProcessGuids are stable
through CREATE, network, access, and TERMINATE records; eCAR actor relationships remain within the
visible process lifetime; and logon IDs stay host-local. These are meaningful signs of a mature
generator or authentic collection. They are not used as evidence of synthetic origin merely because
they are complete.

The network layer shows similarly careful modeling. Protocol rows remain inside the corresponding
connection interval, SSL chains point to concrete certificate files and X.509 records, OCSP rows point
to HTTP response files, SMB records reuse transport tuples, and independent sensor observations have
different local IDs and realistic clock offsets. DNS authoritative/recursive flags vary sensibly:
internal answers commonly have both AA and RA, while external recursive answers are usually AA false
and RA true. TLS cipher selection respects protocol version.

The 403/PE transaction breaks that otherwise strong semantic model. Two independent sensors agree
that the proxy returned 1,474 bytes with status 403, so this is not an observation-loss artifact. Both
also agree that the body hash is a PE, and their PE analyzers expose detailed executable structure.
The record therefore cannot be explained as a missing companion, a collection-window edge, or thin
telemetry. The response outcome and body identity were assembled from incompatible templates.

The LSASS sequence exposes a second owning-model weakness. Event ID 10 correctly models an open
handle and Event ID 8 correctly uses the CreateRemoteThread schema, but their combination does not
match the visible command's behavior. Resolving the remote start routine to `NtCreateThreadEx` is a
specific semantic error: the creator API has been placed in the field that should identify code run by
the new target thread. This is exactly the kind of error that survives schema validation while failing
expert detection review.

The process-source timing is not independently decisive. Endpoint products often report the same
occurrence with stable latency ordering. Still, hundreds of records obeying the same bounded hierarchy
without a single reversal suggests timestamps are being assigned by an explicit rendering policy. It
raises confidence only after the hard content and companion contradictions establish a synthetic
explanation.

Overall, the evidence supports a synthetic verdict with high confidence, but it also shows that most
of the dataset is suitable for practical detection engineering. The remaining authenticity gap is
semantic composition, not basic schema formatting or correlation coverage.

## Synthetic Indicator Summary

| Category | Concrete indicator | Scope | Weight |
|---|---|---:|---:|
| Cross-source content semantics | 403 response rendered as a complete 1,474-byte, five-section PE with certificate table on two sensors | One transaction, independently repeated | Decisive |
| Companion-event semantics | `sekurlsa::logonpasswords` memory access expanded into a remote LSASS thread | One high-value sequence | Strong |
| Sysmon field semantics | Event ID 8 start routine resolves to `ntdll.dll!NtCreateThreadEx` | Same sequence | Strong |
| Call-stack semantics | Direct renamed executable's LSASS-open trace terminates in `wbemcomn.dll` without a visible WMI execution relationship | Same sequence | Moderate |
| Timing distribution | 944/944 eCAR process creates after Sysmon; matched Sysmon always 35–648 ms before Security | Dataset-wide | Supporting |

## Realism Score by Category

| Category | Score | Assessment |
|---|---:|---|
| Windows Security schema fidelity | 94/100 | Provider, event version, field sets, WFP values, and record lifecycle are strong. |
| Sysmon schema fidelity | 91/100 | Structures are accurate; the remote-thread start-function semantics are the major exception. |
| eCAR field and identity fidelity | 92/100 | Actor/object UUIDs, PID ownership, target identity, and lifecycles are coherent. |
| Zeek schema fidelity | 93/100 | UIDs, FUIDs, tuples, TLS, X.509, OCSP, SMB, and HTTP schemas are well formed. |
| Cross-source semantic coherence | 76/100 | Usually excellent, but the 403/PE contradiction is severe and survives two sensors. |
| Companion-event authenticity | 72/100 | Most companions are plausible; credential reading is incorrectly conflated with injection. |
| Timing and distribution texture | 82/100 | Sensor offsets are excellent; process-source ordering is overly one-sided and bounded. |
| Detection utility | 91/100 | Rich pivots and contextual noise support realistic rule development and investigation. |
| **Overall realism** | **86/100** | High-quality synthetic telemetry with a small number of expert-visible semantic seams. |

## Recommendations

1. Make HTTP terminal status own response content. A 403/407/5xx response should render the proxy or
   origin error body, MIME type, size, hashes, and file analyzers consistently. Do not retain the
   requested artifact's PE metadata when the request terminates in an error response. Add a contract
   asserting that any PE record's FUID belongs to a success response or to an explicitly modeled
   binary error body whose size and structure are independently plausible.
2. Separate credential-memory access from process injection. A `sekurlsa::logonpasswords`-style
   action should ordinarily produce process access/read semantics, not automatically a remote thread.
   Generate Event ID 8 only for an explicit injection technique or a tool behavior known to inject.
3. When Event ID 8 is appropriate, model the target thread entry point, not the creation API. Use a
   credible exported routine such as `LoadLibraryW` only when DLL injection is actually modeled, or
   use an unresolved/private address for shellcode and keep `StartModule`/`StartFunction` empty when
   Zeek/Sysmon would not resolve them.
4. Couple process-access call traces to the source process family and its loaded-module state. Avoid
   selecting a WMI library frame for a direct credential-dumping binary unless a concrete WMI-hosted
   execution path and module load are modeled.
5. Preserve source latency profiles but introduce calibrated overlap and tails. Independent endpoint
   channels should occasionally reverse Security/Sysmon/eCAR arrival order, experience longer queue
   delays, or batch records. Keep causal occurrence order intact while varying collection timestamps.
6. Retain the strong existing contracts: host-local logon IDs, stable process identities, WFP
   direction/layer mappings, sensor-local Zeek UIDs, sensor clock offsets, certificate/file hashes,
   TLS cipher/version validity, and lifecycle-safe eCAR actor relationships.
