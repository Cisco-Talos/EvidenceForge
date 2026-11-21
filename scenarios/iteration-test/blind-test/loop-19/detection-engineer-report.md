# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 31

## Executive Summary

The supplied records are mostly production-like from a detection engineering perspective: they parse cleanly, preserve source-specific identities, and pass the visible process, authentication, certificate, and network correlation checks I performed. A conspicuously narrow Linux daemon-message vocabulary is a weak synthetic indicator, but I did not establish an impossible visible lifecycle, malformed identifier, or conflicting shared identity that would justify a synthetic verdict. This is a moderate-confidence lean toward real data, not proof of provenance.

## Evidence For Synthetic

- [distribution_texture] Several Linux hosts emit exactly four distinct `irqbalance` message texts repeatedly, with a shared four-message structure and host-specific substitutions. `MAIL-EDGE-01.meridianhcs.local/syslog.log` contains 55 such messages, `LOG-MON-01` 70, `APP-INT-01` 67, and `WEB-EXT-01` 155. On MAIL-EDGE-01 the texts concern IRQ 45/CPU 0/virtio0-input, on LOG-MON-01 IRQ 137/CPU 3/ens192, and on APP-INT-01 IRQ 16/CPU 0/ahci. This looks compatible with a small parameterized message pool. Repetitive daemon diagnostics and a shared Linux image are also credible explanations, so this receives limited weight.
- [weak_signal] On WEB-EXT-01, those 155 `irqbalance` rows form a substantial component of its 1,486 syslog records, despite using only four exact messages. This makes the repeated vocabulary operationally noticeable in a SIEM. It is a source-texture concern, not a claim that endpoint or application sources must have been collected more broadly.

## Evidence For Real

- All JSON/NDJSON records parsed successfully, including 37,971 eCAR rows, 23,125 Zeek connection rows, 324 Endpoint Security records, and the five Unified Log records. All 29,236 Windows XML events parsed successfully.
- Every checked Zeek DNS, HTTP, SSL, SMB-files, and SMTP row resolved to a connection UID in its own sensor's `conn.json`, with matching originator/responder addresses and ports. None preceded the matching connection start by more than the 100 ms tolerance used in this check. This supports usable correlation; completeness itself was not treated as proof of authenticity or as a synthetic tell.
- All 949 visible Sysmon process creates and 830 terminations passed the checked visible GUID-based lifecycle relationships, including parent and process-access references where the corresponding create was present. I found no checked dependent event before the visible create or after the visible termination for that GUID.
- Windows authentication and file-access records preserve meaningful source distinctions: local service logons use absent remote addresses, network share activity carries source addresses and ports, and share access/handle operations use consistent subject LogonIDs.
- DC-01's Security record counter resets from 28,260,991 at `2026-11-02T18:42:19.3278392Z` to 1 at the Event 1102 log-clear record at `18:42:21.4159803Z`. The 1102 payload correctly resides under namespaced `UserData/LogFileCleared`, rather than being silently lost because it lacks `EventData`.
- The apparent hash variation around browser startup is explained by source semantics: Sysmon Event 1 hashes the executable, whereas Event 7 hashes `ImageLoaded`. Firefox executable and DLL hashes should differ. After restricting the comparison to process creates, there were no multiple SHA256 values for the same host/image/version combination.
- Network failure and transport patterns are varied: core Zeek has SF, S0, OTH, RSTO, RSTR, REJ, S1, S2, and S3 states, along with TCP, UDP, and ICMP. Successful connections are not the only represented outcome.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The inventory contains 116 files spanning Windows Security and Sysmon, normalized eCAR, Linux syslog and shell histories, macOS Endpoint Security and Unified Log exports, three Zeek sensor directories, proxy access, ASA, web access, and Snort alerts. Counts above reflect parsed records, not filesystem modification times.

I parsed every Windows XML file and every JSON/NDJSON file. I then checked explicit GUID/LUID/UID relationships and inspected representative source-native fields. The record samples below cover more than 20 event shapes. I used no scenario, ground truth, origin metadata, repository code, or other reviewers' findings.

### Representative record checks

All times below are on 2026-11-02, UTC. Paths are relative to the supplied data directory.

| Source and time | Observed fields and interpretation |
|---|---|
| DC-02 Security 5156, 13:00:02.5627328 | Decimal ProcessID 5272, native device application path, UDP protocol 17, inbound direction token `%%14592`, remote `10.10.1.31:57565` to local `10.10.2.11:53`; fields retain filtering-platform semantics. |
| DC-02 Sysmon 3, 13:00:02.6083531 | ProcessId 5272, `dns.exe`, `Initiated=false`, same tuple as the inbound 5156; millisecond `UtcTime` is distinct from the seven-digit Windows envelope timestamp. |
| DC-02 Sysmon 22, 13:00:48.6270019 | `_kerberos._tcp.meridianhcs.local`, QueryStatus 0, semicolon-delimited SRV-style QueryResults, SYSTEM process attribution. |
| DC-02 Sysmon 5, 13:01:34.2679659 | spoolsv.exe PID 5904 with a braced ProcessGuid; the endpoint identity is usable for termination matching. |
| DC-02 Security 4689, 13:01:34.3749534 | ProcessId `0x1710` equals decimal 5904, matching that spoolsv termination; Status `0x0`. |
| DC-02 Security 4624, 13:02:20.2761604 | LOCAL SERVICE SID `S-1-5-19`, LogonType 5, TargetLogonId `0x3e5`, services.exe caller, and no remote IP/port. This is service authentication, not a fabricated remote login. |
| DC-02 Security 4672, 13:02:20.2773683 | Same LOCAL SERVICE SID and LUID, privilege list containing assign-primary-token/audit/impersonate privileges. |
| DC-02 Sysmon 10, 13:02:43.8573010 | MsMpEng.exe PID 5280 accessing svchost.exe PID 5132; source/target GUIDs, GrantedAccess `0x1400`, and a pipe-delimited CallTrace are represented separately. |
| DC-02 Security 4769, 13:03:13.7575377 | FILE-LNX-01$ requests service DC-02$, encryption `0x12`, status `0x0`, IPv4-mapped IPv6 client address. A Linux machine account is not itself contradictory in a domain environment. |
| DC-02 Sysmon 13, 13:03:48.6922536 | `EventType=SetValue`, Windows Defender registry path and `DWORD (0x00000000)` detail; not a process-create schema reused for a registry event. |
| DC-02 Sysmon 1, 13:04:02.1664283 | dllhost.exe PID 6908, DcomLaunch parent PID 5116, SYSTEM LUID `0x3e7`, correct-length SHA1/MD5/SHA256/IMPHASH tokens. |
| DC-02 Security 4688, 13:04:02.2254321 | NewProcessId `0x1afc` equals decimal 6908; parent `0x13fc` equals 5116. CommandLine matches the Sysmon create. |
| DC-02 Security 4776, 13:04:43.9915830 | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, diego.ramirez, source workstation WS-DRAMIREZ-01, Status `0x0`; no invented IP field is required for this event. |
| DC-02 Security 5140, 13:04:44.0918414 | diego.ramirez, LUID `0xcb5c02d`, SYSVOL share, local share path and mapped source address/port. |
| DC-02 Security 4634, 13:04:47.2745208 | Same diego.ramirez LUID, LogonType 3; follows the visible share access. |
| DC-02 Sysmon 8, 14:29:32.9272823 | SearchIndexer.exe to SearchProtocolHost.exe, separate process identities, new thread ID, hexadecimal StartAddress, ntdll StartModule and RtlUserThreadStart function. This is not automatically malicious merely because it is a remote-thread event. |
| DC-02 Security 4768, 13:36:25.3804590 | MAC-MROSS-02$, krbtgt service/SID, encryption `0x12`, PreAuthType 2, successful status and mapped client IP; certificate fields empty rather than fabricated certificate authentication. |
| DC-02 Security 4625, 16:20:44.3345949 | svc_mgmt from FILE-SRV-01, NTLM/Type 3, Status `0xc000006d`, disabled-account SubStatus `0xc0000072`, failure Keywords `0x8010000000000000`. |
| DC-02 Security 4697, 17:25:33.2643165 | DirectoryCacheSvc, service executable path, ServiceType `0x10`, ServiceStartType 3, LocalSystem account and named installing subject. |
| DC-02 Security 4771, 18:45:08.2594541 | lina.nguyen, krbtgt, Status `0x18`, PreAuthType 2, mapped source IP, failure Keywords; distinct from successful TGT issuance. |
| FILE-SRV-01 5145/4656/4663/4658, 13:00:05.9658107–13:00:09.7044242 | ClinicalExports share and local path agree; handle `0xc5b31bd7` opens, receives access, and closes. The 4663 access mask `0x2` agrees with write-data token `%%4417`. |
| MAC-MROSS-02 Endpoint Security lines 1–3, 13:12:07.845472–13:12:07.873566 | A launchd fork is followed by xpcproxy and iTerm exec stages for PID 88252. Actor and target identities are separate; pidversion changes across exec rather than treating PID alone as the entire identity. |
| MAC-MROSS-02 Endpoint Security line 13, 13:12:13.920255 | sw_vers exit event has event_type 15 and an exit `stat` value. The event is an observation, not an authorization verdict inferred from process success. |

### Correlation tests and their limits

The three Zeek sensors contain 12,377, 10,384, and 364 connections respectively. Within each sensor, I checked all 4,442 DNS, 5,479 HTTP, 3,613 SSL, 253 SMB-files, and 79 SMTP rows for UID resolution and tuple agreement. Different sensors need not assign the same UID to the same traffic. No checked protocol timestamp preceded its own connection start by more than 100 ms. File timestamps also did not exceed their associated connection close by more than the two-second tolerance used for that check.

I checked that recorded IP-byte counts were neither smaller than their corresponding payload-byte counts nor below 20 bytes per recorded packet. No contradiction was found by those bounded checks; this does not establish the exact packet composition. HTTP 204/304 records did not claim a nonzero response body.

Across X.509 logs, 200 distinct certificate fingerprints had consistent certificate metadata after excluding observation time, local file ID, and host/client classification. Across file logs, the 322 distinct SHA256 values did not conflict in MD5, SHA1, or total-byte metadata. This supports stable identity handling rather than independent per-observation invention.

The Windows authentication check excluded reserved service LUIDs and treated unlock/reconnect activity separately from creation of an original session. With those distinctions, I found no checked process or file-access event before all visible initiating logons for the same LUID, nor after all visible logoffs. Treating a later Type 7 unlock as the original login would have produced false positives. Likewise, pre-window processes and sessions were not penalized for lacking an initiating record.

### macOS and normalized endpoint interpretation

The macOS native files declare Endpoint Security message version 11 and expose fork, exec, and exit records, including audit tokens, signing metadata, process start times, executable stat data, and actor/target separation. I did not independently validate every field against the exact version-11 SDK and therefore do not claim exhaustive native schema certification. The inspected event roles and identity transitions did not reveal a contradiction.

Unified Log records are sparse but are not interchangeable with eCAR FLOW or USER_SESSION records. MAC-MROSS-02 records sshd-session accepting keyboard-interactive/PAM authentication at `14:24:34.657611+0000`; MAC-MROSS-01 records public-key acceptance at `16:02:06.829781+0000`. The kernel policy message on MAC-MROSS-01 at `15:42:09.009673+0000` was not interpreted as proof that its named executable ran. Source sparsity alone was not scored negatively.

The normalized eCAR corpus also passed a visible object/actor lifecycle comparison against its PROCESS CREATE/TERMINATE rows. Its JSON string-valued ports and normalized property names were treated as normalization choices, not incorrectly judged against native Sysmon or Endpoint Security schemas.

### Remaining authenticity uncertainty

The Linux `irqbalance` vocabulary is the strongest remaining concern. For example, MAIL-EDGE-01 contains IRQ affinity/balancing messages at `13:01:01.534288Z` and `13:02:50.523946Z`, and repeats related diagnostics throughout the slice. The same four functional message forms recur with different device/CPU substitutions on the other inspected hosts. This warrants a small texture penalty, but repetitive software logging can produce exactly this effect. The check did not establish an impossible state transition, and I did not infer that missing application logs must exist.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux syslog / irqbalance | Four inspected hosts; 55, 70, 67, and 155 rows respectively, each using four exact texts | Small increase: parameterized vocabulary is visible, but shared software and repetitive diagnostics are plausible. |
| weak_signal | Linux syslog source distribution | WEB-EXT-01: 155 of 1,486 rows are the above daemon messages | Small corroborating concern about message concentration; not independent evidence of a generator. |
| hard_contradiction | Checked endpoint/network relationships | None established | No increase. |
| contract_gap | Checked GUID/LUID/UID, certificate and hash relationships | None established within the bounded tests | No increase; unmatched pre-window initiators were excluded. |

## Realism Score by Category

- **Field format accuracy:** 9 — Clean parsing and plausible source-specific identifiers, payloads and timestamp precision; exact version-11 ES SDK compliance was not exhaustively certified.
- **Temporal patterns:** 8 — Checked visible lifecycles and transport/protocol ordering hold; Linux diagnostic repetition leaves some texture uncertainty.
- **Cross-source correlation:** 9 — Checked process/PID, session/LUID, tuple/UID, file/hash and certificate identities agree.
- **Behavioral realism:** 8 — Mixed transport outcomes, real service-account semantics and varied endpoint activity; narrow daemon text pools are a mild concern.
- **Environmental consistency:** 8 — Windows, Linux and macOS evidence remains platform-appropriate in inspected examples, with no established contradictory collection claim.

## Recommendations

- If this were synthetic, improve the `irqbalance` text/state model visible on MAIL-EDGE-01, LOG-MON-01, APP-INT-01 and WEB-EXT-01: generate diagnostics from changing device/state conditions, with repetition rates reflecting the specific service configuration, rather than relying on four interchangeable message forms.
