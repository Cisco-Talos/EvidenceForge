# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 18

## Executive Summary

The supplied telemetry behaves like a plausible, selectively collected production dataset: native fields parse correctly, process identities remain coherent, and the authentication, network and filesystem examples examined have sensible causal relationships. I found no demonstrated source-native contradiction or convincing generator fingerprint; the Real verdict is a moderate-confidence classification, since a sufficiently careful synthetic dataset could pass these same checks.

## Evidence For Synthetic

- No material synthetic indicator was demonstrated. I tested apparent process-before-logon cases, repeated logon identifiers, missing connection references, hash consistency and cross-source ordering rather than treating initial suspicions as findings. The cases examined either resolved under their source semantics or remained compatible with the stated slice-of-time collection.

## Evidence For Real

- All 20 Windows XML exports parsed successfully. They contain 17,894 Security events covering 28 Event IDs and 11,689 Sysmon events covering nine Event IDs. The reviewed records distinguish Security hexadecimal process IDs from Sysmon decimal IDs, use suitable provider/channel metadata, and retain appropriate event-specific field names.
- Process lifecycle checks found no visible Sysmon dependency before its matching ProcessGuid creation or after its matching termination. Across 38,411 eCAR records, the checked process object/actor references similarly produced no dependency outside a visible matching process lifecycle, no mismatching parent PID for a visible parent CREATE, and no duplicate event IDs.
- `DC-02.meridianhcs.local/windows_event_security.xml` provides a coherent NTLM example: 4776 at `13:04:43.9915830Z`, Type 3 4624 at `13:04:44.0178827Z`, 5140 at `13:04:44.0918414Z`, and 4634 at `13:04:47.2745208Z`. The logon/share/logoff records agree on user `diego.ramirez`, LUID `0xcb5c02d`, and the applicable client tuple `10.10.1.34:53066`.
- The three Zeek sensors contain 23,014 connection records with a range of states, including SF, S0, REJ, RSTO, RSTR, OTH, S1, S2 and S3. All matched protocol rows checked agree with their sensor's connection tuple; none precedes its connection start by more than the 300 ms comparison tolerance.
- Repeated Zeek certificate fingerprints retain consistent certificate metadata. Repeated complete file hashes retain consistent complete sizes and accompanying hashes; I found no identical SHA256 mapped to conflicting complete file sizes.
- Both macOS endpoint exports distinguish fork, exec and exit, carry message `version: 11`, audit tokens and PID versions, and maintain unique global sequence values. The visible image transitions do not silently change an executable under an unchanged PID version, and inspected actors do not reappear after their matching exit.
- Linux SSH examples distinguish authentication acceptance from PAM session opening. On `WEB-EXT-01`, sshd PID `3030818` accepts lina.nguyen's public key at `13:00:54.830747Z`, then opens the PAM session at `13:00:54.940587Z`; on `DB-PROD-01`, PID `1367366` accepts her password at `13:09:02.848109Z`, then opens the session at `13:09:02.915188Z`.

## Detailed Analysis

### Scope and method

I examined only files under the supplied data directory. I parsed XML and JSON records, counted event families, inspected actual event payloads, and performed identifier, tuple, lifecycle and hash joins. I did not use copied filesystem modification times, external domain resolution, missing Sysmon event types, attack-story completeness or broad source completeness as authenticity indicators.

The endpoint records cover Windows, Linux and two macOS machines, with Zeek sensors at core, DMZ and database collection points. Endpoint timestamps examined span approximately `2026-11-02 13:00–19:00 UTC`; earlier DHCP/network timestamps exist, as can occur with transactions whose timing semantics differ from endpoint occurrences. I did not assume every file represents a complete boot-to-shutdown trace.

The analysis is a bounded source-semantic assessment, not a claim that every field of every event was certified against a vendor manifest. In particular, I did not infer a macOS release from network user agents or claim an unfamiliar version-11 ES field was invalid without proof.

### Native record inspection

The following 20 representative event shapes were inspected in actual records. Windows times below are on 2026-11-02 UTC; host names abbreviate their supplied `.meridianhcs.local` directories.

| Record | Log-visible check | Result |
|---|---|---|
| DC-02 Security 5156, `13:00:02.5627328` | Decimal ProcessID `5272`, device-form Application, UDP protocol `17`, inbound direction token `%%14592`, destination `10.10.2.11:53` | Coherent inbound DNS filtering audit |
| DC-02 Sysmon 3, UtcTime `13:00:02.607` | PID `5272`, dns.exe, UDP, `Initiated=false`, identical source/destination tuple | Coherent endpoint view of the DNS server |
| DC-02 Security 4624, `13:02:20.2761604` | Type 5, LOCAL SERVICE SID `S-1-5-19`, LUID `0x3e5`, Advapi, services.exe, absent remote IP/port | Plausible service authentication |
| DC-02 Security 4672, `13:02:20.2773683` | LOCAL SERVICE/LUID `0x3e5`, AssignPrimaryToken/Audit/Impersonate privilege list | Consistent with preceding service event |
| DC-02 Sysmon 10, `13:02:43.857` | MsMpEng source, svchost target, separate source/target GUIDs, thread ID, access `0x1400`, call trace | Appropriate process-access shape |
| DC-02 Security 4769, `13:03:13.7575377` | Machine requester `FILE-LNX-01$`, service `DC-02$`, mapped IPv6 client address, AES type `0x12`, status `0x0` | Plausible TGS audit; no requirement that initial TGT be in this slice |
| DC-02 Sysmon 13, `13:03:48.691` | `EventType=SetValue`, Defender registry path, `DWORD (0x00000000)` | Suitable registry-value representation |
| DC-02 Sysmon 1 / Security 4688, `13:04:02.165` / `13:04:02.2254321` | dllhost PID `6908` equals hex `0x1afc`; parent `5116` equals `0x13fc`; path and COM command agree | Consistent cross-source process creation |
| DC-02 Security 4776, `13:04:43.9915830` | Authentication package `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation WS-DRAMIREZ-01, success status | Appropriate NTLM credential-validation shape |
| DC-02 Security 4624, `13:04:44.0178827` | Type 3, NtLmSsp/NTLM, NTLM V2, key length 128, client tuple and named account | Compatible with the preceding credential validation |
| DC-02 Security 5140 / 4634, `13:04:44.0918414` / `13:04:47.2745208` | SYSVOL access and network logoff share LUID `0xcb5c02d` | Correctly scoped session continuity |
| FILE-SRV-01 Security 5145, `13:00:05.9658107` | ClinicalExports share/local path, relative target, client source, access mask and access-token list | Suitable detailed-share-access shape |
| FILE-SRV-01 Security 4656, `13:00:06.0000868` | Full archive filename, handle `0xc5b31bd7`, ProcessId `0x4`, ProcessName System | Plausible server-side SMB file handle |
| FILE-SRV-01 Security 4663 / 4658, `13:00:06.1459007` / `13:00:09.7044242` | WriteData mask `0x2`/token `%%4417`, then close of same handle, PID and LUID | Coherent file-handle lifecycle |
| WS-PPATEL-01 Security 4625, `15:07:36.8434414` | Type 2, User32, winlogon.exe, status `0xc000006d`, bad-password substatus `0xc000006a`, no remote address | Suitable failed local interactive logon |
| WS-PPATEL-01 Sysmon 7, `14:01:52.750` | OUTLOOK.EXE loading OLMAPI32.DLL; Signed true, Microsoft signature, Valid status | Suitable image-load shape; missing optional version strings are not a contradiction |
| DC-02 Security 4768, `13:36:25.3804590` | MAC-MROSS-02$ TGT request, krbtgt SID ending 502, preauth 2, AES type `0x12`, client `::ffff:10.10.1.42` | Plausible domain-joined machine authentication |
| DC-01 Security 1102, `18:42:27.2904094` | Microsoft-Windows-Eventlog provider, Level 4, Task 104, UserData/LogFileCleared payload and record ID 1 | Correctly differs from ordinary Security-Auditing EventData events |
| MAC-MROSS-02 ES rows 1–3, `13:12:07.845472–13:12:07.873566` | launchd fork; exec to xpcproxy; exec to iTerm2; same PID `88252` with PID versions `6461355`, `6461356`, `6461357` | Explicit, identity-preserving image transitions |
| MAC-MROSS-02 Unified Log, `14:24:34.657611+0000` | sshd-session writer/sender, empty subsystem/category, `%.500s` format and SSH acceptance message | Plausible unstructured daemon message inside Unified Log, not an ES authorization decision |

### Process and authentication correlation

I joined visible Sysmon process GUIDs to creations and terminations using UtcTime rather than assuming publication timestamps are the exact occurrence time. This found zero lifecycle violations under a 2 ms tolerance. Source/target process-access GUIDs and parent GUIDs were included where those fields were present.

Across all eCAR exports, I inspected 2,785 PROCESS/CREATE and 2,632 PROCESS/TERMINATE records. Matching visible process actors and process objects did not violate their creation/termination interval. Parent CREATE rows, when present, agreed with child ppid. The difference between creation and termination totals is not a defect in a time slice.

Apparent authentication inversions required semantic filtering. WS-MCHEN-01 has processes using LUID `0x6c29844` before a 4624 at `14:33:57.0143858Z`; that 4624 is Type 7, an unlock, so it is not proof of a newly created session. Likewise, repeated built-in service LUIDs `0x3e7`, `0x3e5` and `0x3e4` are not ordinary new-session identifier collisions. I did not count these cases as synthetic evidence. Comparisons found no user-name mismatch between visible corresponding non-built-in logon records and the examined Sysmon process identities.

DC-01's Security EventRecordID decreases from `28260971` at `18:42:24.5578567Z` to `1` at the 1102 clear event `18:42:27.2904094Z`. This is an explained reset, not an arbitrary counter discontinuity. No duplicate record IDs were found within the individual supplied Windows channels.

### Network, certificates and files

For each sensor, I indexed conn.json by UID and compared protocol record tuples. Matched protocol rows retained the same originator/responder addresses and ports. I checked timestamp inversions beyond 300 ms to avoid turning modest observation offsets into impossible causality; none was found. This test does not assert every protocol timestamp falls inside a fully observed connection lifetime.

Connection byte/packet checks found no negative duration, nonzero payload with zero packets on the same side, or payload byte count exceeding that side's IP-byte count. A representative database SSH flow, UID `ChB3CLFkEJTwzhVeNJ`, starts at epoch `1793624933.576285`, runs `3144.071603` seconds, carries `26711` originator and `43547` responder payload bytes, and has an established/closed `SF` state and `ShADadfF` history. The matching Linux authentication occurs after the transport start.

In zeek-db, SSL UID `CoqzJj8pa3bM3ZNHN` has SNI `FILE-LNX-01.meridianhcs.local`, destination `10.10.2.21:443`, and certificate references `FBTXrynqCxUI1qZ1eZ` and `F7ued3f0Lel0GHNDn1`. Its files/x509 rows distinguish leaf and CA records, maintain fingerprints, and give the leaf a compatible subject/SAN. Repeated fingerprint metadata and repeated complete file lengths were consistent throughout the scanned Zeek files.

One zeek-core smb_mapping row at `17:35:24.871469Z` has UID `C5PgTblRidxF4DQCi8`, tuple `10.10.1.22:44244 → 10.10.2.20:445`, and share ClinicalExports without a conn row for that UID in the supplied sensor file. I did not score this as a synthetic indicator: a live SMB connection can emit mapping evidence while its eventual connection summary falls outside the export. The supplied collection context does not establish that all active connection summaries must be present.

### Linux and macOS interpretation

Linux syslog uses parseable RFC5424-style headers with distinct application and PID fields. SSH acceptance, PAM open and close messages provide useful correlation without conflating daemon lifetime with user-session lifetime. Bash histories use epoch marker lines; the supplied zsh history uses extended-history records such as `: 1793624859:0;/usr/bin/id`. These are source-appropriate representations, not interchangeable endpoint event schemas.

The 320 native ES records consist of 118 exec, 102 fork and 100 exit events. I compared process identities using PID plus pidversion, checked actor images against previously observed identities, and checked visible exit reuse. No contradiction emerged. ES process credential changes and successive exec images were not assumed invalid merely because they differ from their parent or pre-exec actor.

Unified Log is only five rows and was treated as a selected export. MAC-MROSS-01's `15:42:09.009673+0000` kernel message says the security policy “would not allow” MeetingAssist. I did not infer a conclusive denied-execution outcome or claim that any later process evidence proves a bypass without a matching explicit decision and identity chain. The two Macs have different bootUUID values; shared executable UUIDs for the same Apple image are compatible with matching builds.

### Detection-stack implications and limitations

These files should support ordinary field extraction and the identity joins examined. The Windows 1102 example demonstrates why ingestion must support UserData as well as EventData, and the 4688/Sysmon example demonstrates why PID radix normalization matters. Per-sensor Zeek UID scoping remains necessary; independent sensors need not assign the same UID to traffic they both observe.

I did not validate every free-text Linux daemon message against a particular package build, certify every macOS version-11 extension against a full SDK schema, or reconstruct every user session. The Real verdict therefore expresses the balance of observed evidence, not proof of production provenance. Complete matching was used to test for contradictions, never as evidence that the data was suspiciously complete.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| None demonstrated | Windows, eCAR, Zeek, Linux and sampled macOS records | Parsed inventories and the identity/tuple/lifecycle checks described above | No hard contradiction, contract gap, schema defect or material distribution fingerprint established. Score remains in the production-like band. |

The unmatched SMB reference and the apparent process-before-unlock cases are explained or unresolved collection/semantic observations, not scored synthetic indicators.

## Realism Score by Category

- **Field format accuracy:** 9 — Native payloads inspected have appropriate types, identifiers and event-specific structures; exhaustive vendor-manifest certification was outside this bounded review.
- **Temporal patterns:** 9 — Transport/authentication and visible process/file lifecycles are plausible, with distinct occurrence and publication times.
- **Cross-source correlation:** 9 — Tested tuples, process identities, PIDs, session identifiers and file hashes agree without a demonstrated contradictory join.
- **Behavioral realism:** 8 — Service, interactive, SSH, SMB and background activity are represented with plausible semantics; deeper activity-distribution attribution remains uncertain.
- **Environmental consistency:** 9 — Endpoint source types and OS-specific representations are consistent in the examined records; no platform was inferred solely from sensor observation.

## Recommendations

- If this were synthetic, retain the existing distinctions between unlock and new-session events, native ES PID versions and normalized eCAR process identities, and transport opening versus authentication acceptance. Those distinctions materially support reliable detections in the records examined.
- For collection/export diagnostics, investigate whether UID `C5PgTblRidxF4DQCi8` closes outside the slice. If so, document connection-summary export semantics or provide an active-connection reference when that is part of the intended collection product; do not fabricate a closed flow merely to force a join.
- No specific mandatory realism repair is supported by this examination. Additional source volume or extra event families should not be added solely to satisfy a generic expectation of completeness.
