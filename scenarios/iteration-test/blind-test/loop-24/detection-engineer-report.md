# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 68

## Executive Summary

The dataset is largely usable for a detection pipeline: its JSON and XML parse, source-specific representations are differentiated, and the process and network correlation checks performed well. The strongest evidence of synthesis is repeated arithmetic structure in native Mac endpoint timestamps: nine application launches have successive gaps in a 1:2 ratio to within one microsecond, while two independent SSH shutdown chains space three process exits almost exactly evenly. These are measurable distribution artifacts, not impossible lifecycle orderings; they support a likely-synthetic score rather than the highest-confidence contradiction band.

## Evidence For Synthetic

- [distribution_texture] Nine nonterminal desktop application launches across both `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` and `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` share the same timing equation. For each launchd fork → xpcproxy exec → application exec triplet, the second gap equals twice the first gap within one microsecond. For example, MAC-MROSS-02 lines 22–24 start at `2026-11-02T13:21:53.735767000Z` and have gaps of **2,767 µs and 5,534 µs**; lines 41–43 have **4,448 µs and 8,896 µs**; MAC-MROSS-01 lines 32–34 have **5,806 µs and 11,612 µs**. The applications include Outlook, Chrome, Word, DBeaver, Zoom, VS Code, and Slack. Such repeated proportionality across unrelated launches is difficult to attribute to ordinary scheduling variability.
- [distribution_texture] Two SSH shutdown chains in the same native endpoint source repeat equally spaced process exits. MAC-MROSS-02 lines 74–76 show zsh PID `99712` and sshd-session PIDs `99711`, `99697` exiting at `14:34:59.703109000Z`, `.850218000Z`, `.997327000Z`: both gaps are **147,109 µs**. MAC-MROSS-01 lines 108–110 show zsh PID `44187` and sshd-session PIDs `44186`, `44182` exiting at `16:17:59.335275000Z`, `.666550000Z`, `.997826000Z`: gaps are **331,275 µs and 331,276 µs**. Child-before-parent ordering is reasonable; the repeated near-exact interpolation is the indicator.

## Evidence For Real

- All **78,941 JSON/NDJSON records** parsed successfully, as did **17,780 Windows Security events** and **11,606 Sysmon events**. The XML retains provider namespaces, source-specific field capitalization, numeric resource tokens, and channel metadata.
- Across all ten Windows Sysmon hosts, GUID-based checks found no visible process evidence preceding that GUID's visible creation, no evidence following its visible termination, and no child creation after its visibly terminated parent. GUID-to-PID/image assignments were stable, and parent GUIDs that resolved to visible creations agreed with their PID/image fields.
- Zeek DNS, HTTP, and SSL rows consistently resolved to same-sensor connections with matching endpoint tuples and timestamps within the connection intervals checked. SMB file rows also passed these checks. Completeness is treated as positive functional fidelity, not evidence of synthesis.
- FILE-SRV-01 Security records `271777`–`271780` show a credible share/access/handle sequence: 5145 → 4656 → 4663 → 4658, with a stable subject logon ID, matching path, and handle `0xb013d0ff`.
- DB-PROD-01 syslog lines 90–92 distinguish an SSH connection at `14:28:27.941325Z`, public-key acceptance at `14:28:33.105583Z`, and PAM session opening at `14:28:33.283067Z`, all under sshd PID `1378783`. Session closure appears at line 104, `15:01:29.395348Z`.
- Mac endpoint exports distinguish fork, exec, and exit; keep the pre-exec actor separate from the exec target; increment PID version across exec; and retain stable signing/hash/file identity for repeatedly observed executable paths. Unified Log SSH messages identify the same server-side sshd-session PIDs as the endpoint chains.

## Detailed Analysis

### Scope and method

I inspected only the supplied log directory. I parsed every JSON/NDJSON record and every Windows XML event, inspected representative native records from more than twenty event types, and ran bounded identifier, tuple, byte-accounting, timestamp, and lifecycle checks. Windows source timestamps span approximately `2026-11-02T13:00:02Z` through `18:59:51Z`; lifecycle checks respect this slice-of-time scope.

I did not use filesystem modification times, domain resolvability, absent selected Sysmon event types, thin source coverage, or the shape of suspicious activity as authenticity indicators. I did not interpret normalized eCAR rows as native Mac Endpoint Security events. No external documentation was consulted, so unfamiliar version-specific fields are not claimed as schema errors.

### Windows schema and native-field spot checks

The following examples are from `windows_event_security.xml` or `windows_event_sysmon.xml` under the named host directory. Record IDs uniquely identify the examples within each file.

| Host/source/event | Visible example | Detection-relevant result |
|---|---|---|
| DC-02 Security 5156 | Record `25377457`, `13:00:04.6195699Z` | Decimal ProcessID `5272`, protocol `17`, device-path Application, resource-token Direction; the inbound DNS tuple agrees with its Sysmon view. |
| DC-02 Security 4776 | `25377461`, `13:00:08.9498956Z` | NTLM package name, machine account ending `$`, workstation and hexadecimal status are represented coherently. |
| DC-02 Security 4769 | `25377469`, `13:00:27.0756073Z` | Ticket options/encryption type are hexadecimal; IP uses IPv4-mapped IPv6; service SID and domain context are plausible. |
| DC-02 Security 4688 | `25377490`, `13:01:05.9719627Z` | Version 2 includes target subject placeholders, creator PID, parent path, elevation token, and MandatoryLabel. New PID `0x1a94` equals Sysmon PID `6804`. |
| DC-02 Sysmon 1 | `1368547`, UtcTime `13:01:05.871` | WmiPrvSE PID `6804`, process/parent GUIDs, hashes and parent command line are present. Source timestamps need not be identical to 4688. |
| DC-02 Sysmon 3 | `1368530`, UtcTime `13:00:04.669` | UDP, `Initiated=false`, DNS server process, address-family flags, source/destination ports agree. |
| DC-02 Sysmon 22 | `1368538`, UtcTime `13:00:48.916` | SRV query and semicolon-delimited answer representation are coherent. |
| DC-02 Sysmon 5 | `1368546`, UtcTime `13:01:05.030` | Termination uses a process GUID, decimal PID, image, and user. |
| DC-02 Sysmon 10 | `1368568`, UtcTime `13:03:35.692` | Source/TargetProcessGUID capitalization, thread ID, access mask `0x1010`, and CallTrace are represented. |
| DC-02 Sysmon 8 | `1368569`, UtcTime `13:03:35.857` | NewThreadId, StartAddress, StartModule and StartFunction are distinct from process-access fields. |
| DC-02 Sysmon 7 | `1369309`, UtcTime `13:52:37.016` | Loaded DLL, signature status, hashes and image version are separated from the owning process image. |
| DC-02 Sysmon 11 | `1369706`, UtcTime `14:24:10.613` | TargetFilename and CreationUtcTime are present. |
| DC-02 Sysmon 13 | `1372205`, UtcTime `17:31:25.303` | `EventType=SetValue`, TargetObject, Details and process identity are present. |
| DC-02 Security 4624 | `25377568`, `13:04:44.0171612Z` | Type 3 NTLM network logon has remote IP/port, NtLmSsp, NTLM V2 and 128-bit key length. |
| DC-02 Security 5140 | `25377569`, `13:04:44.0918410Z` | Same subject logon ID `0xcb5c02d` and remote tuple as the 4624, accessing SYSVOL. |
| DC-02 Security 4634 | `25377570`, `13:04:47.0513596Z` | Matching target logon ID, user and type; closes after authentication/share access. |
| DC-02 Security 4768 | `25378109`, `13:22:14.0689810Z` | krbtgt, preauth type `2`, certificate placeholders, ticket metadata and mapped IP are plausible. |
| WS-PPATEL-01 Security 4625 | `359186`, `17:11:56.5878667Z` | Local Type 2 failure has absent remote tuple and password-related status/substatus. |
| WS-PPATEL-01 Security 4800/4801 | `359203` / `359262` | Lock/unlock retain target logon ID `0xd9f40cf` and SessionId `2`. |
| WS-AJOHNSON-01 Security 4778 | `130655`, `16:21:55.6281007Z` | Uses event-specific `LogonID`, RDP session name and remote ClientAddress. |
| DC-01 Security 4698 | `28257046`, `17:19:47.7438924Z` | Contains escaped Task Scheduler XML with task namespace, principal, action and repetition interval. |
| DC-01 Security 1102 | Record `1`, `18:42:20.0702537Z` | Correctly differs structurally: Eventlog provider and namespaced UserData/LogFileCleared rather than ordinary audit EventData. Later records use the reset sequence. |

The sampled Security events use Level `0`/Opcode `0` and success/failure audit keywords in the expected roles; Sysmon examples use Level `4`/Opcode `0`. GUIDs and SIDs inspected are syntactically valid. The Sysmon GUID timestamp component in the WmiPrvSE example resolves to `2026-11-02T13:01:05Z`, agreeing with creation time.

A naive logon-order query initially produces apparent pre-logon activity for SYSTEM `0x3e7` and for Type 7 unlocks. Those are not valid initiating-logon contradictions: reserved SYSTEM identity and unlocks can refer to already-existing sessions. After accounting for these semantics, the checked nonreserved sessions had no visible ordering violations. I do not score the naive matches.

### Zeek and normalized endpoint correlation

The sensor connection counts are **12,230 core**, **430 database**, and **10,481 DMZ**. Across DNS (**4,385**), HTTP (**5,547**) and SSL (**3,668**) records, UID/tuple joins to their respective sensor's connection file succeeded and the timestamps fell inside the tested connection intervals, allowing 1 ms at the start and 100 ms at the end. SMTP's 79 records and all 224 SMB file records also passed. Connection payload bytes never exceeded IP bytes, and positive payload counts did not appear with zero packets in these checks.

One SMB mapping, `zeek-core/smb_mapping.json` line 93, UID `C4bqaKVpaYQLPkuTrz`, has no same-file connection row. It occurs at epoch `1793640924.871449` for `10.10.1.22:59392 → 10.10.2.20:445`. A long-lived or selectively observed connection can explain this in a slice-of-time export; the mapping alone proves neither an impossible ordering nor an unrealistic collection profile. I therefore give it no synthetic-score weight.

All 23 eCAR host files were checked for process actor/object references materially preceding a visible creation or following a visible termination, using a two-second allowance for source observation differences. No such violations were found. This is a bounded timestamp/reference check, not proof of every semantic relationship.

### macOS timing and source semantics

The 307 native endpoint records declare message version `11` and contain fork (`event_type=11`), exec (`9`) and exit (`15`) observations. Per-type sequence numbers and global sequence numbers are contiguous in the exports. Audit identities, hashes and executable paths are internally differentiated; these are positive realism features. I do not infer denied execution from the Unified Log text “Security policy would not allow process,” and I do not require native network FLOW records in ES exports.

The strongest authenticity issue survives these semantic checks. The nine desktop application launch triplets have the following gaps, calculated directly from their native `time` fields:

| Host | Lines | Application | Fork→xpcproxy, µs | xpcproxy→application, µs |
|---|---:|---|---:|---:|
| MAC-MROSS-01 | 17–19 | Chrome | 3,642 | 7,283 |
| MAC-MROSS-01 | 32–34 | VS Code | 5,806 | 11,612 |
| MAC-MROSS-01 | 47–49 | Slack | 4,127 | 8,255 |
| MAC-MROSS-02 | 22–24 | Outlook | 2,767 | 5,534 |
| MAC-MROSS-02 | 25–27 | Chrome | 5,394 | 10,789 |
| MAC-MROSS-02 | 41–43 | Outlook | 4,448 | 8,896 |
| MAC-MROSS-02 | 83–85 | Word | 4,429 | 8,859 |
| MAC-MROSS-02 | 120–122 | DBeaver | 2,705 | 5,409 |
| MAC-MROSS-02 | 125–127 | Zoom | 4,949 | 9,899 |

These are all nine nonterminal GUI launches in the inspected launchd→xpcproxy→application set. Terminal/iTerm bootstrap, inventory services and SSH bootstrap do not generally have that ratio. This scoped family pattern is more suggestive of a timing template than a sensor-wide timestamp quantization issue. The SSH exit interpolation supplies a second, related timing motif. Neither motif requires an allegation about undocumented ES message-version fields.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS Endpoint Security | Nine GUI launches, seven applications, two hosts | Main indicator: second timing gap is twice the first within 1 µs in every nonterminal GUI triplet examined. |
| distribution_texture | Native macOS Endpoint Security | Two separate SSH session shutdowns, two hosts | Supporting indicator: three ordered exits form equal-spaced timestamp chains within 1 µs. |

No hard contradiction, demonstrated native schema defect, or generator identity leak was established. The two indicators share a timing concern and are not counted as independent failures across the entire dataset. This limits the score to the likely-synthetic band despite a confident directional verdict.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed cleanly; source-specific Windows, Zeek and Mac structures are well differentiated in inspected records.
- **Temporal patterns:** 5 — Ordinary lifecycle ordering is good, but exact proportional launch gaps and interpolated SSH exits are strong native-timing tells.
- **Cross-source correlation:** 9 — Process identities, Windows handle/session examples and network tuple joins are coherent in the checks performed.
- **Behavioral realism:** 8 — Visible service, local-session and SSH behaviors are plausible; the substantive concern is execution timing texture.
- **Environmental consistency:** 9 — Mixed-platform path/identity conventions and host-specific services are coherent in the inspected records; limited collection is not penalized.

## Recommendations

- If this were synthetic, give launchd fork, xpcproxy exec and application exec separately modeled latency components. Preserve causality while removing the repeated `gap2 = 2 × gap1` relationship demonstrated above.
- If this were synthetic, model shell exit, SSH child exit and SSH supervisor exit as dependent but separately varying waits, rather than evenly interpolating all three across the shutdown interval.
- Retain the existing distinction between native Mac observations and normalized endpoint rows, and the demonstrated process, handle, session and connection identity fidelity while improving those two timing distributions.
