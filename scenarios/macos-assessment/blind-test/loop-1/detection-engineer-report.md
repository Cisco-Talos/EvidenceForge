# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 90  
**Synthetic-Confidence Score:** 82

## Executive Summary

Most records have credible source formats and would ingest successfully into a conventional SIEM. The strongest contrary evidence is a macOS process sequence that timestamps execution and credential changes before the corresponding process forks, supported by repeated Windows session inconsistencies and Linux authentication normalization errors.

## Evidence For Synthetic

- **[hard_contradiction] Process modifications precede visible process creation.** In `NS-MAC-02.northstar.example/ecar.json`, line 392 records PID `45580`, objectID `54f5c1e1-773d-4259-8050-40ea65da994d`, executing `/usr/libexec/sshd-auth` at `2026-10-20T15:07:59.799Z`. Its explicit `operation=fork` creation appears at line 399, timestamped `15:08:01.165Z`—1.366 seconds later. Comparable reversals affect PIDs `45591` and `45592`.
- **[contract_gap] All three examined `/netonly` children acquire terminal session 0 despite direct parents in session 1.** In `NS-WIN-01.northstar.example/windows_event_sysmon.xml`, EventRecordID `607009` records `runas.exe /netonly ...`, PID `6564`, `TerminalSessionId=1`. Its direct `cmd.exe` child, EventRecordID `607011`, PID `6592`, has `TerminalSessionId=0`. The same transition repeats for parent/child records `607388→607390` and `607394→607395`. New network credentials should preserve the calling interactive terminal session.
- **[contract_gap] Two native SSH failures become local authentication attempts in normalized telemetry.** `NS-BUILD-01.northstar.example/syslog.log` line 178 reports `sshd` failing authentication for `svc_mgmt` from `10.42.0.31:42331` at `14:27:26Z`. The corresponding eCAR record, line 225, has `session_type=local` and `src_ip="-"`. This repeats at syslog line 458 and eCAR line 699 at `18:02:06Z`, with native source port `60124`.

## Evidence For Real

- **Windows schemas are largely convincing.** The XML uses appropriate provider identifiers, channels, field names, success/failure keywords, hexadecimal Security process IDs, decimal Sysmon process IDs, SID structures, and timestamp precision.
- **Process correlation is strong.** All 214 Security 4688 records match a Sysmon Event 1 by PID, image, command line, and parent PID. No conflicting hashes appeared for the same process image.
- **Visible Windows lifecycles are coherent.** I found no Sysmon dependent event before its matching visible process creation or after its matching termination, and no visible child creation after its parent’s matching termination.
- **Authentication pairing works.** All 60 Security 4634 records have matching visible 4624 records with consistent account, SID, LogonID, and logon type, in the correct order.
- **Zeek references and accounting are credible.** All 1,994 connection UIDs are unique. Examined protocol rows retain their connection tuples and occur within their associated transport intervals; file, certificate, and OCSP references resolve.
- **The network data includes operational variation.** Connection states include `SF`, resets, rejection, incomplete handshakes, and partial connections. DNS includes A, AAAA, PTR, and NXDOMAIN results.
- **The macOS evidence distinguishes normalized telemetry from native logging.** The supplied Unified Log rows use `loginwindow` writer paths and appropriate subsystem/category fields. I did not find grounds to treat the eCAR rows as native Endpoint Security exports.

## Detailed Analysis

All filenames below are relative to the evidence directory. Times are UTC.

### Examination scope

I parsed:

- 816 Windows Security events and 589 Sysmon events.
- 4,779 eCAR records across four hosts.
- 4,619 network records across ten source families.
- 531 Linux syslog messages, the two Unified Log records, and supplied shell histories.

The populated XML and JSON structures parsed successfully. I examined examples of all 19 Windows event types present, then checked identifier and lifecycle relationships across the record populations.

### Representative Windows schema checks

The following checks concern field structure and ordinary value interpretation; the separate `/netonly` finding concerns session semantics.

| Source | Event ID | EventRecordID | Representative check |
|---|---:|---:|---|
| Security | 4688 | 245262 | Version 2; hexadecimal process IDs; `TokenElevationType=%%1938`; medium mandatory label `S-1-16-8192`. |
| Security | 4624 | 245334 | Version 2; Type 3 Kerberos logon; mapped IPv4 source `::ffff:10.42.0.11`; source port `64846`. |
| Security | 4672 | 245332 | Subject LogonID and multiline privilege list have credible shapes. |
| Security | 4689 | 245286 | PID `0x1e54`, SSH image, and exit `Status=0x0` are appropriately represented. |
| Security | 5156 | 245397 | Decimal `ProcessID=5624`; protocol `17`; DNS destination port 53; device-style application path. |
| Security | 4634 | 245369 | Target LogonID `0x1049b9bc`, account SID, and Type 3 are consistent with its matching logon. |
| Security | 4648 | 245393 | Caller PID `0x1f28`, `runas.exe`, explicit target account, and separate target-server fields. |
| Security | 4625 | 245364 | Failure keywords `0x8010000000000000`; `0xc000006d/0xc000006a`; Type 2 with absent network address. |
| Security | 4800 | 245265 | Lock record identifies session 1 and LogonID `0x10373548`. |
| Security | 4801 | 245274 | Unlock identifies the same session and LogonID, after the lock. |
| Sysmon | 1 | 607288 | Version 5; process/parent GUIDs, decimal PIDs, parent user, hashes, and terminal-session fields. |
| Sysmon | 5 | 607302 | Process GUID, PID `7764`, image, and user match termination semantics. |
| Sysmon | 11 | 607250 | Target filename and separate `CreationUtcTime` are present. |
| Sysmon | 10 | 607355 | Source/target process identities, thread ID, `GrantedAccess=0x1000`, and call trace. |
| Sysmon | 22 | 607366 | `QueryStatus=0`; semicolon-delimited results for `graph.microsoft.com`. |
| Sysmon | 7 | 607372 | Loaded DLL metadata, hashes, `Signed=true`, and `SignatureStatus=Valid`. |
| Sysmon | 13 | 607464 | `EventType=SetValue`; HKU target and `DWORD (0x00000001)` representation. |
| Sysmon | 3 | 607314 | TCP initiation; IPv4 booleans; source `10.42.0.21:54061` to `10.42.0.12:22`. |
| Sysmon | 8 | 607035 | Separate source/target process identities, new thread ID, start address, module, and function. |

Security and Sysmon EventRecordIDs are unique and increasing within their respective supplied streams. Windows `TimeCreated` values retain seven fractional digits, while Sysmon `UtcTime` uses milliseconds; these different precision conventions are credible.

Repeated LogonIDs for service identities and Type 7 unlock events were not counted as duplicate-session defects.

### macOS process ordering

The problematic SSH sequence is internally identifiable without relying on another sensor’s clock.

| PID | ObjectID suffix | Earlier dependent record | Later creation record | Reversal |
|---:|---|---|---|---:|
| 45580 | `40ea65da994d` | Line 392, `operation=exec`, `15:07:59.799Z` | Line 399, `operation=fork`, `15:08:01.165Z` | 1.366 s |
| 45591 | `c4ca2db41938` | Line 395, `operation=privilege_drop`, `15:08:00.480Z` | Line 402, `operation=fork`, `15:08:01.168Z` | 0.688 s |
| 45592 | `864186b66ed5` | Line 396, `operation=exec`, `15:08:00.505Z` | Line 400, `operation=fork`, `15:08:01.165Z` | 0.660 s |

PID `45580` also has a credential transition at line 393 before its fork. PID `45592` has a job-control modification at line 397 before its fork. Its parent PID `45591` is itself recorded as created three milliseconds after the child.

These are explicit visible initiators and dependents with matching durable object identities. They cannot be explained by processes that started before collection.

A production exporter could produce faulty timestamps or reorder observations. However, no separate occurrence timestamp is supplied to repair the represented sequence. As delivered, this timeline would impair process-ancestry and execution-transition detections. I count this as one concentrated lifecycle defect, rather than treating every affected row as an independent indicator.

The SSH transport itself is plausible: `office-span/conn.json` line 757, UID `CKBTkWaa6k8MWPNsIB`, opens at `15:07:57.712171Z`; the destination eCAR FLOW appears at `15:07:57.980Z`, before the session login at `15:08:01.164Z`.

### Windows network credentials and terminal sessions

The first example provides a clear chain:

1. Sysmon record `607009`, `13:34:53.514Z`: PID `6564`, `runas.exe /netonly /user:nora.ellis-admin ...`, terminal session **1**.
2. Security record `244968`, `13:34:54.6762271Z`: Type **9**, `LogonProcessName=seclogo`, with outbound identity `nora.ellis-admin`.
3. Sysmon record `607011`, `13:34:54.814Z`: PID `6592`, direct child of PID `6564`, terminal session **0**.

The local user remains `NORTHSTAR\nora.ellis`, which is appropriate for `/netonly`; the new LogonID also correlates correctly. The terminal-session change is the defect: alternate outbound credentials do not ordinarily move a direct interactive child into the isolated service session.

The same session-1-to-0 transition occurs at `15:29:58Z` and `15:30:05Z`. Repetition makes an isolated unusual launch less persuasive as an explanation.

### Linux authentication normalization

At `14:27:26Z`, syslog line 178 explicitly contains:

`sshd 61962 ... Failed password for svc_mgmt from 10.42.0.31 port 42331 ssh2`

Four milliseconds later, eCAR line 225 represents a failed login for the same account as:

`src_ip="-"`, `session_type="local"`, `failure_reason="bad_password"`.

The second occurrence at `18:02:06Z` repeats this discrepancy, with native PID `93324` and port `60124`.

The native source is the same host’s IP, so this could be self-directed SSH. That does not remove the visible SSH mechanism or source tuple. The normalized representation loses distinctions used by detections separating console failures from SSH authentication.

By contrast, successful SSH examples correlate well. Syslog lines 77–80 show connection, public-key acceptance, PAM session opening, and logind session creation for `nora.ellis`. eCAR line 93 and connection UID `CKUwYp8oEskhyqKEAa4` preserve source port `54438` and sensible transport-before-authentication timing.

### Network parsing and correlation

The network evidence is comparatively strong:

- All 920 DNS records have matching answer/TTL array lengths.
- Protocol records carrying UIDs retain matching connection tuples.
- Checked DNS, HTTP, TLS, SMB, and NTP timestamps fall within their associated transport intervals.
- HTTP response FUIDs, TLS certificate-chain FUIDs, and OCSP file references resolve.
- Certificate validity intervals cover their observations; OCSP update intervals cover their observations.
- Connection byte accounting does not place IP byte totals below application payload totals.

For example, SMB UID `CVOCtOJ581SiLpeAg3` appears in `conn.json` line 3, `smb_mapping.json` line 1, `smb_files.json` lines 1–2, and `files.json` line 1. The reported file is `878226` bytes, fitting within the connection’s `880920` responder payload bytes.

I did not penalize missing connection rows for SSH sessions still active near the collection boundary: Zeek connection logging and the slice boundary can legitimately account for those cases.

### Limits on interpretation

The two Unified Log records do not establish broad native macOS collection coverage. I therefore did not require additional Unified Log categories, Endpoint Security notifications, or native filesystem evidence. Likewise, selective Sysmon coverage and absent domain-controller telemetry were not treated as authenticity indicators.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `hard_contradiction` | macOS eCAR process telemetry | Three process identities in one SSH sequence | Explicit execution/credential changes precede matching visible forks by 0.660–1.366 seconds. |
| `contract_gap` | Windows Sysmon and Security | Three `/netonly` parent/child chains | Credential cloning correlates, but direct children repeatedly switch from terminal session 1 to 0. |
| `contract_gap` | Linux syslog and eCAR authentication | Both visible `svc_mgmt` SSH failures | Native SSH mechanism and source tuples are replaced with local-login semantics. |

## Realism Score by Category

- **Field format accuracy:** 9 — Strong XML/JSON structure and credible native field representations.
- **Temporal patterns:** 6 — Most timing is plausible, but the macOS fork/exec reversals break a visible lifecycle.
- **Cross-source correlation:** 7 — Broad identifier integrity is strong; authentication normalization and Windows session semantics introduce concrete inconsistencies.
- **Behavioral realism:** 8 — Application, administration, and network behavior is generally plausible; `/netonly` session placement is the main demonstrated exception.
- **Environmental consistency:** 8 — Host roles and source types largely agree; Linux failure classification conflicts with its native SSH records.

## Recommendations

If this were synthetic, the following changes would improve it:

- Preserve fork-before-exec and fork-before-credential-change ordering for each macOS process identity, including parent-before-child creation. Apply collection delays coherently or retain separate occurrence and observation timestamps.
- Preserve the caller’s terminal session when modeling `/netonly` children, while assigning the separate network-credentials LogonID and outbound identity.
- Carry native SSH mechanism, source IP, and source port into normalized failure records, including self-directed SSH.
- Retain the existing Windows field fidelity, process identity consistency, and Zeek reference/accounting checks while adding assertions for these specific lifecycle and session relationships.
