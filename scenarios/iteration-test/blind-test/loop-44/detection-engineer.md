# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 28

## Executive Summary

The supplied telemetry is production-like from a detection-engineering perspective: the parsed Windows, endpoint, and network evidence preserves the identities and source-specific relationships needed for practical SIEM correlation. I did not establish a hard contradiction, malformed selected event family, or required-companion failure; the principal reservation is a small and repetitive macOS command vocabulary, which is weak evidence because the same user operates both endpoints. “Real” is a modest-confidence likelihood judgment, not a claim that coherent logs establish provenance.

## Evidence For Synthetic

- [weak_signal] **Repeated small command vocabulary on both macOS endpoints.** In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, `/usr/bin/id` appears as exec arguments on lines 9, 82, and 96; `/usr/bin/sw_vers -productVersion` on 12 and 93; and the exact `find /Users/maya.ross/Documents -maxdepth 2 -type f -name '*.pdf'` arguments on 54 and 105. On `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, the same `find` arguments recur on 69, 78, and 137; `sw_vers -productVersion` on 12, 66, and 89; and `ps aux` on 75, 130, and 140. This resembles a bounded command pool, but one person's repeated diagnostics or automation can explain it. It carries little weight and does not demonstrate a schema or lifecycle defect.

## Evidence For Real

- **Windows provider-specific details hold together.** Security 4624 uses version 2 fields, 4688 uses version 2 target/parent/integrity fields, failure audits carry failure keywords, and 1102 changes provider and uses `UserData/LogFileCleared`. Examples and exact locations are in the event audit below.
- **Visible process identities have coherent lifetimes.** Across 11,785 Sysmon records, joins to visible ProcessGuid creations and terminations found no checked occurrence before its creation or after its termination, and no checked PID/image disagreement for that GUID. The test includes parent references and ProcessAccess/CreateRemoteThread source and target references. It does not assume that an unmatched process must have started inside the slice.
- **Visible session pairs agree.** There are 393 matched non-well-known 4624/4634 LogonIDs across the ten Windows hosts, with no logoff-before-logon or target SID disagreement. For example, `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml:13047` logs `aisha.johnson`, Type 3, LogonID `0x26b317e`, at `15:41:27.7664217Z`; line 13102 closes that identity at `15:41:53.2512902Z`.
- **Network records are usable as correlated evidence.** Across the three sensors, all 12,509 checked DNS/HTTP/TLS/SMB/SMTP records join to a same-sensor conn UID with matching four-tuple. Their timestamps fall within the connection interval with a 300 ms tolerance. This is a positive usability result, not an argument that completeness itself proves either origin.
- **Collection effects have concrete representation.** `zeek-dmz/files.json:1` observes 349 of 353 bytes with `missing_bytes=4`, while `zeek-core/files.json:1` observes all 353 bytes of the corresponding health response on its own connection. The records preserve total size while allowing different sensor observations.
- **Source precision and record sequencing are differentiated.** Security XML uses seven fractional digits, Sysmon payload `UtcTime` uses milliseconds, native ES has nanosecond-shaped UTC strings, Unified Log uses its own timestamp representation, and ASA uses second-resolution syslog. DC-01's Security RecordID reset coincides with the visible log-clear event rather than occurring arbitrarily.

## Detailed Analysis

### Scope and method

I read only the supplied data directory as evidence, together with the supplied reviewer instructions. File modification times, domain resolvability, scenario narratability, missing selected Sysmon event families, and mere completeness or thinness of collection were excluded from the judgment.

The visible network window is approximately `2026-11-02 13:00–19:00 UTC`. I parsed all 19,030 Security XML events and 11,785 Sysmon XML events across ten Windows hosts; all eCAR JSON files; all three sensors' Zeek JSON files; and both native ES and Unified Log exports. I also inspected Linux syslog, shell history, web/proxy access, ASA, and alert samples. The checks are structural and relational, not proof of exhaustive conformance to every possible product release schema.

The three conn files contain 22,148 records: core 12,314, DMZ 9,401, and DB 433. A missing pre-window parent, session start, or post-window termination was neutral. Authentication-cache state and the observed source selection also prevent treating every logon as requiring a fresh visible TGT request.

### Representative source-native event audit

The following table records actual fields inspected, rather than merely counting event IDs. XML line references identify the beginning of the event element. Paths are relative to the supplied data directory; host names below omit the common `.meridianhcs.local` suffix only for readability.

| Source / location | Event and actual values | Assessment |
|---|---|---|
| DC-01 Security, line 3 | 5156 v1; `Direction=%%14592`, source `10.10.2.11:63605`, destination `10.10.2.10:53`, protocol `17`, DNS application device path | Coherent inbound UDP DNS observation on DC-01; decimal PID and protocol fields are appropriate. |
| DC-01 Security, line 208 | 4689 v0; `ProcessId=0xcd4`, `ProcessName=C:\Windows\System32\taskhostw.exe`, `Status=0x0` | Correct process-termination field shape. |
| DC-01 Security, line 448 | 4769 v0; `TargetUserName=DC-02$`, `ServiceName=DC-01$`, encryption `0x12`, IPv4-mapped client address | Plausible machine-account service ticket. |
| DC-01 Security, line 645 | 4688 v2; new PID `0xd94`, parent PID `0x8cc`, conhost path, `MandatoryLabel=S-1-16-16384`, target null SID | Matches the versioned extended process schema and system token context. |
| DC-01 Security, line 1656 | 4624 v2; `NETWORK SERVICE`, SID `S-1-5-20`, Type 5, `Advapi`, `Negotiate`, no remote IP | Plausible local service logon; no domain-ticket requirement inferred. |
| DC-01 Security, line 1711 | 4672; same SID and LogonID `0x3e4` as preceding service login, privilege list includes audit/impersonation privileges | Consistent service-token privilege assignment. |
| DC-01 Security, line 2317 | 4768; `WS-EBROOKS-01$`, `krbtgt`, service SID ending `502`, preauth `2`, encryption `0x17` | Fields and identities are coherent; RC4 use alone is not impossible. |
| DC-01 Security, line 3090 | 4776; `PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, machine account and workstation, `Status=0x0` | Appropriate credential-validation schema. |
| DC-01 Security, line 20297 | 5140; `ObjectType=File`, share `\\*\NETLOGON`, SYSVOL path, access `0x1` | Plausible DC share access. |
| DC-01 Security, line 22496 | 4648; SYSTEM caller, `svc_backup` target, Veeam caller image, source address `10.10.2.10` | Separates credential subject, target account, and caller process; no invented remote-origin requirement applied. |
| DC-01 Security, line 61701 | 4771; status `0x18`, preauth `2`, failure keywords `0x8010000000000000` | Failure semantics fit preauthentication failure. |
| DC-01 Security, line 140749 | 4625; `Status=0xc000006d`, `SubStatus=0xc0000072`, Type 3, `NtLmSsp`, `NTLM V2` | Coherent disabled-account network failure. |
| DC-01 Security, line 183744 | 4697; `PSEXESVC`, `%SystemRoot%\PSEXESVC.exe`, type `0x10`, start type `3`, `LocalSystem` | Correct service-install shape. |
| DC-01 Security, lines 195839 / 195937 / 196014 / 196405 | 4720, 4724, 4738, 4728; same `svc_dirsync` SID ending `2456`, followed by Domain Admins SID ending `512` | Account-management identities persist; account-control changes are represented explicitly. |
| DC-01 Security, line 200293 | 4698; escaped Task XML, task `\Microsoft\Windows\Maintenance\DeviceSync`, SYSTEM principal, executable action | Parses as task content rather than breaking the surrounding XML. |
| DC-01 Security, line 270291 | 1102; Eventlog provider, Level 4, Task 104, `EventRecordID=1`, `UserData/LogFileCleared`, SYSTEM subject | Source-specific log-clear form and associated RecordID reset are correctly represented. |
| FILE-SRV-01 Security, lines 146 / 199 / 240 | 4656 / 4663 / 4658; handle `0x1b169349`, System PID `0x4`, same account/logon; `4663 AccessMask=0x2` | Open/use/close relationship is coherent; `RestrictedSidCount=0` is a count, not a malformed SID. |
| DC-01 Sysmon, line 203 | Event 10 v3; uppercase `SourceProcessGUID` and `TargetProcessGUID`, source Defender, target winlogon, `GrantedAccess=0x1410`, pipe-delimited CallTrace | Appropriate ProcessAccess casing and field structure. |
| DC-01 Sysmon, line 614 | Event 1 v5; PID `3476`, conhost, parent csrss PID `2252`, four hash algorithms | Hash hex lengths are valid and parent identity remains coherent. |
| DC-01 Sysmon, line 1207 | Event 5; same GUID/PID/image as line 614, payload time `13:04:56.909` after creation `13:02:30.859` | Reproducible same-identity lifecycle check. |
| DC-01 Sysmon, line 1630 | Event 22 v5; query `DC-02.meridianhcs.local`, status `0`, results `10.10.2.11;` | Appropriate DNS query shape and semicolon-delimited result. |
| DC-01 Sysmon, line 54186 | Event 8 v2; source MpCmdRun, target MsMpEng, thread ID and start address/module/function | Appropriate remote-thread event structure. |
| DC-01 Sysmon, line 57777 | Event 7; module `vmStatsProvider.dll`, `Signed=true`, VMware signature, `SignatureStatus=Valid` | Source-native module-load fields and booleans are plausible. |
| DC-01 Sysmon, line 105100 | Event 11; Defender DetectionHistory path, creation time distinct from event wrapper precision | Appropriate file-create fields. |

For all 992 observed hash-bearing Sysmon records, SHA1, MD5, and SHA256 values had the expected 40/32/64 hexadecimal lengths; the 981 present IMPHASH values had 32. SID-to-account joins across the Security records did not reveal one domain SID assigned to contradictory account names.

### Network semantics and SIEM joins

`zeek-core/conn.json:1` and `zeek-core/dns.json:1` share UID `Cuq507OFNo7MpYfALL`, timestamp `1793624402.898315`, and `10.10.1.31:51161 → 10.10.2.11:53`. The conn duration is `0.028925`, equal to the DNS RTT, with a one-packet request and response. DNS SRV answers preserve the expected string representation and matching TTL-array length in this example.

`zeek-core/http.json:1` is a CONNECT to `prod-useast-a.online.tableau.com:443` over client `10.10.1.22:40446 → 10.10.3.20:8080`, with a 200 “Connection Established” response and zero HTTP body lengths. `PROXY-01.meridianhcs.local/proxy_access.log:1–2` separately records CONNECT control accounting and the inspected HTTPS request under tunnel ID `PT-a5e41cdf86225d43`. Treating the tunnel's whole payload as the CONNECT HTTP response body would be a mistake; the supplied records distinguish them.

TLS version/cipher pairing passed across 3,142 ssl records: TLS 1.3 entries use TLS 1.3 cipher names, and the TLS 1.2 entries use the older cipher families. I found no nonzero response body on the checked HEAD/204/304 HTTP rows. SSL chain references resolve to same-sensor file and certificate records; checked file SHA1 values agree with the corresponding X.509 fingerprint.

For example, `zeek-db/files.json:1` and `zeek-db/x509.json:1` share ID `FeLtr64jeZOQESJ26Jm` and SHA1/fingerprint `7ed25bb3f0d4bcf0f7b31bcf0f01f7175047f1a3`. This is an identity check, not reliance on certificate issuer authenticity or public DNS.

Across conn rows, neither direction has IP-layer byte totals smaller than its payload totals. ASA built/teardown ID parsing found no teardown without a visible build in the supplied firewall file: 7,410 TCP builds / 7,407 TCP teardowns and 1,109 UDP builds / 1,109 UDP teardowns. The three remaining TCP closures can fall outside the window and were not scored as defects.

### macOS: separate native and normalized evidence

The ES exports declare message `version=11`; the rows contain explicit action/result wrappers, audit tokens, pidversions, executable/file metadata, and event-specific fork, exec, and exit payloads. I did not substitute an older message-version layout or demand network FLOW fields from native ES.

On MAC-MROSS-01, native ES lines 1–7 preserve launchd fork, xpcproxy, Terminal, login, and zsh phases. The exec source and target can share a PID while changing pidversion and image: line 2 transitions PID `42152`, version `10 → 11`, and line 3 transitions `11 → 12`. Across both exports' 283 records, repeated `(pid,pidversion)` identities retain their executable path/start time; no actor uses the same exited identity later. Per-type sequence counters and global counters increase in file order. These are limited consistency checks, not certification of every OS-specific metadata field.

MAC-MROSS-01 Unified Log line 3 records acceptance of public-key SSH authentication at `16:01:38.551396+0000`, written by `/usr/libexec/sshd-session`, PID `64329`; ES lines 66–80 show the associated process chain and subsequent shell transition. MAC-MROSS-02 Unified Log line 2 instead says `Accepted keyboard-interactive/pam ... from 10.10.1.41 port 49252`, consistent with a different authentication mechanism. Native Unified Log precision, writer images, and empty subsystem/category for the sshd text are not interchangeable with normalized eCAR fields.

MAC-MROSS-01 Unified Log line 2 says the security policy “would not allow” MeetingAssist. I do not turn that line into proof of a denied authorization decision or successful child execution. The native ES subset here consists of process lifecycle notifications, so absent authorization/file events do not establish missing required evidence. Likewise, the small Unified Log export is a collection scope, not a volume defect by itself.

### Linux and behavior texture

Linux records use RFC5424-shaped messages with distinct program/PID fields and microsecond timestamps. For example, `DB-PROD-01.meridianhcs.local/syslog.log:1–3` records sudo PID `1043495`, a `lina.nguyen` request, PAM session opening for root, and session close approximately two seconds later. `APP-INT-01.meridianhcs.local/syslog.log:3–4` closes an SSH session shortly after the window opens; the absence of its earlier login is neutral.

The half-hour sysstat cron records are regular because they are scheduled jobs: APP-INT-01 syslog lines 1, 58, 84, and 96 occur at `13:00`, `13:30`, `14:00`, and `14:30` with subsecond scheduling variation. I did not call that periodicity synthetic. Repeated human-facing macOS utility commands remain the only modest command-texture reservation; their frequency alone does not outweigh coherent state and schema evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Native macOS ES exec records and supporting shell histories | Two endpoints used by maya.ross; repeated id/sw_vers/find/ps invocations at cited lines | Small increase: consistent with a short command pool, but readily explainable by repeated diagnostics or automation. |
| hard_contradiction / contract_gap / schema_or_format | Checked Windows, native macOS, eCAR, and Zeek relationships | No demonstrated finding in the tests described above | No score contribution. A passing consistency check does not prove real origin. |

The score of 28 means mostly realistic with minor, explainable texture; it is not the 62-point confidence in the binary provenance judgment. There is no demonstrated defect warranting the rubric's 61–100 bands.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed XML/JSON and the inspected versioned event families have appropriate fields, native representations, and valid identity/hash shapes.
- **Temporal patterns:** 9 — Checked visible process and session lifecycles preserve ordering, with different source precisions and plausible scheduled jobs.
- **Cross-source correlation:** 9 — Checked GUID, LogonID, UID/four-tuple, certificate, and file relationships are usable and internally consistent.
- **Behavioral realism:** 8 — Roles and utility use are plausible; the repeated small macOS command vocabulary is the main weak reservation.
- **Environmental consistency:** 9 — Windows domain/service distinctions, Linux service messages, macOS native exports, and sensor observations remain coherent within their visible collection scopes.

## Recommendations

- If this were synthetic, broaden the macOS command long tail and vary arguments according to the actual task, where appropriate. The exact repeated `find`, `sw_vers`, and `ps` argument sets cited above are the concrete reason for this recommendation; repetitions should remain when attributable to automation or repeated diagnostics.
- If this were synthetic, retain the current identity/lifecycle and source-specific schema behavior while changing vocabulary. The checked records do not justify a recommendation to add arbitrary event families, force fresh tickets before every login, or fill collection-window boundaries.
