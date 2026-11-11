# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 18

## Executive Summary

The bounded sample behaves like usable production telemetry: Windows field representations are source-appropriate, and two exact pivots preserve identity, tuple, and timing relationships. I found no demonstrated synthetic indicator; the Real verdict is tentative because a well-built synthetic collection could also pass these checks, and this review does not certify the full dataset.

## Evidence For Synthetic

- No substantiated indicator in the inspected sample. No hard contradiction, required-companion gap, invalid hash width, or demonstrated distribution defect was established. The residual uncertainty is a limit of the assessment, not log-visible evidence of synthesis.

## Evidence For Real

- `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml`, record 129968, Event 4688 v2 at `2026-11-02T13:10:02.1751666Z`, uses hexadecimal process IDs, `TokenElevationType=%%1936`, a System mandatory label, and the v2 target/parent fields. `NewProcessId=0x143c` and `ProcessId=0x1104` resolve to 5180 and 4356, matching Sysmon and eCAR for the same image/command.
- On that host, Security 4624 v2 record 130016 at `13:24:17.7484449Z` describes a service logon: `LogonType=5`, `SYSTEM`, `TargetLogonId=0x3e7`, `Advapi`, and `services.exe`, with `IpAddress=-`. It does not incorrectly assign a remote address to this sampled service logon.
- `DC-01.meridianhcs.local/windows_event_security.xml` records 28245294/28245392 distinguish TGS and TGT evidence: 4769 uses a service account name and `TransmittedServices`, while 4768 includes `krbtgt`, `TargetSid`, `PreAuthType=2`, and certificate fields. IPv4-mapped IPv6 client addresses and decimal source ports are credible native representations.
- The first `zeek-core/conn.json` and `dns.json` records share UID `ClnAf4xMznbwm13HlN` and the exact UDP tuple. DNS RTT agrees with the 0.000469-second transaction interval; one packet each way and IP-byte accounting are internally consistent.
- The scoped Zeek aggregates contain successful DNS and several failure classes, both TLS versions, and diverse observed services. This is credible operational variety, although it cannot establish authenticity alone.

## Detailed Analysis

### Scope and method

I read only the supplied briefing and assigned data directory. I inspected 18 distinct representative records: five Windows Security records (4624, 4634, 4688, 4768, 4769), four Sysmon records (1, 3, 7, 10), two eCAR records, two Linux syslog records, two macOS records, and three Zeek records. The two exact pivots below reuse those records. Additional operations were aggregate counts and a narrowly scoped hash-width check, not an exhaustive lifecycle audit. File paths below are relative to the assigned data directory.

The scoped core network timestamps span approximately `2026-11-02 13:00–19:00 UTC`. I did not penalize absent pre-window process creation, unpaired sessions that could survive the window, selected Sysmon coverage, sanitized names, or cross-source completeness.

### Pivot 1: Windows process identity across three sources

On `WS-AJOHNSON-01`:

| Source | Exact reference | Time UTC | Identity and behavior |
|---|---|---|---|
| Sysmon Event 1 | record 30326 | UtcTime `13:10:01.794`; envelope `13:10:01.7957426` | PID 5180, parent PID 4356, taskhostw.exe, `taskhostw.exe /Run`, System, logon `0x3e7` |
| eCAR PROCESS/CREATE | line 17, ID `5c1723f1-42a0-4cdf-a011-c0ae868771ad` | timestamp_ms 1793625002033 = `13:10:02.033` | PID 5180, PPID 4356, same image, command and logon; actorID matches source_process_uuid |
| Security Event 4688 | record 129968 | `13:10:02.1751666` | NewProcessId `0x143c`, creator `0x1104`, same image, command and svchost.exe parent |

These are exact identity matches with plausible source-dependent reporting offsets, rather than an apparent sequence inferred from nearby unrelated rows. No conflicting user or parent identity is visible in this pivot. I did not search the entire collection for every reuse of PID 5180.

### Pivot 2: Zeek DNS transaction

`zeek-core/conn.json:1` and `zeek-core/dns.json:1` share UID `ClnAf4xMznbwm13HlN`, timestamp `1793624400.006178`, and `10.10.2.20:58104 → 10.10.2.11:53/udp`. The query is `DC-01.meridianhcs.local`, transaction ID 46234, answer `10.10.2.10`, NOERROR, A/IN, with DNS `rtt=0.000469` and connection `duration=0.000469`. The connection's 41/57 payload bytes become 69/85 IP bytes, a 28-byte IPv4/UDP overhead per single packet. UDP `history=Dd` is compatible with bidirectional data. This establishes a coherent sampled transaction; exact matching itself is not suspicious.

### Schema, parser and field observations

The sampled Windows XML uses the Windows Event namespace and distinct Security versus Sysmon provider/channel identities. Security uses Level 0 and audit-success keywords; Sysmon uses Level 4 and informational-channel keywords. Sysmon Event 10 record 30319 has source/target process identity, `GrantedAccess=0x1000`, and a delimited module-offset call trace. Event 3 record 30322 places `lsass.exe` PID 4292 on an outbound UDP/88 tuple. Event 7 record 30503 distinguishes the explorer.exe process image from the loaded OneDrive DLL and supplies signature status and file metadata. These sampled shapes support normal field-based detections.

The additional hash-width aggregate covers the 118 Event 1 and 17 Event 7 rows on this one host: 134 SHA1 values have 40 hex-character positions, 134 MD5 values have 32, 134 SHA256 values have 64, and 131 IMPHASH values have 32. There were no width failures. This checks representation only, not whether any digest matches the named binary.

The sampled eCAR APP-INT FLOW/CONNECT row uses numeric PID 36008, object/actor UUIDs, and string-valued ports inside properties. Such normalized fields require the appropriate parser mapping; I did not impose native Zeek or Windows typing rules on this source.

Linux samples are RFC5424-shaped messages with PRI/version, UTC timestamps, host, application, PID and absent-value markers: APP-INT rsyslogd queue status at `13:00:32.218756Z` and WS-OHADDAD accounts-daemon login text at `13:02:49.263305Z`. Neither establishes an SSH session or requires a domain-authentication companion.

The macOS sample is deliberately interpreted by source: the Endpoint Security row declares message version 11 and a fork notification with actor launchd PID 1 and child PID 41136; the Unified Log row is a loginwindow writer record at `13:03:16.611945+0000` with subsystem/category, formatString and eventMessage. I found no obvious JSON parsing or actor/child distinction error. I did not independently certify Apple's version-specific export schema or equate notification result fields with execution authorization; these two rows receive limited weight.

### Bounded distribution context

For `zeek-core`, aggregate denominators are 12,943 conn rows, 3,265 DNS rows and 413 SSL rows. DNS responses comprise 3,025 NOERROR, 222 NXDOMAIN, 14 SERVFAIL and 4 REFUSED; SSL versions are 199 TLSv12 and 214 TLSv13. Connection services include DNS 3,272, Kerberos 2,607, HTTP 2,475, LDAP 1,105, SMB 467, syslog 379, SSH 58 and other categories. Different family counts do not establish missing evidence: there may be transactions without responses, repeated handshakes, or analyzer-specific logging. I did not perform an exhaustive UID cardinality reconciliation or claim a defect from unequal counts.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| No demonstrated indicator | Windows, eCAR, Linux, macOS, Zeek | 18 representative rows; two exact pivots; scoped aggregates | No affirmative synthetic penalty; inspected rows appear production-like. Sampling uncertainty is captured by verdict confidence, not treated as a synthetic indicator |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled native Windows/Zeek shapes and hash widths are credible; macOS version-specific schema was not independently certified.
- **Temporal patterns:** 8 — Sampled reporting offsets and DNS timing are coherent; session-wide and long-duration behavior was not audited.
- **Cross-source correlation:** 9 — Exact process and DNS pivots preserve IDs, ownership and timing.
- **Behavioral realism:** 8 — Sampled service, Kerberos, shell-extension and operational records are plausible; behavior coverage is limited.
- **Environmental consistency:** 8 — Inspected platform/source distinctions are coherent; no complete topology or collection-profile reconstruction was attempted.

## Recommendations

No specific synthetic-data repair is justified by the bounded evidence. If this were synthetic, preserve the demonstrated source-specific PID representations, process ownership, DNS packet accounting and independent reporting offsets. Any further investigation should validate a targeted suspected defect before changing telemetry; missing uninspected sources or events alone do not support a repair recommendation.
