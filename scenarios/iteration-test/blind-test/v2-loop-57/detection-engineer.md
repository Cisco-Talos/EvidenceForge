# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 65

## Executive Summary

The dataset is highly convincing at the schema and correlation layers, and I found no hard contradiction: Windows event versions and fields are source-appropriate, process and session lifecycles hold together, and Zeek, proxy, firewall, IDS, and endpoint observations correlate without impossible ordering. I nevertheless assess it as synthetic because several independent workstation logon-failure bursts preserve nearly identical fractional seconds while retry intervals fall on exact whole seconds, and all 840 observed Windows process exits carry the same successful exit status. Those distribution-level artifacts are stronger than ordinary collection neatness, but the substantial production-like detail keeps the score in the lower part of the “likely synthetic” range.

## Evidence For Synthetic

- `[distribution_texture]` Windows Security 4625 retry bursts retain a common fractional-second anchor while gaps land almost exactly on integer seconds. On `WS-MCHEN-01`, five failures occur at `12:51:52.4618066`, `12:51:56.4616292`, `12:51:58.4614345`, `12:52:00.4612294`, and `12:52:16.4609814`—gaps of approximately 4, 2, 2, and 16 seconds while the fractional part stays near `.461`. `WS-PPATEL-01` shows the same construction at `.839` with gaps of 2, 2, 20, and 4 seconds, and `WS-AJOHNSON-01` has separate `.802` and `.173`-anchored clusters. Eighteen of the 20 events in multi-attempt clusters exhibit this behavior across four independent workstations. Human retries can be approximately periodic, but retaining the sub-millisecond phase across multiple attempts is a strong generated-timing signature.
- `[distribution_texture]` All 840 Security Event 4689 records across ten Windows hosts report `Status=0x0`. The records cover 62 image names, including 153 `taskhostw.exe`, 131 `WmiPrvSE.exe`, 117 `dllhost.exe`, 111 `conhost.exe`, 25 `ssh.exe`, 21 `powershell.exe`, and 14 `cmd.exe` exits. A six-hour, ten-host population this large would normally have at least a small tail of cancellation, application error, forced-termination, or exception statuses. This is not an impossible value, but the dataset-wide absence of any nonzero exit status looks like a default-value generator path.
- `[weak_signal]` All 140 Snort alerts have a matching Zeek connection tuple and are timestamped after the matching Zeek connection start. Core deltas occupy a narrow `216–325 ms` band; perimeter deltas are `105–319 ms`. A stable clock offset or alerting delay can explain this, so I assigned little weight, but the strictly one-sided and tightly bounded timing resembles an applied source-delay model more than independent packet-capture clocks.
- `[distribution_texture]` The shell histories contain 588 commands and 511 unique strings, but some exact composite commands recur across unrelated hosts and users—for example, `find /tmp -maxdepth 1 -type f | head` appears four times across four hosts, and `cat /proc/version | cut -d' ' -f1-3` appears three times across three hosts. These are plausible administrative commands and therefore only a minor indicator; the concern is exact reuse of multi-token command forms rather than ordinary repetition of `ls`, `cd`, or `sudo`.

## Evidence For Real

- Windows Security and Sysmon XML are structurally valid and source-native. The Security provider GUID, Sysmon provider GUID, channels, event versions, tasks, keywords, levels, and event-specific field sets match the event IDs present. Examples include Security 4624 v2, 4688 v2, 5156 v1, and Sysmon 1 v5, 3 v5, 5 v3, 8 v2, 10 v3, and 22 v5.
- The domain SID base is stable (`S-1-5-21-1524654518-2022274387-1755902678`), account-to-SID mappings do not collide, GUIDs are well formed, and Windows paths, process IDs, logon IDs, ports, and protocol numbers are correctly formatted for their fields.
- Process telemetry correlates exceptionally well without relying on mere source completeness as evidence. Of 1,028 Security 4688 events, 1,025 match a Sysmon Event 1 on host and PID within two seconds; every matched pair agrees on image, command line, parent PID, and parent image. The three unmatched creates are isolated and consistent with selective observation. Sysmon process GUIDs are not used before creation or after termination, and eCAR actor references stay within their visible process lifetimes.
- The `DC-01` Security-log clearing sequence is particularly source-authentic. `cmd.exe /c wevtutil cl Security` at `17:42:04.3445846Z` creates `wevtutil.exe` at `17:42:04.6265788Z`; Event 1102 follows at `17:42:08.0542673Z` using the Eventlog provider and `UserData/LogFileCleared`, with `SYSTEM`, SID `S-1-5-18`, and logon ID `0x3e7`. Its `EventRecordID` resets to 1 and subsequent visible records continue at 3, 4, and 7, which is realistic for a filtered export after a channel clear.
- Windows logon semantics are internally plausible: service logons use Type 5 and `Advapi`, network logons use Type 3 with Kerberos or NTLM, RDP uses Type 10, unlocks use Type 7, and NewCredentials uses Type 9. Visible 4634 events do not precede their matching 4624 sessions; repeated logon IDs are limited to expected unlock reuse.
- The FILE-SRV object-audit sequence has valid handle lifecycles. Handle `0x43d3159e` receives Event 4656 for `D:\Shared\Projects\2023\action-items.xlsx` at `12:04:06.225`, Event 4663 with access mask `0x2` at `12:04:06.365`, and Event 4658 at `12:04:06.455`. Across 28 handles, 24 have `4656→4663→4658` and four have `4656→4658`, with no close-before-open or identity mismatch.
- Zeek records have native field shapes and strong internal integrity. Every DNS, HTTP, SSL, SMTP, and SMB UID resolves to a same-sensor `conn.json` record with matching tuple; all SSL certificate FUIDs resolve through `files.json` and `x509.json`; HTTP transaction depths are ordered; and no protocol record falls outside its connection interval. Packet counts, lengths, connection states, histories, TLS versions/ciphers, and certificate validity windows are plausible.
- Sensor-vantage differences add realistic imperfection. The same long SSH activity can have different Zeek UIDs, packet counts, and `missed_bytes` between core and DMZ sensors rather than appearing as cloned rows. A small number of HTTP/SMB file references lack a `files.json` companion, which is compatible with file-analysis selection or packet loss.
- Higher-level network lifecycles are credible. Forty-five successful eCAR SSH sessions have an earlier matching TCP/22 flow, with authentication 5.804–17.855 seconds after transport open; all 18 Windows Type 10 RDP logons have a preceding matching TCP/3389 flow, 4.582–6.350 seconds earlier. No authentication-before-transport contradiction was found.
- All 640 explicit-proxy `tunnel_id` groups contain one CONNECT setup and one or more same-host HTTPS requests with the same client, principal, and source port. Declared tunnel byte totals equal the sum of their request records. ASA connection IDs are unique and monotonic, teardown never precedes build, and stated durations agree with the second-resolution timestamps after normal rounding.
- Source-specific timestamp precision is appropriate: Windows uses 100-nanosecond-formatted UTC, Sysmon `UtcTime` uses milliseconds, eCAR uses integer milliseconds, Zeek and Snort use microseconds, RFC 5424 syslog uses fractional UTC, and ASA/Apache-style logs use their normal second-resolution forms.

## Detailed Analysis

### Scope and parsing

The visible window is approximately `2024-03-18 12:00:01–17:59:58 UTC`. I parsed 18,199 Windows Security events and 11,552 Sysmon events from ten Windows hosts, 33,203 eCAR records from 20 endpoints, approximately 33,080 Zeek records from core, DMZ, and database sensors, 19,015 ASA messages, 2,473 proxy records, 744 web-access records, 140 Snort alerts, 3,820 Linux syslog records, and 588 shell-history commands. The XML and newline-delimited JSON inputs parsed without malformed records.

### Windows event schemas and values

The Security event types contain the expected data contracts. Event 4624 has the v2 fields through `ElevatedToken`; Event 4625 carries status/substatus, authentication package, workstation, source address/port, and process context; 4688 contains creator and target subject fields, token elevation type, mandatory-label SID, command line, and parent process; 4768/4769/4771 contain the appropriate Kerberos ticket, encryption, status, and client-address fields; and 5140/5145/5156 use their native share and WFP fields. Authentication combinations also make sense: the 804 successful logons consist of 425 Type 5, 347 Type 3, 18 Type 10, six Type 7, five Type 2, and three Type 9 records. NTLM Type 3 events use `NTLM V2` and key length 128, while Kerberos and Negotiate paths use the expected zero key-length representation.

Sysmon event contracts are similarly sound. Event 1 includes process/parent GUIDs, hashes, session and integrity metadata; Event 3 uses canonical network fields; Event 5 closes the same process GUID; Event 7 has module hashes and signature metadata; Events 8 and 10 distinguish source and target process identities; and Event 22 uses numeric DNS query status with semicolon-terminated results. Across repeated paths, Sysmon Event 1/Event 7 hashes remain stable. The 170 module-load records contain coherent software metadata, including consistent Chrome `120.0.6099.225`, Firefox `121.0`, Office `16.0.17628.20006`, and Edge `120.0.2210.144` versions.

I spot-checked the more error-prone Event 8 records. For example, `WS-AJOHNSON-01` records `ms-index-service.exe` creating a remote thread in `lsass.exe` at `15:44:59.1235530Z`, with a hexadecimal start address, `ntdll.dll`, and `NtCreateThreadEx`; benign-looking records retain source and target users and module/function fields. Event 10 has seven plausible access masks and 180 distinct call traces across 702 records rather than one universal stack. I did not find malformed addresses, missing source/target identity, or impossible process-GUID timing.

### Process and session correlation

The process chain around the Security-log clear demonstrates the three endpoint views agreeing on concrete identity. On `DC-01`, Sysmon Event 1 records PowerShell PID 5884 at `17:42:03.6876522Z`; Security 4688 records new PID `0x16fc` at `17:42:03.8414082Z` with the identical encoded command, parent PID/image, and executable; eCAR records the same PID, command line, parent, and SYSTEM principal at epoch millisecond `1710783723770`. The subsequent `cmd.exe` PID 5900 and `wevtutil.exe` PID 5936 preserve the same parent chain in all available endpoint representations. Termination then occurs in order in Sysmon Event 5, Security 4689, and eCAR.

Across the full Windows set, the Sysmon-to-Security creation delay is 35–648 ms with a median near 135 ms and a nonuniform distribution. There is no process termination before creation, no process-GUID reuse conflict, and no dependent Sysmon Event 3/7/8/10/11/13/22 outside the visible lifetime of its process GUID. These checks matter more than simple record-count alignment because they test whether a SIEM join on PID/GUID, image, parent, and time would produce contradictory results; it would not.

Logon lifecycles also survive keyed checks. All visible eCAR session closes follow their corresponding opens, and Security 4634 uses the same `TargetLogonId` as an earlier host-local 4624 except for a small number of sessions already open before the six-hour window. RDP transport precedes Type 10 authentication. SSH flows precede PAM/session login on Linux and remain open long enough for the visible session activity. I found two Kerberos TGS records tens of milliseconds before the nearest same-tuple TGT record, but concurrent requests or a cached TGT can produce that ordering; it is not an impossible KDC chain and was not scored as synthetic.

### Temporal distributions

The principal defect is not timestamp formatting but retry generation. Four independent workstations have failed interactive-logon clusters whose timestamps behave as “base fractional phase plus integer-second offsets.” On `WS-PPATEL-01`, the five-event sequence from `13:11:53.8394510Z` through `13:12:21.8394257Z` keeps the `.839` phase to within 0.249 ms despite 2, 2, 20, and 4 second gaps. On `WS-MCHEN-01`, the analogous five-event phase varies by less than 0.826 ms over 24 seconds. Windows records failures when LSASS completes authentication processing, so independent keyboard retries should not preserve a sub-millisecond phase this consistently.

The exit-code population supplies a separate long-tail check. All 840 Event 4689 records have status zero despite spanning interactive shells, remote clients, administrative utilities, COM/WMI hosts, and user applications. Lifecycle timing and PID ownership are correct, so this is not a contract error; it is a distribution that appears to have been populated from one default.

### Network, proxy, firewall, and IDS telemetry

The Zeek corpus has useful protocol and state diversity rather than a single happy-path template. Core `conn.json` includes TCP, UDP, and ICMP and states such as `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `S1`, `S2`, `S3`, and `OTH`; service labels include DNS, Kerberos, HTTP, LDAP, SMB, SSL, syslog, SSH, DHCP, SMTP, RDP, and DCE/RPC. DMZ and database sensors emphasize SSL/HTTP and MySQL in ways consistent with their positions. No negative duration, invalid packet-accounting relationship, impossible TLS cipher/version combination, or invalid certificate time range was found.

The Snort record at `03/18-12:02:20.435523` for UDP `10.10.2.25:55778 → 10.10.2.11:53` matches Zeek core UID `CWoWuHPVUkAxOXOMC6` at epoch `1710763340.209636`; the BitTorrent alert at `12:17:54.284927` matches the TCP connection `10.10.2.21:48501 → 34.104.145.3:6881` in state `S3`. All 140 alerts resolve similarly. This completeness was not counted as a synthetic indicator; only the narrow, always-positive relative delay was retained as a weak timing signal.

Proxy semantics are unusually detailed and internally correct. Tunnel `PT-00000000173974c3` starts with CONNECT to `fonts.signalwire.app:443` at `12:57:58`, then carries four HTTPS GETs with the same client `10.10.1.22`, source port 40515, and tunnel ID; request byte sums equal the CONNECT record's declared `tunnel_cs_bytes` and `tunnel_sc_bytes`. The broader proxy population includes tunnels, inspected sessions, forwarded HTTP, denials, authentication challenges, and gateway failures. ASA build/teardown and NAT-translation messages use valid message families (`302013/14`, `302015/16`, `302020/21`, `305011/12`, and `106023`) and maintain connection ordering.

### Behavioral and environmental texture

The host roles and observed services are coherent: Kerberos/LDAP/DNS concentrate on domain controllers, SMB object access on the file server, MySQL on the database path, proxy transactions on `PROXY-01`, and public HTTP/scanner traffic on `WEB-EXT-01`. Windows service installation and account-management records use appropriate event types and ordering—for example, account creation, password reset, group membership, and later deletion on `DC-01`; service installs use 4697 with credible service type, start type, account, and image fields.

Linux RFC 5424 logs include SSH/PAM/logind lifecycles, sudo open/close pairs, CRON, package maintenance, systemd, NetworkManager, kernel/UFW, printing, queue pressure, and hardware-daemon noise. Shell histories contain chronological reversals compatible with multiple shells appending history, which is a useful production-like imperfection. The exact reuse of a few composite commands slightly weakens the long tail, but most commands are unique and the duplicates are operationally plausible.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Windows Security 4625 | 18 of 20 events in multi-attempt clusters across four workstations | Highest impact: integer-second retry offsets preserve a sub-millisecond phase across independent attempts, strongly suggesting scheduled generation. |
| `distribution_texture` | Windows Security 4689 | 840 of 840 exits, 62 executable names, ten hosts | Moderate impact: the total absence of nonzero exit statuses removes an expected production long tail and resembles a universal default. |
| `weak_signal` | Snort and Zeek | 140 alerts; all Snort timestamps 105–325 ms after matched Zeek starts | Low impact: narrow one-sided timing could indicate a source-delay model, but clock skew or alert latency remains a reasonable explanation. |
| `distribution_texture` | Bash history | 588 commands across Linux hosts; several exact multi-token commands reused by unrelated users | Low impact: vocabulary reuse is visible, but the overall command set is diverse and the repeated commands are plausible. |

No `hard_contradiction` was identified. I also did not find a material `schema_or_format`, lifecycle, ownership, or source-observation defect; the verdict is driven by distribution texture rather than broken contracts.

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Sysmon, Zeek, eCAR, syslog, proxy, ASA, Apache, and Snort records are structurally credible with source-appropriate values and precision.
- **Temporal patterns:** 5 — Causal ordering is strong, but fractional-phase-preserving failed-logon retries are a pronounced synthetic timing signature.
- **Cross-source correlation:** 9 — PID/GUID, logon, UID/FUID, tunnel, flow, handle, and lifecycle joins agree without impossible ordering; isolated gaps are collection-plausible.
- **Behavioral realism:** 6 — Host activity and protocol behavior are broad and role-aware, but all-zero process exits and a small reused command pool weaken the expected long tail.
- **Environmental consistency:** 9 — Host roles, services, traffic direction, source coverage, and source-specific volumes form a coherent enterprise environment.

## Recommendations

- If this were synthetic, generate each authentication attempt from its own event-time and processing-delay model. Avoid retaining a burst's original fractional-second phase when adding retry delays; incorporate human think time, UI submission latency, LSASS/KDC processing variance, and scheduler noise independently per attempt.
- If this were synthetic, sample process exit codes by executable class and termination cause. Preserve normal `0x0` as the majority, but include a small, correlated tail for cancellation, killed processes, application failures, and exceptions, with the same result reflected wherever another source exposes termination reason.
- If this were synthetic, model IDS and network-sensor clocks separately using stable per-sensor offsets plus slow drift and occasional synchronization corrections. Packet-derived timestamps should not all receive a strictly positive per-record delay in the same narrow band unless that collection behavior is explicitly represented.
- If this were synthetic, expand shell-command construction at the parameter and pipeline level so unrelated users do not repeatedly select identical composite commands. Repetition should follow shared runbooks, scripts, aliases, or host roles when it occurs.
- Preserve the existing Windows event contracts, 1102 channel-reset behavior, keyed process/session lifecycles, multi-sensor Zeek differences, proxy tunnel accounting, and source-specific timestamp formats; these are the strongest realism features in the dataset.
