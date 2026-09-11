# Threat Hunter — Authenticity Assessment

## Verdict (Assessment: Synthetic|Real|Inconclusive, Verdict Confidence, Synthetic-Confidence Score)

- **Assessment:** Synthetic
- **Verdict Confidence:** 78/100
- **Synthetic-Confidence Score:** 66/100 — likely synthetic

## Executive Summary

The corpus is highly realistic in format, volume, background noise, and multi-source attack reconstruction. Windows process and session lifecycles are internally sound; network sessions have varied outcomes and durations; host roles produce credible service-specific noise; and the principal intrusion paths are operationally pivotable from endpoint to authentication, network, proxy, and server evidence.

The synthetic assessment rests on concrete defects rather than coverage or unusually complete correlation. Most importantly, one exact proxied HTTP transaction has a Referer value in both Zeek observations that contradicts the proxy's record of the same request, even though Referer values are normally retained by that proxy log. Two unrelated shell workflows also inspect named archive outputs before the logs show the commands that create those outputs. Finally, a recurring set of future-year, formulaic SMB paths—including nonstandard GPO-like paths in NETLOGON and SYSVOL—looks catalog-composed rather than organically accumulated. These indicators outweigh the strong realism, but not by enough for an 81–100 confidently-synthetic score.

## Evidence For Synthetic

1. **[hard_contradiction] The same HTTP request has incompatible Referer values across sources.** At `2024-03-18 16:28:07 UTC`, `zeek-core/http.json:1176` records a POST from `10.10.1.21:33699` to `support.valeworks-health.net/api/v1/cases/MHS-48217/attachments`, user agent `curl/7.81.0`, body length `1573258`, and `referrer="https://www.reddit.com/"`. `zeek-dmz/http.json:1313` records the same client-side transaction with the same Referer. The matching proxy record, `PROXY-01.meridianhcs.local/proxy_access.log:1759`, has the same client, second, method, URI, status, user agent, and approximately corresponding client bytes (`cs_bytes=1573373`), but its Referer field is `"-"`. This is not a global parser difference: an exact join over client, second, method, and URI produced 1,571 Zeek/proxy request pairs; 1,570 Referer values agreed and only this request disagreed. The initiating process at `WS-LNGUYEN-01.meridianhcs.local/ecar.json:526` is `/usr/bin/curl ... --form ...` with no `--referer`, `-e`, or header argument. A hidden curl configuration is theoretically possible, but it would not explain why both Zeek sensors saw the header and the proxy handling that request did not.

2. **[contract_gap] The DB archive is inspected before its recorded creation.** In `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history:12-22`, root runs `mysqldump` at epoch `1710782094`, then `sha256sum /tmp/rpt_0318.sql.gz` at `1710782100` and `du -h /tmp/rpt_0318.sql.gz` at `1710782111`, but does not invoke `gzip -9 /tmp/rpt_0318.sql` until `1710782112`. Endpoint telemetry agrees that `mysqldump` starts at `2024-03-18 17:14:54.310 UTC` (`ecar.json:548`), `gzip` starts at `17:15:12.935` (`:554`), and `/tmp/rpt_0318.sql.gz` is created only at `17:15:16.883` (`:555`). The hash and size commands could simply have failed, so this is not treated as impossible execution. It is nevertheless an operationally backward sequence embedded in an otherwise carefully coordinated collection-and-exfiltration workflow.

3. **[distribution_texture, contract_gap] A second host repeats the pre-creation inspection pattern.** `WS-LNGUYEN-01.meridianhcs.local/bash_history/lina.nguyen.bash_history:52-54` invokes `file /tmp/mhs-support-48217.tar.gz` at `2024-03-18 15:32:00 UTC` and `du` at `15:32:11`. The archive-producing `tar -czf` does not appear until `16:27:21` (`:76`); eCAR starts tar at `16:27:22.459` and records the file creation at `16:27:26.213` (`ecar.json:522-523`). A pre-existing file could explain this host in isolation, but the recurrence of the same output-before-production sequence in two unrelated workflows is a stronger synthetic planning artifact than either instance alone.

4. **[environment_or_collection_plausibility, distribution_texture] SMB names contain a conspicuous future-year template family.** In a capture dated `2024-03-18`, `zeek-core/smb_files.json` contains 33 records covering 16 distinct names with `2025`, `2026`, or `2027`. Examples include `\\DC-01\NETLOGON\Preferences\2026\policy.ps1` at `12:09:09.264` (`:8`), `\\DC-02\NETLOGON\Machine\2025\gpt.xml` at `13:45:43.386` (`:39-40`), `\\DC-02\NETLOGON\User\2027\startup-final.ps1` at `14:07:14.785` (`:53-54`), and `\\DC-01\SYSVOL\Policies\2027\groups-v2.pol` at `17:06:56.291` (`:168`). Future-year business folders can be legitimate. The weaker point is their repeated coupling with formulaic suffixes such as `-v2`, `-final`, `-review`, and `-draft`, plus nonstandard year-oriented GPO-like locations under NETLOGON/SYSVOL.

5. **[weak_signal] One staging step is operationally redundant.** `WS-AJOHNSON-01.meridianhcs.local/ecar.json:1316` runs a self-UNC copy at `2024-03-18 17:17:03.705 UTC`, copying `\\WS-AJOHNSON-01\C$\ProgramData\Microsoft\cache_7f3a.zip` to the user's temporary directory. The later curl process at `17:25:27.833` and file read at `17:25:30.900` (`:1348`, `:1355`) upload the original `C:\ProgramData\Microsoft\cache_7f3a.zip`, not the copied file. This could be credential validation or abandoned staging and is therefore weighted only as a weak signal.

## Evidence For Real

1. **Network lifecycle texture is strong.** The ASA log contains 6,355 TCP build records and 6,351 teardowns, with only four sessions still open at the end of the slice. Parsed build/teardown direction and identity were coherent, and teardown causes were varied: 4,045 FIN, 2,118 SYN timeout, 129 `Reset-O`, and 59 `Reset-I`. Across `zeek-core/conn.json`, `zeek-db/conn.json`, and `zeek-dmz/conn.json`, no overlapping reuse of an active TCP five-tuple was found. Zeek states include `SF`, `RSTO`, `RSTR`, `S0`, `S2`, and `S3`, with varied durations, byte counts, histories, and missed-byte values.

2. **Endpoint lifecycles hold up under graph-style checks.** Across all eCAR files, process termination never precedes the matching `PROCESS/CREATE`, session logout never precedes login, and no dependent actor reference occurs after its process terminates. Duplicate process-create, process-terminate, session-login, and session-logout identities were absent. Across all Windows Sysmon files, no process termination preceded creation and no child creation occurred after the recorded parent termination. Executable hashes were stable for the same image within host/OS cohorts without being implausibly universal across different builds.

3. **The credential-theft-to-domain-compromise chain is operationally coherent.** On `WS-AJOHNSON-01`, eCAR starts `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` at `2024-03-18 15:45:04.530 UTC` (`ecar.json:846`), then records LSASS access with `granted_access="0x1FFFFF"` at `15:45:08.194` and a remote thread at `15:45:08.277` (`:856-857`); Sysmon independently exposes the process and command line at `windows_event_sysmon.xml:12248-12254`. On `DC-01`, the later PsExec sequence records `C:\Windows\PSEXESVC.exe` creation at `15:59:44.960`, service creation at `15:59:45.227`, service start at `15:59:52.185`, and child `cmd.exe /c whoami && hostname` at `15:59:52.569` (`ecar.json:3478`, `:3480`, `:3482`, `:3488`). Security event data independently contains the PSEXESVC service and process fields (`windows_event_security.xml:173090-173220`).

4. **Persistence and cleanup can be pivoted across process and audit evidence.** On `DC-01`, command telemetry creates `svc_dirsync`, adds it to Domain Admins, creates `DeviceSyncSvc`, and registers a scheduled task (`ecar.json:3664-3802`). The Security log contains the corresponding account, group, service, and task fields around `windows_event_security.xml:182415-187304`. At `17:42:23.625`, eCAR starts `wevtutil cl Security` (`ecar.json:5363`), and Security event 1102 appears at `17:42:34.7208375Z`; its `EventRecordID` resets to `1` (`windows_event_security.xml:265232-265239`). The attacker later invokes deletion of `svc_dirsync` at `17:49:31` (`ecar.json:5509-5514`).

5. **Exfiltration accounting is unusually useful but physically plausible.** The AJOHNSON archive is created at `17:01:02.374` (`ecar.json:1258`), read by curl at `17:25:30.900`, and connected through the proxy on source port `51904` at `17:25:31.313` (`:1355-1356`). Zeek records the CONNECT on the same client port at `17:25:31.950` (`zeek-core/http.json:1472`). Proxy lines `2177-2178` use the same port and tunnel ID, with `18,782,896` client tunnel bytes and a successful POST. This is a viable hunt pivot, not merely duplicated labels.

6. **The Linux DB-to-staging lifecycle has credible transport timing.** `DB-PROD-01` creates the SQL dump at `17:14:56.566`, creates the gzip output at `17:15:16.883`, starts scp at `17:15:23.113`, opens `10.10.4.10:45291 -> 10.10.2.30:22` at `17:15:26.375`, and reads the archive at `17:15:32.873` (`ecar.json:549`, `:555`, `:557-559`). The corresponding Zeek TCP session begins at `17:15:25.882` and lasts `39.860` seconds. Receiver-side APP telemetry records inbound transport, SSH login, file creation, and logout in a sensible order.

7. **Background activity is role-aware and noisy.** Linux syslog includes Postfix/Dovecot on mail hosts, Samba and audit activity on the Linux file server, DB multipath activity, workstation NetworkManager/dhclient/desktop services, and web-host firewall noise. Windows Security mixes logons/logoffs, Kerberos service and ticket activity, process auditing, and WFP connections. DHCP leases vary by client (`3,600`, `7,200`, and `14,400` seconds) and renew near half-life with jitter. Web traffic includes varied status codes (`200`, `206`, `301`, `302`, `304`, `403`, `404`, `429`), while IDS and firewall records include failures, resets, timeouts, and benign noise rather than only storyline-positive events.

## Detailed Analysis

The collection spans roughly six hours beginning at `2024-03-18 12:00 UTC` and represents Windows endpoint/audit data, Linux endpoint/syslog/bash history, multiple Zeek observation points, ASA firewall events, proxy access records, web access records, and two Snort sensors. The breadth was not counted as evidence by itself. The assessment instead tested whether identities, tuples, sessions, timing, byte accounting, and source-native fields remained plausible when pivoted between those sources.

For operational lifecycle coherence, the corpus performs well. Windows attack processes have sensible parents and termination boundaries. Remote administration shows transport before target execution. SSH sessions have transport, authentication, shell/process work, file movement, and closure. TCP state and teardown distributions are nonuniform and include incomplete sessions at the capture boundary. These properties materially reduce synthetic appearance because they survive relationship checks rather than merely matching on names.

Signal-to-noise is also credible. The malicious activity is discoverable but embedded among browser, mail, SMB, authentication, package-management, monitoring, DNS, and routine server traffic. Hunting pivots are practical: LSASS access leads to the suspect executable and user session; the source IP and SMB/RPC traffic lead to the target service installation; the service leads to account and scheduled-task changes; archive file identity leads to curl, proxy, and egress byte counts. Ambient scanner and web-probing activity creates realistic competing alerts.

The decisive negative evidence occurs where source contracts should be independent. The support POST's single Referer mismatch is more probative than generic perfect correlation because the proxy and Zeek are rendering the same HTTP header differently, and the mismatch is isolated inside an otherwise 99.94% agreement set. The two archive-order anomalies are weaker individually—history records commands, not success, and pre-existing files are possible—but their repeated structure across unrelated hosts suggests that command plans were assembled with an ordering defect. The future-year SMB family adds moderate environmental texture evidence, particularly where arbitrary year directories appear inside GPO-like shares.

No material broad schema failure was found: JSON records parsed, Windows XML was structurally readable, Zeek fields were type-consistent for their logs, and source-specific timestamps and identifiers had plausible forms. The conclusion is therefore not that the telemetry is crude. It is that a sophisticated synthetic corpus likely contains a small number of generation-contract and catalog-texture leaks.

## Synthetic Indicator Summary

| Category | Weight | Concrete indicator | Benign alternative considered |
|---|---:|---|---|
| hard_contradiction | High | Zeek reports Reddit Referer while the exact proxy request reports `-`; 1,570/1,571 comparable pairs agree | Proxy-specific suppression, though contradicted by its preservation of Referers on other requests |
| contract_gap | Medium-high | DB hashes/sizes `.sql.gz` before invoking gzip and before endpoint creation telemetry | Commands may fail; merged shell history or an earlier file is possible |
| distribution_texture | Medium | A second host inspects a ticket archive about 55 minutes before tar creates it | A stale archive may have existed before the observed slice |
| environment_or_collection_plausibility | Medium-low | 33 SMB records/16 names use 2025–2027 folders in a March 2024 slice, including GPO-like shares | Future planning folders and arbitrary SYSVOL content are possible |
| schema_or_format | No adverse finding | Source formats parse and generally preserve native field conventions | N/A |
| weak_signal | Low | Self-UNC copies an archive to Temp, but exfiltration reads the original | Credential validation, abandoned staging, or operator error |

The score does not rely on filesystem timestamps, sanitized domains, absent event types, source coverage, or complete cross-source matching.

## Realism Score by Category (Field format accuracy, Temporal patterns, Cross-source correlation, Behavioral realism, Environmental consistency, each 1-10)

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 9/10 | Strong Windows XML, Zeek JSON, ASA, proxy, web, syslog, and eCAR structure; one HTTP-header contradiction |
| Temporal patterns | 7/10 | Good jitter, lifecycle ordering, lease timing, and varied transport duration; archive command ordering is suspect |
| Cross-source correlation | 9/10 | High-quality pivots across endpoint, audit, proxy, firewall, and multiple Zeek views, with plausible source latency |
| Behavioral realism | 7/10 | Credible attacker progression and background activity; repeated pre-output checks and unused self-copy reduce realism |
| Environmental consistency | 7/10 | Host roles, addressing, services, and collection topology are coherent; year-templated SMB/GPO-like paths are artificial-looking |

## Recommendations

1. Validate the support POST against raw packet data, if available. Presence or absence of the HTTP `Referer` header on `10.10.1.21:33699` would resolve the strongest authenticity discriminator.
2. Obtain command exit status, terminal output, or file metadata for the two pre-creation archive checks. A `No such file` result would confirm failed, backward command sequencing; evidence of a pre-existing inode would weaken this indicator.
3. Compare the observed SYSVOL/NETLOGON paths with an authoritative directory listing or Group Policy inventory. Determine whether the `2025`-`2027` paths are genuine organizational content or synthetic catalog entries.
4. Preserve the existing pivotable relationships and background-noise mix in any future test corpus. If this is synthetic telemetry, correct the HTTP-header contract and command-plan ordering without making source timestamps or coverage artificially exact.
5. For hunting use, prioritize the concrete chain: `ms-index-service.exe` LSASS access → AJOHNSON session → SMB/RPC to `DC-01` → PSEXESVC → `svc_dirsync`/DeviceSync persistence → proxy check-ins and archive uploads. This chain remains analytically useful regardless of authenticity.
