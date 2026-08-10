# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 34

## Executive Summary

The host telemetry is mostly production-like: Windows Security, Sysmon, and eCAR preserve process identity and ordering, Linux SSH sessions have source-native lifecycle detail, and host roles produce visibly different process and service mixes. I found no hard lifecycle contradiction in the bounded six-hour window; the main synthetic pressure comes from a few repeated distribution patterns, especially the low-diversity UFW block stream on `WEB-EXT-01` and unusually frequent, broadly shared Windows maintenance-process/script motifs.

## Evidence For Synthetic

- `[distribution_texture]` `WEB-EXT-01.meridianhcs.local/syslog.log` contains 1,021 UFW block records in six hours but only 10 source IPs. Two sources each account for 179 records, and the stream draws from only 19 destination ports, three TCP window sizes, nine TTL values, and five packet lengths. Repeated scanners are realistic, but this much volume from such a compact attribute pool gives the perimeter-host noise a generated texture.
- `[distribution_texture]` `wsqmcons.exe` is unusually recurrent on Windows servers: 16 creates on `DC-01` (median interarrival 19.5 minutes), 10 on `FILE-SRV-01` (33.3 minutes), and 11 on `MAIL-FIN-01` (23.5 minutes). The broad process trees are otherwise varied, but this legacy telemetry executable is overrepresented as routine background churn.
- `[environment_or_collection_plausibility]` Nineteen SYSTEM PowerShell launches across nine Windows hosts use only `C:\Scripts\service-health.ps1` or `C:\Scripts\backup-check.ps1`, generally as direct children of `services.exe`. A PowerShell-backed service is possible, but the same two scripts and parent shape recurring on workstations, a domain controller, file server, and mail server looks more standardized than most lived-in fleets.
- `[weak_signal]` Eight Linux hosts repeatedly emit the identical sysstat chain `CRON -> /bin/sh -> /usr/lib/sysstat/debian-sa1`, normally 10–12 times per host. This is consistent with a Debian-family default and is not suspicious alone, but its uniformity adds slightly to the broader repeated-background-pattern concern.

## Evidence For Real

- Across 18 eCAR files there are 1,626 process creates and 1,444 terminates. Of these, 1,319 object IDs form visible create/terminate pairs; none terminate before their visible create. The 307 visible creates without termination and 125 terminations without visible creates are reasonable boundary effects in a six-hour slice.
- The same bounded check for eCAR sessions found 896 visible login/logout pairs with zero reverse-order pairs. There are 347 logins without a visible logout and 23 logouts without a visible login, which is plausible for long-running service, network, and interactive sessions crossing the collection boundaries.
- Windows process correlation is strong without being literally complete. Across nine Windows hosts, 836 Security 4688 events matched Sysmon Event 1 by PID and image within five seconds; only seven Security creates and two Sysmon creates were source-local exceptions. Matched Security/Sysmon timestamps were generally within about 22 ms, while eCAR observations arrived later by roughly 0–1.4 seconds in most samples, a plausible endpoint-observation delay.
- Process ownership is coherent. No visible eCAR child was created before its visible parent or after that parent terminated, and no overlapping reuse of the same PID was found. Examples include `explorer.exe -> firefox.exe` for `aisha.johnson` at `2024-03-18T12:02:38Z`, `cmd.exe`/PowerShell spawning OpenSSH clients on the admin workstations, `sshd -> bash -> administrative command` chains on Linux servers, and role-specific processes such as Exchange, Postfix, PostgreSQL/MySQL, proxy, and web-service activity.
- Sysmon process records have source-native detail: ProcessGuid/ParentProcessGuid, logon identity, session ID, command line, file metadata, four hash algorithms, and parent identity agree with Security 4688 and eCAR on sampled processes. Identical images remain hash-stable within each host; cross-host variants group by host rather than changing per process.
- Linux SSH evidence is rich and ordered. I found 102 same-PID sequences containing connection, acceptance, PAM open, and PAM close; 11 close-only records occur at the left collection boundary and seven sessions remain open at the right boundary. Failed sessions also use credible pre-auth sequences, for example `APP-INT-01` PID 949999 at `2024-03-18T12:41:03Z` records connection, invalid user, failed password, and pre-auth close.
- User and host behavior is differentiated. `WS-LNGUYEN-01` shows Chrome, Git, Cargo, SSH, GNOME terminal, and SMB browsing; `WS-PPATEL-01` shows Outlook, Chrome, VPN, and office-oriented activity; admin workstations show many SSH/RDP launches; servers show role-specific processes and substantially different logon and flow volumes.
- Windows lock/unlock semantics are convincing. On `WS-AJOHNSON-01`, Event 4800 at `17:19:47Z` is followed by a type 7 4624 and Event 4801 at `17:35:30Z`, all retaining logon ID `0x265b8f5`; `WS-SMARTINEZ-01` shows the same reuse and ordering for `0xc107bbc`.

## Detailed Analysis

### Collection scope and lifecycle

The endpoint set covers 18 hosts from approximately `2024-03-18T12:00Z` through `18:00Z`: nine Windows systems with Security, Sysmon, and eCAR, and nine Linux systems with syslog and eCAR. I treated this strictly as a bounded window. Missing left-edge creates/logins and right-edge terminates/logouts were neutral unless the same identifier had an impossible visible order; none did.

At the eCAR layer, 1,319 process identities have a visible create followed by termination. Parent checking also found no visible child-before-parent, child-after-parent-termination, or overlapping PID interval. The unmatched lifecycle edges are not concentrated into an impossible shape: Linux daemons and shells, Windows services, persistent user applications, and network/service sessions naturally cross the boundaries.

Windows Security logons also preserve order. Examples of paired type 3 duration distributions are broad rather than fixed: `DC-01` has 386 visible pairs with median 18.94 seconds and range 0.99–4,769.35 seconds; `FILE-SRV-01` has 344 with median 30.59 seconds and range 1.17–4,001.26 seconds. Remote interactive type 10 sessions last thousands of seconds, while workstation type 2 sessions run for hours. That separation by session purpose is realistic.

### Windows process and source correlation

The nine Windows hosts contain 843 Security 4688 records and 838 Sysmon Event 1 records. Matching by PID, image, and time produced 836 pairs. Representative source-local gaps include a Security-only `dllhost.exe` on `WS-DRAMIREZ-01` at `12:32:43Z` and a Sysmon-only `cmd.exe` on `WS-MCHEN-01` at `15:12:06Z`; these small gaps look like collection texture rather than broken identity.

The `WS-AJOHNSON-01` Firefox launch illustrates the normal correlation. Security 4688 at `12:02:38.5582985Z` records PID `0x14d8`, parent PID `0x1388`, `explorer.exe`, user `aisha.johnson`, logon ID `0x24dcd22`, and the Google Docs command line. Sysmon Event 1 at `12:02:38.5556074Z` records PID 5336, the same image and command line, parent PID 5000, the same user/logon ID, plus stable hashes and process GUIDs. eCAR observes the same process at millisecond timestamp `1710763359293`, retaining the same parent process UUID and session identity.

Background process trees generally fit Windows semantics: `services.exe` owns service binaries, `SearchIndexer.exe` owns search filter/protocol hosts, `csrss.exe` owns console hosts, `svchost.exe` owns WMI/task/COM-related children, and explorer owns interactive applications. The repeated `wsqmcons.exe` population and direct `services.exe -> powershell.exe` maintenance scripts are the notable texture exceptions rather than widespread tree corruption.

### Linux evidence

Linux syslog has credible role variation. `MAIL-EDGE-01` includes Postfix, Dovecot, SSH, resolver, cron, and package/service activity; `DB-PROD-01` includes SSH, multipath, database-client commands, and storage messages; `WEB-EXT-01` includes public-facing UFW rejects, web-service maintenance, and SSH; desktop systems include NetworkManager, DHCP, GNOME, package, firmware, printing, and user-session activity.

SSH lifecycle evidence is particularly strong. Successful sessions retain the sshd PID from connection through acceptance and PAM open, then close on that PID after variable durations. On `DB-PROD-01`, PID 121876 connects from `10.10.1.31:60141` at `12:12:49Z`, accepts Marcus Chen's ECDSA key at `12:12:51Z`, opens PAM immediately, and closes at `12:27:04Z`. Concurrent sessions use separate PIDs and source ports, and password versus public-key methods vary by user.

The UFW block stream is plausible in kind but compressed in diversity. Across 1,021 records its median interarrival is 10.823 seconds, with gaps from 0.002 to 567.743 seconds, so timing is not mechanically periodic. The stronger concern is categorical reuse: 10 sources, 19 ports, three window sizes, and fixed-looking TTL/length traits for dominant sources.

### User, role, and environmental behavior

The activity does not use one universal endpoint profile. Windows user processes differ by persona and workstation; Linux developer/admin desktops differ from mail, proxy, web, app, and database servers; and server logon volumes are materially larger than endpoint volumes. The environment also contains realistic routine texture such as failed/stale credentials, lock/unlock cycles, DHCP renewal chatter, scheduled sysstat collection, service health activity, package components, and inbound scan noise.

The main environmental concern is excessive reuse of a compact maintenance vocabulary. The same two PowerShell script paths appear 19 times on nine Windows hosts, and server-side `wsqmcons.exe` runs recur much more frequently than expected. Neither is impossible, but together they reduce the sense that each host accumulated its own operational history.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Linux syslog/UFW | 1,021 records on one public host | High-volume perimeter noise is drawn from only 10 sources and a small packet-attribute pool. |
| `distribution_texture` | Windows Security/Sysmon/eCAR process telemetry | Three servers plus several workstations | `wsqmcons.exe` appears unusually often, with server medians of roughly 20–33 minutes between launches. |
| `environment_or_collection_plausibility` | Windows process telemetry | 19 launches on nine hosts | Two PowerShell maintenance scripts recur across dissimilar roles with the same direct `services.exe` ownership shape. |
| `weak_signal` | Linux syslog/eCAR | Eight hosts | Identical sysstat command chains recur 10–12 times per host; plausible distro behavior, but low-entropy background texture. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Sysmon, eCAR, and RFC5424-like syslog fields are detailed and source-appropriate in sampled records.
- **Temporal patterns:** 8 — Lifecycles and source delays are coherent and durations vary by behavior, with only some repeated background families looking overused.
- **Cross-source correlation:** 9 — Security, Sysmon, and eCAR preserve PID/image/session identity with realistic small source-local gaps and no impossible visible order.
- **Behavioral realism:** 8 — Process trees, SSH sequences, user roles, and session-duration classes are convincing; shared maintenance pools reduce long-tail individuality.
- **Environmental consistency:** 7 — Host roles and source volumes broadly fit, but UFW source diversity and fleet-wide maintenance motifs are narrower than expected.

## Recommendations

- If this were synthetic, expand public-host UFW noise using a substantially longer-tailed source population and per-source behavior profiles. Preserve scanner persistence, but vary port portfolios, TTLs, packet lengths, TCP windows, burst lengths, and one-off sources so 1,000+ rejects are not dominated by a ten-source pool.
- Reduce `wsqmcons.exe` frequency, especially on servers, and make its scheduling conditional on OS version, telemetry configuration, and host role. Favor less conspicuous, role-native background processes for recurring churn.
- Diversify fleet maintenance ownership and vocabulary. Model some health checks as Task Scheduler children, management-agent children, service binaries, WMI activity, or no visible PowerShell at all; vary script paths and deployment by host class instead of placing the same two scripts across nine dissimilar Windows systems.
- Retain the current bounded lifecycle and correlation behavior. In particular, preserve source-local observation gaps, positive eCAR delay, stable process/hash identity, variable SSH and logon durations, and the rule that no visible dependent event precedes its same-identifier initiator.
