# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 97
**Synthetic-Confidence Score:** 89

## Executive Summary

The dataset is impressively parseable and internally correlated, but it contains two strong generator fingerprints: several endpoint product versions did not yet exist on the universal March 18, 2024 evidence date, and hashes for nominally identical vendor builds vary with the username-bearing installation path. A dataset-wide Windows 4624 service-logon field pattern adds a source-native defect, while otherwise accurate Windows, Zeek, syslog, and eCAR structures prevent the score from being still higher.

## Evidence For Synthetic

- `[hard_contradiction]` Sysmon Event ID 1 records dated March 18, 2024 identify multiple builds released after that date. Examples include Visual Studio Code `1.89.1` at `2024-03-18T14:05:43.2097371Z`, DBeaver `24.0.5` at `14:06:07.0818783Z`, Docker `26.1.1` at `14:06:12.4225473Z`, and Postman `11.2.14` at `15:06:05.4419038Z` on `WS-MCHEN-01`. The same problem appears on other hosts: Webex `44.4.0.28421` at `13:29:31.0625980Z` on `WS-SMARTINEZ-01`, Zoom `6.0.11.39959` on three workstations, and Google Drive `97.0.1.0` on three workstations. This is not an isolated stale or malformed version string; it is a cross-vendor temporal impossibility in a dataset whose Windows, Zeek, proxy, web, SMTP, firewall, and syslog clocks all agree on March 18, 2024.
- `[hard_contradiction]` Sysmon content hashes behave as though installation path or user identity contributes to the digest. The same `Zoom.exe` version `6.0.11.39959` has SHA-256 `6D48DD...EAFC88` for Aisha, `A3B44F...B48D63` for Marcus, and `5EBB1B...0ACA5C` for Sophia; all four recorded algorithms, including IMPHASH, change. The same occurs for Teams `24124.2315.3009.6699` (Diego SHA-256 `1CA527...0077E` versus Marcus `31274F...F7B2`), Slack `4.38.125` (Aisha `31CDFF...0D93F` versus Sophia `210EFF...390F3`), and OneDrive `24.070.0407.0003` (Aisha `FE9E70...53CB0` versus Diego `6401D2...42E1`). Per-user paths should not alter the bytes or import table of the same signed vendor executable build. The systematic multi-product pattern would corrupt allowlisting, reputation, and hash-based detection.
- `[schema_or_format]` All 325 successful Windows service logons (`4624`, `LogonType=5`) populate `WorkstationName` with the destination computer's own short name. For example, `DC-01` at `2024-03-18T12:01:55.2118589Z` reports `WorkstationName=DC-01`, and `WS-AJOHNSON-01` at `12:57:03.4905274Z` reports `WorkstationName=WS-AJOHNSON-01`, while both correctly show `Advapi`, `Negotiate`, `services.exe`, and `IpAddress/IpPort=-`. Native local service logons normally leave the network-origin workstation field as `-`; universal self-host population across every server and workstation is a template artifact.
- `[distribution_texture]` The hash defect has a particularly generator-like boundary: ordinary system executables with the same path/build remain stable across like-version hosts, while per-user applications acquire different values when the username segment changes. That is much more consistent with deriving hashes from identity/path inputs than with measured file content.
- `[weak_signal]` Shell-history commands show modest pool reuse across otherwise separate users and hosts: 234 commands contain only 185 unique strings, with exact commands such as `hostname`, `uptime`, `groups`, `free -h`, and `journalctl --since '10 min ago' --no-pager -n 20` repeated two or three times. These are common administrator commands and are not decisive alone, but the repetition reinforces the stronger generator evidence.

## Evidence For Real

- Windows event envelopes and per-ID payloads are unusually accurate. Security `4624` uses Version 2 and the expected 28-field layout; `4688` uses Version 2 with `ParentProcessName` and `MandatoryLabel`; `5156` uses Version 1; and success/failure keywords, tasks, channels, provider GUIDs, SID forms, hexadecimal LogonIDs, and IPv4-mapped IPv6 addresses are well formed.
- Process correlation is excellent without being observation-perfect. Across the nine Windows hosts, every observable Security `4688` has a matching Sysmon Event 1 by PID and image, with creator SID/user, LogonID, parent PID, and parent image agreeing; paired timestamps are normally within 20 ms. A few deliberate-looking gaps exist, such as Security `4688/4689` for PID 6872 (`ssh.exe`) on `WS-AJOHNSON-01` without corresponding Sysmon 1/5 and a Sysmon-only OneDrive updater lifecycle on `WS-EBROOKS-01`, which resembles real collection loss rather than forced completeness.
- Sysmon lifecycle semantics are coherent. Across 1,003 observed Event 1 process creates, I found no matching Event 5 before its create and no dependent Event 3/7/10/11/13/22 after a known terminate. Process GUIDs are syntactically valid, host-specific, and encode plausible creation-time components.
- Windows session correlation is strong. Logoff `4634` records match earlier `4624` LogonIDs and logon types whenever the session began inside the six-hour window; the few unmatched closes are at-window lifecycle edges. `4672` privilege events reuse the successful session LogonID, and local/system/service SIDs remain stable across hosts.
- The DC's `1102` audit-log-clear record at `2024-03-18T17:42:18.8498896Z` correctly switches provider to `Microsoft-Windows-Eventlog`, uses `UserData/LogFileCleared`, resets `EventRecordID` to 1, and is followed by record IDs 2, 3, 5, and 9 as filtered collection continues. This is a convincing source-native detail.
- Zeek correlation is strong. Both sensors have unique connection UIDs (6,408 core and 5,467 DMZ); every DNS, HTTP, and SSL UID resolves to a same-sensor `conn.json` record with the identical 4-tuple, and every file `conn_uids` reference resolves. No protocol child precedes its connection or falls materially beyond its interval. Connection states and histories are varied (`SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `S1/S2/S3`, `OTH`) and packet/IP-byte accounting passes basic invariants.
- Protocol detail is credible: DNS includes A, AAAA, PTR, TXT, SRV, NS, MX, and SOA with NOERROR/NXDOMAIN/SERVFAIL/REFUSED; TLS mixes 1.2 and 1.3 with valid cipher names and certificate-file links; DHCP uses correlated UDP/67-68 REQUEST/ACK renewals; SMTP message IDs, recipients, relay paths, and file IDs align with the connection layer.
- RFC 5424 syslog is parser-friendly and semantically rich. For example, `APP-INT-01` records an SSH connection from `10.10.1.35:60674` at `12:01:55.521828Z`, acceptance at `12:01:57.717047Z`, PAM open at `12:01:57.767203Z`, logind session creation at `12:01:58.360389Z`, then ordered close/removal at `12:22:57.792880Z` and `12:22:58.880662Z`. User UIDs remain consistent across Linux hosts.
- eCAR records use valid JSON lines, millisecond integer timestamps, UUID-shaped IDs, stable object/action vocabulary, and coherent actor/process/session properties. Endpoint FLOW tuples are usable for SIEM correlation, while omission of actor identity on some flows looks like plausible observation texture rather than malformed data.

## Detailed Analysis

### Scope and ingest behavior

The evidence covers approximately `2024-03-18 12:00:00Z` through `18:00:00Z` and 17 named endpoints: nine Windows systems with Security, Sysmon, and eCAR; eight Linux systems with syslog, bash history, and eCAR; two Zeek sensors; an ASA firewall; two Snort views; a proxy; and a public web server. All JSON-line files parsed cleanly, every Windows XML document parsed as a namespaced `Events` container, and RFC 5424/syslog plus conventional access-log records are directly ingestible.

### Windows schema and Event ID checks

I sampled and programmatically grouped every Windows event by Event ID, metadata tuple, and EventData field set. The available Security IDs include `1102`, `4624/4625/4634/4648/4672/4688/4689`, `4697/4698`, `4720/4724/4726/4728/4738`, `4768/4769/4771/4776`, `4800/4801`, and `5156`; Sysmon includes Events `1`, `3`, `5`, `7`, `8`, `10`, `11`, `13`, and `22`. Within an ID, field order and names are stable and generally faithful to the native manifest.

Representative process correlation is strong. On `WS-AJOHNSON-01`, Security `4689` at `12:01:15.4800225Z` terminates PID `0x13fc` (`5116`) at `C:\Windows\System32\OpenSSH\ssh.exe`, while Sysmon Event 5 at `12:01:14.8634116Z` names PID `5116`, the same image, user `MERIDIANHCS\aisha.johnson`, and a well-formed ProcessGuid. Across all hosts, the maximum matching `4688`-to-Sysmon-1 delta was about 149 ms, and field identity was exact. Termination deltas varied more naturally, up to about 1.92 seconds.

Logon fields are mostly strong: Type 2 uses `User32/Negotiate`, Type 7 unlocks use local addresses, Type 10 records preserve remote source addresses, Type 3 differentiates Kerberos and NTLM, and Type 5 uses `Advapi/Negotiate/services.exe`. The repeated Type 5 `WorkstationName=<self>` behavior is the important exception. A production SIEM detection using `WorkstationName` to distinguish local service starts from remote authentication would be fed misleading values on every Type 5 event.

### Temporal software and hash validity

The endpoint product inventory breaks the stated time plane. This is visible in ordinary Sysmon Event 1 fields, not inferred from the suspicious storyline: March 18 evidence contains a collection of post-March product builds across Microsoft, Docker, DBeaver, Postman, Cisco/Webex, Zoom, and Google. The breadth rules out a single vendor backport or one incorrect resource version.

Hash stability is the most damaging detection-engineering defect. Hashes are stable when image path/build are stable, but change across username-bearing paths for the same exact product version. All SHA-1, MD5, SHA-256, and IMPHASH fields change together. A real file's digest is a function of bytes, not its pathname; three different IMPHASH values for the nominally identical Zoom build additionally imply three different import tables. Possible localized or repackaged binaries might explain an isolated SHA-256 difference, but they do not credibly explain the same systematic behavior across Zoom, Teams, Slack, and OneDrive.

### Zeek and network-source checks

I loaded each Zeek family and joined protocol records to connections. Core contains 6,408 connections, 2,250 DNS, 1,039 HTTP, 110 SSL, 328 files, 69 DHCP, 67 SMTP, 76 X.509, and 7 OCSP records. DMZ contains 5,467 connections, 774 DNS, 1,232 HTTP, 1,583 SSL, 592 files, 471 X.509, and 42 OCSP records. UIDs are unique per sensor, protocol tuples match their connection tuples, and timestamps sit inside plausible connection intervals.

For example, core UID `CZzWHDfzjBgCfZO2zG` identifies `10.10.1.21:36229 -> 10.10.2.26:587`; its SMTP record at `12:08:50.564466Z` and TLS record at `12:08:51.026996Z` agree on that tuple and show a STARTTLS transition. Core DHCP UID `CXpoLxcFUfO2BrUG1Q` records `10.10.1.22:68 -> 10.10.2.10:67`, one request and one response packet, then a REQUEST/ACK lease row two milliseconds later. These are useful, detection-ready correlations.

The traffic is not unrealistically all-successful: core states include 6,161 `SF`, 84 `RSTO`, 57 `RSTR`, 44 `REJ`, 29 `S0`, plus smaller `S1/S2/S3/OTH`; DMZ has 1,280 `S0` alongside 3,937 `SF` and other failures. Basic byte/packet invariants hold. The certificate and OCSP structures use appropriate scalar/vector types and valid epoch times.

### Linux, eCAR, and behavioral texture

Linux sources retain convincing lifecycle ordering and fixed host process identities. SSH connection, authentication, PAM, logind, and close records use the same source tuple and session ID; `sudo` open/close pairs are ordered; cron, anacron, journald, package, resolver, rsyslog, snap, DBus, and IRQ noise provide useful non-attack texture. Central users retain the same numeric UID across systems (`aisha.johnson=2528`, `marcus.chen=4119`, `lina.nguyen=5302`).

eCAR is structurally consistent across all hosts. The first visible `WS-AJOHNSON-01` FLOW at `timestamp_ms=1710763311364`, for example, supplies a string-valued UDP tuple, direction, process, principal, image, and command line. The next SSH FLOW omits actor/PID rather than inventing late process ownership, which is believable endpoint collection behavior. PROCESS CREATE/TERMINATE and USER_SESSION LOGIN/LOGOUT records preserve UUID identities and session properties.

The behavioral baseline has a long enough tail to be useful, though shell history still shows some shared command-pool texture. I treat that only as weak supporting evidence because common operational commands naturally recur.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---:|---|
| `hard_contradiction` | Sysmon Event 1 | Multiple products on at least four hosts | Post-March-2024 builds appear in universally March 18, 2024 telemetry; this is a cross-vendor temporal impossibility. |
| `hard_contradiction` | Sysmon Event 1 hashes | Zoom, Teams, Slack, OneDrive across multiple users | Same-version vendor executables change all content hashes and IMPHASH with username-bearing paths, strongly indicating derived rather than measured hashes. |
| `schema_or_format` | Windows Security 4624 | 325 of 325 Type 5 logons across nine hosts | Local service logons universally put the destination's own name in the network-origin `WorkstationName` field. |
| `distribution_texture` | Sysmon process metadata | Dataset-wide path/build boundary | Stable common-path binaries but user-dependent hashes create a repeated generator-shaped rule. |
| `weak_signal` | Bash history | 234 commands across Linux hosts | Modest exact command reuse suggests a finite pool, but the commands are generic and not independently decisive. |

## Realism Score by Category

- **Field format accuracy:** 7/10 — XML/JSON/source fields parse well, but service-logon workstation semantics and non-content-derived hashes are material detection defects.
- **Temporal patterns:** 5/10 — Event ordering and timing are strong, but future software builds make the global March 2024 time plane impossible.
- **Cross-source correlation:** 9/10 — Process, session, UID, tuple, file, and lifecycle joins are exceptionally coherent with a few believable observation gaps.
- **Behavioral realism:** 8/10 — Host roles, user tools, failures, maintenance, and protocol behaviors are varied; shell-command reuse is only a mild concern.
- **Environmental consistency:** 5/10 — Host OS families and roles cohere, but the anachronistic multi-vendor inventory and path-sensitive hashes substantially damage environment credibility.

## Recommendations

1. If this were synthetic, make product inventory time-aware: store a release date (and preferably signing timestamp) with every executable build and reject any process event where the selected build postdates the scenario clock. Cover both PE metadata and version-bearing installation paths in the validation.
2. Generate hashes from a canonical binary/build artifact identity, never from hostname, username, installation path, event ID, or RNG scope. The same vendor build/architecture/language must yield the same SHA-1, MD5, SHA-256, and IMPHASH everywhere; intentional binary variants must carry a corresponding build, architecture, language, or signature distinction.
3. Correct 4624 Type 5 rendering so local service logons use source-native `WorkstationName=-` unless a real authentication package observation supplies a workstation value. Add an Event-ID/logon-type matrix test covering LogonProcess, AuthenticationPackage, ProcessName, workstation, IP, and port.
4. Add temporal and content-identity linting to dataset QA: compare event time against software/certificate validity, group executable records by product/version/architecture, and flag divergent hashes or IMPHASH values without an explicit binary-variant reason.
5. Retain the strong existing correlation behavior—especially ProcessGuid lifecycle ordering, partial observation gaps, Zeek UID/tuple integrity, audit-log record-ID reset, and SSH session ordering—while expanding shell-command selection from role- and task-specific histories to reduce exact cross-user reuse.
