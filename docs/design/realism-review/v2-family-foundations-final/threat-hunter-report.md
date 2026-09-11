# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 66

## Executive Summary

The dataset is operationally convincing: endpoint, authentication, proxy, firewall, and Zeek evidence support several technically feasible hunt paths amid substantial background noise. I nevertheless assess it as synthetic because of concrete process-lifecycle contradictions, collapsed shell-pipeline ownership, and repeated human-command texture that looks generated rather than organically produced.

## Evidence For Synthetic

- `[hard_contradiction]` In `WEB-EXT-01.../ecar.json`, PID `1480939` is created at `2024-03-18 13:20:25.781Z` with `bash -c 'echo ... | base64 -d | bash'`; the decoded payload launches another Bash reverse shell. No `base64` or descendant Bash process is recorded, yet the `10.10.3.10:59311 -> 45.33.32.30:8443` socket at `13:20:29.389Z` is attributed directly to outer PID `1480939`. A real pipeline necessarily creates at least the decoder and downstream shell, and this source elsewhere records pipeline children separately.
- `[hard_contradiction]` `WS-AJOHNSON-01.../ecar.json` creates PowerShell PID `6496` at `17:19:40.220Z`, terminates it at `17:19:40.246Z`, and then records five DLL loads by that same process from `17:19:40.256Z` through `.293Z`. Loading `kernel32.dll`, `kernelbase.dll`, `ucrtbase.dll`, `advapi32.dll`, and `rpcrt4.dll` 10–47 ms after termination is impossible as event-occurrence ordering.
- `[distribution_texture]` One Aisha Johnson session on `WEB-EXT-01` executes 34 primary administrative commands in 219 seconds, with a 6.18-second median gap. It jumps through package checks, filesystem searches, Apache/PHP/SSH diagnostics, service restarts, VM statistics, firewall inspection, and repeated commands across several simultaneous shells—far more like a generated command pool than organic troubleshooting.
- `[distribution_texture]` Exact command templates recur across otherwise distinct users and hosts during the six-hour window: three users on three hosts execute identical `sudo /usr/bin/find /etc/systemd/system -maxdepth 2 -type l`, identical `sudo /usr/bin/lsof -i -P -n`, and identical `sudo /usr/bin/tail -n 40 /var/log/syslog`; `sudo /usr/bin/apt-cache policy openssl` appears four times across three hosts and three users.
- `[environment_or_collection_plausibility]` There are no port-123 connections in 14,861 Zeek connection rows or 23,190 eCAR rows, despite visible `chronyd -F 2` activity and chrony state-file writes on `DB-PROD-01`. A six-hour, multi-OS domain environment with otherwise broad flow visibility would normally expose at least some NTP synchronization.
- `[weak_signal]` The apparent Aisha staging sequence reads roughly 17.4 MB over SMB into `VaultCache`, creates `cache_7f3a.zip`, and later posts 314,782,800 bytes to `/upload/telemetry/7f3a2b19`. The proxy does not name the uploaded file, so this is not a hard contradiction, but the shared `7f3a` identifier and timing leave the apparent staged-versus-uploaded volume poorly reconciled.

## Evidence For Real

- The reverse-shell transport is tightly but naturally aligned: eCAR records the endpoint flow at `13:20:29.389Z`, Zeek sees it at `13:20:29.412Z` for 24.305 seconds, and ASA records the connection at `13:20:29` with teardown at `13:20:53`.
- SSH and file-transfer pivots remain usable across sources. At `17:28:16.956Z`, `DB-PROD-01` runs `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`; eCAR records `10.10.4.10:50218 -> 10.10.2.30:22`, the receiver records the matching inbound tuple and root SSH session, and the destination file appears at `17:28:27.785Z`.
- The large proxy upload has credible accounting across observation points. The proxy reports `cs_bytes=314782800`; the client-to-proxy Zeek leg has `orig_bytes=314783323`, the upstream leg has `orig_bytes=315494352`, and ASA totals are consistent after protocol and proxy overhead.
- The DC Security log behaves correctly when cleared. `cmd.exe /c wevtutil cl Security` and `wevtutil.exe` appear at `17:41:38`; Event 1102 follows at `17:41:41.853Z`, and `EventRecordID` resets from `28260889` to `1` before resuming monotonically.
- DHCP renewals follow lease semantics with per-client jitter: 3,600-second leases recur near 1,800 seconds, 7,200-second leases near 3,600 seconds, and 14,400-second leases near 7,200 seconds.
- TLS evidence has realistic reuse and diversity. The DMZ sensor contains 2,151 SSL rows with TLS 1.2/1.3 variation, 760 resumed sessions, repeated certificate fingerprints, reusable intermediates, and coherent SNI/certificate relationships.
- The suspicious activity is embedded in meaningful noise: Kerberos and LDAP traffic, SMB access, mail delivery, user browsing, proxy tunnels, UFW blocks, DHCP renewals, routine service processes, inbound scanning, and failed authentication are all visible.

## Detailed Analysis

### Scope and collection profile

The observation window is approximately `2024-03-18 12:00–18:00Z`. It covers 18 endpoint identities across workstation, domain-controller, file, mail, application, database, proxy, and DMZ-web roles. The principal sources are 23,190 eCAR records, 10,549 Windows Security events, 3,572 Sysmon events, 14,861 Zeek connections, 2,628 proxy rows, 18,259 ASA rows, two Snort views, Linux syslog, web access, and Bash history.

The volume is sufficient to require real pivoting. Suspicious events do not stand alone in an empty exercise feed, although baseline process and command diversity is much thinner than the network diversity.

### Hunt paths and tradecraft

At `13:20:25.781Z`, Apache on `WEB-EXT-01` launches a base64-decoded reverse shell toward `45.33.32.30:8443`. Network telemetry confirms a successful 24-second session. A root SSH session from `10.10.1.99` follows at `13:39:46.829Z`; commands enumerate interfaces, hosts, resolver settings, credentials, and `10.10.2.0/24` with `nmap`.

A separate Windows-centered trail is also coherent. `WS-AJOHNSON-01` runs `whoami /all`, domain enumeration commands, and `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords"`. Subsequent DC activity creates `svc_dirsync`, adds it to Domain Admins, creates `DeviceSyncSvc`, establishes a scheduled task, stages data through SMB, performs a large proxy upload, and clears the DC Security log. The account-management, process, service, task, transport, and log-clear evidence is technically plausible.

On the Linux server path, root logs into `DB-PROD-01`, enumerates databases, executes `mysqldump --single-transaction ehr patients insurance_claims`, compresses the result, hashes it, and transfers it to `APP-INT-01` over SCP. The command syntax, privileges, destination, tuple, and receiver artifact agree.

These coherent narratives are not themselves synthetic indicators. They are evidence that the data models useful hunt pivots.

### Process and lifecycle coherence

Most paired eCAR lifecycles are orderly: no observed process termination precedes its matching create, and no observed logout precedes its matching login. Boundary-only unpaired events are not penalized.

The two exceptions materially affect authenticity. The reverse-shell pipeline collapses several required process identities into its outer Bash PID, including socket ownership. Separately, PowerShell PID `6496` receives five module-load events after its recorded termination. The latter is localized, but it is a direct event-order contradiction rather than merely incomplete visibility.

### Cross-source and byte coherence

Network tuples generally align to sub-second precision without being timestamp-identical. Proxy legs correctly separate client-to-proxy and proxy-to-origin identities, while Zeek and ASA byte totals reflect payload plus transport overhead. The SCP transfer similarly preserves source port `50218` across sender, receiver, and network evidence.

The weaker point is file-volume continuity around `cache_7f3a.zip`. Five parsed SMB reads total 8,774,303 bytes, and a second ClinicalExports connection carries about 8.65 MB. The later proxy POST carries 314.8 MB. Pre-existing directory content or a different upload could explain this, so it remains a weak signal rather than a contradiction.

### Baseline and collection realism

Network behavior has convincing entropy: variable connection durations, failures, retransmission histories, TLS resumption, certificate reuse, external scanning, mail flow, and browser/proxy bursts. DHCP timing is especially credible.

Human shell behavior is less convincing. The 34-command Aisha session compresses unrelated administrative actions into 219 seconds, while several exact command lines recur across distinct administrators and systems. Common runbooks can cause repetition, but the breadth, exact spelling, and short shared window create a generator-like texture.

The total absence of NTP is also conspicuous because chronyd state activity is visible and the same sensors observe other DB, server, and domain traffic. It is not independently decisive, but it weakens the collection profile.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---|---|
| `hard_contradiction` | Linux eCAR | One reverse-shell execution | Required pipeline children are absent and the socket is assigned to the wrong process layer. |
| `hard_contradiction` | Windows eCAR | PowerShell PID 6496 | Five module loads occur 10–47 ms after process termination. |
| `distribution_texture` | Linux eCAR/Bash activity | Multiple users and hosts | Fast, wide-ranging command burst and exact cross-user command templates resemble a shared generator pool. |
| `environment_or_collection_plausibility` | Zeek/eCAR network | Dataset-wide | No NTP transport appears despite chronyd evidence and broad network visibility. |
| `weak_signal` | SMB, endpoint, proxy | One staging/upload sequence | Apparent staged and uploaded volumes differ by roughly an order of magnitude without visible reconciliation. |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Zeek, ASA, proxy, DHCP, TLS, and syslog structures are largely source-native and internally detailed.
- **Temporal patterns:** 6 — Most cross-source offsets are credible, but post-termination module loads and the compressed command burst are notable defects.
- **Cross-source correlation:** 8 — Tuples, source ports, session identities, proxy legs, and byte accounting align unusually well without relying on exact timestamp equality.
- **Behavioral realism:** 6 — Attack tradecraft is workable, but the shell-pipeline ownership and repeated administrator command texture reduce authenticity.
- **Environmental consistency:** 7 — Host roles, subnets, services, and baseline traffic fit together, with NTP absence as the main collection anomaly.

## Recommendations

If this were synthetic, the following changes would improve it:

- Model shell pipelines as real process trees and assign sockets to the descendant process that actually opens them.
- Enforce process-lifecycle ordering so module loads, file actions, and dependent activity cannot occur after termination.
- Expand administrator behavior with user-specific habits and runbooks; reduce exact command reuse across unrelated users and avoid dense, unrelated command bursts unless explicitly modeled as automation.
- Add role-appropriate NTP traffic, or provide source-visible evidence that time synchronization uses an unobserved route or non-NTP mechanism.
- Carry canonical artifact sizes from SMB reads through archive creation and proxy upload so staged and transmitted byte volumes reconcile, or visibly distinguish the uploaded object.
