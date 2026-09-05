# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 64

## Executive Summary

The dataset presents a technically convincing intrusion amid substantial background activity, and most major pivots can be followed across endpoint, network, firewall, proxy, and host-audit sources. I nevertheless assess it as synthetic because the decisive root-SSH pivot chain repeatedly has rich receiver-side lifecycle evidence but only anonymous source-side endpoint flows, while several unrelated Linux histories reuse unusually specific diagnostic commands in a template-like fashion.

## Evidence For Synthetic

- `[contract_gap]` The three root SSH pivots that carry the intrusion forward are anonymous on the initiating endpoint despite eCAR coverage on every source host. At `2024-03-18 13:39:59.532 UTC`, `WS-OHADDAD-01` records only a FLOW from `10.10.1.22:44149` to `10.10.3.10:22`, with no PID, principal, actor ID, image, or command line; `WEB-EXT-01` then records `sshd: root [priv]`, a successful root login at `13:40:05.632`, and a root shell. The pattern repeats for `WEB-EXT-01:50885 -> APP-INT-01:22` at `14:15:04.808` and `APP-INT-01:37296 -> DB-PROD-01:22` at `17:54:25.868`: each receiver has a detailed root SSH process/session/shell lifecycle, but each monitored source has only an unattributed FLOW and no `/usr/bin/ssh` process. This repeated asymmetry affects the exact operational pivots rather than ordinary thin coverage.
- `[distribution_texture]` Linux shell histories reuse several unusually specific commands across unrelated users and hosts within the six-hour window. Exact repetitions include `udevadm info --query=property --name=/dev/null | head` on `LOG-MON-01`, `MAIL-CLIN-01`, and `MAIL-EDGE-01`; `find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head` on `APP-INT-01`, `DB-PROD-01`, and `PROXY-01`; and `netstat -an | grep ESTABLISHED | wc -l` on three systems. Common commands naturally recur, but `/dev/null` udev inspection is an odd routine check, and the exact syntax recurring three times looks drawn from a shared pool.
- `[contract_gap]` The `WS-AJOHNSON-01` staging sequence has muddled process/session ownership. A Type 9 session at `17:01:25.383` is locally attributed to `aisha.johnson` with outbound credentials for `marcus.chen`, created by `C:\Windows\System32\svchost.exe`; the ensuing malicious PowerShell processes run as Aisha but are parented by that NETWORK SERVICE `svchost.exe`. File staging immediately afterward is attributed instead to an existing `explorer.exe` under Aisha's older interactive logon ID. Token impersonation can produce unusual ancestry, but the split ownership across the new Type 9 context, service parent, and old interactive explorer context is not cleanly explained by the visible evidence.
- `[weak_signal]` The `WS-AJOHNSON-01` collection command copies `\\WS-AJOHNSON-01\C$\ProgramData\Microsoft\cache_7f3a.zip` back onto the same host at `17:17:50.516`, then the later curl upload reads the original `C:\ProgramData\Microsoft\cache_7f3a.zip` rather than the copied Temp artifact. A self-admin-share copy is possible, but here it has no visible operational purpose and resembles an inserted lateral/file-transfer step.

## Evidence For Real

- The initial compromise is unusually well grounded in independent evidence. `WEB-EXT-01` logs a successful `POST /ehr/admin/upload.php` from `185.70.41.45` at `13:20:24`; at `13:20:26.257` Apache spawns a `www-data` shell with a base64-decoded reverse-shell command; at `13:20:36.715` that process connects from `10.10.3.10:46196` to `45.33.32.30:8443`. Zeek observes the same tuple at `13:20:36.599` with an `SF` state and `18.829156`-second duration, while the ASA builds the connection at `13:20:36` and tears it down at `13:20:55` after 18 seconds.
- The reconnaissance behavior has believable execution and transport texture. On `WEB-EXT-01`, root runs `nmap -sn 10.10.2.0/24`, producing 252 ICMP attempts over 3.757 seconds, then `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24`, producing 1,262 endpoint flows over 8.507 seconds. Zeek records the burst with a realistic mixture dominated by `S0`, plus `REJ`, `RSTO`, `RSTR`, and a small set of `SF` connections rather than marking all probes successful.
- The database theft lifecycle is coherent. `DB-PROD-01` accepts root SSH from `APP-INT-01`, executes MySQL discovery, creates `/tmp/rpt_0318.sql` with `mysqldump`, compresses and hashes it, and sends it by SCP to `/tmp/.cache/rpt_0318.sql.gz` on `APP-INT-01`. The receiver creates the file, then the same named artifact is written through SMB to `FILE-LNX-01`; Zeek `smb_files.json` and `files.json` preserve the share path, size (`779214` bytes), FUID, and cryptographic hashes.
- The Windows phase has useful host pivots rather than isolated indicators: account creation and Domain Admins membership for `svc_dirsync`, service and scheduled-task persistence for `DeviceSyncSvc`, execution under SYSTEM, subsequent encoded PowerShell, Security-log clearing, and account cleanup are visible in Security, Sysmon, and eCAR records.
- Exfiltration through the explicit proxy is measurable and plausible. The proxy-origin connection from `10.10.3.20:60315` to `45.33.32.30:443` at approximately `17:25:28 UTC` carries about 18.8 MB outbound; Zeek and ASA agree on the tuple, direction, duration, and order of magnitude.
- The source volume is credible for a six-hour enterprise slice: 33,805 eCAR records across 18 endpoint directories, 20,004 ASA lines, more than 20,000 Zeek connection records across core/DMZ/database sensors, and substantial Windows Security/Sysmon telemetry. Ordinary browsing, Kerberos/LDAP, DNS, SMB, mail, DHCP, external scanning, service activity, failures, scheduled jobs, and administrator sessions materially dilute the attack evidence.

## Detailed Analysis

### Environment and collection window

The visible window runs from approximately `2024-03-18 12:00:00 UTC` through `17:59:58 UTC`. The environment contains Windows workstations, two domain controllers, Windows and Linux file/mail/application/database systems, an internet-facing web server, an explicit proxy, a monitoring host, perimeter firewall and Snort sources, and Zeek sensors covering core, DMZ, and database segments. Addressing and roles are stable enough to hunt: workstations occupy `10.10.1.0/24`, core servers are primarily `10.10.2.0/24`, the DMZ uses `10.10.3.0/24`, and `DB-PROD-01` is `10.10.4.10`.

### Intrusion reconstruction

The first high-confidence malicious event is the successful upload to `/ehr/admin/upload.php` at `13:20:24`, followed 2.257 seconds later by Apache PID `23958` creating bash PID `1480939` as `www-data`. The decoded command is a reverse shell to `45.33.32.30:8443`; eCAR, Zeek DMZ, and the perimeter ASA show the same connection beginning near `13:20:36` and ending near `13:20:55`. This prerequisite-to-effect chain is operationally sound.

At `13:39:59`, a new SSH transport arrives at the web server from `WS-OHADDAD-01` (`10.10.1.22`), and by `13:40:05` the target has a successful root session and shell. Root performs network and resolver discovery, searches `/opt/ehr` for credential material, then runs ICMP and TCP sweeps against `10.10.2.0/24`. At `14:15:04`, the web server opens SSH to `APP-INT-01`; the application server accepts root at `14:15:18`, and the shell later reads `/etc/passwd` and `/etc/shadow`. The network sequence and target-side session timings are plausible, but the absence of source-side SSH process ownership at both hops is the first major authenticity break.

The later Windows activity includes directory/account manipulation and service persistence on the domain controllers, plus document collection and proxy upload from `WS-AJOHNSON-01`. The events are highly pivotable, but the workstation's Type 9/service-parent/interpreter ownership is difficult to reconcile from the visible logon and process contexts. This is not a complaint that the evidence is complete; the problem is that the visible ownership fields point to three different execution contexts for one staging action.

At `17:54:25`, `APP-INT-01` opens SSH to `DB-PROD-01`, which accepts root at `17:54:35`. The subsequent SQL discovery, dump creation, compression, hash, SCP transfer, and SMB staging are all temporally ordered and supported by file and network evidence. As before, however, `APP-INT-01` contains no source SSH process for the transport that created the receiver's root session. The third recurrence makes this look like a generation/observation contract rather than a one-off sensor loss.

### Signal-to-noise and behavioral texture

The attack does require active hunting: routine Kerberos, LDAP, DNS, SMB, web, proxy, mail, service, and interactive activity dominate most sources, and internet scanner traffic creates useful competing noise around the web server. User behavior is somewhat differentiated—for example, developer-oriented commands for `lina.nguyen`, database work for `omar.haddad`, and infrastructure checks for `marcus.chen`. The baseline is therefore much stronger than a minimal exercise dataset.

The shell-history pool is the main texture weakness. Repeated basics such as `whoami` or `df` are harmless, but the exact reuse of niche pipelines, particularly querying udev properties for `/dev/null`, is difficult to explain as independent organic behavior across different users and servers in six hours. Repeated `systemctl restart sshd` activity on several systems adds to that impression, although it is weaker evidence by itself.

### Pivot feasibility and collection consistency

DNS, connection, firewall, endpoint, proxy, SMB, and file pivots generally work and use compatible timestamps, addresses, ports, sizes, and identities. Sensor-to-sensor timestamps differ by small, believable observation offsets, and the bounded window contains both incomplete lifecycles and properly paired short sessions without requiring every state object to begin or end in view.

The root SSH pivots are different from ordinary collection incompleteness. Each source host has eCAR process telemetry for many mundane binaries and even records the exact outbound transport, while each target records the SSH daemon process, source tuple, login, shell, commands, and logout. Repeating the omission only on the initiating side of all three consequential root hops materially weakens operational provenance and is my largest score driver.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---|---|
| `contract_gap` | eCAR SSH/process/session | Repeated across three root pivots | High: monitored sources expose the transport but omit the process and actor that initiated every consequential root hop. |
| `distribution_texture` | Linux bash history | Repeated across unrelated hosts/users | Medium: niche diagnostic commands recur with identical syntax in a short window. |
| `contract_gap` | Windows Security/eCAR process ownership | One multi-event staging sequence | Medium: Type 9, service-parent, local principal, outbound principal, and explorer file ownership do not form one clear execution context. |
| `weak_signal` | Windows file/process activity | One event sequence | Low: a self-admin-share copy creates an unused duplicate of the staged archive. |

## Realism Score by Category

- **Field format accuracy:** 8 — The reviewed fields, paths, identifiers, tuples, and commands are mostly source-appropriate and internally usable.
- **Temporal patterns:** 9 — Attack and background timing are varied, and the principal execution/network/file sequences obey plausible order and latency.
- **Cross-source correlation:** 7 — Most pivots correlate strongly, but all three root SSH hops lack source process ownership despite rich endpoint coverage.
- **Behavioral realism:** 6 — Tradecraft is technically credible, while repeated niche admin commands and the self-copy reduce organic texture.
- **Environmental consistency:** 8 — Host roles, network segments, source volumes, and the overall collection mix are largely believable.

## Recommendations

- If this were synthetic, model outbound SSH from the initiating endpoint as a complete source-side process/transport lifecycle. The source should expose the shell parent, `/usr/bin/ssh` process, user or root context, command line, source port, and termination corresponding to the receiver's accepted session; apply this consistently to workstation-to-web, web-to-application, and application-to-database pivots.
- Diversify Linux administrative histories by user role and host purpose, and remove niche exact-string reuse across unrelated actors. Commands such as udev inspection of `/dev/null` should appear only when an event on that host gives them an operational reason.
- Keep Windows Type 9 and impersonated execution ownership explicit across session, parent process, child process, and file events. If a service creates a process under a user token with alternate outbound credentials, preserve enough context to explain that transition and avoid attributing adjacent staging files to an unrelated older explorer session.
- Remove the self-admin-share copy unless its destination is subsequently consumed, or make the subsequent upload/read use the copied Temp artifact so the visible operation has a concrete purpose.
