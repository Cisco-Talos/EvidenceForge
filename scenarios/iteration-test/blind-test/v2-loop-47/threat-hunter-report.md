# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 79
**Synthetic-Confidence Score:** 52

## Executive Summary

The collection is operationally convincing in many respects: it has believable enterprise noise, workable pivots across endpoint, authentication, network, proxy, and firewall sources, and several technically coherent suspicious lifecycles. Two concrete defects keep it out of the production-like range: a large proxied upload loses roughly 25 MB between the client and proxy-origin legs, and two SSH sessions execute session-tagged commands before their session shells exist while reusing the same unrelated parent identity.

## Evidence For Synthetic

- `[contract_gap]` The 17:24:59 UTC proxied upload is byte-incompatible across its two visible network legs. `zeek-dmz/conn.json` records 44,025,877 origin bytes for `10.10.1.35:50989 -> 10.10.3.20:8080` (UID `CaVejAvxWVJ0Edov4O`), and `PROXY-01.../proxy_access.log` reports `cs_bytes=44025410` for the POST under tunnel `PT-00000000a93f2b92`; however, the corresponding `10.10.3.20:54839 -> 45.33.32.30:443` TLS leg (UID `C0zQKB0rheGUB1ITcJ`) carries only 18,813,517 origin bytes. The two legs start 0.192 seconds apart, last 9.296/9.290 seconds, and the proxy reports HTTP 200, so the roughly 25.2 MB loss is not explained by a deny, retry, cache hit, or truncated transaction.
- `[hard_contradiction]` On `WEB-EXT-01`, SSH session `351031` logs `ip addr show` at 13:39:51.283 UTC with parent PID `23967`, parent image `/bin/bash`, and source process UUID `625ae27c-b394-4ce0-bcd7-17cf735878e9`; the actual session shell (`-bash`, PID `1485099`) is not created until 13:39:51.947. Session `353197` repeats the defect: `shred -u /root/.bash_history` starts at 17:40:27.957 with the same PID `23967` and source UUID, while its session shell (PID `1513161`) appears at 17:40:28.534. Distinct SSH sessions and logon IDs cannot both inherit their first command from the same unrelated shell identity before their own server-side shell exists.
- `[environment_or_collection_plausibility]` A short 15:39:04-15:39:10 UTC burst originates from domain-controller address `10.10.2.11` and probes several systems on 445, 3389, 22, and 8080. `zeek-core/conn.json` shows completed but tiny RDP handshakes to `10.10.1.35` and `10.10.1.32`, plus failed RDP attempts to Linux addresses; corresponding `DC-02.../ecar.json` FLOW rows have no initiating process identity. A DC acting as a broad service scanner is possible, but the host role and tightly bundled port sweep make this a weak environmental tell rather than standalone proof.

## Evidence For Real

- The six-hour window contains a credible source and volume mix for the visible environment: 19 endpoint directories, three Zeek observation points, perimeter ASA telemetry, two Snort alert streams, proxy access, web access, Windows Security/Sysmon, Linux syslog/bash history, and eCAR. Baseline traffic is materially larger than the suspicious sequence, including Kerberos, LDAP, SMB, DNS, browser/CDN traffic, software updates, scheduled activity, external scans, failed authentication, and service traffic.
- The initial web compromise pivots cleanly. `WEB-EXT-01.../web_access.log` records `185.70.41.45` POSTing `/ehr/admin/upload.php` at 13:19:41 UTC; eCAR observes the inbound HTTPS flow at 13:19:42.187, Apache spawning a base64-decoding `/bin/bash` at 13:19:42.527, and that process connecting to `45.33.32.30:8443` at 13:19:46.689. `zeek-dmz/conn.json` and the ASA log independently show the same `10.10.3.10:45829` C2 tuple and approximately 25.9-second lifetime.
- The later SSH and discovery lifecycle is mostly strong. Syslog shows password authentication for root from `10.10.1.35:58495`, PAM open, and logind session `351031`; eCAR then ties `/etc/hosts`, resolver inspection, `find`, `nmap -sn`, and `nmap -sT` to the session shell. Zeek exposes the resulting ICMP discovery and TCP service scan with realistic mixed `SF`, `S0`, `REJ`, and reset outcomes rather than depicting every target as live.
- Windows remote execution is pivotable. Around 16:00:21-16:00:35 UTC, eCAR on `DC-01` shows a network logon from `10.10.1.35`, SMB/RPC traffic, creation of `C:\Windows\PSEXESVC.exe`, service installation, execution under SYSTEM, and `cmd.exe /c whoami && hostname`. The ordering and host/account semantics are consistent with PsExec-style lateral movement.
- The client side of the later collection/exfiltration sequence is internally coherent despite the proxy-origin byte defect: eCAR records staged files, `Compress-Archive`, creation and subsequent read of `C:\ProgramData\Microsoft\cache_7f3a.zip`, `curl.exe`, and the exact client-to-proxy tuple. The proxy log preserves user, destination, method, URI, tunnel, and upload size, providing useful hunting pivots.
- Background endpoint behavior is not monolithic. Windows workstations show different interactive users and application mixes, while Linux systems include sysstat, package/update activity, cron/timers, SSH administration, service-specific commands, and external-facing firewall noise. Repeated commands exist, but they are limited and often naturally attributable to standard administration.

## Detailed Analysis

### Scope, source mix, and signal-to-noise

The visible collection runs from approximately 12:00:01 to 17:59:54 UTC on 18 March 2024. It covers eight Windows workstation/laptop-like systems, Windows infrastructure including two domain controllers, a file server and mail server, multiple Linux application/mail/file/monitoring systems, a proxy, a web server, and network sensors. The principal Zeek connection volumes are 10,960 core, 7,847 DMZ, and 434 database records; eCAR FLOW records number roughly 23,866. These volumes make the suspicious activity discoverable but not isolated from routine authentication, browsing, infrastructure, server, and Internet-background noise.

The largest ten-minute network spike is explained by observed attack tooling rather than an unexplained generator pulse. At 13:47:23.974 eCAR creates `/usr/bin/nmap` with `nmap -sn 10.10.2.0/24`, followed by ICMP observations across the subnet; at 13:48:36.269 it creates the service scan. The core sensor consequently records 1,827 connections in the 13:40-13:50 bucket, dominated by `10.10.3.10` and `S0`, while still retaining replies and resets for responsive hosts.

### Operational lifecycle and pivots

The web compromise, reverse connection, SSH access, network discovery, credential access, Windows remote execution, persistence, staging, and exfiltration can be followed through multiple independent sources. The important positive is not merely that sources correlate; their visible ordering is generally feasible. The web request precedes Apache's child process, the child precedes its C2 connection, SSH transport precedes authentication and session open, scan process creation precedes scan traffic, and PsExec transport/service installation precedes target command execution.

The SSH lifecycle has one repeated ownership flaw. In both root sessions on `WEB-EXT-01`, authentication and the canonical session login occur before the first command, but the first command is emitted before the session's `/bin/bash` process and points to PID `23967`/UUID `625ae27c-b394-4ce0-bcd7-17cf735878e9`. Later commands in session `351031` correctly use shell PID `1485099` and its UUID. The recurrence in session `353197`, with a different SSH daemon PID, shell PID, logon ID, and source address, makes this more than harmless collection latency: the command's declared parent relationship itself is wrong.

### Tradecraft and host-role plausibility

The observed commands are executable and recognizable: Apache-to-bash command execution, root SSH, host and resolver enumeration, Nmap discovery/service scans, sensitive-file reads, credential dumping via a renamed binary, PsExec service execution, WMI-launched domain account and group changes, service and scheduled-task persistence, PowerShell staging, and curl multipart upload through an explicit proxy. The sequence uses accounts and protocols that fit the target systems. The use of an internal workstation to authenticate directly as root to the public web host is conspicuous but technically possible and is supported by SSH transport and target authentication evidence.

The 15:39 DC-originated multiport burst is less natural. A domain controller making near-simultaneous RDP, SSH, SMB, and HTTP checks against Windows and Linux peers resembles a scanner or health probe, but no source process identifies that role. Because collection may omit process evidence and the connections themselves are possible, I treated this as a low-weight plausibility concern rather than a contradiction.

### Proxy and exfiltration accounting

The 17:24:59 upload provides excellent identity and tuple pivots but fails conservation of application bytes. The client Zeek leg differs from proxy `cs_bytes` by only 467 bytes, exactly consistent with the CONNECT control request described by the proxy. The origin leg, however, carries only 18,813,517 bytes while the proxy says it accepted and forwarded a 44,025,410-byte POST over the successful tunnel. Re-encrypting an already compressed ZIP multipart upload cannot plausibly remove about 57% of the request body without an explicit transformation or a second origin flow; no such companion is visible near the transaction. This materially increased the synthetic-confidence score because it breaks the operational meaning of a high-value pivot.

### Collection-window interpretation

I did not penalize open processes, unmatched logins/logouts, missing source processes, or absent post-window shutdown evidence by themselves. Several long-lived sessions correctly terminate near the end of the slice, while others can plausibly extend beyond it. The scored SSH issue is based on visible, declared parent/session relationships, and the upload issue is based on two visible legs of the same successful transaction, not on missing pre- or post-window evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Zeek + explicit proxy | One high-value 44 MB upload | Same successful transaction loses about 25.2 MB between client and origin legs, undermining a core exfiltration pivot. |
| `hard_contradiction` | Linux eCAR + SSH lifecycle | Repeated in two root SSH sessions | Session commands precede their own shells and reuse one unrelated parent PID/UUID across distinct sessions. |
| `environment_or_collection_plausibility` | DC eCAR + Zeek | One short multi-host burst | A domain controller behaves like a multiport scanner without visible initiating-process context; possible, but role-odd. |

## Realism Score by Category

- **Field format accuracy:** 8 — The reviewed fields and commands are generally source-appropriate; the main issue is semantic parent ownership rather than broad formatting failure.
- **Temporal patterns:** 7 — Business-hour bursts, scheduled traffic, Internet noise, and attack timing are varied, but two SSH commands visibly precede their session shells.
- **Cross-source correlation:** 6 — Most pivots are unusually useful and causally sound, while the large proxy upload has a material byte-conservation failure.
- **Behavioral realism:** 8 — User, service, scan, lateral-movement, staging, and administration behavior is diverse and technically plausible.
- **Environmental consistency:** 7 — Host roles and network placement mostly fit; the DC-originated multiport probing is a localized concern.

## Recommendations

- If this were synthetic, ensure an explicit-proxy transaction derives client, proxy-access, and proxy-origin byte accounting from one canonical application payload. Preserve only defensible protocol overhead differences, and add a check that successful non-transforming uploads cannot shrink materially on the origin leg.
- If this were synthetic, make each SSH session's shell the parent of commands issued in that session. Do not emit a session-tagged command until the shell is visible, and never reuse a preexisting shell PID/process UUID across different SSH logon IDs.
- If this were synthetic, either attach the DC-originated multiport probe to a visible, role-appropriate health/scanner process or move that activity to a dedicated monitoring/scanner host. Preserve the current mixture of success, rejection, timeout, and target-side observations.
