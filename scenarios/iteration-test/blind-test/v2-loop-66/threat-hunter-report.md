# Threat Hunter — Authenticity Assessment
## Verdict
**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 73

## Executive Summary

The telemetry is technically strong and substantially more realistic than a simple hand-built
exercise. It contains 33,946 endpoint eCAR records, 18,529 Windows Security events, 11,690
Sysmon events, and 34,354 Zeek records across core, DMZ, and database sensors. Most pivots work:
process identity, logon IDs, network tuples, Zeek UIDs, file paths, authentication context, and
service roles remain coherent across source families. Network distributions include failed and
successful connections, DNS errors and qtype diversity, HTTP status variation, TLS session and
certificate variation, SMB activity, SMTP, and DHCP renewals. I found no broad schema failure,
negative-duration connection, impossible Zeek byte accounting, process termination before its
observed creation, or application-protocol row detached from its Zeek connection.

The deciding defect is operational rather than cosmetic. The RDP session on
`WS-AJOHNSON-01` with LogonID `0x27015bf` loses its only observed RDP transport at
15:41:30.471Z and is explicitly recorded as disconnected by Windows Event 4779 at
15:45:18.4778787Z. Nevertheless, from 16:06:32Z through 17:24:44Z, eleven new processes with
human-interactive semantics are created in that same session, mostly as direct children of the
session's `explorer.exe`: three `mstsc.exe` launches, two MMC consoles, two Firefox launches,
PowerShell/SSH, and `curl.exe`. There is no Event 4778 reconnect anywhere in the host Security
log and no later RDP connection from the originating client. A disconnected RDP desktop can
remain alive and run existing/background work, but this specific sequence needs a continuing
operator/control mechanism. None is visible, and the parentage points to interactive shell
launches rather than a service, scheduled task, WMI provider, or surviving script. That is a
material lifecycle contract gap and is unlikely in production telemetry with this otherwise rich
endpoint and network coverage.

A second, lower-weight signal is repeated shell-history texture: the same uncommon diagnostic
commands recur verbatim under the same administrator on three unrelated Linux roles. This could
reflect personal habits, so it is not decisive by itself. Taken together with the RDP lifecycle
gap, the balance favors synthetic telemetry. The score remains below “confidently synthetic”
because no hard field-level or protocol contradiction was found, and several complex chains are
implemented convincingly.

## Evidence For Synthetic

- **contract_gap — RDP control plane ends while new interactive work continues.**
  `zeek-core/conn.json:6811` records `10.10.1.99:58332 -> 10.10.1.35:3389`, state `SF`,
  beginning 2024-03-18 15:20:19.758569Z with duration 1270.712993 seconds; it therefore closes
  at 15:41:30.471562Z. `WS-AJOHNSON-01.meridianhcs.local/ecar.json:908` records the matching
  successful Type 10 login at 15:20:25.365Z, LogonID `0x27015bf`, session 5. The exact source
  address and port agree. Windows then records Event 4779 at
  `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml:23005`, timestamp
  15:45:18.4778787Z, with the same LogonID, client address, client port, and `RDP-Tcp#5`.
  No Event 4778 exists anywhere in that host's Security file, and no subsequent Zeek RDP tuple
  reconnects this source to the host.

- **contract_gap — eleven post-disconnect process creations have interactive Explorer
  parentage but no visible driver.** After Event 4779, the same `0x27015bf`/session 5 creates
  `mstsc.exe /v:FILE-SRV-01` at 16:06:32.931Z (`ecar.json:1076`), `mstsc.exe /v:DC-02` at
  16:12:09.807Z (`:1102`), `mstsc.exe /v:MAIL-FIN-01` at 16:13:05.116Z, `mmc.exe dsa.msc`
  at 16:26:16.576Z (`:1146`), Firefox at 16:35:07.106Z (`:1172`), PowerShell and then SSH at
  16:43:11.844Z/16:43:17.350Z (`:1205`/`:1212`), `mmc.exe gpmc.msc` at 16:46:12.842Z
  (`:1228`), Firefox at 16:49:12.721Z (`:1260`), another `mstsc.exe` at 17:06:29.826Z
  (`:1348`), and `curl.exe` at 17:24:44.728Z (`:1438`). The top-level launches consistently
  name PID 6760 `C:\Windows\explorer.exe` as parent and preserve session 5. The session does
  not log out until 17:55:01.885Z (`ecar.json:1527`). A disconnected session remaining resident
  is normal; a long series of newly launched GUI/admin tools from its Explorer shell without a
  reconnect or another execution mechanism is not operationally self-sufficient.

- **distribution_texture — unusual shell commands recur as a small reusable pool.** Across 350
  timestamped Bash commands, only 253 are unique. More telling than common commands such as
  `ls` is the exact repetition of
  `udevadm info --query=property --name=/dev/null | head` by `marcus.chen` on three distinct
  systems and roles: `WEB-EXT-01.../bash_history/marcus.chen.bash_history:16` at epoch
  1710769017 (13:36:57Z), `MAIL-CLIN-01.../bash_history/marcus.chen.bash_history:28` at epoch
  1710774163 (15:02:43Z), and `APP-INT-01.../bash_history/marcus.chen.bash_history:32` at epoch
  1710778002 (16:06:42Z). The same user also repeats
  `journalctl -u systemd-resolved --since today --no-pager | tail -20` on APP-INT, DB-PROD,
  and MAIL-EDGE, and `tail -f /var/log/syslog &` on FILE-LNX, MAIL-CLIN, and MAIL-EDGE.
  Administrator habits can repeat, so this is supporting texture evidence rather than a
  contradiction.

- **weak_signal — RDP lifecycles are unusually template-like.** All 20 observed eCAR Type 10
  logins have an exact corresponding Zeek RDP tuple and all transports are successful `SF`
  sessions. In every case the endpoint logout occurs well after transport close—approximately
  9.8 to 36.8 minutes for ordinary server sessions, and 133.5 to 139.8 minutes for the two
  sessions sourced from `10.10.1.99`. Disconnect-before-logoff is valid Windows behavior, and
  the intervals vary, so this is not a defect on its own. Its weight comes from the fact that the
  one high-activity session is the only session that starts many processes after transport close,
  yet it lacks the reconnect/control evidence that would explain the exception.

No `hard_contradiction` or material `schema_or_format` synthetic indicator was found. The
synthetic verdict rests primarily on the RDP lifecycle `contract_gap`, with the other findings
serving only as corroborating texture.

## Evidence For Real

- **Strong endpoint/network RDP joins.** The suspicious session is not merely correlated by a
  convenient label: the Zeek tuple at `zeek-core/conn.json:6811`, the source and target eCAR FLOW
  observations, the eCAR Type 10 login at `WS-AJOHNSON-01.../ecar.json:908`, and Windows 4624/
  4779 fields agree on `10.10.1.99:58332`, target `10.10.1.35:3389`, account
  `aisha.johnson`, and LogonID `0x27015bf`. Login occurs 5.607 seconds after transport open,
  a plausible ordering.

- **A multi-hop database staging chain is operationally pivotable.** On DB-PROD,
  `mysqldump --single-transaction ehr patients insurance_claims` creates
  `/tmp/rpt_0318.sql` at 17:15:03.985Z (`DB-PROD-01.../ecar.json:535-536`); `gzip -9`
  creates `/tmp/rpt_0318.sql.gz` at 17:15:23.528Z (`:540-541`); and `scp` connects from
  `10.10.4.10:47871` to `10.10.2.30:22` and reads that file (`:543-545`). APP-INT records the
  receiver-side create of `/tmp/.cache/rpt_0318.sql.gz` at 17:15:55.530Z
  (`APP-INT-01.../ecar.json:800`). At 17:18:46Z, Zeek SMB records open and write operations for
  `\\FILE-LNX-01\ClinicalResearch\Integration\DB-Staging\rpt_0318.sql.gz`, including size
  1,424,627 bytes (`zeek-core/smb_files.json:210-211`), while FILE-LNX records the corresponding
  `smbd` write at 17:18:48.297Z (`FILE-LNX-01.../ecar.json:1192`). The actor, file, transport,
  receiver, and subsequent SMB staging semantics line up.

- **Credential-access telemetry has sensible layered evidence.** The process
  `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` is created under
  the RDP session at 15:45:12.650Z (`WS-AJOHNSON-01.../ecar.json:1027`). Sysmon contains its
  process image/command line (`windows_event_sysmon.xml:15514-15520`) followed by source-image
  references for access/thread activity (`:15560`, `:15595`, `:15629`). This is much stronger
  than a lone conspicuous command line with no host-side consequences.

- **Log clearing behaves like a Windows lifecycle, including the counter reset.** DC-01 records
  `cmd.exe /c wevtutil cl Security` and child `wevtutil.exe` at 17:41:57.107Z/.252Z
  (`DC-01.../ecar.json:5279`, `:5286`), while the Security XML contains the same process evidence
  and Event 1102 (`windows_event_security.xml:261948`, `:261988-261991`, `:262169`). The
  EventRecordID then restarts and continues monotonically. This is realistic source-native
  behavior, not merely a generic “log deleted” marker.

- **Network protocol families satisfy basic physical and reference constraints.** Across 20,261
  Zeek `conn.json` rows, no negative durations, impossible packet/byte lower bounds, `S0` row
  with response traffic, or successful `SF` row with zero-sided packet counts were found. Every
  inspected DNS, HTTP, SSL, SMTP, and SMB application row had a same-sensor connection with a
  matching UID/tuple; none preceded its connection or fell beyond the connection interval by
  more than the allowed timestamp tolerance. Of 24,907 eCAR FLOW records, 24,037 (96.5%) found
  a Zeek tuple within ten seconds; the dominant unmatched classes were host-local DNS and paths
  outside a sensor's apparent visibility, not contradictory tuples.

- **The traffic mix has production-like failure and protocol texture.** Core Zeek connection
  states include 9,021 `SF` and 2,023 `S0` plus `RSTO`, `RSTR`, `OTH`, and `REJ`; DMZ traffic
  includes 5,563 `SF` and 2,630 `S0`. Core DNS contains 2,166 A, 307 TXT, 262 AAAA, 136 PTR,
  and 95 SRV queries with 2,744 `NOERROR`, 224 `NXDOMAIN`, 15 `SERVFAIL`, and 4 `REFUSED`
  responses. HTTP includes CONNECT/GET/POST and successful, redirect, authorization, client, and
  server error statuses. TLS contains both TLS 1.2 and 1.3, varied ciphers, resumed and full
  sessions, and stable leaf-certificate fingerprints per server name. These are meaningful
  distributions, not thin single-path coverage.

- **Lifecycle bookkeeping is generally coherent.** Across all eCAR files, no observed process
  termination precedes the matching process creation, no logout precedes its login, no PID is
  recreated while its prior instance is still active, and no dependent event references an
  actor before that actor's observed creation. Bounded-window unmatched starts/ends remain
  plausible. Windows Security and Sysmon timestamps are nondecreasing within files, with natural
  EventRecordID gaps and only the explained DC-01 post-clear reset.

- **Host roles shape activity rather than merely changing hostnames.** DB-PROD includes MySQL/
  PostgreSQL administration and dumping; APP-INT includes Git, Docker, and application tooling;
  mail systems include Postfix/Dovecot activity; FILE-LNX includes `smbd`; Windows servers and
  workstations have distinct service, interactive, and application mixes. This environmental
  differentiation supports authenticity.

## Detailed Analysis

The review covered every record family present in the supplied directory rather than sampling
only the obvious malicious sequence. Endpoint volume comprises 24,907 FLOW, 4,677 PROCESS,
2,276 MODULE, 1,475 USER_SESSION, 328 FILE, 268 REGISTRY, 12 THREAD, and 3 SERVICE eCAR
records. Windows Security is dominated by 11,863 Event 5156 network permits but also contains
authentication, Kerberos, process, object-access, share, account-management, RDP disconnect,
service-install, scheduled-task, and log-clear events. Sysmon includes 7,643 Event 3 network
connections, 1,223 Event 22 DNS events, 938 process creations, 817 terminations, 738 process
accesses, 148 image loads, 146 registry events, 25 file creates, and 12 remote-thread events.
The assessment does not treat the absence of other Sysmon event types as evidence.

The source-family mix is plausible for a deliberately scoped collection: Zeek-core carries AD,
SMB, DHCP, SMTP, internal RDP/SSH, and explicit-proxy client traffic; zeek-dmz carries heavier
TLS/HTTP and proxy-origin traffic; zeek-db is much smaller and role-local. The three sensors have
17,687, 16,086, and 581 records respectively. That is low for an unfiltered enterprise backbone
but credible for a six-hour lab, subnet, or selected-host capture, so thinness was not scored as
synthetic evidence.

Temporal joins are generally credible. RDP logins trail TCP open by roughly 5.6-7.3 seconds.
DHCP renewals occur near T1 rather than at rigid hourly boundaries. DNS response times and
endpoint-versus-sensor timestamp deltas vary by host and source. Process/module bursts occur in
the expected first fractions of a second, while network and file consequences follow executable
startup. The data does not exhibit wholesale timestamp equality across sources.

The principal weakness is not that an attack can be reconstructed cleanly; it is that the
execution substrate disappears. The `0x27015bf` desktop is explicitly disconnected, but new
Explorer children continue for almost 100 minutes. Because the dataset captures process
parentage, Sysmon process creation/access/thread telemetry, Windows Security process creation,
and the relevant network sensors, a hidden mechanism capable of producing this exact series
would ordinarily leave at least one pivot: RDP reconnect (4778 plus a new/continued transport),
another remote administration channel, a scheduled-task/service creation, WMI-hosted children,
a resident script, or injection into Explorer. None appears. This is therefore a
`contract_gap`, not a penalty for incomplete storytelling.

The shell-history repetition is intentionally weighted much less. A senior administrator can
carry habitual one-liners between hosts, and all repeated commands are syntactically valid. The
issue is the recurrence of an oddly specific `/dev/null` udev query and the same bounded
`journalctl`/`grep` forms across unrelated roles within one short window. That resembles a
finite command pool, but it remains `distribution_texture` rather than proof.

Conversely, several details argue strongly against a crude generator: Windows-native IDs and
hex process/logon fields are internally stable; RDP, SSH, proxy, SMB, Kerberos, and file-transfer
ordering is mostly correct; Zeek UIDs bind protocol rows to connections; failed network and DNS
states have realistic diversity; and the DC-01 Security-log clear is represented with both the
initiating process chain and the source-native counter reset. Those strengths are why the final
synthetic-confidence score is 73 rather than above 80.

## Synthetic Indicator Summary

| Indicator | Category | Weight | Log-visible basis |
|---|---|---:|---|
| Post-disconnect interactive activity in RDP session `0x27015bf` | `contract_gap` | High | RDP TCP closes 15:41:30.471Z; Event 4779 at 15:45:18.477Z; eleven new session-5 processes through 17:24:44Z; no 4778 or later source RDP transport |
| Interactive Explorer parentage without a replacement execution mechanism | `contract_gap` | High | `mstsc.exe`, MMC, Firefox, PowerShell, SSH, and curl are created under PID 6760 `explorer.exe`, not a visible service/task/WMI/script/control process |
| Repeated uncommon Linux diagnostic one-liners | `distribution_texture` | Low | Exact `/dev/null` udev query on WEB-EXT, MAIL-CLIN, and APP-INT; two other exact admin one-liners each span three hosts |
| Uniform disconnect-before-logoff shape across all Type 10 sessions | `weak_signal` | Low | 20/20 Type 10 sessions have successful matching RDP flows whose transport closes 9.8-139.8 minutes before logout; only the high-activity session lacks a needed reconnect/control explanation |
| Hard contradictions | `hard_contradiction` | None found | No impossible field, protocol, or lifecycle ordering survived cross-source checking |
| Material format defects | `schema_or_format` | None found | Windows XML, eCAR JSON, Bash history, and Zeek JSON are parseable and source-shaped |
| General collection thinness | `environment_or_collection_plausibility` | Not scored | Volume is low for an enterprise but credible for a scoped six-hour capture; source roles and sensor visibility are internally differentiated |

## Realism Score by Category
- **Field format accuracy:** 9 — Windows XML fields/versions, hexadecimal IDs, eCAR types, Zeek tuples/states, and Bash timestamp format are consistently parseable and source-appropriate; no material schema defect was identified.
- **Temporal patterns:** 7 — Network/application ordering, process lifecycles, DHCP timing, and cross-source jitter are strong, but the active-work-after-RDP-disconnect gap is material.
- **Cross-source correlation:** 9 — Exact tuple, UID, logon, actor, process, and file pivots are unusually robust; the database-to-SSH-to-SMB staging path is especially strong.
- **Behavioral realism:** 6 — Role-specific baseline activity and tradecraft consequences are credible, but the disconnected-session execution and small repeated Linux command pool reduce authenticity.
- **Environmental consistency:** 8 — Host roles, subnets, proxy routing, sensor visibility, and protocol mix agree; the principal unexplained environmental issue is the missing control mechanism for the continued RDP-session activity.

## Recommendations

- Require every remotely operated interactive sequence to retain an observable control path. For
  this case, either keep the `10.10.1.99:58332 -> 10.10.1.35:3389` transport open through the
  final interactive action, emit a realistic 4778 reconnect with a corresponding RDP transport,
  or move later actions to an explicit service, scheduled task, WMI, WinRM, injected process, or
  resident script whose parentage and authentication evidence support unattended execution.

- Add a validation rule that flags new GUI/shell children in a disconnected RDP session when no
  reconnect or alternate execution ancestor exists. Check both session ID/logon ID and process
  ancestry; merely delaying logout is insufficient.

- Increase per-user and per-role shell-history diversity, particularly for uncommon diagnostic
  commands. Preserve genuine habitual overlap for common commands, but avoid repeating the same
  idiosyncratic one-liner on three unrelated systems during one short window.

- Preserve the current strengths: canonical network tuples, Zeek UID relationships, endpoint
  actor identities, Windows logon IDs, source-native log clearing, protocol failure texture, and
  multi-hop file lineage. These features materially improve huntability and authenticity.

- For future blind review, include enough collection metadata to distinguish a local EVTX export
  from a centrally retained event stream and to state sensor visibility boundaries. That would
  allow collection gaps to be judged without treating mere absence as synthetic evidence.
