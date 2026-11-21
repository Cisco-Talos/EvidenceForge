# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 43

## Executive Summary

The data supports practical threat hunting across a six-hour mixed-platform enterprise collection, with convincing process, authentication, transport, file-access, and proxy pivots. I found a scoped concern about SCP process ownership, but no demonstrated impossible ordering or decisive generator fingerprint; the available normalization and collection details are insufficient to distinguish a good simulation from sanitized production data confidently.

## Evidence For Synthetic

- [contract_gap] The database-to-application-server SCP transfer simplifies executable ownership in a way that is questionable for conventional OpenSSH. In `DB-PROD-01.meridianhcs.local/ecar.json`, line 481 creates `/usr/bin/scp` PID `1418155` at `18:15:41.710Z`; line 483 directly attributes TCP `10.10.4.10:49550 -> 10.10.2.30:22` to that same executable/PID at `18:15:45.039Z`. No child process of PID 1418155 is present in this file. Conventional OpenSSH SCP delegates its SSH transport to an `ssh` process. This is a moderate ownership concern, not a hard contradiction: these are normalized eCAR records, the exact SCP implementation is unestablished, and the collector could attribute transport to its initiating ancestor or filter helper processes.
- [weak_signal] The same transfer's receiver is represented entirely by PID `3431531` in `APP-INT-01.meridianhcs.local/ecar.json`: line 794 creates `sshd: root [priv]`, and line 796 attributes creation of `/tmp/.cache/rpt_0318.sql.gz` to that PID with command line `sshd: root@notty`. There is no intervening visible process modification or receiver child. This adds to the executable-ownership concern because ordinary OpenSSH privilege separation and subsystem execution have more distinct process identities. It is not independently decisive: command-line/title changes need not produce an event, and receiver subsystem/normalization behavior is unspecified. I do not count this as a separate major defect.

## Evidence For Real

- The Windows-to-Linux administrative pivot has the right source and destination evidence. `WS-MCHEN-01.meridianhcs.local/ecar.json` line 259 records PID `7320`, `ssh.exe root@WEB-EXT-01.meridianhcs.local`, at `14:39:20.007Z`; the receiver records inbound `10.10.1.31:60616 -> 10.10.3.10:22`, then root authentication and a root shell, before the discovery commands and network scans.
- Credential-access telemetry has useful executable, privilege, and target detail. On WS-AJOHNSON-01, Sysmon records `ms-index-service.exe` PID `6024` with `IntegrityLevel=High`, then access to `winlogon.exe` with `GrantedAccess=0x1010`, access to `lsass.exe` PID `4292` with `0x1FFFFF`, and a remote thread into that same LSASS process before the accessing process exits.
- Authentication context changes are distinguishable. WS-AJOHNSON-01 Security event 4624 at `16:01:25.7620464Z` records an RDP logon from `LT-MRIVERA-02`, source `::ffff:10.10.1.99:57338`, using logon ID `0x26db420`. A later Type 9 logon at `18:00:45.8375845Z` creates `0x27c9918` and explicitly records outbound credentials for `MERIDIANHCS\marcus.chen`, while retaining aisha.johnson as the local identity. That distinction enables credential-boundary hunting rather than collapsing all activity into one username.
- The database transfer has plausible operational ordering despite the ownership concern: root SSH authentication, shell creation, dump, compression, transfer, receiver file creation, and termination are ordered coherently. The core and database sensors agree on the transfer tuple and payload counts while using distinct sensor UIDs and timestamps.
- The background is materially varied. There are successful and failed authentication events, workstation locking/unlocking, Kerberos and NTLM activity, DNS and protocol traffic, mail queues with multiple recipients, scheduled sysstat activity, package/service administration, and host-specific daemon messages. A hunter must separate suspicious behavior from substantial unrelated activity.
- macOS evidence preserves distinctions between process fork and exec, downloaded scripts and their subsequent execution, and local and SSH sessions. A Unified Log policy message naming MeetingAssist has no matching visible successful execution; I do not infer an execution or downstream compromise from that message alone.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and used no scenario, ground truth, generator code, other reviewer results, or filesystem timestamp clues. All times below are UTC on 2026-11-02 unless noted.

The collection spans approximately `13:00–19:00Z` and contains 23 endpoint directories: ten Windows hosts with Security/Sysmon XML, eleven Linux hosts with syslog, and two Macs with Endpoint Security and Unified Log NDJSON. The fleet includes two apparent domain controllers, Windows and Linux file servers, application/database/web infrastructure, mail infrastructure, a proxy, and user workstations. Addressing covers at least `10.10.1.0/24` through `10.10.4.0/24`; the exact security-zone boundaries cannot be established from names alone.

Available sources include 37,414 normalized eCAR records; 17,780 Windows Security events; 11,606 Sysmon events; 4,088 syslog records; 307 macOS Endpoint Security records; six Unified Log records; 23,141 Zeek connection records across three sensors; DNS, TLS, HTTP, SMB, SMTP, DHCP, file, PE, X.509 and OCSP records; 25,529 ASA lines; 4,379 proxy lines; 899 web access lines; and 145 Snort alert lines. These are record counts except for explicitly named text-line counts. Network counts include overlapping sensor observations and should not be interpreted as unique enterprise connections.

I parsed the eCAR process graph on every endpoint, checking visible parent creation/termination against child creation using process UUIDs. I also checked visible process-dependent records against their referenced process lifetimes with a one-second tolerance for source timing. Neither check found a violation. This is a bounded consistency check, not proof that every event is authentic or that subsecond ordering is exact. I parsed the Windows XML, compared repeated process-image hashes within each host, and checked Zeek payload/IP-byte/packet counters for basic contradictions. Those checks found no issue of the tested kinds.

### Windows-to-Linux discovery pivot

On WS-MCHEN-01, a command shell PID `7292` appears at `14:39:16.396Z`, followed by OpenSSH client PID `7320` at `14:39:20.007Z`. WEB-EXT-01 records the inbound connection at `14:39:27.340Z`, `sshd: root [priv]` PID `3050029`, root session `290`/logon ID `0x13665815` at `14:39:35.877Z`, and bash PID `3050069` at `14:39:36.995Z`.

Subsequent children inspect interfaces, hosts and resolver configuration, and search `/opt/ehr`. The host-discovery process `nmap -sn 10.10.2.0/24` is PID `3050125`, created at `14:39:51.212Z` and terminated at `14:40:22.713Z`. The subsequent TCP connect scan is a separate PID `3050301`, created at `14:40:24.067Z` and terminated at `14:40:58.593Z`. Numerous endpoint flow observations attributed to the latter PID occur between its visible creation and termination. The source/client, receiver/session and scanner ownership make this a usable pivot, without an observed causal inversion.

### Credential access, alternate credentials and outbound transfer

WS-AJOHNSON-01's Sysmon Event 1 at `16:45:04.295Z` creates PID `6024` with command `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`, parent `cmd.exe` PID `5976`, high integrity and logon ID `0x26db420`. Events 10 at `16:45:07.351Z` and `16:45:08.757Z` identify the winlogon and LSASS targets. Event 8 at `16:45:08.895Z` identifies LSASS again, with thread `18440`, a concrete start address, `ntdll.dll` and `RtlUserThreadStart`. Event 5 closes PID 6024 at `16:45:10.676Z`.

This is actionable credential-access and injection evidence. It does not by itself prove successful recovery of a particular password. Later Type 9 authentication explicitly exposes the distinction between the local user and outbound marcus.chen credentials. File-copy and archive commands then operate under the new local logon ID. At `18:25:17.759Z`, eCAR records curl PID `6604` reading and uploading `C:\ProgramData\Microsoft\cache_7f3a.zip` through the proxy. Proxy line 4045 records a corresponding POST at `18:25:21+0000`, the same client `10.10.1.35`, URI `/upload/telemetry/7f3a2b19`, `cs_bytes=18783258`, and `proxy_action=ssl-inspect` with `ssl_bump=bump`. Thus visibility into the HTTPS request is explicitly explained by interception; it is not incorrectly assumed to be available from an opaque CONNECT tunnel.

### Database staging and SCP ownership

APP-INT-01 starts `ssh root@DB-PROD-01` at `18:14:42.160Z`. DB-PROD-01 records the inbound session from `10.10.2.30:39333`, successful root login at `18:15:08.055Z`, and bash at `18:15:10.415Z`. The dump process starts at `18:15:14.113Z`, a SQL file appears at `18:15:15.413Z`, the dump exits at `18:15:27.952Z`, gzip starts at `18:15:29.703Z`, and its output appears at `18:15:33.651Z` before gzip exits. The subsequent SCP reads the compressed file and the receiver creates the matching destination.

`zeek-core/conn.json` line 10909 records `10.10.4.10:49550 -> 10.10.2.30:22`, UID `CoQeNZSBHFcAaYbn4G`, start epoch `1793643344.306524`, duration `23.395479`, `SF`, `orig_bytes=27702`, and `resp_bytes=34200`. `zeek-db/conn.json` line 372 observes the same tuple and byte counts with UID `Caw0PCv0QDbH6LdGNG`, a slightly later start and duration `23.394947`. Endpoint and network timestamps have plausible collection offsets; receiver file observation slightly after the sensor's transport close does not establish an impossible ordering.

The concern is specifically executable ownership: source SCP directly owns TCP in the normalized endpoint data, without a visible ssh helper; the receiver writes the file under the privileged sshd PID. This warrants checking the collector's process-attribution contract and actual SSH implementation. Without that information, I cannot promote the concern into a hard authenticity verdict.

### Background and platform interpretation

The six-hour duration is short enough that missing process births or session closes can fall outside collection. I did not penalize that. Scheduled sysstat commands occur 36 times on many Linux hosts, but a ten-minute cron schedule naturally yields that count across six hours; regularity in this explicitly scheduled workload is not a synthetic tell. Host process volumes differ substantially: DB-PROD-01 has 47 visible process creations, while FILE-LNX-01 has 257, including 92 smbd creations. The Linux syslog mix also varies by role: database-host messages are dominated by multipathd and irqbalance, while MAIL-EDGE-01 contains substantial Postfix activity with queue IDs, relay-specific responses and recipient-level delivery evidence.

The Macs' sparse Unified Log coverage is not by itself suspicious. Their Endpoint Security records include version 11 messages and explicit fork/exec structures, whereas eCAR is a separate normalized representation. I did not apply Linux syslog or Windows event expectations to those native Mac records, equate policy language with an authorization outcome, or require every possible platform source to be present. The support-tool downloads seen across Windows, Linux and macOS could be an ordinary coordinated support activity; their cross-platform similarity alone does not establish artificiality.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Linux normalized eCAR process/network attribution | One visible DB-PROD-01 to APP-INT-01 SCP transfer | Moderate concern: conventional OpenSSH normally gives TCP transport a separate ssh process; normalization and implementation uncertainty limit weight. |
| weak_signal | Linux normalized eCAR receiver attribution | Same transfer, receiver PID 3431531 | Supporting concern about collapsed privilege/subsystem identities; not counted as an independent major defect. |

No demonstrated hard contradiction, generator identity disclosure, dataset-wide timing artifact, or source-volume impossibility was established. The score reflects uncertainty around a specific ownership contract, not the completeness or narrative shape of suspicious activity.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed XML/JSON and the checked native Windows fields, hashes and network counters are internally plausible.
- **Temporal patterns:** 9 — Observed process/session/transport ordering works; scheduled regularity has a legitimate explanation.
- **Cross-source correlation:** 8 — Practical pivots work, with a scoped unresolved SCP process-ownership concern.
- **Behavioral realism:** 8 — Discovery, credential access, alternate credentials and staging have technically plausible prerequisites and effects.
- **Environmental consistency:** 8 — Source diversity and host-dependent background are believable; exact collector normalization remains unknown.

## Recommendations

- If this were synthetic, represent the SCP client's transport helper and receiver privilege/subsystem processes using the actual modeled implementation, retaining the real socket-owning PID in endpoint flow evidence. The issue to resolve is the direct `/usr/bin/scp` ownership of tuple `10.10.4.10:49550 -> 10.10.2.30:22` and the receiver file write attributed to its privileged sshd PID.
- If ancestor-level attribution is intentional in this collection, document that normalization contract alongside the dataset rather than changing otherwise coherent timestamps or adding arbitrary background events. That would make this specific ownership concern assessable without pretending normalized eCAR is raw process telemetry.
