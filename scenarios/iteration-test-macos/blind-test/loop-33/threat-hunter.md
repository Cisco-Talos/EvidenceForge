# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 36

## Executive Summary

The collection is operationally credible: web execution, SSH transport and authentication, database staging, SMB transfers, and a proxy-mediated upload support usable investigative pivots. I found weak signs of reusable administrative activity templates, but no demonstrated impossible lifecycle or attack-effect contradiction in the checks performed. The evidence supports a mostly realistic collection while remaining insufficient to establish its provenance.

## Evidence For Synthetic

- [distribution_texture] Administrative commands are unusually concentrated toward the beginning of an otherwise six-hour collection: across all endpoint `ecar.json` files, 114 `PROCESS/CREATE` records whose `command_line` begins `sudo ` occur by hour as **82, 22, 5, 3, 1, 1** for 13:00–18:59 UTC. Thus 104/114 appear in the first two hours, across 11 hosts. This could reflect morning maintenance; it is a modest distribution cue, not an impossible behavior.
- [weak_signal] Identical fully qualified maintenance commands recur across different administrators and server roles. `sudo /usr/bin/apt list --upgradable` occurs in MAIL-EDGE eCAR line 59, DB-PROD line 33, WEB-EXT line 230, PROXY line 957, and FILE-LNX line 335. `sudo /usr/bin/lsof -i -P -n` occurs on five hosts. These are common real commands, so repetition carries little weight alone; its relevance is the shared texture alongside the front-loaded distribution.
- [environment_or_collection_plausibility] Several maintenance commands target generic protocol/package names as service units: APP-INT `syslog.log:60` runs `service smb-client status`, line 79 runs `systemctl restart cifs-utils`; MAIL-CLIN `syslog.log:92` runs `systemctl restart imaps`; WS-OHADDAD `syslog.log:25` runs `systemctl restart smbclient`; FILE-LNX `syslog.log:76` runs `systemctl restart smb-server`. This resembles service vocabulary being reused as command targets. Custom units or unsuccessful commands remain plausible, and these records do not establish successful restarts. I assign limited weight and do not call them hard contradictions.

## Evidence For Real

- WEB-EXT `web_access.log:532` records a POST to `/ehr/admin/upload.php` at 14:20:12. WEB-EXT `ecar.json:1025–1029` then shows Apache PID 23966 spawning bash PID 2702837, an outbound connection to `45.33.32.30:8443`, and the bash process terminating. `zeek-dmz/conn.json:1876` confirms source port 37451, an established connection, and a 12.087564-second duration. Transport ends before the visible shell termination.
- DB-PROD `ecar.json:489–501` supports an intelligible SSH-root session, shell, database dump, gzip, and SCP sequence. The history retains shell redirection while process telemetry reports the executable arguments without it. APP-INT `ecar.json:722–727` supplies the receiver-side connection, root SSH authentication, file creation, process termination, and session logout.
- The SCP artifact is subsequently used in a coherent SMB operation: APP-INT `ecar.json:729–731`, `zeek-core/smb_files.json:217–218`, `zeek-core/files.json:758`, and FILE-LNX `syslog.log:466–468` agree on destination share, relative file path, client address, and operation direction. The transmitted file is 402,886 bytes; its TCP connection has sufficient origination payload to carry it.
- WS-AJOHNSON `ecar.json:1059,1066,1126–1127` connects archive creation to a later curl file read and proxy connection. PROXY `proxy_access.log:3123–3124` identifies that same client source port 56465, authenticated user, CONNECT tunnel, and inspected POST, with roughly 18.8 MB sent. `zeek-dmz/conn.json:8691` independently records an outbound proxy connection with compatible volume.
- Checks across all eCAR files found no actor reference more than 100 ms before its visible process creation or after its visible termination. All 12 successful Type 10 logons had matching `SF` RDP transports using the logged source IP and port within a 45-second opening neighborhood.
- Static resource responses show internally stable content sizes: for example `/assets/css/main.min.cdfb17fb.css` appears 25 times in WEB-EXT access logs, with every 200 response reporting 37,108 bytes; the corresponding application and vendor bundles also retain stable 200-response sizes. Cache hits coexist with full responses.

## Detailed Analysis

### Scope and investigation method

There are 23 endpoint directories with eCAR telemetry, totaling 35,721 eCAR records. The visible window is approximately 2026-11-02 13:00–19:00 UTC. Windows Security/Sysmon, Linux syslog and shell history, macOS Endpoint Security and Unified Log, Apache-style access logs, explicit-proxy access logs, ASA logs, Snort alerts, and three Zeek sensor directories are present. Address ranges include `10.10.1.*`, `10.10.2.*`, `10.10.3.*`, and `10.10.4.*`; the observed names and activity support workstation, directory, file, mail, web, proxy, application, and database roles.

I followed suspicious process commands into endpoint flows, network records, server authentication, and transferred file evidence. I also checked broader process-actor lifetimes, successful remote interactive logons, and Zeek protocol/connection relationships. These are bounded checks, not a claim that every field in every source was exhaustively validated.

### Web execution and reverse connection

The upload request at WEB-EXT access line 532 precedes bash process creation at 14:20:13.774. The parent image is `/usr/sbin/apache2`, the principal is `www-data`, and the command decodes a shell command using `/dev/tcp/45.33.32.30/8443`. Endpoint flow line 1026 uses `10.10.3.10:37451`; the Zeek observation begins at epoch 1793629217.169988, with the same tuple, `SF`, and bidirectional payload. Bash terminates at 14:20:41.753, after transport closure around 14:20:29.258. This is a technically coherent high-priority pivot. The request alone would not prove exploitation; the process and connection supply the stronger evidence.

### Database extraction, SCP, and SMB staging

DB-PROD receives root SSH from APP-INT `10.10.2.30:42289`; eCAR lines 489–492 provide the server process, inbound transport, successful root login, and shell. Its history records `mysqldump ... > /tmp/rpt_0318.sql`, while eCAR line 493 records `mysqldump --single-transaction ehr patients insurance_claims` as a process command. Omitting shell redirection from executable arguments is appropriate. File creation follows, gzip starts after the dump process exits, and SCP starts after gzip exits.

The reverse SCP transport uses `10.10.4.10:44357 → 10.10.2.30:22`. Zeek core line 10870 and database sensor line 389 have separate sensor UIDs and slightly different timestamps for this same tuple. APP-INT syslog lines 210–215 show accepted public-key authentication and PAM/logind lifecycle evidence; its eCAR line 725 places `/tmp/.cache/rpt_0318.sql.gz` on the receiver.

At 18:18:57.216, APP-INT eCAR line 729 launches `smbclient` as local root while requesting remote identity `svc_mhsync`. FILE-LNX audit lines 466–468 attribute the server-side write to `svc_mhsync`, rather than incorrectly carrying the client's local root account into server authentication. `zeek-core/conn.json:10944` carries 405,191 originating bytes; the corresponding SMB file is 402,886 bytes. No size contradiction appears.

### Windows staging and outbound upload

WS-AJOHNSON's visible staging commands retain a consistent process/session chain. Powershell PID 6660 copies five Finance files; eCAR lines 1023–1027 name those five outputs. A later archive process PID 6760 creates `C:\ProgramData\Microsoft\cache_7f3a.zip`. Curl PID 6772 reads that archive and connects to the proxy, using source port 56465.

PROXY access lines 3123–3124 distinguish the CONNECT control exchange from the inspected POST and retain a shared tunnel identifier. The latter records `cs_bytes=18783067`. The proxy's upstream Zeek flow at DMZ line 8691 records 18,819,932 originating bytes, compatible with TLS/network overhead rather than less payload than the claimed upload. The curl process remains visible until after this flow's close. This supports a feasible exfiltration investigation without requiring the absence of unrelated noise to carry the inference.

### Remote sessions and macOS evidence

MAC-MROSS-01 eCAR lines 142–144 show a zsh fork/exec into SSH and a connection from `10.10.1.41:55704` to MAC-MROSS-02. The latter's Unified Log line 2 reports accepted keyboard-interactive/PAM authentication at 14:24:38.925429. Core Zeek connection line 2234 opens earlier and lasts 627.549771 seconds; the source SSH process terminates later at MAC-MROSS-01 eCAR line 158. The visible order is compatible.

MAC-MROSS-01 Unified Log line 2 also reports that policy "would not allow" a MeetingAssist process. I do not infer successful execution or effects from that message. Similarly, the inventory plist creation/deletion observations do not by themselves prove launch-item activation. Sparse Unified Log coverage is neutral under the stated collection scope.

### Broader checks and limitations

For every Zeek sensor, I joined HTTP, DNS, SSL, and SMB companion UIDs to connection records. No checked companion timestamp was more than 0.5 seconds outside its connection interval. Across 2,442 file-to-connection joins, no file's `seen_bytes` exceeded its corresponding connection's directional payload total. TCP records without retransmission/gap history markers also passed a generous IP/header accounting upper bound. These checks strengthen operational realism; their successful matching is not evidence of synthetic origin.

The six-hour window cannot establish normal daily volume or prove that every account and service belongs on every host. I did not treat missing pre-window process creation, post-window session closure, missing Sysmon families, sanitized domains, sparse sources, or the narratability of suspicious activity as authenticity defects.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux eCAR process commands | 114 sudo launches across 11 hosts; 104 in first two hours | Modest cue of activity scheduling/templates; also consistent with maintenance |
| weak_signal | Linux eCAR maintenance vocabulary | Identical administrative commands across multiple roles and users | Low weight because common commands are naturally shared |
| environment_or_collection_plausibility | Linux sudo/syslog commands | Generic service targets on several hosts | Low weight; custom units and command failure are not excluded |

No hard contradiction or demonstrated lifecycle contract gap was established in this review.

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled native records are detailed and internally usable; no demonstrated format impossibility.
- **Temporal patterns:** 8 — Transport/auth/process ordering works; administrative activity is notably front-loaded.
- **Cross-source correlation:** 9 — Independent endpoint, network, authentication, proxy, and file pivots retain compatible identities and amounts.
- **Behavioral realism:** 8 — Suspicious operations are technically feasible; background administrative vocabulary is somewhat repetitive.
- **Environmental consistency:** 8 — Mixed fleet and server roles are credible; several generic service-unit command targets merit clarification.

## Recommendations

- If this were synthetic, tie administrative commands to installed unit names rather than broadly reusing protocol/package labels such as `cifs-utils`, `imaps`, or `smb-client`. Preserve genuine failed commands when intended; the present sudo records do not prove success.
- If this were synthetic, check whether the 104/114 sudo launches in the first two hours represent an intended maintenance window. If not, vary administrative work timing by role and operator while retaining legitimate shared runbooks.
- If this were synthetic, retain the current transport-before-auth ordering, executable-versus-shell-history distinction, client-versus-remote-account separation, transfer-byte feasibility, and proxy control/data distinction. Those concrete relationships are the collection's strongest realism features.
