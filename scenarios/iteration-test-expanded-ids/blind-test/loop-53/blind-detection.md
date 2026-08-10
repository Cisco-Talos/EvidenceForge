# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 93
**Synthetic-Confidence Score:** 84

## Executive Summary

The corpus is unusually strong in source-native formatting, network/session lifecycle construction, and cross-source investigative coherence. I nevertheless assess it as synthetic because endpoint telemetry repeatedly attributes successful SMB sessions to the native Linux `rsyncd` daemon—a process/protocol contradiction reproduced 138 times across six unrelated Linux server roles—along with a tightly bounded dual-sensor timing pattern consistent with generated observation jitter.

## Evidence For Synthetic

- `[hard_contradiction]` Linux `rsyncd` is repeatedly shown originating successful SMB/445 sessions. In `APP-INT-01.meridianhcs.local/ecar.json:7`, PID 935251 is `/usr/sbin/rsyncd --daemon --config=/etc/rsyncd.conf` connecting from `10.10.2.30:59119` to `10.10.2.27:445`. `zeek-core/conn.json:29` confirms this was not merely a failed socket attempt: Zeek classified it as `service:"smb"`, `conn_state:"SF"`, with 7,864 origin and 5,125 response bytes over 22.201459 seconds. `rsyncd` does not implement SMB; an SMB client, CIFS kernel worker/mount path, or desktop GVFS process would own this traffic.
- `[hard_contradiction]` A second APP-INT example is equally explicit: `APP-INT-01.../ecar.json` records PID 935251 connecting from port 41247 to FILE-SRV `10.10.2.20:445`; `zeek-core/conn.json:62` observes a completed SMB exchange with `SF`, 1,531 origin bytes and 23,021 response bytes. This rules out a one-off EDR misclassification of a rejected port probe.
- `[distribution_texture]` The same incompatible mapping is dataset-wide: 138 outbound `/usr/sbin/rsyncd`→TCP/445 FLOW records—34 on APP-INT-01, 29 MAIL-EDGE-01, 25 MAIL-CLIN-01, 23 DB-PROD-01, 14 WEB-EXT-01, and 13 PROXY-01. Exact examples occur at `DB-PROD-01.../ecar.json:27`, `MAIL-CLIN-01.../ecar.json:78`, `MAIL-EDGE-01.../ecar.json:92`, `PROXY-01.../ecar.json:90`, and `WEB-EXT-01.../ecar.json:56`. Reusing the same daemon command as an SMB actor across database, mail, proxy, web, and application roles is a generator-like baseline fingerprint.
- `[distribution_texture]` For 1,870 five-tuples that appear exactly once in both `zeek-core/conn.json` and `zeek-dmz/conn.json`, every DMZ observation follows the core observation by only 41.487–66.099 ms; median is 54.535 ms and p99 is 65.601 ms, with zero samples outside 40–67 ms. The first shared connection is `10.10.1.34:49463 → 10.10.3.20:8080`, timestamped `1710763205.841123` in core and `1710763205.886365` in DMZ. A persistent sensor clock offset is possible, but the hard bounded range across the entire six-hour window resembles deliberate jitter more than independently collected sensor clocks and queues.
- `[weak_signal]` Bash command texture has substantial exact reuse: 220 commands but only 179 unique strings; 78 records belong to repeated exact commands. Some are naturally common, but long forms such as `journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30` recur verbatim on DB-PROD-01 and MAIL-CLIN-01, reinforcing the shared command-pool impression. This did not materially drive the verdict by itself.

## Evidence For Real

- Network texture is not uniformly clean. `zeek-core/conn.json` contains 6,179 `SF`, 93 `RSTO`, 64 `RSTR`, 22 `OTH`, 17 `REJ`, 12 `S0`, and smaller `S1/S2/S3` populations. DMZ collection is materially different, with 3,909 `SF` and 1,132 `S0`, consistent with an exposed perimeter vantage.
- The protocol mix is operationally credible: core telemetry includes 2,231 DNS, 1,090 Kerberos, 1,006 SMB, 938 HTTP, 619 LDAP, 115 SSH, 89 SSL, 69 DHCP, 67 SMTP, and 12 RDP connections.
- SMTP relay behavior carries realistic envelope/header distinctions. `zeek-core/smtp.json:2` shows external delivery of message ID `<notices-b9dac45a-8235363@benefits-serviceportal.com>` through `10.10.2.25`, with distinct envelope recipients, header `To`, `Cc`, transit path, queue reply, and attached file UIDs. Line 3 preserves the message ID and content metadata on the internal hop to `10.10.2.27` while changing the queue response and relay path.
- Explicit proxy behavior is internally coherent. `PROXY-01.../proxy_access.log:1-2` separates a `CONNECT aws.amazon.com:443` control transaction from the bumped `GET https://aws.amazon.com/`, including distinct control/tunnel byte scopes. The corresponding Zeek connection begins at `1710763205.841123`, lasts 4.279133 seconds, and carries 801/18,412 application bytes.
- The SSH/SCP lifecycle is exceptionally plausible. DB syslog records a root SSH connection from `10.10.2.30:58612` at `17:14:24.500579Z`, password acceptance, PAM open, and logind session 279097 creation; the same session closes at `17:52:19.936034Z` and is removed at `17:52:21.035738Z`. Within it, `DB-PROD-01.../bash_history/root.bash_history:10-22` shows database dumping, inspection, compression, hashing, and SCP.
- That SCP has correct independent evidence: `DB-PROD-01.../ecar.json:599` creates `/usr/bin/scp` PID 159695, line 601 emits its outbound `10.10.4.10:45232 → 10.10.2.30:22` FLOW, Zeek records an 18.405299-second `SF` SSH transport with 77,949/19,027 bytes, APP syslog records connection/auth/PAM/logind open and close, and `APP-INT-01.../ecar.json:651` records `/tmp/.cache/rpt_0318.sql.gz` created by destination `sshd`.
- Source formats are generally convincing: RFC5424 Unix messages, ASA message IDs and lifecycle forms, Snort signature/classification syntax, Windows Security/Sysmon XML, and Zeek JSON all appear structurally source-appropriate.

## Detailed Analysis

### Corpus and source coverage

The detached corpus covers approximately six hours, from 2024-03-18 12:00 UTC to shortly before 18:00 UTC. It includes eCAR telemetry for 18 hosts, Windows Security/Sysmon on Windows systems, RFC5424 syslog and bash history on Linux systems, two Zeek vantages, perimeter ASA, two Snort vantages, explicit proxy access, web access, and SMTP/DNS/SSL/X.509/file metadata.

The volume and source-family mixture are plausible for a deliberately scoped collection. I did not penalize the corpus for completeness or for the selected Sysmon event types.

### Detection and investigation realism

The corpus supports realistic detection pivots. SMTP message IDs and file UIDs survive relay transitions; proxy client identities, methods, hosts, byte scopes, and downstream transports align; authentication sessions maintain ports, users, process ownership, and close evidence; and network outcomes include both successes and substantial exposed-DMZ failure noise.

The database-to-application SCP sequence is the strongest example. It can be investigated from shell history to endpoint process, transport, destination authentication, destination file creation, and session teardown without an impossible visible ordering. The timestamps retain realistic small source delays rather than being bit-identical.

### Process/network ownership defect

The decisive defect is not “too much correlation”; it is incorrect semantic ownership. Native `rsyncd` listens for and speaks the rsync protocol, normally on TCP/873. It does not originate SMB conversations on TCP/445. If a Linux host accesses an SMB share, credible owners include `smbclient`, `mount.cifs`, `gvfsd-smb`, or kernel CIFS activity depending on collection semantics. If a backup process writes through an already-mounted CIFS filesystem, endpoint telemetry should not represent the userspace rsync daemon itself as opening and speaking the SMB socket.

This defect appears on six different server roles and is corroborated as successful SMB by Zeek, making it a repeated canonical process/protocol mismatch rather than a single malformed field.

### Timing distributions

Within each source, lifecycle ordering is generally excellent. The concern is instead the population-level relationship between the two Zeek sensors. Unique shared tuples have a universal positive offset confined to a 24.6 ms-wide band for all 1,870 observations. Real sensor clocks can have stable offsets, but one would expect drift, step corrections, asymmetric buffering, or a longer-tailed delay distribution over six hours. The observed hard range is characteristic of a bounded random timing model.

### Behavioral and environmental texture

The corpus includes useful role-specific behavior—SMTP on mail hosts, web activity on WEB-EXT, directory services on DC-01, database administration, proxy transactions, workstation browsing, and remote administration. That realism is weakened by assigning an identical root `rsyncd` daemon command to SMB activity on application, database, mail, proxy, and web servers. Exact shell-command reuse is a lesser issue: common administrative commands naturally repeat, though more operator- and host-specific variation would help.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `hard_contradiction` | eCAR + Zeek SMB | 138 flows, 6 Linux hosts | Native `rsyncd` is asserted as owner of completed SMB/445 conversations it cannot speak. |
| `distribution_texture` | Endpoint baseline/environment | App, DB, two mail, proxy, web roles | The same daemon command and incompatible protocol mapping recur across unrelated server roles, creating a generator fingerprint. |
| `distribution_texture` | Zeek core/DMZ | 1,870 unique shared tuples | Every cross-sensor delay is constrained to 41.487–66.099 ms over six hours. |
| `weak_signal` | Bash history | 78 of 220 command records in repeated exact strings | Shared command-pool texture is visible, though much reuse is operationally explainable. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Source-native structures and most field values are highly convincing.
- **Temporal patterns:** 7/10 — Individual lifecycles are strong, but dual-sensor delays are implausibly bounded at population scale.
- **Cross-source correlation:** 9/10 — SMTP, proxy, SSH/SCP, file, and network evidence correlate with credible ordering and source delay.
- **Behavioral realism:** 5/10 — The repeated `rsyncd`-as-SMB-client contradiction is severe despite otherwise rich user and attack behavior.
- **Environmental consistency:** 5/10 — Role-aware services are present, but the same impossible backup/SMB actor is stamped across six disparate Linux roles.

## Recommendations

- If this were synthetic, fix process/protocol ownership at the canonical activity layer. Model SMB access from Linux with `smbclient`, `mount.cifs`/kernel CIFS semantics, or `gvfsd-smb`; model genuine rsync traffic on the rsync protocol/port. Do not relabel only the eCAR renderer, because Zeek confirms the underlying activity is SMB.
- Make server baseline bundles role- and software-aware. Application, database, mail-edge, mail-clinical, proxy, and public web servers should not all receive the same root daemon, command line, and SMB behavior by default.
- Replace independently bounded cross-sensor jitter with a per-sensor clock model: persistent offset, slow drift, rare NTP corrections, and source/queue-specific long-tail delay. Preserve sensor-local UIDs and minor accounting differences.
- Increase administrator command texture by conditioning commands on host role, installed tooling, operator habits, prior output, and session purpose. Exact reuse of common commands is fine; long diagnostic pipelines should recur less mechanically across unrelated systems.
