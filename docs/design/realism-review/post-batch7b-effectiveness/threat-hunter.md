# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment: Synthetic**

**Verdict Confidence: 84**

**Synthetic-Confidence Score: 72**

The score falls in the 61–80 “likely synthetic” range. The corpus is unusually strong in field construction, entity consistency, and multi-source pivots, but several concrete lifecycle and distribution defects outweigh those strengths. The conclusion does not rely on filesystem metadata, sanitization, source completeness, missing optional telemetry, or narrative neatness.

## Executive Summary

The corpus contains approximately 53,548 logical records across Windows Security, Sysmon, ECAR endpoint telemetry, Linux ECAR/syslog, ASA, Snort, proxy and web access logs, bash history, and seven Zeek logs. Most activity covers 2024-05-14 12:00–18:00 UTC, with endpoint lifecycle tails extending to approximately 18:37 UTC.

Operationally, it supports a credible hunt. One particularly strong chain begins with 63 Nikto-style requests from `185.199.110.42`, generates 13 Snort alerts, and is followed by a successful SSH password login as `www-data` to `WEB-BO-01`, an interactive bash shell, and `id`, `ip addr`, and `ss -tulpn` discovery. Routine user, service, Kerberos, SMB, proxy, update, and Internet-scanning activity provides useful background texture.

The authenticity decision turns on four findings:

- Zeek reports 22 SMB files whose fully observed file byte count exceeds all responder payload bytes recorded for the containing connection.
- Windows Type 3 session lifetimes exhibit near-perfect 30- and 60-second upper bounds rather than a natural heavy-tailed session distribution.
- The malicious `www-data` SSH transport closes normally in both Zeek and ASA at 13:47:28, but its endpoint session, PAM close, shell termination, and logout never occur despite hours of subsequent endpoint logging.
- One administrator opens 44 successful interactive SSH sessions in six hours, with up to six concurrent shells on the web server, while both Linux hosts exhibit similarly templated high-rate daemon chatter.

These are concrete contract and distribution defects, not conclusions drawn from a clean attack narrative.

## Evidence For Synthetic

1. **[hard_contradiction] Zeek file bytes exceed connection payload bytes.**

   Of 196 SMB records in `files.json`, 22—11.2%—claim more `seen_bytes` than the corresponding sending direction contains in `conn.json`. Excesses range from 36 to 559 bytes, with a median of 174.5 bytes. All 22 files claim `missing_bytes: 0`.

   Examples:

   - At `2024-05-14T13:37:48.576764Z`, UID `CWBNWQnG474cH7g5bx` carries `\\DC-BO-01\Users\Public\Documents\meeting-notes.xlsx`. The file claims `seen_bytes=46904`, `total_bytes=46904`, and `missing_bytes=0`; the server-to-client connection direction has only `resp_bytes=46345`, 559 bytes less than the purportedly observed file.
   - At `2024-05-14T12:13:19.204852Z`, UID `CJYRHQYjKQD5Q4pU7TL` carries `roadmap.xlsx` with 44,850 observed bytes over a connection with only 44,457 responder payload bytes.
   - At `2024-05-14T16:16:35.236446Z`, UID `CAXAAVRytkTcplrbdG` claims a complete 45,376-byte PPTX over 44,922 response payload bytes.

   SMB framing would require the connection payload to be larger than the file, not smaller. The connection-level `missed_bytes` values closely track the deficits while the file-level records still claim complete capture, reinforcing the contradiction.

2. **[distribution_texture] Windows network-logon durations have generator-like hard bounds.**

   On `FILE-BO-01`, there are 341 successful Type 3 logons and 340 matched logoffs. Of those matched sessions, 339—99.7%—last less than 60 seconds. The lone exception lasts 7,131 seconds. The largest non-outlier is 59.606 seconds.

   On `DC-BO-01`, 207 of 209 Type 3 logons have matched logoffs. Of those, 204—98.6%—last less than 30 seconds, while three are long-lived outliers. The largest short session is 29.883 seconds.

   The short sessions broadly fill their respective ranges rather than clustering around an organic application timeout. This resembles uniformly sampled “1–30 second” and “2–60 second” lifecycles. It also produces excessive reconnect-and-reauthenticate behavior in a six-hour period where persistent SMB and authenticated channel reuse should create a much longer tail.

3. **[contract_gap] The compromised SSH session outlives its closed transport.**

   Zeek UID `CBqqr8A9Ebil48BiEf` begins at `13:05:12.996601Z` from `185.199.110.42:54705` to `10.44.30.10:22`, lasts 2,535.235 seconds, and ends in `SF` at approximately `13:47:28.232Z`. ASA independently logs connection `1217486` built at 13:05:12 and torn down with TCP FINs at 13:47:28.

   Endpoint evidence records:

   - password accepted for `www-data` at `13:05:16.916909Z`;
   - PAM session opened at `13:05:17.060087Z`;
   - ECAR login at `13:05:17.518Z`;
   - `/bin/bash`, `id`, `ip addr`, and `ss -tulpn` processes.

   It never records a PAM session close, ECAR logout, bash termination, or terminating `sshd` child. This is not a collection-boundary issue: the transport closes more than four hours before the endpoint corpus ends, and comparable Nina Kapoor SSH sessions consistently close within roughly 0.1–15 seconds of their transport.

4. **[distribution_texture] Excessive overlapping interactive SSH churn.**

   Nina Kapoor records 34 successful SSH logins to `WEB-BO-01` and 10 to `PROXY-BO-01` in six hours. The web server reaches six simultaneous sessions. Thirty of its 34 matched sessions terminate before 30 minutes; all eight matched proxy sessions do so. Source telemetry shows repeated `ssh.exe nina.kapoor@...` commands, and the receivers create `-bash`, so these are interactive shells rather than one-shot remote-command transports.

   An administrator can use several terminals, but 44 fresh interactive sessions, six-way overlap, and another sharp concentration below 30 minutes collectively look more like independently generated session objects than a human workflow or multiplexed SSH practice.

5. **[environment_or_collection_plausibility] Linux background noise is unusually templated and chatty.**

   In six hours, `WEB-BO-01` emits 153 `rsyslogd`, 148 `irqbalance`, 141 `snapd`, and 134 `systemd-resolved` messages. These include 22 rsyslog SIGHUP reload completions, 38 normalized “NUMA balancing pass complete” messages, 35 resolver feature-restoration messages, and 20 UDP/EDNS downgrade messages.

   `PROXY-BO-01` repeats the same uncommon families: 43 `rsyslogd`, 43 `irqbalance`, 34 `snapd`, and 43 `systemd-resolved` messages, including seven rsyslog SIGHUP reloads and eleven NUMA balancing passes. The messages are individually credible, but their repeated high-rate use on both hosts looks like a background-template pool rather than ordinary production daemon behavior.

## Evidence For Real

- **Strong source-native formatting.** Windows XML uses credible provider GUIDs, event versions, tasks, keywords, channels, SIDs, hexadecimal IDs, Sysmon schemas, and seven-digit event timestamps. ASA PRI/severity values and message IDs, RFC 5424 syslog structure, proxy/web formats, Snort alert syntax, and Zeek JSON fields are generally accurate.

- **Coherent Windows entity identity.** All observed domain users share one domain SID prefix, `S-1-5-21-1195943476-1993654859-1558797721`, with stable RIDs across hosts: Maya Patel `1001`, Owen Reed `1002`, Lena Morris `1003`, Nina Kapoor `1004`, and Victor Hale `1005`.

- **OS-cohort binary consistency.** Windows 11 workstation telemetry consistently identifies system binaries as version `10.0.22621.1` with identical hashes across the workstation fleet. The DC uses `10.0.20348.1` and the file server `10.0.17763.1`, with distinct but internally stable hashes. No image changes hash on the same host during the window.

- **Mostly valid process lifecycles.** Across 714 Sysmon process creates and 576 terminations, 497 terminations join to a visible create. None precedes its create, no dependent event occurs after a matched termination, and no visible PID reuse creates overlapping lifetimes. Boundary-started and boundary-ended processes explain much of the unmatched population.

- **Rich network texture.** The 6,547 Zeek connections occupy every minute of the six-hour sensor window and include 4,999 `SF`, 1,277 `S0`, and seven less-common connection states. Traffic spans DNS, Kerberos, SMB, LDAP, HTTP, TLS, SSH, RDP, PostgreSQL, SMTP, and RPC.

- **Realistic DNS and TLS variation.** DNS contains 938 `NOERROR`, 112 `NXDOMAIN`, and seven `SERVFAIL` responses; median RTT is 0.965 ms, p90 is 69.43 ms, and the maximum is 2.411 seconds. TLS contains TLS 1.2 and 1.3 with seven version/cipher combinations. All 346 certificate-bearing named sessions match their leaf SAN, all 640 X.509 IDs join to certificate file records, and all 35 OCSP records join to OCSP files.

- **Good protocol fan-out.** Every DNS, HTTP, and TLS UID joins a connection with coherent tuples and timestamps. HTTP bodies never exceed their containing connection payload. Static web objects preserve exact sizes: for example, 24 successful requests for `app.bundle.8ed994fa.js` are all 92,713 bytes, 23 `hero.webp` requests are all 387,266 bytes, and 23 successful favicon requests are all 890 bytes.

- **Plausible firewall state.** ASA contains 2,695 TCP build/teardown pairs, 769 translation build/teardown pairs, 91 UDP pairs, and 57 ICMP pairs, plus 128 policy denies. Connection IDs, NAT directions, ports, durations, and termination reasons are coherent.

- **Useful signal-to-noise.** Only 50 Snort alerts sit among thousands of network and host events. There is routine user browsing, updates, Kerberos, file access, service activity, failed credentials, Internet scanning, proxy denial/cache/tunnel behavior, and internal policy-denied traffic. This is substantially richer than an attack-only trace.

## Detailed Analysis

### Inventory and scope

| Source group | Logical records |
|---|---:|
| ECAR across nine hosts | 17,028 |
| Windows Security across seven hosts | 10,325 |
| Sysmon across seven hosts | 3,609 |
| Zeek `conn`, `dns`, `files`, `http`, `ocsp`, `ssl`, `x509` | 11,043 |
| Cisco ASA | 7,352 |
| Snort | 50 |
| Linux syslog | 2,247 |
| Proxy access | 1,240 |
| Web access | 601 |
| Bash-history commands | 53 |

The principal sensor window begins around `2024-05-14T12:00:05Z` and ends near `18:00Z`. Some Windows lifecycle evidence extends past the network window: the DC to 18:01, file server to 18:22, and one workstation to 18:37.

### Threat-hunting pivots

The highest-confidence malicious chain is centered on `185.199.110.42`:

1. It generates 63 Nikto requests between 12:54:51 and 12:57:47, probing `.git`, `.env`, `.htaccess`, phpMyAdmin, WordPress, SQL backups, and CGI paths.
2. Thirteen Snort alerts identify repository access, environment-file access, `.htaccess`, phpMyAdmin backdoor access, rapid HTTP connection attempts, and related reconnaissance.
3. ASA and Zeek preserve exact request tuples and connection state.
4. At 13:05:12 it establishes SSH to the same public web server.
5. Syslog records an accepted password and PAM session for `www-data`; ECAR then shows an interactive bash shell and discovery commands.

This sequence is operationally huntable without needing a supplied narrative. Its neatness is not itself an authenticity indicator; the missing close lifecycle is.

A second useful pivot is `10.44.10.21`, which accounts for 70 ASA denies. Sixty-six target external database services—17 PostgreSQL/5432, 17 MySQL/3306, 16 Redis/6379, and 16 MSSQL/1433—while four target HTTPS. This merits endpoint review independently of the web-server compromise.

### Role and account plausibility

The IP and host-role model is consistent: workstations occupy `10.44.10.0/24`, servers `10.44.20.0/24`, and the public web server `10.44.30.10`. Workstations use the proxy on `10.44.20.30:8080`, the DC on `10.44.20.10`, and the file server on `10.44.20.20`.

Nina Kapoor plausibly behaves as an administrator, using RDP, SSH, Group Policy tools, DHCP management, service scripts, and file shares. Stable Windows SID and Linux UID values support that identity. The issue is not her capability but the statistically excessive count and overlap of freshly created interactive sessions.

The `www-data` SSH login is an egregious configuration in many environments—its observed UID is 3989 and it receives `/bin/bash`—but real compromises often exploit precisely such misconfiguration. I therefore do not treat the account choice alone as synthetic evidence.

### Volume and distribution realism

Network and web activity have good variation. All 360 minutes contain connections; HTTP has ten status codes; DNS has successful, negative, and failure outcomes; TLS has version, cipher, certificate-chain, and resumption texture. External web activity includes ordinary browsers, mobile clients, bots, scanners, internal health checks, and stable cacheable assets.

The weak area is lifecycle distribution. FILE and DC Type 3 sessions almost entirely occupy fixed-width ranges with isolated long outliers. Linux SSH sessions show a similar sub-30-minute concentration. These patterns are visible only after aggregation, but once quantified they are difficult to reconcile with naturally reused authenticated channels.

### Cross-source correlation and pivot feasibility

Most pivots work well:

- Zeek UIDs join DNS, HTTP, TLS, certificate, OCSP, and file records.
- ASA connection IDs pair cleanly across build/teardown events.
- Web tuples join ASA, Zeek, web access, ECAR FLOW, UFW, and Snort where applicable.
- Windows process IDs, GUIDs, logon IDs, SIDs, principals, parent images, and hashes remain stable.
- Successful Nina SSH connections usually order transport, auth, shell, commands, close, PAM logout, and endpoint termination correctly.

The notable exceptions are the SMB file byte contradictions and the unclosed `www-data` endpoint session.

## Synthetic Indicator Summary

| ID | Classification | Quantified indicator | Weight |
|---|---|---|---|
| S1 | `hard_contradiction` | 22/196 SMB files contain more fully observed bytes than exist in the sending connection direction; excess 36–559 bytes | High |
| S2 | `distribution_texture` | FILE: 339/340 matched Type 3 sessions under 60 seconds; DC: 204/207 under 30 seconds, with sharp upper bounds | High |
| S3 | `contract_gap` | `www-data` SSH transport closes via FIN in Zeek and ASA at 13:47:28, but endpoint/PAM session never closes | High |
| S4 | `distribution_texture` | 44 successful interactive SSH sessions for one administrator in six hours; six concurrent on WEB; strong sub-30-minute concentration | Medium |
| S5 | `environment_or_collection_plausibility` | Repeated rsyslog reload, irqbalance, snapd, and resolver diagnostic templates on both Linux hosts | Medium |
| S6 | `weak_signal` | Several source volumes and process populations appear curated, but filtering could explain them and they were not used materially | Low |

No material `schema_or_format` defect was found. Most individual records are syntactically strong.

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 9/10 | Strong Windows, Zeek, ASA, Snort, proxy, web, and syslog construction with credible field values |
| Temporal patterns | 5/10 | Good jitter and traffic clustering, offset by sharp session-duration bounds and repeated short lifecycles |
| Cross-source correlation | 8/10 | Excellent joins and ordering overall; reduced by SMB byte contradictions and the missing SSH close |
| Behavioral realism | 6/10 | Credible attack and user activity, but excessive interactive-session churn and limited channel reuse |
| Environmental consistency | 7/10 | Stable identities, roles, OS cohorts, and network topology; Linux daemon chatter is questionable |

## Recommendations

- Correct file/connection accounting so each file’s observed bytes, missing bytes, framing overhead, and directional connection payload are physically compatible.
- Replace independent per-connection Type 3 logons with durable authenticated SMB/Kerberos sessions and a heavy-tailed lifetime model. Preserve short sessions, but avoid fixed 30- or 60-second population ceilings.
- Tie SSH shell, PAM, endpoint session, and transport closure into one lifecycle contract. A FIN/RST must result in compatible session-close and process-termination evidence unless an explicit collection drop affects the entire source-local lifecycle.
- Model administrator behavior as a workflow: reuse or multiplex shells, associate bash-history commands with a specific session, and limit overlapping interactive sessions unless the scenario intentionally requires them.
- Make rsyslog reloads, resolver degradation, irqbalance diagnostics, and snap/scheduler messages depend on host state or a visible triggering incident rather than repeated background pools.
- Preserve the strongest existing features: stable SIDs and binary hashes, OS-specific metadata, static-object sizes, certificate/SAN chains, stateful ASA pairs, varied connection outcomes, and cross-source tuple reuse.
- Operationally, treat the `185.199.110.42` → `www-data` SSH chain as a confirmed-compromise lead: isolate `WEB-BO-01`, revoke the credential, inspect the long-lived shell and its descendants, and search for the source across authentication, proxy, firewall, and file-access evidence.
- Separately investigate `10.44.10.21` for the 66 policy-denied external database probes.
