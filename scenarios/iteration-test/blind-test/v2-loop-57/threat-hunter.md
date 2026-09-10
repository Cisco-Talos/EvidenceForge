# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 44

## Executive Summary

This is a highly production-like six-hour telemetry slice with credible source volumes, substantial benign background activity, and several technically workable hunt paths across endpoint, authentication, network, proxy, and file evidence. I found no hard contradiction or parser-level generator leak, but two concrete lifecycle/collection gaps—an absent Windows account-enable event and an SSH/SCP session with only closing syslog evidence—plus weaker DNS-cache and command-pool texture prevent a confident Real verdict.

## Evidence For Synthetic

- `[contract_gap]` On `DC-01`, the `svc_dirsync` lifecycle is internally incomplete. Security Event 4720 at `2024-03-18T16:14:58.9089659Z` creates the account with `NewUacValue=0x15`; Event 4724 at `16:15:00.6001724Z` resets its password; Event 4738 at `16:15:00.8500102Z` changes UAC from `0x15` to `0x10` and explicitly records `%%2081` (account enabled); and Event 4728 at `16:15:09.9948983Z` adds it to Domain Admins. There is no Event 4722 anywhere in the supplied Security logs, despite adjacent account-management events—including later Event 4726 deletion—being retained. A real collector filter could explain this, but within the visible collection profile this looks like a missing required companion event.
- `[contract_gap]` The inbound SCP session from `DB-PROD-01` (`10.10.4.10:52275`) to `APP-INT-01` has an eCAR inbound flow at `17:15:27.237Z`, an `sshd` child, a root `USER_SESSION LOGIN` at `17:15:34.029Z`, a file create for `/tmp/.cache/rpt_0318.sql.gz` at `17:15:55.034Z`, and a logout at `17:15:56.035Z`. Yet `APP-INT-01/syslog.log` contains only `pam_unix(sshd:session): session closed` at `17:15:55.051439Z`; the connection, acceptance, and PAM-open messages are absent. Other SSH sessions in the same file consistently contain those opening records, making this more specific than generally thin coverage.
- `[distribution_texture]` In `zeek-core/dns.json`, 108 of 1,277 repeat intervals for successful A lookups (8.5%) occur before the prior answer's TTL expires for the same client, resolver, and name. The concentration is strongest in internal service traffic: `DC-02` querying `DC-01` repeats within the 300-second TTL in 18 of 48 intervals (minimum 18.455 seconds), and the reverse direction does so in 13 of 43 intervals (minimum 11.433 seconds). Applications can bypass the OS cache, so this is a moderate texture concern rather than a contradiction.
- `[weak_signal]` Several exact interactive administration commands recur across four unrelated Linux hosts—for example `sudo /usr/bin/systemctl list-units --state=failed --no-pager`, `sudo /usr/sbin/iptables -L -n -v`, and `sudo /usr/bin/ss -ltnp`. These are reasonable runbook commands, but the exact repeated strings modestly suggest a shared command pool.

## Evidence For Real

- The scope is credible for a selectively collected enterprise slice: approximately 122,814 logical records/lines from 21 named hosts over `2024-03-18 12:00–18:00 UTC`, plus core/DMZ/database Zeek sensors, perimeter firewall, IDS, proxy, web, Windows Security/Sysmon, Linux syslog, shell history, and endpoint eCAR telemetry. Domain controllers and network sensors dominate volume rather than every host receiving uniform coverage.
- The Linux intrusion pivots work operationally. A root SSH launch from `LT-MRIVERA-02` leads to a root login on `WEB-EXT-01`, then to `APP-INT-01`, then to `DB-PROD-01`; database export, gzip, SCP, and SMB staging all preserve the expected hosts, ports, identities, filenames, and ordering.
- The Windows path has source-native detail rather than generic attack labels. On `DC-01`, `C:\Windows\PSEXESVC.exe` is written at `15:59:50.898Z`, Security Event 4697 installs `PSEXESVC` at `15:59:51.2318584Z`, the service process starts at `15:59:53.303Z`, and its child executes `cmd.exe /c whoami && hostname` at `15:59:53.863Z`.
- Event-log clearing is modeled with convincing Windows semantics. Security 4688 records `wevtutil cl Security` at `17:42:04.6265788Z`; Event 1102 follows at `17:42:08.0542673Z` under provider `Microsoft-Windows-Eventlog`, with `EventRecordID=1` and SYSTEM identity, after which record numbering restarts.
- Multi-sensor observations retain independent sensor identity. The APP-to-DB SSH connection uses different Zeek UIDs on core (`CeYZLXTgDT0EGVO6RU`) and database (`CRUXJozXMDMy5tEqJX`) sensors, with starts separated by about 72 ms, while tuple, byte counts, duration, and `SF` state remain coherent.
- Background activity has useful entropy and long-tail behavior: Kerberos/LDAP/SMB chatter, DHCP and NTP, proxy and mail traffic, updates, browser and office processes, Linux timers and package maintenance, failed SSH attempts, suspicious-DNS and scan red herrings, and a few shell typos. This creates a believable hunting signal-to-noise ratio rather than leaving only the suspicious chain visible.
- Lifecycle checks did not reveal impossible ordering. eCAR process actors were not referenced before their process creation, same-object session logouts did not precede logins, and 7,224 of 7,226 firewall connection IDs had paired build/teardown records; the two unpaired connections occur at the end of the capture window.

## Detailed Analysis

### Orientation and source mix

The dataset covers 21 systems: two domain controllers, Windows workstations, an application server, a database server, Windows and Linux file servers, mail roles, a proxy, monitoring, a DMZ web server, and an apparent operator laptop. The largest source families are perimeter firewall (`19,015` lines), Zeek core (`17,054` records), Zeek DMZ (`15,462`), Windows Security/Sysmon, and per-host eCAR. Zeek core alone contains 11,036 connection records, 2,884 DNS records, 1,620 HTTP records, 590 file records, and smaller SMB, TLS, X.509, DHCP, OCSP, SMTP, and PE streams. This distribution fits the visible roles: DCs and network choke points are noisy, while user and specialist hosts vary substantially.

All 47 JSON files parsed successfully (`66,283` JSON records), and all 20 XML files parsed successfully (`29,751` Windows events). Source-native structures are generally accurate: Security process IDs use hexadecimal while Sysmon uses decimal fields; Security logons include IPv4-mapped addresses where appropriate; Zeek protocol records carry valid UIDs/FUIDs and connection tuples; proxy CONNECT control records are separated from inspected HTTP requests; and RFC 5424 syslog has plausible facility/severity values and process identifiers.

### Linux foothold, lateral movement, and data staging

The first strong pivot is `LT-MRIVERA-02/bash_history/root.bash_history`: epoch `1710769186` records `ssh -A root@WEB-EXT-01.meridianhcs.local`. `WEB-EXT-01/syslog.log` then records the connection from `10.10.1.99:50563`, public-key acceptance for root at `13:40:03.481Z`, PAM open at `13:40:03.585Z`, and close at `13:42:58Z`.

The next hop reaches `APP-INT-01` from `WEB-EXT-01` (`10.10.3.10:35485`). The application server logs the connection at `14:14:33.174881Z`, password acceptance for root at `14:14:38.742417Z`, and PAM open at `14:14:38.860971Z`; endpoint telemetry follows with the session identity and root commands such as `cat /etc/passwd` and `cat /etc/shadow`.

At `17:14:29.456Z`, APP endpoint telemetry creates `ssh -tt root@DB-PROD-01`. Core and database Zeek sensors observe `10.10.2.30:53130 -> 10.10.4.10:22` at `17:14:37.099645Z` and `17:14:37.171449Z`, both as successful, roughly 728.57-second SSH connections. `DB-PROD-01` accepts the password at `17:14:48.883Z`, then records `mysqldump --single-transaction ehr patients insurance_claims`, creation of `/tmp/rpt_0318.sql`, gzip output `/tmp/rpt_0318.sql.gz`, and an SCP process.

The SCP transport begins in core Zeek at `17:15:25.855867Z` as `10.10.4.10:52275 -> 10.10.2.30:22`, with 776,183 origin bytes and `SF` state. APP receives `/tmp/.cache/rpt_0318.sql.gz`, after which core Zeek records an SMB write at `17:18:36.958426Z` from `APP-INT-01:49771` to `FILE-LNX-01:445`, path `\\FILE-LNX-01\ClinicalResearch\Integration\DB-Staging\rpt_0318.sql.gz`, size 752,097 bytes. The associated Zeek file record reports the same size, no missing bytes, gzip MIME type, and stable hashes. This is a technically viable sequence with realistic processing and observation delays. Its one meaningful defect is the missing opening syslog sequence for the SCP receiver session described above.

### Windows compromise, persistence, and cleanup

The PSEXESVC chain on `DC-01` aligns file, service, process, and child-process evidence. Later, WMI-launched SYSTEM commands create `svc_dirsync`, change its password/state, and add it to Domain Admins. Service persistence follows: `sc.exe create DeviceSyncSvc ... start= auto` begins at `16:20:29.830Z`, Security 4697 records installation at `16:20:33.616Z`, and a scheduled task is created shortly afterward. `DeviceSyncSvc.exe` later executes under `services.exe`, while `DC-02` shows a separate `DirectoryCacheSvc` service lifecycle and eventual stop/delete commands.

The account sequence is the clearest authenticity concern because the visible 4738 explicitly describes a disabled-to-enabled transition but no 4722 exists. That is not merely an absent optional source: it is a missing member of a retained Security account-management lifecycle.

The workstation staging/exfiltration sequence is also mechanically sound. `WS-AJOHNSON-01` Security/Sysmon records `Compress-Archive` at `17:01:12Z` and Sysmon Event 11 creates `C:\ProgramData\Microsoft\cache_7f3a.zip` at `17:01:16.1438760Z`. Curl starts at `17:24:58.0511697Z`, eCAR reads that archive at `17:25:01.183Z`, and connects from `10.10.1.35:63146` to proxy `10.10.3.20:8080`. Zeek sees the connection at `17:25:02.030350Z`; proxy logs then record the matching CONNECT and POST to `/upload/telemetry/7f3a2b19`, with approximately 18.78 MB of client-to-server tunnel data and a 15.434-second duration.

### Timing, lifecycle, and pivot feasibility

Across 24,059 endpoint FLOW observations, 23,265 could be matched to a Zeek connection on exact tuple/protocol within two minutes. For matched records, endpoint-versus-sensor start delta had a median near `+0.176` seconds; no endpoint observation occurred more than five seconds after its matched connection ended. Those offsets are neither bit-identical nor implausibly inverted.

The network logs preserve useful source boundaries. Mirrored core/database SSH observations use independent Zeek UIDs, while SMB mapping, SMB file, generic file, endpoint file, and process records converge on the same transfer without treating every timestamp as identical. Firewall durations and byte counts have broad distributions, including common 30-second SYN timeouts, zero-duration short sessions, and long high-volume sessions. This is closer to live collection behavior than to a single perfectly synchronized event stream.

### Baseline and distribution texture

The malicious activity is a minority of the available telemetry. Benign processes include Office, browsers, Webex, AnyConnect, Defender, Windows Update, WMI, scheduled tasks, Linux cron/systemd activity, package maintenance, log rotation, and service health checks. Authentication noise includes interactive and network logons, Kerberos activity, service sessions, and failures. Network traffic includes DNS, NTP, DHCP, LDAP/Kerberos, SMB, SQL, mail, proxy, web, and IDS alerts. Host-specific volume varies enough to fit role and activity differences.

The main statistical caveat is DNS cache behavior. Most repeat intervals occur after TTL expiry, but the within-TTL internal repeats—especially DC-to-DC lookups—are more numerous than I would expect if every process relied on a shared OS cache. Exact admin command reuse across hosts is another low-weight concern. Neither pattern is decisive: direct resolver libraries, service isolation, cache flushes, and common operations runbooks can produce both effects in real estates.

### Competing hypotheses

The Real hypothesis explains the independent sensor UIDs, small source-specific delays, capture-edge lifecycle truncation, command typos, role-weighted source volume, and detailed native Windows/Linux semantics. The Synthetic hypothesis better explains why the `svc_dirsync` transition omits 4722 while retaining all neighboring account events, why one high-value SCP session has a syslog close without its opening/authentication sequence, and why some baseline DNS and command activity repeats from a limited vocabulary. Because the defects are concrete but localized, and no hard contradiction was found, the evidence is mixed rather than sufficient for a confident Synthetic or Real classification.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Windows Security / account management | One high-value account lifecycle on `DC-01` | Highest impact: visible UAC enablement lacks expected Event 4722 despite adjacent retained events. |
| `contract_gap` | Linux syslog + eCAR + Zeek | One inbound SCP/SSH receiver session on `APP-INT-01` | Moderate impact: close-only syslog conflicts with the full opening pattern used by other SSH sessions in the same source. |
| `distribution_texture` | Zeek DNS | 108 of 1,277 successful-A repeat intervals in core data | Low-to-moderate impact: positive records are sometimes re-queried before TTL, concentrated in internal service lookups. |
| `weak_signal` | Linux process/shell activity | Several exact commands across four hosts | Low impact: possible shared generator pool, but equally compatible with a standard admin runbook. |

## Realism Score by Category

- **Field format accuracy:** 9 — JSON/XML parse cleanly and Windows, Zeek, proxy, firewall, IDS, syslog, and endpoint fields are predominantly source-native and internally typed correctly.
- **Temporal patterns:** 8 — Human, service, timeout, and sensor-delay timing is varied and plausible; DNS cache-bypass texture is the main reservation.
- **Cross-source correlation:** 7 — Most important pivots preserve tuples, identities, files, and ordering, but the missing 4722 and SCP receiver opening records are material lifecycle gaps.
- **Behavioral realism:** 8 — The observed administration, compromise, persistence, staging, exfiltration, cleanup, and benign activity are technically executable and role-compatible.
- **Environmental consistency:** 8 — Source volumes and protocols fit the 21-host topology and visible roles, with no dataset-wide coverage contradiction.

## Recommendations

- If this were synthetic, emit Security Event 4722 whenever an account transitions from disabled to enabled, and validate the complete 4720/4722/4724/4738/4728/4726 account-management lifecycle against the UAC values actually rendered.
- If this were synthetic, make Linux SSH observation decisions lifecycle-coherent. An accepted SCP subsystem session should either retain connection/accept/PAM-open/close together or model an explicit, source-level collection loss that can plausibly remove the opening group.
- If this were synthetic, add host/process-aware DNS caching so successful A answers suppress subsequent prerequisites until TTL expiry unless a modeled application explicitly bypasses the system resolver, switches resolver context, or flushes cache.
- If this were synthetic, widen per-host administrative command vocabularies and parameterization while retaining the exact repeated commands only for hosts governed by a shared runbook or automation mechanism.
