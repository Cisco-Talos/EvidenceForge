# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 74

## Executive Summary

The intrusion lifecycle is technically coherent and unusually strong at the correlation layer: process, authentication, network, proxy, firewall, and Zeek evidence generally agree in ordering and byte counts. However, repeated hardware-specific syslog messages across heterogeneous hosts, probabilistically thinned cron schedules, and generator-like web-scan variation are concrete dataset-wide artifacts that outweigh the otherwise high realism.

## Evidence For Synthetic

- `[distribution_texture]` Ten Linux hosts with substantially different roles—web, database, proxy, mail, monitoring, file server, laptop, and workstation—share the exact message `IRQ 137 classified for CPU 3 balancing on ens192`. It occurs 22 times across files including `APP-INT-01.../syslog.log`, `DB-PROD-01.../syslog.log`, `WEB-EXT-01.../syslog.log`, and `LT-MRIVERA-02.../syslog.log`. Identical IRQ number, CPU assignment, and interface across that breadth of hardware roles resembles a shared message template rather than host-derived telemetry.
- `[distribution_texture]` The same problem affects other hardware vocabulary: `IRQ 181 classified for CPU 0 balancing on mlx5_comp2` appears 17 times across eight hosts, while `NUMA node 1: balancing pass complete, 2 IRQs moved` appears 25 times across eight. The repeated IRQ/device/NUMA combinations create a narrow common hardware pool across otherwise unrelated systems.
- `[distribution_texture]` All 110 visible `CRON`/`sysstat` messages have timestamps ending in three zero microsecond digits, such as `12:00:00.249000Z`, even though neighboring RFC5424 syslog records routinely carry full microsecond entropy. That event-family-specific quantization is consistent across ten hosts.
- `[contract_gap]` The half-hour `sa1` jobs use sensible per-host minute offsets, but isolated executions disappear on many continuously observed servers. For example, FILE-LNX-01 has `16:31` and `17:31` but no `17:01`; LOG-MON-01 has `15:37` and `16:37` but no `16:07`; PROXY-01 has `13:36` and `14:36` but no `14:06`. The corresponding eCAR records omit precisely the same executions, suggesting event-generation thinning rather than transport loss.
- `[distribution_texture]` The purported Nikto run in `WEB-EXT-01.../web_access.log` repeatedly resamples a small set of paths while adding arbitrary-looking query variants and six-digit `Test:` values. Examples include repeated `/sitemap.xml`, `/phpinfo.php`, `/cgi-bin/test-cgi`, `/.env`, and `/xmlrpc.php` requests with randomized `id`, `cache`, `debug`, or `_` parameters. Across 377 requests from `185.70.41.45`, this looks more like stochastic recombination of a scan vocabulary than a stable scanner test database.
- `[environment_or_collection_plausibility]` On WS-AJOHNSON-01, the command `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` is followed by full-access LSASS opening and a Sysmon Event 8 remote thread whose reported start module/function is `ntdll.dll!NtCreateThreadEx`. Credential reading explains the process access, but an injected LSASS thread beginning at the thread-creation API itself is an odd additional behavior for this command. It is possible for a custom tool, so I treat it as supporting rather than decisive evidence.

## Evidence For Real

- The dataset contains a credible six-hour enterprise slice across 21 hosts: ten Windows systems with Security/Sysmon/eCAR and eleven Linux systems with syslog/eCAR, plus Zeek, ASA, Snort, web, proxy, SMTP, SMB, DNS, DHCP, TLS, and file telemetry.
- The baseline has meaningful long-tail behavior. Zeek core DNS contains 826 distinct query names, 655 of them singletons; DMZ TLS has 417 distinct server names, 295 singletons. Zeek connection states include `SF`, `S0`, `RSTO`, `RSTR`, `OTH`, `REJ`, `S1`, `S2`, and `S3`, rather than only successful flows.
- Cross-source byte accounting is notably realistic. For a `12:00:10` workstation-to-proxy transfer, the proxy’s control and tunnel byte fields reconcile with the Zeek flow, while ASA reports a plausibly larger total including additional accounting overhead.
- DHCP renewals have realistic lease behavior: approximately 30-minute renewals for one-hour leases, one-hour renewals for two-hour leases, and two-hour renewals for four-hour leases, with stable hostname/MAC/IP mappings.
- The attack chain has no identified impossible visible ordering. Network connections, server processes, authentication, file creation, and cleanup occur in operationally credible order, allowing for the stated slice-of-time boundaries.
- Windows metadata is source-appropriate. Security and Sysmon event versions/tasks are internally consistent, XML files validate, and all JSON records parsed successfully.
- The Security-log clearing sequence is especially convincing: process creation for `wevtutil cl Security` precedes Event 1102 at `17:42:07.097`, after which the Security `EventRecordID` restarts while Sysmon continues independently.

## Detailed Analysis

### Scope and collection profile

The visible window is approximately `2024-03-18 12:00:00–17:59:45 UTC`. I identified 21 endpoint/server directories, divided into ten Windows and eleven Linux systems, plus core, database, DMZ, firewall, IDS, and application-layer sensors.

The principal normalized volumes include 33,687 eCAR events, 18,939 Windows Security events, 11,839 Sysmon events, and 19,728 Zeek connection records. Windows Security is dominated by 12,217 Event 5156 records, with substantial Kerberos, process, session, privilege, and SMB telemetry. eCAR includes 24,645 flows, 2,064 process creations, 1,919 terminations, 953 logins, 767 process opens, and smaller file, registry, remote-thread, and service populations. This is enough routine activity that the intrusion is not presented as the only telemetry in the environment.

### Initial access and web-host execution

`WEB-EXT-01.../web_access.log` records scanning from `185.70.41.45`, subsequent injection-oriented requests, and:

- `13:20:08`: `POST /ehr/admin/upload.php`, HTTP 200.
- `13:20:09.587`: eCAR records an Apache child launching `/bin/bash` as `www-data`.
- The command decodes to an interactive bash connection to `45.33.32.30:8443`.
- `13:20:13.130`: Zeek DMZ sees that outbound session begin.
- `13:20:14.294`: WEB-EXT-01 eCAR attributes the flow to the malicious shell lineage.

That ordering is workable. The incoming request, child process, and outbound connection align within several seconds without a causality inversion.

### SSH lateral movement

At `14:15:17`, WEB-EXT-01 initiates SSH from `10.10.3.10:38903` to APP-INT-01 at `10.10.2.30:22`. APP-INT-01 then shows:

- `14:15:19`: `sshd` process creation.
- `14:15:21`: incoming connection in syslog.
- `14:15:28`: accepted password authentication for `root`.
- `14:15:30.801`: root shell creation.

Zeek reports a roughly 13,301-second session, and ASA tears it down at `17:56:58` after `3:41:41`, with comparable byte scale. Core and DMZ Zeek sensors have slightly different observation times and independent UIDs, which is more realistic than duplicated sensor output.

The attacker later reads `/etc/passwd` and `/etc/shadow` and uses APP-INT-01 to reach DB-PROD-01. At `17:14:31.161`, the root shell executes `ssh -A root@DB-PROD-01`; at `17:14:40.533`, eCAR records APP-INT-01 connecting from port 55190 to `10.10.4.10:22`.

### Credential access and Windows persistence

On WS-AJOHNSON-01:

- `15:44:41.810`: `ms-index-service.exe` starts with `privilege::debug` and `sekurlsa::logonpasswords`.
- `15:44:57.455`: Sysmon Event 10 records access to LSASS PID 4292 with `GrantedAccess=0x1FFFFF`.
- `15:44:57.576`: Sysmon Event 8 records a remote thread in LSASS.
- eCAR mirrors the process-open and remote-thread events and then records rapid tool termination.

The access sequence is temporally valid, although the remote-thread start metadata is the tradecraft inconsistency noted above.

On DC-01, WMI-hosted execution creates and elevates a new account:

- `16:14:40.416`: `net user svc_dirsync MhsSvc!2024 /add /domain`.
- `16:14:43.930`: Security 4720 creates SID ending `-4441`.
- `16:14:44.911`: Security 4724 records a password reset.
- `16:14:45`: command to add the account to Domain Admins.
- `16:14:53.745`: Security 4728 records the group addition.

Service and scheduled-task persistence follows, with Security 4697/4698 and matching process activity. The order from command execution to directory/audit events is plausible.

### C2 and DNS tunneling

DC-01 launches `service-healthcheck.exe` under `services.exe` at `16:26:42.063`. Beginning at `16:30:24`, proxy records show recurring requests to:

`https://api.westbridge-services.net/api/v2/checkin`

The user agent is `Go-http-client`, and the destination resolves through the proxy to `45.33.32.30`, the same external address used by the reverse shell. Check-ins recur at variable intervals of roughly 9–12 minutes rather than an exact cadence.

APP-INT-01 generates 254 TXT queries under `ns1.westbridge-services.cloud` from `16:44:54.750` through `16:59:50.116`. Timing is irregular: mean spacing is about 3.54 seconds, with gaps ranging from 0.012 to 51.349 seconds. Responses include 233 `NOERROR`, 13 `NXDOMAIN`, and eight `SERVFAIL`, with varied TTLs. eCAR attributes the associated network operations to `systemd-resolved`, which is appropriate for applications using the local resolver rather than communicating directly with the upstream DNS server.

### Collection and exfiltration

On WS-AJOHNSON-01, archive creation begins at `17:01:10.630`, producing `C:\ProgramData\Microsoft\cache_7f3a.zip` at `17:01:14.302`.

On DB-PROD-01:

- `17:14:58`: root shell becomes active through SSH.
- `17:15:04.285`: `mysqldump --single-transaction ehr patients insurance_claims`.
- `17:15:05.365`: `/tmp/rpt_0318.sql` appears.
- `17:15:34.505`: gzip starts.
- `17:15:38.454`: `/tmp/rpt_0318.sql.gz` appears.
- `17:15:55.453`: `scp` sends it to APP-INT-01.
- `17:16:17.732`: APP-INT-01 records the received file creation.

APP-INT-01 subsequently writes the database archive to FILE-LNX-01 over SMB. Zeek identifies the `ClinicalResearch` share and `Integration\DB-Staging\rpt_0318.sql.gz`, while FILE-LNX-01’s `smbd_audit` records open/write/close at `17:18:41.179–17:18:41.498`.

At `17:25:10.440`, WS-AJOHNSON-01 starts `curl` with the archive as multipart form data through `10.10.3.20:8080`. eCAR records the file read at `17:25:13.346` and proxy connection at `17:25:14.534`. The proxy reports 18,782,930 client tunnel bytes; Zeek observes 18,783,211 originating bytes on the client-side flow. That close byte agreement is technically credible.

### Cleanup

At `17:42`, DC-01 runs encoded PowerShell followed by `wevtutil cl Security`. Security Event 1102 follows at `17:42:07.097`, and Security record numbering restarts while Sysmon continues. Later activity removes the created account and services. APP-INT-01 also executes `history -c` and truncates root’s history at `17:46:41.896`.

These actions support lifecycle coherence. I did not use their completeness or ease of narration as evidence of synthetic generation.

### Baseline texture

The strongest authenticity problem is outside the attack. Linux background activity repeatedly assigns the same IRQ numbers and devices to disparate hosts. This is not merely similar daemon vocabulary: it is identical hardware-level state, including `IRQ 137`, CPU 3, and `ens192`, shared across ten systems, plus repeated `mlx5_comp2` and NUMA outcomes.

Cron behavior shows a second independent pattern. Fleet staggering is believable, but every record is millisecond-quantized inside a microsecond-capable syslog stream, and multiple continuously observed servers independently lose isolated slots from otherwise exact half-hour sequences. That combination suggests a scheduled-event generator followed by sampling.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Linux syslog / irqbalance | Exact IRQ 137/CPU 3/ens192 tuple across ten heterogeneous hosts; other hardware tuples across eight | Highest-impact indicator; host-specific hardware telemetry appears drawn from a shared template pool |
| `distribution_texture` | Linux syslog / CRON | All 110 records quantized to `.xxx000Z` | Consistent event-family timestamp fingerprint |
| `contract_gap` | Linux syslog and eCAR | Isolated half-hour cron slots simultaneously absent from both representations on several active servers | Suggests probabilistic event omission rather than collection transport behavior |
| `distribution_texture` | Apache access log | 377-source-request scan built from repeated paths, random query decorations, and arbitrary-looking test identifiers | Moderate generator-like scanner texture |
| `environment_or_collection_plausibility` | Sysmon/eCAR process access | LSASS read command followed by remote thread beginning at `ntdll!NtCreateThreadEx` | Odd but technically possible tradecraft; supporting evidence only |
| `hard_contradiction` | All sources | None established | Prevents the score from entering the 81–100 range |

## Realism Score by Category

- **Field format accuracy:** 8 — XML and JSON validate, Windows metadata is source-appropriate, and most field relationships are credible; the LSASS remote-thread semantics are the main concern.
- **Temporal patterns:** 7 — Attack ordering, sensor offsets, C2 jitter, and DNS timing are strong, but cron quantization and missing periodic slots are conspicuous.
- **Cross-source correlation:** 9 — Authentication, process, network, SMB, proxy, firewall, and file-transfer records reconcile unusually well without an identified impossible ordering.
- **Behavioral realism:** 7 — The intrusion actions work together technically and baseline traffic has a long tail, but scanner and daemon-event pools expose repeated generation texture.
- **Environmental consistency:** 5 — Host roles and addressing are coherent, but identical IRQ/device/CPU messages across heterogeneous systems significantly reduce production plausibility.

## Recommendations

If this were synthetic, the following changes would improve it:

- Derive `irqbalance`, NUMA, network-interface, and storage-device messages from a persistent per-host hardware model. Do not independently sample exact IRQ/device/CPU tuples from a global pool.
- Preserve each source’s native timestamp behavior. Either generate genuine microsecond variation for cron-originated RFC5424 messages or model a collector that consistently quantizes all messages passing through it.
- Generate periodic jobs from persistent schedules and host availability. If an execution is omitted, support that omission with visible sleep, outage, scheduler failure, collection interruption, or other host-state evidence.
- Replay scanner requests from a tool/version-specific ordered test corpus, including stable test identifiers and tool-appropriate parameters, rather than independently recombining common paths and query fragments.
- Align credential-tool behavior with the selected implementation: represent `sekurlsa::logonpasswords` primarily through LSASS access unless the modeled binary explicitly performs injection, and use a plausible injected thread entry point when it does.
