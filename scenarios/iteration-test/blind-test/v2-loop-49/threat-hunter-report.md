# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 91  
**Synthetic-Confidence Score:** 84

## Executive Summary

The collection is unusually strong at reproducing a huntable enterprise incident: the visible six-hour window contains credible background traffic and several attack paths that pivot cleanly across endpoint, Windows, web, network, proxy, firewall, and IDS evidence. I nevertheless assess it as synthetic because a dominant web scanner has a repeated generator-like User-Agent pattern, one Windows NewCredentials chain omits locally expected credential-use evidence despite contiguous records and correct examples elsewhere, and one eCAR process visibly loads modules after its recorded termination.

## Evidence For Synthetic

- `[schema_or_format]` The dominant scanner at `185.70.41.45` generated 349 entries in `WEB-EXT-01.meridianhcs.local/web_access.log`; 346 use Nikto syntax and all 346 have a different six-digit `Test:` token, ranging from `104560` to `995913`, with no repeats. Examples include `Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:702143)` and `(Test:493905)`. A single Nikto run changing an ostensibly test-identifying User-Agent token to a unique random six-digit value on every request is a strong generator fingerprint, not normal tool identity behavior.
- `[hard_contradiction]` In `WS-AJOHNSON-01.meridianhcs.local/ecar.json`, Teams PID `6212`, object ID `83166db9-4507-45e7-8353-7ffe35c45eb4`, terminates at `2024-03-18T16:10:37.492Z`. Seven `MODULE LOAD` records for that exact actor and PID then occur from `16:10:37.497Z` through `16:10:37.575Z` (`kernel32.dll`, `kernelbase.dll`, `msvcrt.dll`, `ucrtbase.dll`, `advapi32.dll`, `sechost.dll`, and `rpcrt4.dll`). The corresponding Sysmon Event 5 records termination at `16:10:37.4718659Z`, reinforcing that this is a visible lifecycle inversion rather than a missing pre-window start.
- `[contract_gap]` `WS-AJOHNSON-01` records a Security 4624 Type 9 NewCredentials logon at `17:00:45.9096226Z`, EventRecordID `131022`, from `aisha.johnson` with `TargetOutboundUserName=marcus.chen`, `LogonProcessName=seclogo`, and `ProcessName=C:\Windows\System32\svchost.exe`. There is no nearby Security 4648 and no `runas.exe` evidence anywhere in that host's Security, Sysmon, or eCAR data. The neighboring visible records are contiguous (`131021`, `131022`, `131023`), while two Type 9 examples on `WS-MCHEN-01` correctly have same-second 4648 records and `runas.exe`; the asymmetric omission therefore looks like an incomplete generated credential-use contract rather than a general audit-policy gap.
- `[contract_gap]` The same Type 9 session (`0x27c991a`) launches the staging PowerShell processes at `17:00:56.216Z` and `17:01:10.216Z` as `aisha.johnson`, but their parent is a long-lived `svchost.exe` owned by `NETWORK SERVICE`. At `17:24:55.822Z`, the upload `curl.exe` is again attributed to `aisha.johnson` and logon `0x27c991a` while directly parented by `services.exe` owned by `SYSTEM`, without a visible service creation/start on the workstation. This actor/session/process ownership is technically strained and compounds the missing 4648/runas evidence.
- `[distribution_texture]` Scheduled Linux process telemetry forms a fleet-wide half-hour lattice. Nine Linux hosts repeatedly launch the identical `/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'` plus `debian-sa1 1 1` pair at a fixed per-host second every 1,800 seconds, with only sub-second jitter and occasional skipped slots. For example, `APP-INT-01` runs at `:00:01` and `:30:01` for all twelve half-hours, while `MAIL-CLIN-01` runs at `:04:00` and `:34:00`; centralized cron configuration is plausible, but the exact fleet-wide cadence and identical command shape add a synthetic timing texture.
- `[distribution_texture]` The core IDS source is unusually concentrated: 58 of 65 `snort-core/snort_alert.log` records (89%) are only five generic TLD-query signatures for `.top`, `.to`, `.bit`, `.cloud`, and `.tk`. The repeated palette is spread across workstations, servers, the proxy, and the web tier while only seven alerts represent all other behaviors. This does not prove synthesis alone, but it makes the red-herring mix look deliberately sampled rather than like an organically noisy ruleset.

## Evidence For Real

- The data has meaningful scale and environmental structure: 21 host directories, three Zeek sensor views, two IDS views, and approximately 114,000 logical records over roughly `12:00-18:00Z`. The mix includes about 32,914 eCAR rows, 32,626 Zeek rows, 23,289 Windows Security/Sysmon events, 18,175 ASA rows, 3,975 syslog rows, 2,262 proxy rows, 706 web rows, and 174 IDS alerts.
- The initial compromise is exceptionally pivotable. `web_access.log` shows `185.70.41.45` POSTing `/ehr/admin/upload.php` at `13:19:41Z`; WEB-EXT eCAR records the inbound TLS flow at `13:19:42.187Z`, a `www-data` base64-decoding Bash process at `13:19:42.527Z`, and its outbound connection at `13:19:46.689Z` to `45.33.32.30:8443`. Zeek DMZ independently records that exact tuple and source port `45829` at `13:19:45.885942Z` with a 25.866842-second `SF` session and bidirectional bytes.
- Later attacker activity remains technically coherent across platforms. A root SSH client starts on `APP-INT-01` at `17:14:34.614Z` and connects to `DB-PROD-01:22` at `17:14:49.438Z`; the database host then produces a root shell, `mysqldump`, `/tmp/rpt_0318.sql`, gzip output, and finally `scp` at `17:30:25.718Z`. The SCP flow uses source port `46790`, and `APP-INT-01` observes the matching inbound tuple, successful root session, and `/tmp/.cache/rpt_0318.sql.gz` creation at `17:30:36.131Z`.
- Windows credential-access evidence is layered rather than represented by a lone command line. `WS-AJOHNSON-01` records `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` at `15:44:56`, followed by Sysmon process-access events against `winlogon.exe` and `lsass.exe` and a remote-thread event against LSASS. Security, Sysmon, and eCAR timestamps differ by realistic small amounts instead of being bit-identical.
- Domain persistence is huntable in native Windows events. On `DC-01`, the `svc_dirsync` creation and Domain Admin addition are visible in process events and Security 4720/4724/4738/4728 records around `16:14:32-16:14:40Z`; service and scheduled-task persistence follow around `16:20Z`. The later `wevtutil cl Security` action is followed by Event 1102 and a plausible Security EventRecordID reset before subsequent cleanup events.
- Network texture is substantially better than a simplistic all-success model. `zeek-core/conn.json` contains `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `OTH`, `S1`, `S2`, and `S3`; the DMZ and database sensors also show mixed failures, resets, ICMP, and a broad duration range. DNS includes A, AAAA, PTR, SRV, TXT, NS, MX, and SOA, plus NOERROR, NXDOMAIN, SERVFAIL, and REFUSED outcomes.
- The background endpoint evidence is varied enough to support normal hunting pivots: service logons, machine-account authentication, DHCP, Kerberos, LDAP, SMB, routine SSH, mail, package/update activity, user browsing, scheduled administration, syslog daemons, process opens, registry changes, module loads, and process termination are all represented. I did not treat unmatched starts or ends at the six-hour boundaries as suspicious.

## Detailed Analysis

### Orientation and collection scope

The visible collection spans approximately six hours on 18 March 2024. It covers 21 named systems across workstation, domain-controller, file, mail, proxy, monitoring, application, web, and database roles. Host evidence consists of Windows Security and Sysmon XML, Linux syslog and Bash history, and eCAR. Network evidence consists of Zeek core/DMZ/database sensors, ASA firewall logs, core/perimeter Snort alerts, explicit-proxy access records, and external-web access logs.

The logical record mix is believable for a filtered hunt dataset rather than a raw full-fidelity enterprise lake. eCAR is dominated by 23,866 FLOW records but still contains 4,449 process lifecycle records, 2,266 module loads, 1,641 user-session records, and several hundred file and registry events. Windows Security is appropriately dominated by 5156 network permits on instrumented hosts and by Kerberos on the two domain controllers. I did not penalize the selected source coverage or high cross-source completeness by itself.

### Initial access and web-to-shell pivot

The public source `185.70.41.45` conducts an intensive HTTPS web assessment against `WEB-EXT-01` from approximately `12:30:04Z` through `13:19:41Z`. Zeek DMZ sees 399 connections from this source to port 443: 350 `SF`, 23 `S0`, 16 `RSTO`, and 10 `RSTR`. The web server logs 349 requests, principally 404 and 403 responses, across common discovery paths such as `/.env`, `/cgi-bin/test-cgi`, `/server-info`, `/phpMyAdmin/`, and `/.git/HEAD`. Median web-request spacing is three seconds, which is credible automated scanning behavior.

The compromise transition works operationally. The final POST to `/ehr/admin/upload.php` at `13:19:41Z` is immediately followed by inbound transport, Apache-spawned Bash as `www-data`, and the reverse-shell transport to `45.33.32.30:8443`. Exact tuple and timing agreement across eCAR and Zeek makes this an effective hunting pivot. The endpoint process ends after roughly 55 seconds, while the Zeek session itself lasts about 25.9 seconds; that is compatible with shell/process setup and teardown rather than an impossible ordering.

The authenticity problem is the scanner's User-Agent identity. Of the source's 349 web rows, every User-Agent is unique. More importantly, all 346 Nikto rows replace the `Test:` token with a non-repeating random-looking six-digit value. This high-cardinality pattern has no operational benefit for a normal Nikto scan and is more consistent with synthetic variation being applied independently to every request. Because these rows account for almost half of the complete web access log, the defect is both repeated and prominent.

### Privilege, discovery, and lateral movement

At `13:39:50Z`, `WEB-EXT-01` records a successful root SSH session from `10.10.1.35`, followed by a root Bash shell and commands including `/etc/hosts`, `/etc/resolv.conf`, credential-file discovery, and two `nmap` scans. A separate legitimate-looking SSH login by `lina.nguyen` arrives from `10.10.1.21` during this activity. This overlap with normal administration makes the attacker evidence less isolated and is a realism strength.

The Windows branch likewise provides useful pivots. Credential discovery and LSASS access on `WS-AJOHNSON-01` precede RDP/SSH and remote-execution activity. The collection shows workstation-to-server Kerberos, SSH, RDP, SMB, and proxy paths rather than teleporting effects between hosts. The `svc_dirsync` domain-account creation, privilege addition, service installation, scheduled task, execution, log clearing, and deletion can be reconstructed through DC Security, Sysmon, and eCAR records.

The weak point is the Type 9 credential lifecycle at `17:00:45.9096226Z`. Its use of `seclogo`, an outbound identity different from the current identity, and a fresh logon ID all indicate explicit alternate credentials. Yet there is no 4648 or initiating `runas.exe`, and the record IDs around it leave no local gap. This is particularly conspicuous because `WS-MCHEN-01` contains two correct Type 9 sequences: at `14:50:15Z` and `16:48:40Z`, each has a same-second 4648 naming `runas.exe`. The AJOHNSON branch therefore appears to have been assembled from a Type 9 session primitive without all of the evidence normally emitted by the same activity family.

Process ownership after that logon remains questionable. The Type 9 PowerShell children inherit Aisha's identity and new logon ID but are directly parented by a NETWORK SERVICE `svchost.exe`. Later, the exfiltration `curl.exe` is parented directly by SYSTEM `services.exe` while attributed to Aisha and the Type 9 logon. Those relationships could be explained by an explicit service or a source-specific broker, but the visible host data does not show that mechanism. This is stronger than a mere missing optional source: the process records themselves expose conflicting ownership cues.

### Collection and exfiltration

The database collection path is one of the most realistic parts of the dataset. The sequence preserves user, process, file, tuple, and timing relationships across the SSH client, server session, `mysqldump`, SQL file, gzip result, SCP read, network connection, remote SSH session, and destination file creation. It also coexists with database application traffic and unrelated administration. These are the kinds of pivots a hunter can actually use.

The Windows upload path includes source-file creation and a correlated file read by `curl.exe` before the client-to-proxy FLOW. The proxy and Zeek views retain the client/proxy/origin separation. That is a strong realism feature, although the anomalous `services.exe` parent and Type 9 evidence gap weaken the host-side provenance.

### Lifecycle and timing analysis

Across all eCAR hosts, I found no dependent record whose known actor process was created later. Unmatched process/session starts and ends exist, but I excluded them because the collection is explicitly a bounded window. The material exception is the Teams utility process on `WS-AJOHNSON-01`: its first module load occurs seven milliseconds after create, then termination is recorded 24 milliseconds after create, followed by seven further module loads over the next 83 milliseconds. Because the same eCAR process UUID and PID are used and the Sysmon termination precedes those loads as well, this is an impossible visible lifecycle under the timestamps presented.

The Linux background schedule is coherent but overly regular. Every observed `debian-sa1` execution has a paired shell and short process lifetime, and occasional slots are absent, so this is not a lifecycle failure. The concern is fleet texture: all nine Linux hosts share the exact half-hour cadence and command form, with each host pinned to one second/minute offset for the whole window. A centrally managed fleet can certainly share cron definitions, so I weighted this below the scanner and Windows contradictions, but more host-level schedule history and execution drift would look less generated.

### Signal-to-noise and source-family mix

The attack is embedded in enough normal activity to require pivots, especially in network and authentication sources. The collection contains substantial ordinary web/proxy traffic, service/machine authentication, DNS, database traffic, administrative SSH, Windows applications, updates, firewall teardown records, failed connections, and internet scanning.

The weakest mix is the core IDS feed. Generic suspicious-TLD alerts comprise 89% of it, and just five TLD rules account for those 58 records. Real deployments can be badly tuned and noisy, but the spread of the same small rule palette across many unrelated hosts and roles looks like intentionally distributed red-herring generation. I treated this as supporting texture, not decisive evidence, because the underlying DNS queries are visible and the perimeter IDS has a broader signature mix.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| `schema_or_format` | External web access | 346 of 349 requests from the dominant scanner | Every Nikto request has a unique random-looking six-digit `Test:` token; this is the strongest repeated generator fingerprint. |
| `hard_contradiction` | eCAR / Sysmon process lifecycle | One process, seven post-termination module loads | Same PID and process UUID load modules 5-83 ms after eCAR termination, also after the Sysmon Event 5 timestamp. |
| `contract_gap` | Windows Security / Sysmon / eCAR authentication | One high-value Type 9 sequence | NewCredentials logon with outbound alternate identity has no 4648 or runas evidence despite contiguous records and correct sibling examples. |
| `contract_gap` | eCAR / Windows process ownership | Repeated within the same staging/upload sequence | User/Type 9 processes are directly parented by NETWORK SERVICE `svchost.exe` and SYSTEM `services.exe` without a visible broker/service mechanism. |
| `distribution_texture` | Linux eCAR process telemetry | Fleet-wide across nine hosts | Identical sysstat command pairs recur on exact 1,800-second per-host lattices. |
| `distribution_texture` | Core IDS | Dataset-wide within that source | Five TLD-query signatures make up 58 of 65 alerts, producing a deliberately sampled red-herring texture. |

## Realism Score by Category

- **Field format accuracy:** 7/10 — Most native and normalized fields are plausible, but the unique-per-request Nikto `Test:` values and strained eCAR process ownership are prominent defects.
- **Temporal patterns:** 6/10 — Cross-source jitter and most lifecycles are convincing, but post-termination module loads and the fleet-wide half-hour lattice reduce confidence.
- **Cross-source correlation:** 9/10 — Web-shell, reverse-shell, Windows persistence, proxy upload, SSH, and SCP pivots are unusually complete and technically useful without relying on completeness itself as an authenticity clue.
- **Behavioral realism:** 8/10 — The attack actions and normal administrative overlap generally work together; the scanner identity mutation and NewCredentials initiation are the main exceptions.
- **Environmental consistency:** 8/10 — Host roles, network paths, authentication services, and baseline traffic largely fit the apparent environment, although IDS and scheduled-task distributions are curated-looking.

## Recommendations

- If this were synthetic, preserve one stable scanner identity per tool execution. For Nikto, use realistic static plugin/test identifiers and permit natural repetition; do not generate a new random six-digit `Test:` token for every HTTP request.
- Enforce source-local lifecycle ordering after observation timing is applied. No module/file/network child should timestamp after the exact process UUID's termination; either move termination after the last child or omit delayed children that cannot be placed inside the visible lifetime.
- Build every Type 9 NewCredentials sequence through one complete credential-use contract. When the Security audit policy visibly emits 4648, include a plausible initiating process and same-activity 4648 before or alongside 4624 Type 9, matching the correct `WS-MCHEN-01` examples.
- Align process parents, principals, and logon IDs at the canonical execution owner. If `svchost.exe` or `services.exe` brokers a user-context process, emit the concrete service/task/WMI mechanism that explains the transition; otherwise use the actual user-context caller as parent.
- Vary Linux scheduled telemetry by deployment cohort and host history. Keep cron-like regularity where appropriate, but mix intervals, minute offsets, enabled/disabled jobs, package defaults, and occasional execution delays rather than applying one half-hour command family fleet-wide.
- Broaden IDS background behavior only where the underlying traffic supports it. Reduce the core sensor's dependence on five suspicious-TLD rules and allow a more organic long tail of policy, protocol, scan, and benign-misclassification alerts.
