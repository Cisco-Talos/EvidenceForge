# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 78  
**Synthetic-Confidence Score:** 44

## Executive Summary

This six-hour enterprise slice is operationally convincing: the malicious activity can be pivoted across web, endpoint, authentication, network, firewall, and IDS telemetry without a visible causal impossibility. The strongest synthetic concerns are repeated operational texture—especially unusually dense SSH administration and paired server health-check processes—and one weak host-role/ownership gap around a user workstation initiating a root session that advances the compromise.

## Evidence For Synthetic

- `[distribution_texture]` SSH activity is unusually dense for the visible environment. In six hours, target-side eCAR records show 50 SSH sessions for `aisha.johnson`, 50 for `marcus.chen`, 32 for `lina.nguyen`, and 9 for `priya.patel`; Aisha and Marcus each connect repeatedly to most Linux servers, including 11–13 sessions apiece to individual mail or web hosts. The median paired-session duration is roughly 16–22 minutes, creating several concurrent administrative sessions per user for much of the window.
- `[distribution_texture]` `APP-INT-01` launches 51 root-owned `/opt/meridian/bin/proxy_healthcheck.py` processes from PID 1/systemd. Twenty-five target `internal-service`, while the others rotate through 21 third-party endpoints such as `registry.npmjs.org`, `js.bugsnag.com`, `analytics.rollbar.co`, `pypi.org`, and `metrics.sentry.io`; many internal/external process pairs start within approximately 0.04–2.5 seconds. This broad rotating target pool and repeated paired-process shape feels more generated than a stable production health-check configuration.
- `[environment_or_collection_plausibility]` `WS-EBROOKS-01` shows `evelyn.brooks` launching `ssh.exe root@WEB-EXT-01.meridianhcs.local` at `13:39:38Z`, followed on the server by root discovery and credential access (`cat /etc/hosts`, `find /opt/ehr -name *credential*`, and `cat /root/.ssh/id_rsa`). The transport and login are present, but there is no visible endpoint-side compromise, credential-use transition, or obvious administrative role explaining why this user workstation becomes the origin of the privileged attack activity. This is possible, but it is a conspicuous role/ownership gap.
- `[weak_signal]` Interactive Linux commands recur across otherwise separate users and hosts from a fairly compact administrative vocabulary: exact commands including `ps aux`, `stat /etc/passwd`, `ls -la`, `journalctl --since '10 min ago' --no-pager -n 20`, and `tail -20` appear repeatedly. The repetition is not strong enough by itself to determine provenance, but it reinforces the session-volume concern.

## Evidence For Real

- The compromise pivots cleanly through independently useful sources. `WEB-EXT-01` records Nikto traffic from `185.70.41.45`, SQL-injection attempts at `13:00:08–09Z`, and a successful upload to `/ehr/admin/upload.php` at `13:20:07Z`; eCAR then shows Apache spawning the base64-decoded reverse-shell command at `13:20:09.727Z`.
- Later stages are technically coherent. `WS-AJOHNSON-01` records `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords"` at `15:44:52.624Z`; DC telemetry then shows SMB/RPC transport, PSEXESVC creation at `15:59:54Z`, and `cmd.exe /c whoami && hostname` under SYSTEM.
- Account and persistence activity has credible visible ordering. On `DC-01`, `net user svc_mhsync ... /add /domain` begins at `16:14:42Z`, followed by Security events 4720, 4724, 4738, and 4728 through `16:14:46Z`. Service and scheduled-task creation follows at `16:19:38–41Z`, with matching 4697/4698 evidence.
- Collection volume is substantial enough to require hunting: approximately 24,499 eCAR rows, 11,088 Zeek connection rows, 11,199 ASA messages, 4,395 syslog rows, 17,576 Windows Security/Sysmon events, 1,420 proxy rows, and 943 web-access rows cover 18 hosts and several network zones.
- Baseline behavior is role-aware and varied: Kerberos/LDAP/SMB traffic concentrates around the DC and file server, application-to-database traffic uses MySQL, proxy transactions include authenticated users and tunneling, mail protocols appear on mail systems, and Linux systems show CRON, systemd, SSH, package, and journald activity.
- The dataset includes ordinary failures and observation texture: failed and disabled-account logons, invalid SSH users, failed connections, HTTP 403/404/429/500 responses, TCP resets, S0 connections, missed bytes, and source-specific timestamp offsets.
- I found no visible same-identifier process or session lifecycle in which a dependent event precedes a later visible initiator. Initial termination or logout records without an in-window start were treated as legitimate bounded-window state.

## Detailed Analysis

The visible window runs from approximately `2024-03-18T12:00Z` to `18:00Z`. The environment contains nine Windows systems, nine Linux systems, core and DMZ Zeek sensors, perimeter ASA and Snort telemetry, endpoint eCAR, Windows Security/Sysmon, Linux syslog and shell histories, proxy access, and public-web access records. Addressing and roles are internally intelligible: workstations occupy `10.10.1.0/24`, infrastructure is primarily `10.10.2.0/24`, the DMZ includes `10.10.3.10` and `10.10.3.20`, and the database is `10.10.4.10`.

The initial-access sequence is plausible. Between `12:30Z` and `12:50Z`, `185.70.41.45` produces a high-rate Nikto campaign against the public web server, with a mix of successful, rejected, missing, reset, and incomplete connections. At `13:00:08Z`, the same source submits a UNION-based patient-search request, followed by an authentication-bypass string at `13:00:09Z`. At `13:20:07Z`, it successfully posts to `/ehr/admin/upload.php`. Two seconds later, `WEB-EXT-01` eCAR attributes a base64-decoding reverse-shell command to `www-data`, parent `/usr/sbin/apache2`, targeting `45.33.32.30:8443`. This is a believable web-process lineage and timing relationship.

Privileged discovery begins from the `evelyn.brooks` workstation at `13:39:38Z`. The corresponding target login occurs at `13:39:41.926Z`, followed by `ip addr show`, `/etc/hosts`, `/etc/resolv.conf`, credential-file discovery, inspection of `/root/.ssh`, and reading `id_rsa`. The mechanics work, but the initiating host and principal are insufficiently explained by the visible workstation activity. Since the collection is bounded, this is not a contradiction; it remains a host-role plausibility concern.

The subsequent attack operations are coherent. Root access from `WEB-EXT-01` reaches `APP-INT-01`, where `/etc/passwd` and `/etc/shadow` are read. Credential dumping on `WS-AJOHNSON-01` precedes SMB/RPC activity to `DC-01` and PSEXESVC execution. Domain-account creation, Domain Admin membership, service persistence, and scheduled-task persistence appear in credible order and under plausible SYSTEM/WMI/service process ancestry.

Collection and exfiltration are also workable. At `17:14:56Z`, `APP-INT-01` launches `ssh -p 22 root@DB-PROD-01`. The database host executes `mysqldump`, creates `/tmp/rpt_0318.sql`, compresses it, hashes it, and at `17:25:06Z` sends it via SCP to `10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`; `APP-INT-01` records the receiver-side file creation. Cleanup then includes shell-history clearing at `17:41:23Z`, Security-log clearing on the DC at `17:42:15Z`, and deletion of `svc_mhsync` at `17:49:50Z`.

The source volume is broadly credible, but interactive SSH is overrepresented. Aisha and Marcus each sustain enough overlapping sessions to account for multiple concurrent terminals throughout much of the six-hour period, spread across nearly every Linux server. This could describe a very active operations team, yet the repeated destinations and recycled diagnostic vocabulary create the strongest generator-like texture in the corpus.

The background is otherwise strong. Windows endpoints display differentiated user software and routine services; Linux hosts show host-specific cron offsets, SSH successes and failures, package work, kernel firewall messages, and ordinary administrator activity. Network telemetry has varied connection states, response sizes, durations, and packet histories rather than a single clean success shape.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | eCAR, syslog, bash history, Zeek SSH | Dataset-wide across Linux administration | High SSH-session density and repeated target/command patterns modestly increase synthetic confidence. |
| `distribution_texture` | APP-INT eCAR and related network traffic | Repeated on one server throughout the window | Root/systemd health checks rotate through a broad third-party pool and repeatedly launch paired processes. |
| `environment_or_collection_plausibility` | WS-EBROOKS eCAR, WEB-EXT eCAR/syslog, Zeek | One privileged pivot | An ordinary user workstation originates the root session carrying credential theft without a visible ownership bridge. |
| `weak_signal` | Linux eCAR and bash history | Repeated across several users and hosts | Exact diagnostic commands recur often enough to look pooled, though all are individually plausible. |

## Realism Score by Category

- **Field format accuracy:** 9 — Fields and values are consistently usable across endpoint, authentication, network, proxy, firewall, and web sources.
- **Temporal patterns:** 8 — Attack and baseline timestamps have credible jitter and lifecycle ordering; repeated SSH and health-check texture reduce the score.
- **Cross-source correlation:** 9 — Pivots are operationally feasible with no verified visible ordering contradiction; completeness itself was not used as an authenticity indicator.
- **Behavioral realism:** 7 — The attack commands and effects work, but the administrative-session density and one privileged host-role transition are less convincing.
- **Environmental consistency:** 8 — Topology, services, and normal traffic mostly fit host roles, with localized concerns around root access origin and rotating health-check destinations.

## Recommendations

- If this were synthetic, reduce the density of interactive SSH administration or justify it with more differentiated operational roles. Favor fewer persistent sessions, stronger user-to-server specialization, and command sequences tied to distinct tickets or workloads instead of repeatedly sampling the same diagnostic vocabulary across users.
- Make server health checks configuration-like: use a small stable role-specific endpoint set, clearer service cadence, and fewer near-simultaneous sibling processes. If broad proxy-egress testing is intentional, add source-visible configuration or naming that explains why consumer CDN and analytics destinations are rotated.
- Strengthen the ownership bridge for the `evelyn.brooks` workstation-to-root pivot. Visible credential access, session takeover, explicit credential use, or another endpoint compromise artifact would make the privileged origin believable; otherwise originate it from a host and account with an established administrative role.
- Preserve the existing source-native timing and lifecycle relationships, especially the web-process lineage, PsExec transport-to-service sequence, domain-account event ordering, and SCP sender/receiver evidence.
