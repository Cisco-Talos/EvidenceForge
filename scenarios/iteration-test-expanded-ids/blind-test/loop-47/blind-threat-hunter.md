# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 67

## Executive Summary

This is a strong, highly huntable collection whose central suspicious lifecycle is technically coherent across endpoint, Windows, Zeek, file, and proxy evidence. I nevertheless assess it as synthetic because several baseline distributions are unusually controlled: DHCP renewals repeat at nearly invariant host-specific periods, administrator SSH activity is both high-volume and drawn from a narrow set of identical command lines, and a comprehensive network view contains no UDP/123 traffic despite endpoint evidence of active time synchronization.

## Evidence For Synthetic

- `[distribution_texture]` The 69 records in `zeek-core/dhcp.json` form exceptionally smooth renewal trains. For `10.10.1.22`, 12 consecutive gaps fall between 1786.704 and 1788.571 seconds; for `10.10.1.32`, 11 gaps fall between 1691.740 and 1693.341 seconds; for `10.10.1.31`, 10 gaps fall between 1968.332 and 1970.589 seconds; and for `10.10.1.21`, 10 gaps fall between 1939.565 and 1941.414 seconds. Each client effectively has one immutable interval with only roughly one-second jitter and no delayed or missed renewal over six hours.
- `[environment_or_collection_plausibility]` The internal SSH-admin baseline is unusually dense and repetitive for a six-hour slice. eCAR contains 91 SSH client process creations: 38 for `aisha.johnson` on `WS-AJOHNSON-01`, 32 for `marcus.chen` on `WS-MCHEN-01`, 16 for `lina.nguyen`, and five others. The commands are a small repeated set, including 14 exact `ssh.exe marcus.chen@WEB-EXT-01.meridianhcs.local`, nine exact Aisha-to-WEB commands, and six exact commands for several other Aisha/Marcus target pairs. Zeek simultaneously shows many successful, long-lived sessions, such as 30 sensor observations for `10.10.1.31 -> 10.10.3.10` averaging about 1,502 seconds and 18 for `10.10.1.35 -> 10.10.3.10` averaging about 1,606 seconds. Some counts include dual-sensor observations, but the endpoint process counts independently establish the repeated behavior.
- `[environment_or_collection_plausibility]` Across 11,385 Zeek connection records (`6,106` core and `5,279` DMZ), there are zero destination-port-123 flows. That is notable because eCAR explicitly shows `systemd-timesyncd` activity on Linux hosts, including writes to `/run/systemd/timesync/synchronized` and `/var/lib/systemd/timesync/clock`, while the same network view captures 69 DHCP renewals, 2,945 DNS records, Kerberos, LDAP, SMB, and low-volume protocol companions. A six-hour window can miss a long-polling Windows client, but zero NTP observations across this mixed Windows/Linux estate is an odd family-level hole.
- `[distribution_texture]` DNS and administrative traffic show a somewhat enumerable baseline. `DC-01.meridianhcs.local` accounts for 564 DNS questions and `FILE-SRV-01.meridianhcs.local` for 137; server-side health-check commands repeatedly select from recognizable external-domain pools. This is weaker evidence because the DC queries respect the visible 300-second TTL rather than occurring before every connection, and periodic health checks can be legitimate.

## Evidence For Real

- The six-hour window has believable source breadth and nontrivial volume: 11,385 Zeek connections, 2,945 DNS records, 1,768 TLS records, 1,609 eCAR process creates, 1,400 process terminations, 1,172 session logins, 813 logouts, ASA state messages, Snort alerts, proxy records, web access, Windows Security/Sysmon, and Linux syslog.
- Network texture is not uniformly successful. Core connection states include 5,908 `SF`, 73 `RSTO`, 55 `RSTR`, 23 `S0`, 17 `OTH`, nine `REJ`, and smaller `S1`/`S2`/`S3` populations; the DMZ has 1,162 `S0` alongside 3,886 `SF`, consistent with exposed-service scanning.
- Protocol detail is varied: DNS includes A, AAAA, TXT, PTR, SRV, MX, NS, and SOA with NOERROR, NXDOMAIN, REFUSED, and SERVFAIL responses. TLS spans TLS 1.2 and 1.3, multiple modern cipher suites, resumed and full sessions, and stable certificate reuse.
- Lifecycle incompleteness fits a bounded collection window rather than exposing impossible ordering. Of 1,724 distinct eCAR process IDs, 1,285 have visible create/terminate pairs, 324 are create-only, and 115 are terminate-only. Of 1,191 session IDs, 794 are paired, 378 login-only, and 19 logout-only. I found no same-ID pair whose visible terminate/logout preceded its visible create/login.
- The suspicious archive/exfiltration chain correlates strongly without a visible causal contradiction. At `17:01:10.628Z`, `FILE-SRV-01` runs `Compress-Archive` as `svc_mhsync`; eCAR records creation of `C:\ProgramData\Microsoft\cache_7f3a.zip`. At `17:21:38.062Z`, Zeek files records a 313,886,828-byte SMB transfer from `10.10.2.20` to `10.10.1.35`; at `17:21:51.395Z`, endpoint telemetry creates the workstation copy. Chrome reads it at `17:21:52.197Z`, and at `17:24:38Z` the proxy records a 314,782,777-byte POST to `api.westbridge-services.net`, matching the corresponding core proxy connection.
- Security-log clearing is modeled credibly. `wevtutil cl Security` is created at `17:42:14.879Z`; Event 1102 follows at `17:42:15.6063384Z` with `EventRecordID=1`, and subsequent Security records restart at IDs 2, 4, and 5.

## Detailed Analysis

### Scope and source-family mix

The visible window runs from approximately `2024-03-18 12:00:04Z` through `17:59:55Z`. It covers 16 named hosts across workstation, domain-controller, file, application, database, mail, proxy, and exposed-web roles. The collection is operationally useful: host process/session evidence can be pivoted into authentication and network telemetry, while the core and DMZ sensors expose both east-west and perimeter behavior.

The family mix is broad but endpoint/network-heavy. eCAR contains 15,582 FLOW records, 2,418 MODULE LOADs, 1,609 PROCESS CREATEs, 1,400 PROCESS TERMINATEs, and 1,172 USER_SESSION LOGINs. Core Zeek is dominated by DNS (2,203 connections), Kerberos (1,013), HTTP (885), SMB (879), and LDAP (615), while DMZ traffic is dominated by SSL (1,759), HTTP (1,083), DNS (758), and MySQL (325). These proportions fit a monitored AD environment with an explicit proxy and exposed services better than a tiny demonstration dataset.

### Operational lifecycle and pivot feasibility

The strongest suspicious chain begins with remote execution and persistence on `DC-01`. A PSEXESVC service is created at `16:00:16.424Z`, its process at `16:00:17.723Z`, and `cmd.exe /c whoami && hostname` at `16:00:18.710Z`. At `16:15:08Z`, WMI-spawned commands create `svc_mhsync` and add it to Domain Admins. At `16:20:24Z`, the activity creates `DeviceSyncSvc`, followed by an hourly scheduled task and a service process at `16:28:59Z`. Parent/child process UUIDs, PIDs, principals, and command lines remain consistent through these steps.

The later data-access chain is especially convincing. The file-server archive command, destination-file event, 313.9 MB server-to-client SMB transfer, local file creation, browser read, client-to-proxy flow, and 314.8 MB proxy POST line up in direction and magnitude. The proxy access lines distinguish CONNECT control bytes from tunnel bytes and show the authenticated user. This is evidence for realism; I did not penalize the fact that the trail is huntable or narratively coherent.

Cleanup is also ordered plausibly. The encoded PowerShell command occurs around `17:42:03Z`; `wevtutil` clearing follows around `17:42:14Z`, with the Security log's EventRecordID resetting correctly after Event 1102. The Linux history-clearing command on `APP-INT-01` occurs separately at `17:40:53.300Z`. Nothing in these bounded samples requires a dependent action to precede its prerequisite.

### Baseline and distribution texture

The collection has genuine-looking failure texture, external scanning, DHCP, DNS suffix noise, scheduled work, updater traffic, service-account activity, and session churn. However, the DHCP renewal series are much smoother than normal operational capture. Four busy clients each repeat one host-specific interval for 10-12 successive gaps with a total spread of only about two to four seconds. That is the most reproducible generator-like signal in the dataset.

SSH administration supplies useful baseline but appears overrepresented. Two Windows workstations alone create 70 SSH clients in six hours, repeatedly targeting the same small Linux fleet with bare `ssh.exe user@host` command lines. Long-lived sessions and dual-sensor visibility explain some network counts, but not the endpoint volume. A real admin-heavy shift could produce this pattern, so I treat it as a strong distribution concern rather than a contradiction.

Finally, the absence of any UDP/123 connection is difficult to reconcile with the otherwise comprehensive network capture and explicit Linux time-sync endpoint activity. It is possible that upstream NTP is excluded or the hosts rely on very long poll intervals, but that collection explanation is not otherwise visible.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Zeek DHCP | Repeated across four high-frequency clients; 43 measured consecutive gaps | Near-invariant renewal trains are the clearest generator-like fingerprint. |
| `environment_or_collection_plausibility` | eCAR + Zeek SSH | Repeated across several users and targets; concentrated in two workstations | High admin-session volume and a narrow exact command vocabulary weaken lived-in behavioral texture. |
| `environment_or_collection_plausibility` | Zeek network + Linux eCAR | Dataset-wide network-family gap | Zero UDP/123 flows despite active time-sync artifacts and otherwise deep protocol visibility makes the collection profile feel curated. |
| `distribution_texture` | DNS + server health checks | Repeated, but lower impact | Recurrent host queries and enumerable health-check destinations add mild templated texture, partly mitigated by TTL-aware timing. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled Windows, eCAR, Zeek, proxy, ASA, and syslog fields are structurally credible, including Security-log reset behavior.
- **Temporal patterns:** 6 — Attack ordering and most background timing are sound, but DHCP renewal trains are implausibly invariant.
- **Cross-source correlation:** 9 — Process, file, SMB, proxy, and Security-event pivots agree in identities, direction, size, and causal order.
- **Behavioral realism:** 6 — There is broad baseline activity, but SSH administration is overrepresented and uses a narrow repeated command vocabulary.
- **Environmental consistency:** 6 — Host roles and major network paths make sense; the absence of all NTP traffic amid visible time-sync state changes is difficult to reconcile with the collection profile.

## Recommendations

1. If this were synthetic, add stateful DHCP-client renewal behavior: preserve lease/T1 semantics but allow OS-specific scheduling drift, delayed or missed renewals, interface sleep/wake, lease changes, and occasional rebinding. Avoid keeping every renewal for a client within roughly one second of a fixed period for the full window.
2. Reduce and diversify the SSH-admin baseline. Use persona- and role-specific session rates, fewer repeated workstation-to-server pairs, a long-tailed target distribution, occasional connection failures, and more varied client invocation forms only where those forms are log-visible and operationally plausible.
3. Reconcile time synchronization with network visibility. Emit plausible UDP/123 exchanges for Linux `systemd-timesyncd` activity, model an explicit internal time source or AD time hierarchy, or make the collection boundary visibly exclude that traffic rather than presenting a comprehensive sensor with zero NTP.
4. Broaden periodic server-maintenance texture with stateful schedules and host-specific tool/domain choices. Keep the existing cache-aware DNS behavior, which is substantially more realistic than one-query-per-connection generation.
