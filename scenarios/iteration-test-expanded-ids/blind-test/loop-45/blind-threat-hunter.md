# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 66

## Executive Summary

The six-hour window is operationally coherent and unusually strong at preserving visible process, session, network, and identity relationships, with no impossible same-identity ordering found. I nevertheless assess it as synthetic because several baseline families expose repeated environment texture: an application server's root/systemd healthcheck repeatedly samples an implausibly broad pool of unrelated public tracking/CDN domains, while the same generic interactive sudo identities and small maintenance-command vocabulary recur across unrelated Linux server and workstation roles.

## Evidence For Synthetic

- `[environment_or_collection_plausibility]` `APP-INT-01.meridianhcs.local/ecar.json` contains 54 process creates in six hours for `/usr/bin/python3 /opt/meridian/bin/proxy_healthcheck.py --target ...`, all as root with parent `/usr/lib/systemd/systemd`. Twenty-six target `internal-service`, but the other 28 sample a conspicuously heterogeneous public pool including `analytics.hotjar.com`, `media.licdn.com`, `app.pollfish.app`, `cdn.branch.io`, `tracking.newrelic.net`, `registry.npmjs.org`, and `pypi.org` (representative lines 5, 7, 13, 31, 47, 127, 162, 283, 371, 429, 490, 853, and 857). A real application healthcheck could probe external dependencies, but this particular mix resembles browsing/ad-tech destination texture assigned wholesale to a system service rather than a defensible application dependency set.
- `[distribution_texture]` The Linux syslogs contain 69 visible TTY-backed sudo invocations across nine hosts in the six-hour slice, repeatedly selecting the same generic identities (`admin`, `ops`, `backup`, `deploy`, `svc_app`, `ubuntu`) regardless of host role. Examples include `svc_app` interactively invoking `needrestart -b` on APP-INT-01 at `12:15:51.556674Z`, `iptables -L -n -v` on DB-PROD-01 at `12:24:42.077449Z`, and `systemctl list-timers --all --no-pager` on workstation WS-OHADDAD-01 at `13:14:06.671506Z`; each is logged with a pseudo-terminal. The repetition across application, database, mail, proxy, DMZ, laptop, and workstation roles is a generator-like shared command/account pool.
- `[distribution_texture]` Exact commands recur across unrelated hosts within the same short window: `/usr/bin/systemctl list-timers --all --no-pager` appears on DB-PROD-01, MAIL-EDGE-01, WEB-EXT-01, and WS-OHADDAD-01; `/usr/sbin/iptables -L -n -v` appears on APP-INT-01, DB-PROD-01, MAIL-CLIN-01, and MAIL-EDGE-01; `/usr/sbin/ss -s` appears on DB-PROD-01, MAIL-CLIN-01, MAIL-EDGE-01, and WEB-EXT-01. Any one is normal, but their repeated distribution among the same shared identities reinforces a small reusable activity pool.
- `[weak_signal]` DHCP renewals have extremely fixed per-client texture. For example, `WS-LNGUYEN-01.meridianhcs.local/syslog.log` repeats `renewal in 1938 seconds` for every visible lease cycle from lines 4-6 through 196-198, while `LT-MRIVERA-02.meridianhcs.local/syslog.log` repeats `renewal in 1927 seconds` across ten cycles and WS-OHADDAD repeats `1785 seconds` across thirteen. Fixed server-supplied timers are possible, so this did not drive the verdict alone, but the near-identical cycle texture adds to the broader regularity.
- `[contract_gap]` The initial web compromise has a semantic mismatch in source-native artifacts. `WEB-EXT-01.meridianhcs.local/web_access.log:435` records a successful `POST /ehr/admin/upload.php` from `185.70.41.45` at `13:20:21Z`; `ecar.json:987` records Apache directly spawning a base64-decoded reverse-shell command at `13:20:22.789Z`; yet `syslog.log:519` attributes the same client/worker interval to a SQL `UNION SELECT username,password FROM users` syntax error. A single request could exercise multiple vulnerable paths, but an upload endpoint, SQL-injection diagnostic, and immediate command execution are insufficiently reconciled and look like adjacent attack templates overlaid on one transaction.

## Evidence For Real

- The environment has a credible source and volume mix for a six-hour enterprise slice: 16 endpoint directories, Windows Security/Sysmon and eCAR endpoint telemetry, Linux syslog and shell histories, proxy and web access logs, two Zeek observation points, firewall logs, and two Snort sensors. The malicious activity is embedded among thousands of flows and substantial authentication, web, mail, DHCP, scanning, and maintenance noise rather than dominating the data.
- Visible attack pivots are technically feasible. The web reverse shell is created at `13:20:22.789Z`, its outbound eCAR flow starts at `13:20:24.845Z`, Zeek DMZ UID `CzXo2HWT5uiSEQt3v0V` sees `10.10.3.10:51198 -> 45.33.32.30:8443` at `13:20:23.662145Z`, and ASA connection `1238915` is built at `13:20:23` and torn down at `13:20:38`. Small source-specific timestamp differences remain plausible.
- The later SSH pivot is coherent across endpoint, network, and host logs. WEB-EXT-01 creates `ssh -p 22 root@10.10.2.30` at `14:14:21.723Z`; ASA builds tuple `10.10.3.10:58729 -> 10.10.2.30:22` at `14:14:33`; APP-INT-01 syslog logs connection at `14:14:35.188945Z`, acceptance at `14:14:37.479189Z`, and session open at `14:14:37.635326Z`; Zeek records the long-lived SSH interval with a successful close. That is convincing lifecycle evidence rather than mere identifier completeness.
- The Windows domain-account sequence is source-native and ordered: DC-01 creates `svc_mhsync` and adds it to Domain Admins at `16:14`, later FILE-SRV-01 records a network session and `svc_mhsync` processes at `17:01`, and DC-01 deletes the account at `17:50`. The matching 4720/4728/4726 family and endpoint principal use are plausible.
- Lifecycle checks found no same-object eCAR process termination before create and no same-object session logout before login when both endpoints were visible. Sysmon Event 5 did not precede Event 1 for a shared visible ProcessGuid, and Security 4688 process IDs were not visibly reused while still active.
- The DC security-log clear is modeled credibly: `wevtutil cl Security` is created at `17:42:16.5704097Z`, Event 1102 appears at `17:42:18.8498896Z` with SYSTEM identity in `UserData`, EventRecordID resets to 1, and subsequent events resume at IDs 2 and 3.

## Detailed Analysis

### Scope, sources, and visible time

The data spans approximately `2024-03-18T12:00Z` through `18:00Z`. Endpoint coverage includes six Windows workstations, Windows domain/file/mail servers, multiple Linux workstations and servers, eCAR on every host, shell histories on selected Linux identities, perimeter ASA, core and DMZ Zeek, and core/perimeter Snort. Zeek alone contains 6,408 core and 5,467 DMZ connection rows; ASA contains 12,176 rows. This is enough background that the suspicious chain must be hunted rather than inferred from a tiny curated source.

### Hunt path and operational coherence

The clearest compromise begins at the public web server. The incoming TLS connection from `185.70.41.45:62581` is visible in `zeek-dmz/conn.json:1395`, ASA lines 2954 and 2962, and `WEB-EXT-01` eCAR line 985. Apache then spawns a bash reverse shell (`ecar.json:987`) and associates the outbound callback with that PID (`ecar.json:988`). Process termination at eCAR line 996 occurs after the callback closes, so there is no visible impossible lifecycle ordering.

The later root SSH session from WEB-EXT-01 to APP-INT-01 is internally consistent. The source process and eCAR flow use PID 588806 and source port 58729; destination syslog, ASA, and both Zeek sensors agree on the tuple and transport-before-auth relationship. The connection remains open for about 3 hours 42 minutes, and APP-INT-01's root session logout appears at eCAR line 939. A long session is not itself artificial.

From APP-INT-01, the DB-PROD-01 activity is likewise feasible. DB-PROD-01 logs a root SSH login from APP-INT-01's `10.10.2.30` at `17:14:50.980120Z`; the root shell runs database discovery, `mysqldump`, size checks, gzip, and SCP. The resulting `/tmp/rpt_0318.sql.gz` is created before eCAR records the SCP file read, and APP-INT-01 eCAR line 891 records the destination-side file creation after the outbound SCP flow starts. I did not penalize the chain for being readily followable; its visible mechanics are correct.

The Windows portion also has credible prerequisite/effect ordering: remote execution on DC-01 creates a domain account, establishes persistence with a service and scheduled task, uses the new account on FILE-SRV-01, stages `cache_7f3a.zip`, copies it to WS-AJOHNSON-01, and sends a large TLS transfer through the proxy. The proxy-to-origin Zeek DMZ connection at `17:24:57.195080Z` (`Cg806pzkLgRCCynhk`) carries 315,340,412 origin bytes to `45.33.32.30:443`, matching the large-upload semantics and firewall byte count. This strong correlation was treated as realism, not as a synthetic tell.

### Baseline and environment texture

The main authenticity failure is baseline ownership, not attack ordering. APP-INT-01's systemd-owned proxy-health process makes 54 process starts and moves through a destination pool spanning package repositories, operational SaaS, ad-tech, audience analytics, social media assets, and fabricated-looking CDN properties. A production health monitor generally has a bounded dependency inventory or a named synthetic-monitor policy; here the pool looks like generic outbound-web texture mapped onto a privileged application-server process.

Linux interactive administration has the same issue at a broader scope. The repeated `admin`/`ops`/`backup`/`deploy`/`svc_app`/`ubuntu` identities, pseudo-terminal assignments, random-looking working directories, and shared maintenance vocabulary occur on unrelated roles throughout the same short window. Real organizations can have shared operations accounts, but service identities such as `svc_app` and `backup` repeatedly receiving TTYs and running generic diagnostics on desktops, DB, mail, and application servers is a notable role/plausibility defect.

### Temporal and schema checks

Within the visible window, eCAR object lifecycles, Sysmon ProcessGuid create/terminate order, and Windows Security process-ID reuse were coherent. I specifically did not count session/process initiators absent before `12:00Z`, nor did I penalize complete UID and reference matching.

DHCP is cross-source coherent: Zeek REQUEST/ACK rows align with Linux dhclient request, acknowledgment, and bound messages. Its timers are unusually invariant per client, but fixed T1 behavior is possible, so this remains a weak supporting texture observation rather than a contradiction.

The web compromise's upload/SQL/command-execution combination is the only material semantic contract concern. It is possible for a deliberately vulnerable application to combine those behaviors, but the logs do not show why an upload handler emitting a SQL `UNION SELECT` error directly launches the encoded shell, leaving a visible mismatch between source families.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `environment_or_collection_plausibility` | APP-INT-01 eCAR | 54 root/systemd healthcheck process creates over six hours, with 28 probes to an unrelated public tracking/CDN/package pool | Highest-impact indicator; process purpose and host role do not plausibly own the destination mix |
| `distribution_texture` | Linux syslog | 69 TTY sudo invocations on nine hosts, using the same six generic identities and recurrent command pool | Strong repeated texture across unrelated server/workstation roles |
| `contract_gap` | Web access, syslog, eCAR | One compromise interval combines upload POST, SQL UNION diagnostic, and direct Apache child reverse shell | Moderate semantic inconsistency, but not impossible |
| `weak_signal` | Zeek DHCP and Linux syslog | Per-client renewal intervals repeat nearly exactly across 10-13 cycles | Small supporting signal only because fixed T1 behavior is plausible |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Zeek JSON, ASA, syslog, proxy, and web records are source-shaped and internally parseable, with no decisive impossible field value found.
- **Temporal patterns:** 8 — Attack and lifecycle ordering is strong; DHCP and pooled maintenance activity are somewhat too invariant.
- **Cross-source correlation:** 9 — Transport, session, process, account, proxy, and file relationships pivot cleanly without visible contradictions.
- **Behavioral realism:** 6 — Attack mechanics work, but baseline privileged healthcheck and shared sudo behavior expose reusable activity pools.
- **Environmental consistency:** 5 — Public destination ownership by APP-INT-01's healthcheck and generic TTY service-account use across diverse roles are difficult to reconcile with a production operating model.

## Recommendations

- If this were synthetic, bind service-generated network activity to a small, role-specific dependency inventory. APP-INT-01's healthcheck should probe actual application endpoints and named infrastructure dependencies rather than rotate through ad-tech, social, package, and generic CDN domains.
- Replace the shared Linux sudo actor/command pool with host- and identity-specific operating models. Reserve `svc_app` and `backup` for non-TTY service execution unless a concrete interactive exception is modeled, and make workstation administration materially different from DB, mail, proxy, and DMZ administration.
- Expand the long tail of maintenance commands per role and reduce identical command reuse across unrelated hosts inside one six-hour window.
- If the upload request is meant to exploit SQL injection plus command execution, add source-native evidence that explains the transition; otherwise align the Apache diagnostic with the actual upload/RCE mechanism.
- Add modest per-renewal DHCP timing variation only if the modeled client/server implementation would actually vary T1; preserve fixed timers where the source implementation specifies them.
