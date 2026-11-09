# Threat Hunter — Authenticity Assessment

## Verdict

- **Assessment:** Inconclusive
- **Verdict Confidence:** 72/100
- **Synthetic-Confidence Score:** 57/100

## Executive Summary

The bundle depicts a mixed Windows, Linux, and macOS fleet for a healthcare organization, with two domain controllers, user workstations, application/database/file/mail/web/proxy roles, and core plus DMZ network sensors. The visible collection window is approximately 13:00–19:00 UTC on 2026-11-02. Host-local eCAR, Windows Security/Sysmon, Linux syslog and shell history, macOS Endpoint Security/Unified Log, Zeek, proxy, ASA, and Snort provide useful but uneven coverage.

Cross-source evidence is unusually coherent around a real operationally plausible support upload from `WS-LNGUYEN-01`: shell history, endpoint process/file activity, proxy access, Zeek DNS/HTTP, and the perimeter path align in time, identity, tuple, filename, content size, and response. Other host and network records also show plausible service and user activity. I found no clear causal or protocol contradiction in the visible interval.

The main concern is distributional: Linux eCAR process-create PIDs are strictly increasing across each host’s observed events, while the PID ranges advance by thousands to tens of thousands across a few dozen or few hundred logged creates. That can reflect unobserved host process churn or source filtering, so it is a tell to investigate rather than proof of fabrication. Given that concern and the otherwise plausible cross-source agreement, raw logs alone do not support a confident real/synthetic call.

## Evidence For Synthetic

- **[distribution_texture]** On the Linux hosts, every observed eCAR `PROCESS/CREATE` PID rises with event time. For example, `DB-PROD-01` advances from PID 1,044,601 at 13:12:05 to 1,089,104 at 18:15:44 across 56 creates; `WS-LNGUYEN-01` advances from 2,942,712 at 13:03 to 2,999,762 at 18:52 across 114 creates. The pattern recurs across the Linux server fleet (for example `APP-INT-01`, `FILE-LNX-01`, and `WEB-EXT-01`). Linux PID allocation is naturally monotonic until wrap, but the large gaps imply substantial unobserved process creation relative to the sparse visible CREATE counts. If these eCAR files are intended to represent broad endpoint process telemetry, the implied gap merits scrutiny. Evidence: `DB-PROD-01.meridianhcs.local/ecar.json` (first/last CREATE rows, lines 11 and 542); `WS-LNGUYEN-01.meridianhcs.local/ecar.json` (lines 1 and 681); same pattern visible in the other Linux-host eCAR files.
- **[weak_signal]** Many host records occupy a nearly common six-hour envelope and shell-history timestamps fall inside it. This is compatible with a bounded export/collection exercise, so it is not a synthetic indicator by itself; it does make the PID and activity distributions harder to judge as ordinary long-running telemetry without longer baseline context.

## Evidence For Real

- `WS-LNGUYEN-01` shows a coherent support-upload sequence. Its history timestamps the tar and curl commands at 16:35:51 and 16:36:19 (`WS-LNGUYEN-01.meridianhcs.local/bash_history/lina.nguyen.bash_history`, lines 49–56). eCAR records the tar process and archive creation, then curl process and archive read (same host `ecar.json`, lines 383–394). The proxy records a successful POST by `lina.nguyen@meridianhcs.local` with 1,573,700 client bytes at 16:36:47 (`PROXY-01.meridianhcs.local/proxy_access.log`, line 2299). Zeek records the matching upload from `10.10.1.21:56675` through `10.10.3.20:8080`, to the same URL, with the same filename and 1,573,258-byte request body and HTTP 200 (`zeek-dmz/http.json`, line 1488); the proxy’s upstream request is also visible at line 1489. DNS for the destination resolves from the proxy at that time (`zeek-dmz/dns.json`, line 541). This is a specific, technically plausible multi-source chain rather than a generic correlation claim.
- The cross-source network path around that upload is consistent: eCAR shows the workstation’s proxy connection on source port 56675 at 16:36:48 (`WS-LNGUYEN-01.meridianhcs.local/ecar.json`, line 395), and ASA records the corresponding inside-to-DMZ proxy connection built at 16:36:47 (`fw-perimeter/cisco_asa.log`, line 15015). The timestamps and tuple align closely with the proxy and Zeek evidence.
- Normal service-role traffic is visible alongside the upload. Zeek core has expected DNS, Kerberos, LDAP, SMB, HTTP(S), SMTP, and database traffic; the DB sensor is concentrated on TCP/3306. The DMZ view includes inbound web traffic and proxy-mediated egress. `zeek-core/conn.json`, `zeek-db/conn.json`, and `zeek-dmz/conn.json` contain a mix of completed and incomplete states (`SF`, `S0`, `RSTO`, `RSTR`, `REJ`, and others), rather than only successful, tidy sessions.
- Windows hosts show a plausible mixture of process create/terminate, network-connect, DNS-query, authentication, logoff, file-share, and filtering-platform records. Domain controllers have the expected concentration of Kerberos events (4768/4769) and permitted network connections (5156); user endpoints have smaller volumes and user-principal activity. Examples are `DC-01.meridianhcs.local/windows_event_security.xml` and `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml`.
- macOS records are distinct native Endpoint Security and Unified Log formats. ES event times, process identities, and parent relationships provide a separate endpoint view; Unified Log entries include login-window, kernel, and `sshd-session` activity. For example, `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` begins with ordered process lifecycle observations, and its Unified Log has a later SSH-session record. The tiny Unified Log sample is thin coverage, not independently evidence of fabrication.
- Linux syslog and histories include routine operational checks, service activity, package/monitoring noise, and per-role actions. The DB host’s MySQL/PostgreSQL/Redis queries, web host’s web-service checks, and file hosts’ Samba checks fit their apparent roles. These behaviors are plausible and do not require an attack narrative to explain them.

## Detailed Analysis

### Sources, scope, and fleet

The dataset includes 11 Linux hosts, 10 Windows hosts with Security and Sysmon, two Macs with Endpoint Security and Unified Log, network sensors in core/DB/DMZ zones, a proxy log, perimeter ASA, Snort alerts, and shell histories. Hostnames and addresses form a consistent private layout: user systems in `10.10.1.0/24`, internal services and domain controllers in `10.10.2.0/24`, proxy/web in `10.10.3.0/24`, and database services in `10.10.4.0/24`. DNS answers in Zeek align with observed addresses, including `WS-LNGUYEN-01` → `10.10.1.21`, `FILE-LNX-01` → `10.10.2.21`, and `APP-INT-01` → `10.10.2.30`.

The principal window is roughly six hours, with some hosts starting a few minutes after 13:00 or ending slightly before 19:00. That stagger is compatible with endpoint uptime, onboarding, or export boundaries. It does not establish source completeness, so absent events at the edges are not treated as defects.

### Operational pivot: support archive upload

The clearest investigation pivot starts on `WS-LNGUYEN-01`. At 16:35:52 UTC the eCAR process record shows `/usr/bin/tar` archiving two `ehr-connector` log files to `/tmp/mhs-support-48217.tar.gz`; a FILE/CREATE follows roughly four seconds later. At 16:36:19 UTC curl is launched with a multipart upload to `support.valeworks-health.net`; eCAR records a read of the archive shortly before curl exits. The proxy logs a successful 200 response with 1.57 MB sent, and Zeek sees the same source, proxy, destination URL, archive name, and near-matching body size. The ASA event records the client’s proxy connection. This is an actual high-value data-transfer event from the logs; the records alone do not establish authorization, the destination’s ownership, or whether the logs contain sensitive data.

This chain is a realism strength because separately collected layers retain their own expected representations: the shell history has command timestamps, eCAR has process and file actions, the proxy has an authenticated user and byte accounting, Zeek has HTTP fields and file metadata, and ASA has a transport tuple. The close match is not scored as suspicious merely because it is complete.

### Lifecycle and privilege boundaries

Windows workstation process create/terminate pairs and Security logon/logoff activity are present, with some unpaired records at window boundaries or for long-lived processes. These are reasonable within a bounded interval. Domain-controller Kerberos ticket activity and WFP connection events have expected volume for the inferred directory role. I did not find a visible dependent event that clearly precedes its initiator in the sampled Windows records.

On Linux, command histories and eCAR records link user shell processes to commands, and service traffic is attributed to plausible service principals such as `systemd-resolve`, `sysstat`, `postfix`, `www-data`, and `root`. Privileged command use is visible through `sudo`/root context rather than being collapsed into the initiating user. Some application, file, and database traffic is present in corresponding Zeek zones.

The Macs show login/terminal and SSH process activity. Endpoint Security observations are not treated as proof of user authorization. I did not infer missing macOS ES or Unified Log companion events from the presence of an eCAR event; each source has separate collection semantics. The small Unified Log files are thin, but without a specific expected collection policy or contradictory companion evidence, that is not a defect.

### Distribution and collection caveat

The Linux process-ID progression is the principal anomaly. A kernel PID counter can advance much faster than an EDR export if the latter filters or samples process activity, and large values alone are normal on long-running Linux systems. Here, though, the same clean direction appears across numerous Linux hosts over the common window, with PID deltas ranging from several thousand to tens of thousands while only tens or low hundreds of process creates are present per host. This pattern may reflect filtered collection, pre-window uptime, or generated PID assignment; raw records do not let me distinguish those explanations. It is therefore a moderate distribution-texture concern, not a hard contradiction.

Other observed artifacts do not materially change the assessment: the proxy and Zeek byte totals differ slightly, which is plausible for different byte-accounting layers; shell histories lack output/status data by design; and the short macOS Unified Log samples cannot support broad conclusions about ES execution coverage.

## Synthetic Indicator Summary

- **[distribution_texture] Moderate:** Linux eCAR process PIDs increase monotonically over the window and advance by large amounts compared with the number of visible process-create records. If the files are broad process telemetry, the implied invisible churn is high. This may also be explained by source filtering or prior uptime.
- **[weak_signal] Low:** Shared collection boundaries and close cross-source alignment are visible, but neither is counted as a synthetic indicator on its own. I found no verified hard contradiction, identity leak, or impossible protocol sequence.

## Realism Score by Category

- **Field format:** 8/10 — Native XML, JSON-lines, syslog, proxy, firewall, and history forms look plausible; records carry source-appropriate fields.
- **Temporal patterns:** 7/10 — Timestamps fit the shared window and observed causal sequences; the Linux PID progression is the main unresolved texture concern.
- **Cross-source correlation:** 9/10 — The support upload and several host/network pivots agree on identity, tuple, URL, filenames, sizes, and timing.
- **Behavioral realism:** 7/10 — Routine operations and service activity fit the apparent roles; there is not enough raw context to assess whether all activity rates are representative.
- **Environmental consistency:** 8/10 — Hostnames, private address ranges, DNS, roles, and major protocols are mutually consistent. Exact organization policy and collection configuration are unknown.

## Recommendations

- Resolve the Linux PID anomaly against the collector’s documented scope: establish whether eCAR records every process start, only selected activities, or a filtered subset, and compare its collection interval with host uptime/PID wrap history.
- For a follow-up hunt, preserve the support-upload trail as a high-priority review item: validate the ticket and destination through authorized internal records, then determine whether the archive included sensitive connector logs. The raw logs show transfer and HTTP success, but not authorization or archive contents.
- If an authenticity decision must be made beyond this bounded sample, compare the Linux process and service distributions with longer source-native baselines and the actual collection policy. The current evidence supports neither a decisive real-world determination nor a firm synthetic verdict.
