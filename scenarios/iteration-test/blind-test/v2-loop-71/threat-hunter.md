# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 78  
**Synthetic-Confidence Score:** 44

## Executive Summary

This six-hour, multi-source enterprise telemetry set is operationally coherent and unusually resistant to simple falsification. The compromise chain is pivotable from external web exploitation through reverse-shell activity, SSH reconnaissance, Windows remote administration, database staging, SMB transfer, local archive creation, and proxy-mediated exfiltration. Event ordering, network direction, byte accounting, process/session lifecycles, log-clear behavior, and sensor-specific timing are generally credible. The surrounding background is also meaningfully role-dependent rather than merely decorative.

The principal synthetic indicators are distributional rather than decisive: highly regular fleet-wide Linux `sysstat` cron behavior, similarly linear PID growth across heterogeneous Linux systems, and repeated endpoint events with identical semantic payloads separated by only milliseconds. A more operationally important `contract_gap` appears on `WS-AJOHNSON-01`: a Type 9 logon carries `marcus.chen` as its outbound identity, while the associated upload is attributed by the proxy to `aisha.johnson`, without a visible credential-use or proxy-authentication transition explaining that change.

No `hard_contradiction` was found. Because the adverse artifacts are plausible in isolation and the strongest real-data indicators—independent sensor clock offsets, source-native lifecycle behavior, and realistic ambient contention—are substantial, the result remains mixed. The score of 44 falls in the rubric's inconclusive range.

## Evidence For Synthetic

- **[distribution_texture] Cloned Linux maintenance cadence.** Ten Linux hosts emit the same two `sysstat`-style command strings—`/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'` and `debian-sa1 1 1`—on a highly regular 30-minute schedule with only sub-second jitter and a fixed per-host phase. The repetition is visible, for example, in `APP-INT-01/syslog/syslog.log` lines 1, 34, 72, 89, 106, 130, 135, 155, 173, 190, 201, and 221, with analogous patterns on `MAIL-CLIN-01`, `WS-OHADDAD-01`, and other Linux hosts. Central configuration can produce this, but the degree of uniformity across unlike server, appliance, and workstation roles is more generator-like than a mixed production fleet.

- **[distribution_texture] Role-insensitive Linux PID velocity.** Observed PIDs rise almost linearly on every Linux host over the full window. Estimated rates cluster narrowly around roughly 1.9–3.7 allocations per second despite very different workloads: `APP-INT-01` is approximately 2.72/s, `DB-PROD-01` 2.42/s, `FILE-LNX-01` 3.29/s, `MAIL-CLIN-01` 3.25/s, `PROXY-01` 3.26/s, `WEB-EXT-01` 2.60/s, `WS-LNGUYEN-01` 2.72/s, and `WS-OHADDAD-01` 2.77/s. Linear fits are mostly very tight. Uncollected processes can explain unseen churn, but similar smooth rates across these roles suggest a shared synthesis mechanism rather than independently evolving hosts.

- **[distribution_texture] Millisecond-separated exact endpoint repeats.** After excluding record IDs and timestamps, there are repeated eCAR records whose remaining semantic payload is identical within 10 ms. `DC-01/ecar/ecar.json` lines 3382 and 3384, for example, describe the same `PROCESS OPEN` from `MpCmdRun.exe` PID 2460/TID 9244 to `MsMpEng.exe` PID 2424, with the same access mask and call trace, only 1 ms apart; another access variant is interleaved at line 3383. Similar exact near-duplicate pairs recur across Windows hosts, including 24 pair relationships on `DC-01` and 28 on `DC-02`. Repeated API calls are legitimate, but identical, tightly spaced payload reuse at this breadth has template-like texture.

- **[contract_gap] Outbound credential identity does not carry cleanly into proxy attribution.** In `WS-AJOHNSON-01/windows/security/windows_event_security.xml`, the 17:00:34 Event 4624 around lines 25720–25772 is Logon Type 9 (`seclogo`): local target user `aisha.johnson`, TargetLogonId `0x27c9552`, and TargetOutboundUserName `marcus.chen`. Subsequent staging and upload processes use that logon ID, including the `curl` upload in `WS-AJOHNSON-01/ecar/ecar.json` line 1348. The proxy records the matching tunnel and POST as `MERIDIANHCS\aisha.johnson` in `PROXY-01/proxy/proxy_access.log` lines 2177–2178. No explicit proxy credential option is visible in the command, and no nearby source-native credential transition explains why the Type 9 outbound identity is not the proxy identity. IP-based attribution or cached proxy authentication could explain it, so this is a contract gap rather than a hard contradiction.

- **[weak_signal] Unexplained service-parented exfiltration process.** The exfiltration `curl.exe` is recorded as a child of `services.exe` while using the same Type 9 logon context. No Event 4697 or 4698 appears on `WS-AJOHNSON-01` to explain a newly installed service or scheduled task. A pre-existing service, injected launch, or uncollected control path remains possible; missing companion coverage alone is not evidence, but the visible parent/token combination is operationally unusual and left unexplained by the records that are present.

## Evidence For Real

- The external foothold is reconstructable with native source transitions. `WEB-EXT-01/web/web_access.log` line 492 records the 13:19:37 upload request; `WEB-EXT-01/ecar/ecar.json` lines 883–884 show the Apache child spawning `/bin/bash` and the resulting outbound flow; `fw-perimeter/cisco_asa.log` lines 3472 and 3483 show the PAT translation and an eight-second TCP teardown. The host process precedes the network connection, and the firewall duration and bytes are plausible for a short reverse-shell exchange.

- The final exfiltration has strong transaction semantics rather than superficial field matching. `WS-AJOHNSON-01/ecar/ecar.json` lines 1348, 1355, and 1356 show the uploader, archive read, and client-to-proxy flow. `PROXY-01/proxy/proxy_access.log` lines 2177–2178 preserve the client port, tunnel identity, request method, and 18,782,896-byte upload. `fw-perimeter/cisco_asa.log` lines 17507 and 17511 show the proxy's separate outbound connection and approximately 19.8 MB teardown accounting. Small source-specific timing offsets preserve the expected process → client flow → proxy transaction → egress ordering.

- Independent sensors show stable, non-zero clock offsets rather than copied timestamps. For 4,120 core/DMZ observations of the same tuples, the core sensor is approximately 0.114 seconds ahead of the DMZ sensor with tight but non-zero jitter; core/database and DMZ/database comparisons have different offsets. The sensors also assign different Zeek UIDs. This resembles separately clocked collection points.

- Source-native lifecycle behavior is credible. The Security log on `DC-01` resets its EventRecordID after the 17:42:34 Event 1102 in `DC-01/windows/security/windows_event_security.xml` around lines 265227–265250. Records before the clear are in the 28-million range and subsequent records restart at 1, 2, 4, and 5. This is a realistic consequence of log clearing, not an arbitrary out-of-order sequence.

- Explicit lifecycle checks found no visible process created after one of its dependent events, no process termination before its corresponding visible creation, no session logout before login, and no dependent activity after the owning process had visibly terminated. Sysmon ProcessGuids were not duplicated, no process was its own parent, and no visible parent was created after its child.

- Network mechanics are internally credible. TCP `SF` records have response traffic, `S0` records do not fabricate responder packets, UDP history flags remain protocol-appropriate, and byte totals satisfy basic packet/header bounds. DNS response cardinality and record types agree with answers. Zeek protocol records and file observations fall within their referenced connection intervals.

- Background activity is differentiated by host role. Domain controllers carry Kerberos, logon, process, and flow volume; the file server carries share and object-access auditing; mail, proxy, web, database, and workstation systems have distinct traffic mixes. The DMZ contains substantial web and scanning contention, while core traffic includes DNS, SMB, HTTP, TLS, DHCP, and alert noise. This makes threat-hunting pivots compete with operational activity rather than presenting only attack records.

- DHCP behavior shows realistic renewal timing. The 3,600-, 7,200-, and 14,400-second leases in `zeek-core/dhcp.json` renew near their respective half-life intervals with drift, jitter, and occasional absent observations. The lack of full DORA sequences in this six-hour slice is not treated as adverse.

- The intrusion tradecraft is plausible as a sequence. The web foothold leads to a long-lived root SSH session and discovery/scanning; Windows movement uses service and WMI-oriented artifacts; database collection produces a compressed dump; SMB server logs record open/write/close activity for the staged archive; the workstation stages and compresses material before proxy exfiltration; and the domain controller log is cleared late rather than unrealistically at initial access.

## Detailed Analysis

### Operational lifecycle coherence

The attack can be followed without relying on a narrative manifest. After the web upload, Apache launches the shell process and the matching egress connection. A root SSH session from `10.10.1.35` to `WEB-EXT-01` begins around 13:40, with accepted-password, PAM/session-open, shell activity, and a later close in the target syslog. The shell performs host and network discovery and launches scanning activity. Later Windows evidence shows `PSEXESVC`-related execution, WMI-driven account and group changes, service/task activity, encoded PowerShell, and `wevtutil` log clearing on `DC-01`.

The collection/staging phase is also operationally usable. Root activity on `DB-PROD-01` includes database sizing, `mysqldump`, compression, hashing, and transfer toward `APP-INT-01`. `FILE-LNX-01/syslog/syslog.log` lines 460–462 record SMB open/write/close events for `/srv/samba/ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz` from `10.10.2.30` as `svc_mhsync`. On `WS-AJOHNSON-01`, file staging and archive activity precede the upload process and network connection. These provide practical pivots through usernames, paths, PIDs, ports, and timestamps.

The lifecycle tests did not expose impossible causality. Host flow direction consistently agrees with each host's own address: outbound records use the local address as source and inbound records use it as destination. Actor processes are established before visible dependent actions and survive until those actions complete. The remote-session evidence similarly keeps transport before authentication and session closure after activity. These checks materially weaken a high-confidence synthetic finding.

### Source volume and noise realism

The telemetry is not volume-flat. Domain controllers produce several thousand eCAR flows and dense Security/Sysmon streams; ordinary workstations are in the hundreds; specialized Linux and mail hosts occupy different ranges. Zeek core and DMZ sensors each carry thousands of connections and protocol companions, while the database sensor sees a smaller scoped population. Firewall build/teardown and NAT activity dominates the perimeter log, with deny and ICMP traffic as secondary populations. This role-sensitive distribution is credible.

Ambient activity includes common web browsing, mail delivery, DNS, TLS, SMB, DHCP renewals, host process activity, scheduled maintenance, Internet scanning, and IDS alerts. The web exploit is interleaved with earlier scanner activity from the same external source and unrelated client traffic. Scanner flows include failed or unanswered attempts rather than only successful attack transport. These details improve hunt realism.

The main weakness is that some background processes are too smooth across hosts. The repeated `debian-sa1` cadence and narrow PID-growth envelope look like shared generation rules. Real centralized configuration can create synchronized or staggered jobs, but a production estate normally accumulates more distro, package, timer, restart, and workload variation. This is a distributional concern, not an impossibility.

### Cross-source correlation and collection realism

The multi-sensor network view has realistic independence. Matching tuples frequently preserve byte and duration relationships, but they use sensor-local UIDs and stable clock offsets. Core-to-DMZ observations differ by about 114 ms; database comparisons have distinct offsets. This is stronger evidence than exact timestamp equality would have been, because it models separately clocked and positioned collectors.

Proxy mediation is correctly represented as two network legs: workstation-to-proxy and proxy-to-origin. The originating workstation port is retained at the proxy boundary, while the proxy chooses a separate egress source port at the firewall. The large uploaded object is visible in both application and transport accounting without implausible equality between every layer.

The principal cross-source weakness is identity ownership during exfiltration. The Type 9 session's outbound principal is `marcus.chen`, but the proxy's authenticated principal is `aisha.johnson`. That can happen if proxy identity comes from a separate cached or endpoint-based mechanism, but the records do not expose that mechanism. For a threat hunter, this creates ambiguity about whose credentials crossed the trust boundary and weakens the intended credential-theft pivot.

### Tradecraft and behavioral realism

The adversary behavior is conventional but not implausibly omniscient. Discovery precedes scans and lateral movement; collection occurs before staging and exfiltration; remote administration uses recognizable Windows mechanisms; cleanup happens late. The external scanner and exploit traffic use varied methods, paths, status codes, and user agents, giving the initial-access period believable contention.

The campaign is compact and comparatively clean, but that characteristic is not used as an authenticity indicator. A six-hour incident slice, a scoped collection policy, or an analyst-selected extract can all produce a concise narrative. Likewise, absent event families and thin sources are not counted against authenticity.

### Schema and field behavior

The inspected XML, JSONL, Zeek, ASA, proxy, web, Snort, syslog, and shell-history records are parseable and largely source-native. Windows event versions and field groupings match their event families; Sysmon process, network, image-load, process-access, file, registry, and DNS records carry appropriate fields. ASA connection IDs and build/teardown semantics are plausible, and Zeek state/history fields agree with packet direction and connection outcome.

No `schema_or_format` defect rose to the level of a meaningful authenticity indicator. Likewise, no `hard_contradiction` was identified. The negative case rests on texture and one identity contract gap rather than malformed records or impossible mechanics.

## Synthetic Indicator Summary

| Label | Concrete observation | Weight | Limitation |
|---|---|---:|---|
| `distribution_texture` | Identical `debian-sa1` command pair on ten Linux hosts at fixed 30-minute per-host phases | Moderate | Centralized configuration can create regular schedules |
| `distribution_texture` | Smooth, narrowly clustered PID growth across heterogeneous Linux roles | Moderate | Unobserved background processes can drive PID allocation |
| `distribution_texture` | Exact semantic eCAR repeats within 1–10 ms, especially Windows `PROCESS OPEN` records | Low–moderate | Real applications can repeat identical API calls rapidly |
| `contract_gap` | Type 9 outbound user `marcus.chen` but matching proxy upload attributed to `aisha.johnson` | Moderate | Cached, IP-based, or separate proxy authentication could explain it |
| `weak_signal` | Service-parented `curl.exe` under the Type 9 context without a visible launch-control transition | Low | A pre-existing service or uncollected mechanism is possible |
| `hard_contradiction` | None found | None | Lifecycle and protocol checks did not expose impossible state |
| `schema_or_format` | None material found | None | Inspected records were parseable and source-appropriate |
| `environment_or_collection_plausibility` | No independent material defect beyond the fleet-wide texture noted above | None | Thin or selected coverage was deliberately not treated as evidence |

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 9/10 | Strong source-native schemas and state fields; no material format defect found |
| Temporal patterns | 7/10 | Excellent attack/lifecycle ordering and sensor offsets, reduced by smooth PID and cron cadence |
| Cross-source correlation | 9/10 | Credible process, network, proxy, firewall, and sensor relationships; one identity gap |
| Behavioral realism | 8/10 | Plausible discovery, movement, collection, staging, exfiltration, and cleanup with ambient contention |
| Environmental consistency | 8/10 | Role-sensitive volumes and protocols, tempered by overly uniform Linux background texture |

## Recommendations

1. Reconcile the exfiltration identity contract. If proxy attribution is intentionally endpoint-, cache-, or SSO-derived, expose a source-native field or preceding event that makes that mechanism observable. Otherwise, carry the Type 9 outbound identity consistently into proxy authentication.

2. Diversify Linux PID allocation pressure by role and workload. Use bursty, host-specific churn with quiet intervals, maintenance spikes, daemon restarts, and longer-term reuse or wrap behavior instead of similarly linear fleet-wide rates.

3. Vary maintenance scheduling according to host image, distribution, role, and configuration history. Preserve some centralized cadence, but mix cron, systemd timers, package-specific jobs, missed runs, restarts, and host-local phase drift.

4. Review exact millisecond duplicate endpoint events. Retain duplicates only where the source behavior genuinely performs repeated calls; when retained, model realistic variation in thread, callsite, access mask, or intervening state rather than replaying an identical payload mechanically.

5. Preserve the strongest realism features: source-local clock offsets and UIDs, role-dependent background volume, stateful network accounting, process/session lifecycle ordering, proxy two-leg semantics, and the authentic Security-log clear/reset sequence.
