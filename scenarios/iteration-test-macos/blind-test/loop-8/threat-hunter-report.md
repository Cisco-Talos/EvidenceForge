# Threat Hunter Blind Authenticity Review

## Verdict

**Likely synthetic, with a high production-like surface and useful hunt paths.** The logs support realistic investigation of several suspicious chains. I found no decisive impossible event ordering or host/address contradiction, so this is a probabilistic authenticity judgment rather than a claim that individual records are invalid.

## Verdict Confidence (0-100)

**76/100**

## Synthetic-Confidence Score (0-100, lower is more production-like)

**72/100**

## Executive Summary

The dataset is operationally convincing in many source-specific details: routine user and service activity, varied protocol telemetry, process/session evidence, and multi-sensor observability. Several high-risk sequences are also readily pivotable. In particular, the web server has a dense internal scan attributed to `nmap`; a workstation stages material from Finance, Clinical, and Research paths and uploads it externally; a developer workstation sends EHR connector logs to a support endpoint; and a database host stages a compressed dump for transfer to an internal application host and file share.

Those chains are coherent enough to support hunting, but the collection presents them with unusually explicit, well-labeled artifacts and tightly coordinated records. This, together with unusually high Linux PID ranges on several hosts and very high event concentration during the web server scan, pushes the overall judgment toward synthetic. The evidence is not strong enough to rule out a real environment with carefully preserved telemetry and an active incident.

## Evidence For Synthetic

- **Curated, unusually explicit staging and transfer artifacts.** On `WS-AJOHNSON-01`, process and file telemetry show a named archive `cache_7f3a.zip` assembled from `VaultCache\Finance`, `Clinical`, and `Research`, copied to a user temp directory, then posted with `curl` to `/upload/telemetry/7f3a2b19`. The command, archive name, destination path, and related proxy transfer are all directly legible and align tightly. This is useful for a training hunt, but unusually self-describing for ordinary production activity.
- **Multiple conspicuous chains share the same compact observed window.** A root session on `WEB-EXT-01` searches for credential-named files and runs two subnet scans; shortly before/around other suspicious activity, `WS-AJOHNSON-01` stages and uploads the archive, and `DB-PROD-01` dumps named EHR tables and transfers the result. The clustering can occur during an incident, but it also resembles intentionally assembled exercise material.
- **Very high scan concentration.** In a five-minute interval, `WEB-EXT-01` eCAR records 1,265 flows attributed to `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24` and 251 flows attributed to `nmap -sn 10.10.2.0/24`. The scan is plausible and highly huntable, yet its volume dominates that host's short interval and produces an unusually clean command-to-flow story.
- **Unusually high Linux PID bands merit caution.** Linux eCAR process IDs are concentrated by host in ranges such as roughly 2.9–3.0 million on `APP-INT-01` and `WS-LNGUYEN-01`, 2.65–2.74 million on `FILE-LNX-01`, and 4.03–4.09 million on `WS-OHADDAD-01`. A high `pid_max` and long uptime can explain these values, so they are not impossible; across several modestly represented hosts they look more like assigned synthetic PID bands than a naturally observed sample.
- **The principal high-risk actions have unusually complete investigation pivots.** The DB dump, archive creation, reads, process launches, proxy upload, Zeek HTTP/file records, and IDS/network observations provide a notably convenient set of pivot fields. Completeness alone is not evidence of synthetic origin; the concern is the combination with conspicuous naming and tightly staged behavior.

## Evidence For Real

- **Source formats and fields are varied and generally plausible.** The bundle contains Windows Security and Sysmon XML, Linux syslog and timestamped shell histories, macOS endpoint/unified logs, eCAR, Zeek protocol logs, proxy access records, ASA firewall records, Snort alerts, and web access logs. Event shapes vary by source rather than appearing as one flat normalized format.
- **There is substantial routine activity around the suspicious events.** Histories include ordinary service checks, package/application work, SSH administration, SQL inspection, mail service maintenance, and developer commands. Web and proxy logs include routine browsing, blocked/failed requests, and normal service traffic alongside the suspicious activity.
- **The inbound web activity has credible multi-sensor evidence.** `185.70.41.45` makes repeated requests to the exposed web service; the access log contains a SQL injection-style request using `sqlmap/1.7.12`, while Snort reports repeated rapid HTTP/HTTPS attempts from that source. The surrounding traffic includes ordinary requests from other clients.
- **The Lina Nguyen support upload is operationally plausible.** Shell history and eCAR show collection of two EHR connector logs into a gzip archive, then a multipart request with a support ticket and component metadata. The proxy records a successful response, and Zeek HTTP/files records the upload and filename. This could be legitimate support work; its contents and authorization are not visible here.
- **The Aisha Johnson upload has an interpretable, technically coherent transport path.** Endpoint telemetry records the archive read and `curl` process; proxy telemetry records an inspected HTTPS upload of about 18.8 MB from the workstation; the command identifies the configured proxy. Network and endpoint attribution are mutually plausible.
- **The database transfer has plausible internal staging.** `DB-PROD-01` records a root `mysqldump` of `ehr` tables followed by gzip and SCP to `10.10.2.30`. `APP-INT-01` later records the received file, and `FILE-LNX-01` logs an SMB write of the same basename under a DB staging share. This is sensitive movement, but the sequence is not inherently impossible.

## Detailed Analysis

### Lifecycle coherence

Visible process launch/termination counts are broadly plausible for a short capture, with long-running services and incomplete lifecycle tails expected. The conspicuous activities have sensible local sequencing: the EHR dump precedes compression and SCP; the Aisha archive is created before it is copied/read for upload; and the Lina archive exists before the multipart request. I found no visible dependent event that clearly precedes its initiating event. Some login/logout ratios differ by host, which is not enough to call a contradiction in bounded telemetry.

### Signal-to-noise and pivot feasibility

The logs provide strong hunt pivots: user, hostname, PID/process identity, command line, source/destination tuple, proxy identity, HTTP URI, filename, and support ticket. Routine Windows, Linux, macOS, web, mail, database, file-share, and network activity provides usable context. The high-risk chains are unusually easy to follow, but the records include realistic intermediate stages and source-specific artifacts rather than only summary alerts.

### Tradecraft realism

The web server behavior is high risk: root executes `find /opt/ehr -name *credential*`, followed by host discovery and a TCP scan of `10.10.2.0/24`. The scan's eCAR attribution makes the process-to-network pivot immediate. Separately, the Aisha archive draws from multiple sensitive business areas and is sent to an external upload endpoint; the Lina support upload also moves internal logs offsite. A database dump is moved through an application host to an internal file share. These are credible patterns for insider misuse, compromised accounts, or authorized workflows being abused. Logs alone do not establish intent or authorization.

### Environment and collection realism

Coverage is broad and heterogeneous, and activity is not restricted to the attack-like records. The proxy and web logs contain varied methods, status codes, user agents, and destinations; IDS and firewall records add perimeter context. The main realism concern is that several high-risk events have unmistakably explanatory paths and hand-picked filenames/identifiers, while ordinary source events appear comparatively generic. This balance looks designed to make the scenario investigable.

### Bounded-window caveats

This review treated the available log interval as bounded. A missing earlier login, initial access event, or archive source is not treated as proof of fabrication. I did not infer origin from file modification times. I did not use absence of particular Sysmon event types, thin coverage by itself, or cross-source alignment by itself as synthetic indicators.

## Synthetic Indicator Summary

| Category | Finding | Strength |
|---|---|---|
| Staging / naming | Explicitly named sensitive archive, upload path, support ticket, and DB dump make the suspicious chains unusually self-describing. | Moderate |
| Temporal / behavioral concentration | Several conspicuous actions occur in the same short observed interval; the web server scan alone produces 1,516 attributed flows in five minutes. | Moderate |
| Process identity realism | Several Linux hosts use tightly grouped PID bands in the high hundreds of thousands to millions despite modest visible process volume. Plausible with high PID limits and long uptime, but unusual. | Low to moderate |
| Record mechanics | I found no decisive impossible ordering, IP/host collision, or lifecycle contradiction in the reviewed chains. | Weak evidence against synthetic |
| Cross-source agreement | Endpoint, proxy, Zeek, syslog, and network records agree on major activities. This was treated as realism evidence only in combination with the curated content, not as evidence of origin on its own. | Neutral |

## Realism Score by Category

Scores are 0–10, where 10 is most production-like.

| Category | Score | Notes |
|---|---:|---|
| Lifecycle coherence | 8 | Major visible chains have sensible ordering; no decisive lifecycle contradiction found. |
| Process and identity attribution | 7 | Useful user/PID/command fields; Linux PID ranges are unusually high and host-clustered. |
| Network and protocol behavior | 8 | Credible transport, HTTP, proxy, DNS, Zeek, firewall, and IDS context. |
| Tradecraft realism | 8 | Scanning, credential search, staging, archive creation, and outbound transfer are plausible behaviors. |
| Signal-to-noise | 7 | Good routine context, although selected suspicious chains are unusually legible and concentrated. |
| Collection/environment realism | 7 | Broad sensor mix and plausible service activity; explicit scenario-like identifiers reduce confidence. |
| Pivot feasibility | 9 | Strong pivots across user, host, process, file, URI, ticket, and network tuple. |
| Overall | 7.7 | Strong training realism; likely synthetic based on the combined presentation and PID/volume clues. |

## Recommendations

1. Treat the `WS-AJOHNSON-01` archive upload as a high-priority data-movement investigation. Establish archive contents, user authorization, destination ownership, proxy policy, and whether the endpoint's earlier copy operation was expected.
2. Investigate the `WEB-EXT-01` root shell and scan as possible compromise activity. Correlate the scan start with inbound requests, authentication/session evidence, and any application or service changes; determine whether `nmap` was an approved diagnostic tool.
3. Validate the EHR dump's business purpose and authorization. Confirm whether `DB-PROD-01` to `APP-INT-01` SCP and the subsequent `FILE-LNX-01` SMB write are part of a sanctioned reporting workflow.
4. Confirm the Lina Nguyen support transfer against the referenced ticket and approved vendor workflow. The log-visible ticket and matching upload are useful pivots, but do not establish that the destination or data set was authorized.
5. For authenticity improvement, vary the prominence and naming of suspicious artifacts, include ordinary incomplete or delayed source observations where appropriate, and use host-specific PID starting points grounded in plausible uptime/activity assumptions. Preserve enough cross-source evidence for pivots without making every suspicious chain self-explanatory.
