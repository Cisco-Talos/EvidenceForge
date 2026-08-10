# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 79/100  
**Synthetic-Confidence Score:** 39/100

The corpus falls in the **21–40 “mostly realistic”** band. I would not confidently classify it as synthetic from telemetry alone.

## Executive Summary

This is a strong, detection-usable corpus spanning Windows Security, Sysmon, normalized endpoint telemetry, Linux syslog and shell history, Zeek, proxy, firewall, IDS, SMTP, TLS/X.509, and web access data.

The strongest authenticity evidence is semantic rather than cosmetic:

- Windows process identities correlate across Security 4688/4689, Sysmon 1/5, and endpoint process lifecycle records.
- Endpoint process and user-session object identifiers persist correctly across creation/termination and login/logout.
- Zeek protocol records reference valid connection UIDs, while independent sensor zones use distinct UID namespaces.
- IDS alerts exhibit small sensor-relative timestamp offsets instead of exact copied timestamps.
- The firewall includes coherent build/teardown and NAT lifecycles, including realistic window-edge incompleteness.
- The DC’s Security log correctly resets its record sequence following event 1102, while preserving the event’s native `UserData` structure.

The principal synthetic indicators are population-level regularity: an unusually consistent normalized endpoint schema across the entire fleet, repeated operational command/message families, finite-looking web-client behavior templates, and an unusually curated six-hour concentration of broadly useful telemetry. These are moderate indicators, not decisive defects.

## Evidence For Synthetic

### Important: Fleet-wide behavioral templating

Operational shell activity repeatedly draws from a recognizable administrative vocabulary across unrelated users and hosts: `systemctl is-active`, short `journalctl` queries, `df`, `ss`, `ps`, `stat`, and compact diagnostic pipelines. Individual commands are credible, but the cross-fleet recurrence feels like a bounded behavior library rather than naturally accumulated operator history.

Linux syslog shows a similar pattern. Each host has useful diversity, but recurring families—session removal, sysstat cron, resolver feature changes, DHCP renewal, package/service checks—appear with consistently clean syntax and controlled variation.

### Important: Web traffic has finite behavioral bundles

The web access log contains convincing browsing sessions, scanners, bots, API clients, status codes, referrers, and cache behavior. At population scale, however, sessions repeatedly assemble from a limited set of browser versions, page sequences, asset groups, API paths, and response-size patterns.

Some unrelated public clients retrieve nearly identical application bundles with tidy page-to-asset transitions. The traffic resembles a well-designed workload model more than a messy production application with long-tail paths, malformed clients, partially loaded pages, application-specific errors, and deployment residue.

### Moderate: Uniform endpoint normalization

Every endpoint record uses the same compact object/action vocabulary, UUID formatting, property naming, and enrichment structure across Windows servers, workstations, and Linux systems. That could reflect a normalized export pipeline, but the consistency is unusually high.

All inspected endpoint event and object identifiers are UUIDv4. The identifiers are valid and lifecycle reuse is correct, yet the universal strategy across all object families contributes to a generated or post-normalized appearance.

### Moderate: Curated source breadth within a short interval

Within approximately six hours, the corpus contains Windows audit, Sysmon, endpoint, SSH, shell history, DHCP, DNS, Kerberos, LDAP, SMB, RDP, SMTP, HTTP, TLS, X.509, OCSP, proxy, firewall/NAT, IDS, file analysis, and web-server evidence.

This breadth is excellent for detection engineering but feels curated. The concern is not thinness or complete matching; it is how many distinct detection-relevant source families become meaningfully populated in one compact capture.

### Minor: Background texture is slightly too legible

Routine events are varied, but many records are immediately interpretable and operationally useful. Genuine enterprise telemetry usually contains more opaque vendor noise, malformed or truncated fields, stale configuration artifacts, collector-specific anomalies, and low-value repetition.

## Evidence For Real

### Strong: Correct endpoint lifecycle identity

Process termination records commonly reuse the process `objectID` established at creation. User-session logout records likewise reuse the corresponding login object identifier when both ends are visible.

Unpaired starts or stops occur naturally near the capture boundary and on long-lived processes. This is preferable to artificially forcing every lifecycle to close inside the window.

### Strong: Credible cross-source process timing

Windows process creation records match across Security 4688, Sysmon event 1, and normalized endpoint telemetry by PID and image. The endpoint observations generally trail native Windows records by hundreds of milliseconds rather than sharing exact timestamps.

Security and Sysmon remain close to one another, while endpoint normalization has a larger collection delay. That is a credible multi-stage telemetry pipeline.

### Strong: Native Windows semantics

The Windows XML retains source-specific characteristics:

- Appropriate providers, channels, versions, tasks, keywords, execution metadata, and 100-nanosecond timestamp formatting.
- Plausible Sysmon process GUID structure and reuse across process-dependent events.
- EventRecordID growth with gaps attributable to unselected event types.
- A DC Security-log clear represented by event 1102 under `UserData`, followed by EventRecordID reset to 1.
- Correctly structured account creation, password reset, group membership, service installation, scheduled task, audit clearing, and account deletion records.

### Strong: Zeek identifier and protocol semantics

All inspected DNS, HTTP, SMTP, SSL, and file references resolve to a connection UID within the same sensor dataset. Core and DMZ sensors do not reuse Zeek UIDs for common traffic.

Protocol timing is sensible:

- DNS records share the initiating packet timestamp with their UDP connection.
- HTTP and TLS records follow connection establishment.
- TLS certificate FUID references resolve to X.509 records.
- Reused HTTP connection UIDs and multi-file connections occur where expected.
- Connection state, history, packets, bytes, and duration are populated with protocol-dependent variation.

### Strong: Independent sensor timing

Matched Snort and Zeek observations use the same tuples but differ by small positive or negative timing offsets. They are not mechanically timestamp-identical. That looks like independent observation or deliberately accurate sensor-clock modeling.

### Strong: Firewall lifecycle behavior

Cisco ASA build and teardown messages preserve connection identifiers and direction/NAT semantics. Nearly all visible builds have a teardown, with one open lifecycle at the window boundary. SYN timeouts, FIN closures, resets, zero-byte attempts, NAT translations, ICMP, and access-list denies are represented with credible source-native syntax.

### Strong: Detection-rule feasibility

The corpus supports meaningful rules without relying on a supplied narrative:

- New domain account creation, password setting, privileged-group addition, subsequent use, and deletion.
- Service creation and PsExec-associated activity.
- Scheduled-task persistence.
- Security audit-log clearing.
- Remote administration through SSH, RDP, SMB, and service-control traffic.
- Suspicious file staging and remote transfer.
- LSASS access differentiated from routine service and Defender access.
- DNS reputation/TLD detections, web scanning, exposed-service probes, and perimeter enforcement.

The necessary identifiers and temporal ordering are generally available for joins.

### Moderate: Source-native asymmetry

The sources do not all expose identical facts. Zeek owns network UID and protocol metadata; Windows retains logon IDs and native process identifiers; endpoint data adds object relationships; syslog owns PAM/logind semantics; proxy logs expose tunnel and policy behavior. This asymmetry is realistic and useful.

## Detailed Analysis

### Schemas and parseability

The JSON logs are structurally valid and maintain source-specific schemas. Windows XML is well formed. Syslog uses credible RFC 5424-like records, while firewall, IDS, proxy, shell-history, and web logs retain their native textual conventions.

Schema variation is controlled rather than random. Optional fields appear according to protocol or object type. Zeek connection records vary for ICMP versus TCP/UDP; HTTP and SSL records have several optional-field shapes; file records vary by analysis depth and available metadata.

The main authenticity concern is the normalized endpoint layer’s extraordinary consistency across heterogeneous operating systems.

### Identifiers and joins

Identifier quality is one of the corpus’s strongest areas:

- Endpoint event IDs are unique.
- Endpoint object IDs persist across lifecycle-related records.
- Actor and target process UUIDs support process graph construction.
- Logon IDs and session IDs connect authentication, process, and logout activity.
- Sysmon process GUIDs recur in dependent process, network, module, file, registry, access, and thread events.
- Zeek UID and FUID references are internally coherent.
- Firewall connection IDs provide reliable lifecycle joins.
- Distinct Zeek sensors maintain distinct identifier spaces.

Missing initiating events are mostly compatible with long-lived or pre-window state. I did not treat them as synthetic evidence.

### Lifecycle semantics

Process and session closure rates vary by host and workload. Servers retain more long-lived processes and sessions, while short-lived commands often terminate within the capture. Network-oriented endpoint records represent connect observations rather than inventing unsupported endpoint disconnect events.

SSH syslog shows auth, PAM session, logind, and closure evidence with sensible separation. DHCP renewals, firewall translations, TCP connections, and process lifecycles show appropriate recurring or terminal behavior.

### Cross-source timing

Cross-source timestamps exhibit plausible collector latency:

- Windows Security and Sysmon are closely aligned.
- Normalized endpoint events tend to arrive later.
- IDS and Zeek differ by tens of milliseconds.
- Firewall timestamps are second-granularity, preventing artificial microsecond equality.
- HTTP and TLS application records occur after the corresponding connection begins.

This timing texture materially supports authenticity.

### Source semantics and detection utility

Kerberos, LDAP, SMB, remote service administration, and endpoint authentication records are sufficiently populated for sequence detections. Web, proxy, SMTP, TLS, and DNS data support content- and infrastructure-oriented rules. The endpoint schemas contain process identity on many flows but omit it where the source might not possess it.

The corpus is unusually convenient for detection engineering, but it is not unrealistically perfect: there are boundary-open lifecycles, optional-field variation, unsuccessful activity, repeated connections, cache behavior, resets, audit discontinuity, and source-dependent observation gaps.

## Synthetic Indicator Summary

| Indicator | Importance | Assessment |
|---|---:|---|
| Repeated administrative command and syslog behavior families | Important | Suggests bounded activity templates |
| Finite-looking web-client sessions and asset bundles | Important | Convincing locally, patterned globally |
| Uniform endpoint normalization across all systems | Moderate | Could be a real normalized export |
| Broad source coverage within six hours | Moderate | More curated than typical collection |
| UUIDv4 used universally in endpoint identities | Minor | Valid but homogeneous |
| Background events are unusually clean and legible | Minor | Limited ingestion and vendor noise |

No single indicator establishes synthetic origin. The strongest technical evidence—identifier persistence, native event structure, source-local timing, and lifecycle behavior—leans realistic.

## Realism Score by Category

| Category | Score |
|---|---:|
| Schema and source-native fidelity | 9/10 |
| Identifier and cross-source correlation | 9/10 |
| Lifecycle and temporal realism | 9/10 |
| Background behavioral diversity | 7/10 |
| Detection-engineering usability | 9/10 |

## Recommendations

1. Expand long-tail Linux activity with host-specific service stacks, administrator habits, package state, error residue, and less universally useful command history.

2. Increase web workload diversity: partial page loads, abandoned sessions, uncommon methods, malformed requests, framework-specific errors, deployment transitions, API authentication failures, retry behavior, and longer-lived clients.

3. Add collector-specific imperfections to normalized endpoint data, such as selective enrichment loss, batching, agent-version differences, benign duplicate delivery, and host-specific field availability—without breaking lifecycle groups.

4. Vary endpoint telemetry schemas by operating system and sensor generation. Preserve the canonical truth while letting individual collectors expose different identifiers and enrichment depths.

5. Extend captures across multiple days to introduce daily and weekly rhythms, persistent sessions, maintenance windows, certificate reuse, DHCP lease evolution, and more natural pre-window/post-window truncation.

6. Preserve the existing Windows, Zeek, firewall, and session-correlation behavior. These are already strong enough that degrading completeness merely for appearance would reduce detection value without necessarily improving authenticity.
