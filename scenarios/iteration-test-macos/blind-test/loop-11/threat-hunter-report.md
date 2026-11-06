# Blind Threat Hunter Authenticity Review — Loop 11

## Verdict

**Likely curated or synthetic telemetry, with strong production-like behavior.** The bundle is internally coherent across host, network, and service logs, but several unusually high-signal behaviors are captured in unusually rich, directly joinable detail within one six-hour window. That concentration is more consistent with a prepared investigation dataset than an unselected production slice. This is an inference from the observed bundle only; real incident telemetry can look the same.

## Verdict Confidence (0–100)

**68** — moderate confidence. The assessment is driven mainly by the concentration of complete, high-value investigation pivots, not by a decisive schema or lifecycle failure.

## Synthetic-Confidence Score (0–100; lower is more production-like)

**58** — mixed. Cross-source timing and attribution are generally production-like; the concentration and presentation of the high-signal chains modestly increase synthetic likelihood.

## Executive Summary

The logs support at least two serious, independently corroborated data-handling events: a root SSH session to `DB-PROD-01` that exports and moves an EHR database archive, and a developer workstation upload of a diagnostic archive to an external support endpoint. A separate stream of Internet scanning against `WEB-EXT-01` is also visible in web, network, firewall, and IDS evidence. These are credible threat-hunting pivots, and their timings, tuples, and artifacts mostly agree across sources.

The strongest authenticity concern is the concentration of these investigation-ready chains, including filenames, usernames, external destinations, process command lines, Zeek file records, and server-side audit lines, all inside the same captured interval. A smaller timing ambiguity exists in the root shell history: several commands precede the matching SSH login, although an earlier local root session on the server provides a possible explanation. I found no decisive event-order contradiction in the corroborated transfer itself.

## Evidence For Synthetic

- **Concentrated investigation-ready signals:** Within the same six-hour interval, the bundle includes a root database export and transfer, a large diagnostic upload to an external support domain, and repeated public-facing service probes. Each has unusually useful pivots across multiple independent log types. This is possible in production but raises the likelihood that the interval was selected or assembled for investigation.
- **Root history pre-dates the matching SSH login:** `DB-PROD-01` root history shows `pwd`, database queries, and a disk check from 18:14:07–18:14:39 UTC. The SSH login from `10.10.2.30` is accepted at 18:14:42 UTC. The later dump and `scp` commands align with that SSH session. An earlier local root session is logged at 18:00 UTC, so this is a qualified attribution/timing ambiguity, not proof of an impossible sequence.
- **High actionability of the curated data transfer:** The export filename `rpt_0318.sql.gz`, the `.cache` destination, the matching SSH tuple, and the later `ClinicalResearch/Integration/DB-Staging` SMB write form a highly legible chain. It is coherent, but this degree of preserved cross-source detail is characteristic of a purpose-built hunt dataset.
- **Observed window is tightly aligned:** Most major feeds cover approximately 13:00–19:00 UTC on the same day. A bounded collection window is normal and is not counted as a standalone synthetic indicator; it contributes only slightly when considered with the event concentration above.

## Evidence For Real

- **DB export chronology is independently corroborated:** `DB-PROD-01` records an accepted password SSH login for `root` from `10.10.2.30` at 18:14:42 UTC, followed by `mysqldump`, gzip, and `scp` process/file evidence. Zeek records the inbound SSH tuple `10.10.2.30:36267 → 10.10.4.10:22` and a later outbound SSH tuple `10.10.4.10:35261 → 10.10.2.30:22`. The session closes at about 18:41 in both host and network records.
- **The staged copy has a second independent trail:** At 18:18:32 UTC, Zeek records `10.10.2.30 → 10.10.2.21:445`, an SMB write of `Integration\DB-Staging\rpt_0318.sql.gz`, size 16,211 bytes. `FILE-LNX-01` audit logs show the same source, share, file, and successful open/write/close under `svc_mhsync`. This is a realistic operationally ambiguous path: it could be authorized staging, abuse of a service account, or both.
- **External support upload is coherent:** `lina.nguyen`'s shell history creates and submits `mhs-support-48217.tar.gz` through the configured proxy to `support.valeworks-health.net`. Zeek records a matching 1,573,258-byte HTTP POST from `10.10.1.21`, the same case path, filename, and a successful response. This is a strong exfiltration or approved support-transfer pivot, with sufficient content and destination detail for investigation.
- **Internet probing is visible at several layers:** `WEB-EXT-01` access records show scanning requests, while endpoint network events, `zeek-dmz`, perimeter firewall records, and Snort alerts expose inbound attempts to web and non-web services. The variety of targeted ports and request paths is consistent with broad scanning and merits triage.
- **Background host behavior is plausible:** Ordinary service, DNS, authentication, process, and user activity surrounds the high-signal events. Counts and timing do not show an obvious fixed-rate flood or identical event storm. Cross-source alignment is generally a strength here, not an authenticity defect.

## Detailed Analysis

### DB-PROD-01 export and staging

The clearest pivot begins with SSH from `10.10.2.30` to `DB-PROD-01` (`10.10.4.10:22`). Zeek sees the connection beginning at 18:14:28 UTC; host syslog records the connection at 18:14:32, password acceptance for `root` at 18:14:42, and session open immediately after. Endpoint telemetry assigns the same source and login ID to the root session. Shell history then records a database dump, gzip, and transfer command. Endpoint records show the dump process and output file, then the `scp` process and outbound connection. The SSH session closes around 18:41 UTC, matching the long-lived Zeek connection.

Three minutes later, `10.10.2.30` writes the same archive name to the ClinicalResearch staging tree on `FILE-LNX-01`. Zeek SMB connection, SMB file records, file metadata, and Linux audit lines agree on the path and transfer. This supports a real operational sequence, although the logged root password use and intermediate hidden directory warrant investigation. The known prior local root session on `DB-PROD-01` means the earliest history commands cannot be confidently assigned to the later SSH session from this bundle alone.

### Workstation diagnostic upload

The Linux workstation history shows a tar archive assembled from EHR connector logs and a `curl` form upload to an external support endpoint. The network record identifies the same workstation, case path, user agent, filename, size, and HTTP success. That is a high-priority data-governance pivot. The log-visible evidence does not establish whether this was an approved vendor workflow, whether the archive contained sensitive data, or who controlled the destination at the time.

### Public-facing service probes

`WEB-EXT-01` has repeated requests for common administrative, CMS, repository, and status paths, including requests attributed to a Nikto user agent. Network and perimeter telemetry show a variety of inbound ports and sources; Snort produces relevant policy/scan alerts. Some attempts target services outside the normal public web surface. The pattern looks like broad scanning rather than a single clean exploit sequence. No successful compromise is established by these records alone.

### Lifecycle, pivots, and collection realism

The strongest event lifecycle (the database SSH session and subsequent transfer) is coherent from connection to authentication, process/file activity, network movement, and session close. Ordinary user and service activity provides background and alternative explanations for some events. I did not use narrative completeness, absent event types, or record volume alone as evidence of synthetic origin.

One limited timing discrepancy remains: the root history's first commands precede the matching SSH login by roughly 35 seconds, but a local root session was opened earlier and the history file is shared by the account. This cannot be resolved from the available logs. The bundle also shows the same DB SSH tuple at both Zeek vantage points with small timing and byte-count differences; that is plausible for overlapping sensor observations and is not treated as a contradiction.

## Synthetic Indicator Summary

| Category | Log-visible indicator | Weight |
|---|---|---|
| Signal concentration | Several high-value incident chains are unusually discoverable in the same short bundle | Moderate |
| Timing | Root history starts before the later matching SSH login; an earlier root session is a plausible alternative | Low to moderate |
| Lifecycle | Corroborated DB SSH/export/staging lifecycle is coherent | Evidence against synthetic artifacts |
| Cross-source join quality | Host, Zeek, SMB, syslog, IDS, and web records expose many exact pivots | Evidence against synthetic artifacts; concentration modestly favors a curated bundle |
| Volume and cadence | No decisive fixed-rate or implausible burst pattern identified | Low / neutral |
| Collection scope | Feeds share a bounded six-hour interval | Low / neutral; expected in a bounded collection |

## Realism Score by Category

Scores estimate production-like behavior, where 100 is highly production-like.

| Category | Score | Rationale |
|---|---:|---|
| Temporal and lifecycle coherence | 82 | Strong ordering and matching session close for the DB SSH chain; one qualified history timing ambiguity |
| Cross-source correlation | 91 | Specific identities, tuples, filenames, and sizes agree across independent sources |
| Endpoint identity and process evidence | 84 | Process, user, source address, and session details support useful pivots |
| Network and application evidence | 86 | Zeek, HTTP, SMB, firewall, and IDS records give plausible source-native views |
| Background noise and signal-to-noise | 76 | Usable ordinary activity exists, but high-signal activity is concentrated |
| Collection and environment realism | 79 | Plausible mixed healthcare environment and bounded capture; one source-host attribution remains unresolved |
| **Overall** | **83** | Realistic event construction with moderate signs of selection or curation |

## Recommendations

1. Confirm the owner, purpose, and endpoint identity for `10.10.2.30`; determine whether root SSH access to `DB-PROD-01` and `svc_mhsync` writes to the ClinicalResearch staging share are approved.
2. Preserve the DB archive and any recovered copy, record hashes, and compare its contents with the export command and downstream access history. Establish whether the 16,211-byte SMB object is the expected compressed output.
3. Review the root SSH credential, authentication source, key/password policy, and the session's full command history. Resolve whether the commands before 18:14:42 UTC came from the earlier local root session or reflect a timestamp/collection issue.
4. Validate the support ticket, vendor domain, proxy policy, and archive contents for case `MHS-48217`. Confirm whether the upload was approved and whether the attached diagnostic logs contain regulated or credential data.
5. Triage inbound scans against `WEB-EXT-01`; correlate attempted ports and request paths with firewall dispositions and web responses, and verify that exposed non-web services are expected.
6. Retain the current multi-source pivots in the hunt record; the bundle's strongest investigative value comes from the agreement between endpoint process context, transport metadata, file records, and server audit evidence.
