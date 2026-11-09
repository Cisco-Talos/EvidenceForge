# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 67  
**Synthetic-Confidence Score:** 48

## Executive Summary

The data contains coherent, cross-source evidence for a large upload from `WS-LNGUYEN-01` and a later database dump transferred from `DB-PROD-01` to `APP-INT-01`. The main authenticity concern is a timestamp mismatch between commands in the DB server’s root shell history and the only visible root SSH session; separate or pre-existing sessions could explain it, so it is not decisive.

## Evidence For Synthetic

- [contract_gap] On `DB-PROD-01`, root shell history records `hostname -f`, two MySQL queries, and `df -h /tmp` at 18:13:44–18:14:24 UTC. The visible SSH connection from `APP-INT-01` begins at 18:14:23, authentication succeeds at 18:14:31, and eCAR records the root shell process at 18:14:33. The subsequent dump, gzip, and SCP commands do align with that session. The earlier commands could belong to a separate or pre-existing root session, but the available records do not show one.

## Evidence For Real

- The support upload has consistent evidence across sources: `WS-LNGUYEN-01` eCAR records Lina’s `tar` and `curl` activity at 16:39:34–16:40:12 UTC; the proxy records a successful POST to `support.valeworks-health.net` from `10.10.1.21` at 16:40:12; and Zeek records the matching connection to `PROXY-01` with about 1.57 MB sent.
- The database transfer is also correlated: DB syslog records root SSH access from `APP-INT-01`; eCAR records the `mysqldump`, gzip, and SCP operations; Zeek records the completed SSH connection to `APP-INT-01`; and the target records the received file.
- The six-hour window includes varied background activity across Windows, Linux, macOS, network, and proxy sources. The sampled records have plausible timestamps and source-native fields, and the visible activity is not uniformly timed.

## Detailed Analysis

### Collection scope and window

The supplied files cover approximately 13:00–19:00 UTC on 2026-11-02. They include endpoint records for Windows, Linux, and macOS hosts; Zeek views for core, DMZ, and database networks; perimeter firewall and Snort logs; and proxy and web access logs. Hostnames, user identities, and private addresses are internally consistent in the sampled activity.

### Upload from `WS-LNGUYEN-01`

At 16:39:34 UTC, eCAR records Lina creating `/tmp/mhs-support-48217.tar.gz` from two EHR connector log files. At 16:39:56 it records the upload command targeting the support attachment endpoint. The proxy logs a successful 200 response at 16:40:12, with 1,573,396 client bytes. Zeek records a completed connection from `10.10.1.21:56692` to `10.10.3.20:8080`, with 1,573,700 origin bytes. The byte counts and ordering are consistent with the observed upload.

### Database dump and transfer

At 18:14:23 UTC, `DB-PROD-01` syslog records an SSH connection from `APP-INT-01`; root authentication succeeds at 18:14:31. eCAR then records a root shell, a dump of the `ehr` database tables `patients` and `insurance_claims`, gzip, and SCP to `APP-INT-01:/tmp/.cache/rpt_0318.sql.gz`. Zeek records the completed SSH connection between those hosts, and `APP-INT-01` records the received file. These are strong cross-source correlations.

The caveat is the earlier root history sequence on `DB-PROD-01`: three inspection commands appear before that visible SSH connection, and `df -h /tmp` is timestamped just before it begins. A separate root session could account for the sequence, but the available window does not establish one.

### Background activity and format

The sampled Linux syslog records include DHCP renewals, service activity, SSH sessions, and ordinary administration commands. The Zeek and proxy data include varied internal and external connections. Windows event records span the same six-hour period, while the macOS endpoint records use a distinct schema from the Unified Log exports. I did not find a second clear source-native contradiction in the examined incident windows.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | DB root shell history, syslog, eCAR | A few root commands on `DB-PROD-01` precede the only visible root SSH session and its shell process | Moderate concern; plausible separate-session explanation keeps it from being decisive |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled Windows, Linux, macOS, Zeek, and proxy fields are generally source-appropriate.
- **Temporal patterns:** 7 — Most event ordering is coherent; the DB root-history sequence is an unresolved exception.
- **Cross-source correlation:** 9 — The upload and SCP transfer align across endpoint, network, proxy, and syslog records.
- **Behavioral realism:** 7 — The visible activity is technically coherent, though the two data-handling sequences warrant investigation.
- **Environmental consistency:** 8 — The host roles, network segments, and source mix fit the observed connections.

## Recommendations

- If this were synthetic, align the earlier DB root-history commands with a visible session, or make their association with a separate pre-existing session clear in the logs.
