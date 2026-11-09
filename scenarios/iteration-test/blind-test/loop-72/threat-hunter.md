# Threat Hunter — Authenticity Assessment

## Verdict

- **Assessment:** Inconclusive
- **Verdict Confidence:** 62%
- **Synthetic-Confidence Score:** 52/100

## Executive Summary

The logs contain a coherent, cross-source sequence of suspicious activity, including a root SSH session that dumps patient and claims tables, compresses the output, and transfers it to another internal host. That coherence supports realism, but the repeated randomized `.top` DNS activity from the web server has a notably regular cadence; it could be genuine DGA-like activity or a generated distribution pattern. I found no impossible event ordering in the reviewed examples.

## Evidence For Synthetic

- **Distribution texture:** In `zeek-core/dns.json`, `10.10.3.10` makes 94 `.top` queries. After two early queries, activity resumes at 17:46 and continues through 18:45, with many successive queries roughly 20–45 seconds apart. The labels vary as random-looking strings, and most replies are `NXDOMAIN`; some resolve to the same `45.33.32.30`. This resembles beaconing or DGA behavior, but the repeated cadence and one reused answer are also consistent with generated activity.
- **Distribution texture:** `WEB-EXT-01.meridianhcs.local/web_access.log` has 99 distinct client IPs. Several prefixes account for an unusually large share: `73.0.*` contributes 24, `98.0.*` 22, and `96.224.*` 18. This may reflect real ISP address space, so it is a weak signal by itself.
- **Weak signal:** The `.top` queries are represented in both `zeek-core/dns.json` and `zeek-dmz/dns.json`, with similar counts and timestamps. That is consistent with sensor coverage and is not, by itself, evidence of synthetic generation.

## Evidence For Real

- **Cross-source correlation:** `DB-PROD-01.meridianhcs.local/ecar.json` records a root SSH login from `10.10.2.30` at 18:15:22, followed by `mysqldump --single-transaction ehr patients insurance_claims` at 18:15:27, creation of `/tmp/rpt_0318.sql`, gzip compression, and an `scp` to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. The same file records the outbound TCP/22 flow at 18:16:14 and a read of the archive at 18:16:21.
- **Cross-source correlation:** `APP-INT-01.meridianhcs.local/ecar.json` shows the matching inbound flow from `10.10.4.10:58676` at 18:16:14, root SSH login at 18:16:21, and creation of `/tmp/.cache/rpt_0318.sql.gz` at 18:16:41. The file path, source and destination IPs, port, and session timings agree across both hosts.
- **Temporal and network realism:** The web scan from `185.70.41.45` appears in `WEB-EXT-01.meridianhcs.local/web_access.log` with Nikto user-agent requests for paths such as `/wp-login.php`, `/.env`, and `/dump.sql`, mostly returning 404 or 403. `snort-perimeter/snort_alert.log` and `zeek-dmz/conn.json` also record activity from that source against the web host. The different sources show a plausible scan-and-response pattern.
- **Behavioral variation:** The logs include failed and successful DNS replies, refused or reset connections, and varied HTTP status codes. These irregular outcomes are consistent with real collection and activity; they are not treated as synthetic clues on their own.

## Detailed Analysis

The dataset spans roughly 13:00–19:00 UTC on November 2, 2026, so conclusions are limited to the visible window. A session or flow may have started earlier or continued after the files end.

The clearest malicious-looking sequence is the DB-to-application-host transfer described above. Its endpoint records agree on the source port, destination, SSH session, archive path, and event order. The source host’s command history, `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history`, also records the dump, gzip, and SCP commands at matching times. This is strong evidence of a plausible incident sequence, though the data alone cannot establish whether the activity was authorized.

The main authenticity uncertainty is the `.top` query pattern. In `zeek-core/dns.json`, `10.10.3.10` queries names such as `30rgw6r7503.top` at 18:01:08, `ipeq1qmxjn.top` at 18:06:17, and `lzncrtuqax.top` at 18:44:13. The cadence is sustained, and a subset resolves to `45.33.32.30`. `zeek-dmz/conn.json` separately records outbound connections to that address, mostly from `10.10.3.20`. This could represent malicious beaconing routed through a proxy; the visible logs do not prove an impossible or contradictory join.

The public-facing web log also contains both ordinary-looking asset retrieval and hostile probing. For example, internal clients request site assets while the Nikto scan produces repeated 404/403 responses. The concentration of client addresses within several prefixes is worth reviewing, but the log slice alone does not show that those clients or addresses are invalid.

## Synthetic Indicator Summary

| Observation | Classification | Assessment |
|---|---|---|
| Sustained randomized `.top` DNS queries from `10.10.3.10`, with many `NXDOMAIN` responses and some answers of `45.33.32.30` | `distribution_texture` | Strongest synthetic-like pattern, but also compatible with DGA-style activity |
| Many web client IPs concentrated in a few prefixes | `distribution_texture` | Weak, ambiguous without external address or collection context |
| Root DB dump, compression, SCP, matching inbound SSH and file creation on the destination | `weak_signal` | Strongly coherent evidence; not a synthetic indicator |

## Realism Score by Category

| Category | Score (1–10) |
|---|---:|
| Field format | 8 |
| Temporal patterns | 7 |
| Cross-source correlation | 9 |
| Behavioral realism | 7 |
| Environmental consistency | 7 |

## Recommendations

- Review the recurring `.top` queries from `10.10.3.10`, including the names that resolve to `45.33.32.30`, against local DNS and proxy records.
- Confirm whether the root database dump and SCP transfer from `DB-PROD-01` to `APP-INT-01` were authorized, and review the destination archive’s subsequent access.
