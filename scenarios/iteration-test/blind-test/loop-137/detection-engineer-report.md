# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 66

## Executive Summary

I lean synthetic, but not because of schema failures or impossible cross-source joins. The Windows, Zeek, ASA, proxy, and eCAR records are mostly SIEM-usable; the main tells are Linux baseline telemetry patterns that look generated rather than emitted by real systemd/journald/logind behavior.

## Evidence For Synthetic

- `WEB-EXT-01.meridianhcs.local/syslog.log` contains 203 `systemd-journald` disk-usage messages from `2024-03-18T12:00:41Z` to `17:51:40Z`, with a median gap of about 62 seconds. Similar repeated journald size accounting appears on `APP-INT-01` (119), `DB-PROD-01` (92), and `PROXY-01` (68). Real journald does not normally emit this as high-volume periodic telemetry.
- `WEB-EXT-01` shows very high `systemd-logind` churn: `root` 100, `ubuntu` 94, and `admin` 94 "New session" records, while `sshd` only accepted `root` 3 times, `admin` 3 times, and `ubuntu` 0 times. The volume and user mix look like baseline-noise templates rather than organic PAM/session activity.
- The same Linux noise motifs recur across unrelated hosts: `admin`/`ubuntu`/`root` sessions, journald free-space lines, sudo probes, and DBus activation messages. Individually plausible, collectively too patterned.

## Evidence For Real

- Windows Security/Sysmon field semantics are strong: no visible logoff-before-logon, no process terminate-before-create, plausible `4624`, `4634`, `4688`, `4689`, `4768`, `4769`, `4697`, `4720`, `4728`, and `1102` usage.
- Zeek correlation is clean: DNS/HTTP/SSL UIDs all join to `conn.json`; SSL certificate FUIDs all join to `x509.json`; repeated HTTP UIDs reflect multiple transactions on one connection, not corruption.
- ASA state is plausible: 5,616 built connections and 5,613 teardowns, with only three unclosed connections at the visible window edge.
- The DB exfil-style chain is coherent: `DB-PROD-01` has root SSH from `10.10.2.30` at `17:15:15Z`, root bash history for `mysqldump`, `gzip`, and `scp`, eCAR process/file/flow records, and corresponding inbound eCAR on `APP-INT-01`.
- Hashes were stable when grouped by Windows path plus version metadata, which is a good sign for detection-rule fidelity.

## Detailed Analysis

Windows telemetry is the strongest part of the dataset. DC Security shows normal KDC-heavy volume (`4769`, `4768`) with plausible machine-account and user-account service ticket activity. The `1102` at `2024-03-18T17:42:15Z` resets `EventRecordID` to `3`, which is believable after audit log clear and not a contradiction in SIEM-collected data.

Sysmon is also usable. Event 22 DNS is attributed to `C:\Windows\System32\svchost.exe` as `NT AUTHORITY\LOCAL SERVICE`, which is source-native Windows DNS Client behavior. Event 1/Event 5 and Security 4688/4689 ordering checks found no impossible visible lifecycle ordering.

Network telemetry holds together. Zeek protocol logs join cleanly to connection records, SSL/x509 references are consistent, and Snort alert timestamps match nearby Zeek DMZ connections. Proxy and web access logs parse cleanly, including expected second-level precision and `304 -` response-byte behavior in web logs.

The main weakness is Linux syslog realism. The journald free-space message pattern is too frequent and too uniformly distributed across hosts, and the logind session churn has a generated feel. This would not break SIEM parsing, but it would stand out to analysts familiar with Linux host logs.

## Realism Score by Category

- **Field format accuracy:** 86 — Windows, Zeek, ASA, proxy, and web formats are mostly source-native.
- **Temporal patterns:** 68 — most event ordering is sound, but Linux journald/logind cadence is unnatural.
- **Cross-source correlation:** 92 — joins and shared identifiers are consistently usable without concrete contradictions.
- **Behavioral realism:** 72 — attack chains are plausible; baseline Linux activity is over-templated.
- **Environmental consistency:** 80 — host roles, IPs, DNS, certs, and services align, with some repeated noise pools.

## Recommendations

Reduce or remove periodic journald disk-usage messages; emit them only around realistic triggers such as startup, rotation, or vacuum activity.

Tie `systemd-logind` sessions to concrete SSH, sudo, cron, GUI, or PAM events, and vary the behavior by host role.

Keep the strong Windows/Zeek/ASA/eCAR correlation model, but add more source-specific messiness to Linux baseline logs so they feel collected rather than rendered.
