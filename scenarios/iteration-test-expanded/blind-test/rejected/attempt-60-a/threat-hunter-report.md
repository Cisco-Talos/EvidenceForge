# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 66  
**Synthetic-Confidence Score:** 45

## Executive Summary

The dataset is highly production-like in schema, source mix, and cross-source correlation, with realistic endpoint, proxy, Zeek, firewall, DHCP, SSH, RDP, mail, and web-access texture. I found one notable SSH lifecycle mismatch and some repeated baseline-noise patterns that feel generated, but not enough hard contradictions to call the dataset synthetic with confidence.

## Evidence For Synthetic

- **contract_gap:** One SSH session has endpoint closure well before the Zeek transport close. `10.10.1.31:53123 -> 10.10.2.30:22` logs root SSH open on [APP-INT syslog](/private/tmp/research-data-40617/dataset/APP-INT-01.meridianhcs.local/syslog.log:399), session close/removal at 17:56:49 on [APP-INT syslog](/private/tmp/research-data-40617/dataset/APP-INT-01.meridianhcs.local/syslog.log:415), and eCAR logout at [APP-INT eCAR](/private/tmp/research-data-40617/dataset/APP-INT-01.meridianhcs.local/ecar.json:767). The same Zeek tuple at [zeek-core conn](/private/tmp/research-data-40617/dataset/zeek-core/conn.json:7030) starts 17:40:37 with `duration=1891.41975`, implying close at 18:12:09. A normal SSH/PAM session closing 15 minutes before TCP `SF` close is unusual.

- **distribution_texture:** Linux syslog repeatedly reports `/etc/rsyslog.d/50-default.conf` reloads with changing checksums. WEB-EXT alone has reloads at [13:28](/private/tmp/research-data-40617/dataset/WEB-EXT-01.meridianhcs.local/syslog.log:495), [14:21](/private/tmp/research-data-40617/dataset/WEB-EXT-01.meridianhcs.local/syslog.log:768), [15:35](/private/tmp/research-data-40617/dataset/WEB-EXT-01.meridianhcs.local/syslog.log:1123), and [17:11](/private/tmp/research-data-40617/dataset/WEB-EXT-01.meridianhcs.local/syslog.log:1341). Across Linux hosts I counted 25 such reloads in six hours.

- **distribution_texture:** Windows Sysmon registry noise repeatedly sets static configuration values: `W32Time\Config\MaxPollInterval`, `Netlogon\Parameters\DynamicSiteName`, and `Microsoft-Windows-Sysmon/Operational\Enabled`, e.g. [FILE-SRV Sysmon](/private/tmp/research-data-40617/dataset/FILE-SRV-01.meridianhcs.local/windows_event_sysmon.xml:1687) and [MAIL-FIN Sysmon](/private/tmp/research-data-40617/dataset/MAIL-FIN-01.meridianhcs.local/windows_event_sysmon.xml:109). This resembles baseline-noise generation more than normal administrator-driven change cadence.

- **weak_signal:** [COLLECTION_PROFILE.json](/private/tmp/research-data-40617/dataset/COLLECTION_PROFILE.json:1) includes `schema_version`, `observation_profile`, and `output_target: default`. This could be a normal export manifest, but the wording is closer to a generated collection package than raw production telemetry.

## Evidence For Real

- SSH correlation is usually strong. For `10.10.1.21:44667 -> APP-INT:22`, syslog shows connection, public-key auth, PAM open, and logind session creation on [APP-INT syslog](/private/tmp/research-data-40617/dataset/APP-INT-01.meridianhcs.local/syslog.log:406); eCAR records the same inbound flow and login on [APP-INT eCAR](/private/tmp/research-data-40617/dataset/APP-INT-01.meridianhcs.local/ecar.json:748); Zeek records the same tuple on [zeek-core conn](/private/tmp/research-data-40617/dataset/zeek-core/conn.json:7151).

- Proxy and Zeek HTTP views align naturally. `10.10.1.22` CONNECT to `media.licdn.com:443` appears in [proxy_access.log](/private/tmp/research-data-40617/dataset/PROXY-01.meridianhcs.local/proxy_access.log:1) and the corresponding Zeek HTTP CONNECT appears in [zeek-core/http.json](/private/tmp/research-data-40617/dataset/zeek-core/http.json:1).

- DHCP behavior has realistic renewal cadence and stable identities. `WS-PPATEL-01` retains `10.10.1.32` and MAC `3c:97:0e:20:23:52` across renewals in [zeek-core/dhcp.json](/private/tmp/research-data-40617/dataset/zeek-core/dhcp.json:1) and [later renewal](/private/tmp/research-data-40617/dataset/zeek-core/dhcp.json:8).

- ASA lifecycle records look source-native: built/teardown pairs, NAT context, SYN timeouts, UDP teardown, and TCP FINs appear coherently in [fw-perimeter ASA](/private/tmp/research-data-40617/dataset/fw-perimeter/cisco_asa.log:1).

## Detailed Analysis

The visible window is 2024-03-18 12:00:00Z to 18:00:00Z per [COLLECTION_PROFILE.json](/private/tmp/research-data-40617/dataset/COLLECTION_PROFILE.json:3). The environment contains Windows workstations/servers, Linux hosts, Zeek core/DMZ sensors, ASA, Snort, proxy access, web access, eCAR, syslog, and bash history.

Operationally, most lifecycle relationships hold up. Process create/terminate, SSH login flow, proxy transactions, DNS/HTTP/SSL parent UIDs, DHCP renewals, and firewall build/teardown behavior are generally coherent. I did not find broad UID breakage, impossible Zeek state/packet combinations, or widespread process lifecycle contradictions.

The main synthetic-looking defect is the SSH close mismatch for `10.10.1.31:53123 -> APP-INT:22`. One such mismatch can occur in edge cases, but the endpoint evidence says the PAM/logind session is gone while Zeek still reports the TCP session active for roughly 15 more minutes with `conn_state=SF`.

The other concerns are texture-based: repeated rsyslog reloads with changing checksums and repeated Sysmon registry writes to static values. These are not hard contradictions, but they look like generated baseline “busywork” rather than organic enterprise drift.

## Synthetic Indicator Summary

| Category | Source Family | Scope | Score Impact |
|---|---|---:|---|
| contract_gap | SSH syslog/eCAR/Zeek | 1 clear tuple | Moderate |
| distribution_texture | Linux syslog | 25 reloads across hosts | Low-moderate |
| distribution_texture | Windows Sysmon registry | repeated static key sets | Low-moderate |
| weak_signal | collection manifest | dataset-level | Low |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Source formats are mostly native-looking across Zeek, Windows XML, ASA, syslog, proxy, and web logs.
- **Temporal patterns:** 6/10 — Mostly coherent, reduced by the SSH transport/session mismatch and repeated baseline reload cadence.
- **Cross-source correlation:** 8/10 — SSH, proxy, DHCP, DNS, firewall, and Zeek correlations are generally strong.
- **Behavioral realism:** 7/10 — User, admin, service, scanning, proxy, and mail behaviors are plausible.
- **Environmental consistency:** 7/10 — Host roles and subnets are coherent, with some collection/package texture that feels artificial.

## Recommendations

- Reconcile SSH session-close timing with Zeek TCP duration for the same tuple, especially boundary-spanning SSH sessions.
- Reduce repeated static baseline events unless backed by visible config-management cadence.
- Keep rsyslog reload checksums stable unless the config file visibly changes.
- If presenting as raw production telemetry, make collection metadata look like an export manifest rather than a generator profile.
