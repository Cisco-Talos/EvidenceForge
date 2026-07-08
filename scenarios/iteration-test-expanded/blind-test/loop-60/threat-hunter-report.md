# Threat Hunter - Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 18

## Executive Summary

The dataset is production-like across source mix, field structure, timing, and cross-source lifecycle coherence. I found no admissible hard contradictions, schema defects, or required companion gaps; the strongest evidence points to a realistic enterprise slice with correlated endpoint, network, proxy, firewall, mail, and web telemetry.

## Evidence For Synthetic

- No scored `hard_contradiction`, `contract_gap`, or `schema_or_format` indicators found in the raw logs reviewed.
- `weak_signal`: The major attack chain is very well correlated across sources, but complete cross-source matching is not scored as synthetic without an impossible ordering or field contradiction.

## Evidence For Real

- DB exfiltration is coherently represented: `DB-PROD-01` eCAR shows `scp /tmp/rpt_0318.sql.gz` at `2024-03-18T17:30:45Z`, Zeek core has the same `10.10.4.10:46080 -> 10.10.2.30:22` SSH flow with `211665` origin bytes, `APP-INT-01` syslog records the SSH login, and APP eCAR records the received file.
- DC command execution is source-native: `net user svc_mhsync /add /domain`, `net group "Domain Admins"`, and cleanup all appear in eCAR, Sysmon, and Security logs with expected Windows event IDs including `4720`, `4728`, and `4726`.
- Security-log clearing is not a gap: `wevtutil cl Security` appears in eCAR/Sysmon/Security 4688, followed by Security `1102` at `2024-03-18T17:41:51.6978749Z`.
- Proxy/C2-like activity is plausible: DC eCAR flow `10.10.2.10:52322 -> 10.10.3.20:8080`, Security 5156, Zeek core and DMZ HTTP `CONNECT api.westbridge-services.net:443`, and proxy access logs align without identical Zeek UIDs.

## Detailed Analysis

The visible environment covers workstations, servers, proxy, DMZ web/mail, firewall, Snort, and two Zeek vantage points. Host/IP mapping is consistent: DHCP places workstations in `10.10.1.0/24`, eCAR identifies servers such as `DC-01=10.10.2.10`, `FILE-SRV-01=10.10.2.20`, `WEB-EXT-01=10.10.3.10`, `PROXY-01=10.10.3.20`, and `DB-PROD-01=10.10.4.10`.

The strongest authenticity evidence is operational lifecycle coherence. The `scp` chain spans bash/eCAR, SSH syslog, endpoint session telemetry, and Zeek network flow with matching tuple and feasible order: process create, file read, TCP/22 flow, server-side SSH accept, file create, session logout.

Windows telemetry also holds together. The domain account creation sequence has process evidence plus Security account-management events. The log clear has the expected `1102` companion. I found no visible logoff-before-logon, process terminate-before-create, or SSH-auth-before-transport contradictions.

Source-family mix is realistic rather than overly thin: Zeek has DNS/HTTP/SSL/SMTP/files/DHCP/NTP, perimeter ASA/Snort noise exists, proxy logs include ordinary browsing and tunnel setup, and endpoint logs include both mundane service activity and suspicious commands.

## Synthetic Indicator Summary

| Category | Source Family | Scope | Impact |
|---|---|---:|---|
| `hard_contradiction` | endpoint/network/auth | none found | none |
| `contract_gap` | SSH, AD, proxy, log clear | none found | none |
| `schema_or_format` | Windows XML, Zeek JSON, syslog, ASA | none found | none |
| `distribution_texture` | source volumes/timing | no scored defect | low |

## Realism Score by Category

- **Field format accuracy:** 92 - Windows, Zeek, syslog, ASA, proxy, and web formats are internally plausible.
- **Temporal patterns:** 88 - Event ordering and source delays are believable across the visible slice.
- **Cross-source correlation:** 95 - SSH, proxy, AD, and log-clear chains correlate without impossible reuse or ordering.
- **Behavioral realism:** 86 - Suspicious activity is supported by normal background traffic and admin noise.
- **Environmental consistency:** 90 - Host roles, IP scopes, users, and services agree across source families.

## Recommendations

- No synthetic-specific correction is indicated by the raw logs reviewed.
- If this dataset is synthetic, preserve the current source-native companion evidence around SSH, AD account operations, proxy CONNECTs, and Security `1102`.
- Document the collection window/tail policy for analysts, because endpoint logs extend beyond the main network window while network sensors are mostly clipped near 18:00.
