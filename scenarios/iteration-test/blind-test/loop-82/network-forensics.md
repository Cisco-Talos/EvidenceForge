# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 67
**Synthetic-Confidence Score:** 62

## Executive Summary

The network records show plausible protocol behavior, varied connection outcomes, coherent DNS-to-flow and TLS/HTTP UID relationships, and sensible differences among core, database, and DMZ sensors. The strongest synthetic signal is a highly consistent timing relationship between matching core and DMZ flow tuples: 5,134 matches have a median timestamp offset of −114.245 ms, and 5,131 (99.9%) fall within 5 ms of that offset. This could reflect a deliberately modeled sensor delay or a stable clock offset, so it raises suspicion without proving synthetic origin by itself.

## Evidence For Synthetic

- [distribution_texture] Matching Zeek core and DMZ flow tuples show an unusually tight sensor-to-sensor timing offset. Of 5,134 core records with a same-tuple DMZ match (same source/destination addresses and ports, protocol), the DMZ timestamp was earlier in every case; median offset was −114.245 ms, standard deviation 1.90 ms, and 5,131/5,134 (99.9%) were within 5 ms of the median. For example, the core `zeek-core/conn.json` DNS flow `10.10.3.20:59968 → 10.10.2.10:53` at `1793624402.471181` has a DMZ counterpart about 115 ms earlier. A nearly invariant offset across thousands of connections is more suggestive of a fixed modeled observation delay than independently observed flow timing, although a stable sensor clock skew or capture placement could also explain it.
- [weak_signal] The three Zeek conn logs all cover almost exactly six hours, beginning at approximately 13:00 UTC on 2026-11-02 and ending near 19:00 UTC. This is consistent with a bounded collection window and is only a weak signal; the window boundary itself is not evidence of synthetic generation.

## Evidence For Real

- `zeek-core/conn.json` contains varied TCP outcomes: 9,937 `SF`, 1,710 `S0`, 160 `RSTO`, 103 `RSTR`, 30 `REJ`, and smaller `S1`/`S2`/`S3` groups. The corresponding DMZ sensor also has a varied mix (7,038 `SF`, 2,337 `S0`, 123 `RSTO`, 89 `RSTR`, 29 `REJ`), with unanswered connection attempts concentrated in a perimeter-facing view.
- DNS has a credible query mix rather than only lookup traffic: core Zeek records include A (2,306), AAAA (292), TXT (244), PTR (175), and SRV (102) queries, plus 205 NXDOMAIN responses and a small number of SERVFAIL/REFUSED outcomes. Database-sensor DNS has a different, lower-volume distribution.
- UID joins are internally coherent: every DNS, HTTP, and SSL UID in each Zeek sensor’s corresponding log was present in that sensor’s `conn.json`. SSL timestamps also fall within their matched connection intervals in all three sensors. Multiple HTTP requests share a connection UID and advance `trans_depth` (for example, the core flow `C7hciNv311gt4sRHJN` serves three sequential GETs, with referrers and response sizes changing plausibly).
- The protocol mix is differentiated by observed role. Core Zeek includes DNS, Kerberos, LDAP, SMB, HTTP/proxy, syslog, SMTP, SSH, RDP, and database flows; the DB sensor is dominated by MySQL on port 3306; DMZ Zeek has substantial TLS/HTTPS, HTTP, DNS, and inbound scan traffic. TLS records show both TLS 1.2 and TLS 1.3, several cipher suites, resumed sessions, and incomplete handshakes with `established:false` and `ssl_history:"C"`.
- Perimeter records add source-native variation: `fw-perimeter/cisco_asa.log` includes ASA connection and translation messages, while `snort-core/snort_alert.log` and `snort-perimeter/snort_alert.log` show multiple signatures, protocols, ports, and timestamps. The perimeter alerts include repeated external connection attempts to DMZ web services, while core alerts include DNS and P2P detections. These are consistent with the Zeek flows and are not independently proof of realism.

## Detailed Analysis

### Flow state, timing, and volume

The Zeek core sensor logged 12,416 connections and the DMZ sensor 9,954 over roughly six hours; the database sensor logged 467, with 281 connections to `10.10.4.10:3306`. The state mix includes completed sessions, unanswered attempts, resets, rejects, and other traffic. In the sampled records, unanswered `S0` entries have no response packets and no duration, as expected for connections without an observed reply. The large `S0` share in the DMZ view is consistent with the visible external scanning and failed connection attempts. These counts do not by themselves show an impossible or source-native-invalid state distribution.

### DNS and application protocols

The core DNS log has 3,132 records, all with matching connection UIDs. It includes internal SRV lookups such as `_ldap._tcp.meridianhcs.local`, external A lookups, reverse PTR queries, and NXDOMAIN/other negative responses. The DMZ DNS view has 1,123 records and the DB view 39; each likewise joins to its own conn log. A and AAAA queries dominate, while SRV/TXT/PTR and occasional errors provide a plausible long tail. HTTP logs are primarily CONNECT traffic to the proxy at `10.10.3.20:8080`, with ordinary GET/POST requests on ports 80/8080. Status codes include 200, redirects, 403/407, and some 5xx responses. TLS is diverse across TLS 1.2 and 1.3; failed handshakes lack negotiated version/cipher fields, which is compatible with their `established:false` state.

### Cross-sensor timing

Matching core/DMZ flows are not joined by Zeek UID; each sensor has its own UIDs, so I compared source/destination tuple, protocol, and nearest timestamp. The 5,134 matches produced an almost fixed −114 ms offset (mean −114.255 ms; standard deviation 1.90 ms). The narrow spread is the clearest synthetic indicator because it repeats across thousands of varied flows. It could also arise from consistently synchronized clocks plus stable capture-point delay, and the logs alone do not establish sensor topology or clock configuration. No timing conclusion here depends on an absent start or close outside the visible window.

Complete UID joins within each sensor are not treated as synthetic evidence by themselves. Likewise, missing pre-window starts or post-window closings alone are not synthetic; this review judges only relationships visible in the supplied interval.

### IDS and firewall observations

The Snort logs include alerts for DNS TLD queries, P2P, scans, ICMP, and other signatures. In the perimeter file, for example, repeated `ET SCAN Rapid HTTP/HTTPS Connection Attempts` alerts target `10.10.3.10:443` from `185.70.41.45`; Zeek DMZ also records external attempts to the web host. ASA records include built UDP connections and dynamic TCP translations. These observations provide plausible network context, although alert and firewall volume cannot establish that every connection was observed by every sensor.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | Zeek core and DMZ `conn.json` | 5,134 matching flow tuples | Cross-sensor timestamp differences cluster unusually tightly around −114.245 ms (99.9% within 5 ms), consistent with a fixed modeled delay. A stable clock/capture offset remains a possible alternative. |
| `weak_signal` | Zeek core, DMZ, and DB `conn.json` | Approximately six-hour common window | Similar window boundaries are compatible with an intentional collection period and carry little weight on their own. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek JSON fields, protocol/state values, port fields, and source-native firewall/IDS lines are coherent in sampled records.
- **Temporal patterns:** 6 — Per-record ordering and connection lifecycles look plausible; the nearly fixed cross-sensor offset is suspicious.
- **Cross-source correlation:** 9 — DNS/HTTP/SSL UIDs join to each sensor’s connection records, with SSL within the connection interval; complete joins alone are not a synthetic tell.
- **Behavioral realism:** 8 — Traffic has varied states, DNS types, TLS versions, application requests, and failed connections; visible volume distributions differ by sensor.
- **Environmental consistency:** 8 — Core, database, and DMZ traffic profiles differ plausibly, and perimeter alerts align with observed web-facing flows.

## Recommendations

- If this were synthetic, vary the per-flow core/DMZ observation-time difference more broadly, or model separate sensor clock drift and capture placement, so thousands of otherwise varied flows do not share an almost fixed 114 ms offset.
- If this were synthetic, document the intended sensor timing relationship so a stable clock skew or topology-specific delay can be distinguished from a generated timestamp fingerprint.
