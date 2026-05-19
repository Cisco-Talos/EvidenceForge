# Network Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 76

## Executive Summary

The Zeek data is internally coherent and has many realistic field-level details, but several network distributions look curated rather than naturally observed. The strongest synthetic indicators are overly tidy HTTP/TLS/application patterns, sparse-but-branded health checks, and repeated red-herring DNS/scan behaviors that correlate cleanly but feel staged.

## Evidence For Synthetic

- `zeek-dmz/http.json`: `ELB-HealthChecker/2.0` appears only in small paired bursts, not regular load-balancer cadence: `1710763563.919212`, `1710763564.663010`, then long gaps to `1710766254.790126`, `1710780059.452659`, and `1710783342.140272` / `1710783342.780811`. Real ELB checks are usually much more periodic.
- `zeek-dmz/http.json`: public `ehr-portal.meridianhcs.com` traffic is unusually template-like: 97 unique client IPs, many single-request visitors, and repeated exact response sizes such as `/` always `75951`, `/assets/main.css` always `33183`, `/assets/app.js` always `301` with `285`, `/login` as `304` with `0`.
- `zeek-dmz/ssl.json`: inbound EHR TLS shows many unrelated public clients using a narrow set of TLS versions/ciphers and a high number of `resumed=true` handshakes for apparently one-off clients, e.g. `125.127.247.218` at `1710763203.743811` and `1710763204.427437`, `90.63.207.77` repeatedly at `1710763796`-`1710763815`.
- `zeek-dmz/dns.json`: suspicious-looking domains resolve cleanly to major CDN/provider IPs with no follow-on connection visible, suggesting planted red herrings: `cdn-check-q1bofnly.top -> 23.45.9.168` at `1710764241.739442`, `cdn-check-byafugmv.top -> 23.45.190.52` at `1710764536.197044`, `update-29u7urfo.top -> 142.250.103.221` at `1710771486.911334`.
- `zeek-core/conn.json` and `zeek-dmz/conn.json`: the `1710771013`-`1710771018` scan burst from `10.10.3.10` to `10.10.2.10/20/30` hits HTTP, SSH, MySQL, SMB, and TLS in a compact, scripted-looking sequence with clean `S0`, `REJ`, and `SF` outcomes.

## Evidence For Real

- `zeek-dmz/ssl.json`, `zeek-dmz/files.json`, and `zeek-dmz/x509.json` correlate cleanly: SSL `cert_chain_fuids` link to certificate file records and matching x509 fingerprints, e.g. `CdjYWlFsXhz3oNJSWb` at `1710763438.962622` with `FmrXpuBFwabnGZwNKE` / `FiBJdFc0IputCwPxC`.
- DNS-to-connection timing is plausible for normal outbound activity, e.g. `app.growthkit.dev` resolves at `1710763437.464348` and TLS follows to `151.101.12.236` at `1710763438.533688`.
- Connection fields generally have plausible Zeek structure: `uid`, `history`, packet counts, byte counts, `conn_state`, and `local_orig/local_resp` are consistently populated.
- Proxy CONNECT behavior is credible at a high level: many internal clients connect to `10.10.3.20:8080`, then the proxy initiates external TLS sessions to domains such as `pypi.org`, `ctldl.windowsupdate.com`, `archive.ubuntu.com`, and `api.snapcraft.io`.

## Detailed Analysis

**TLS and certificates:** The certificate chains are one of the strongest realism points. The x509 records include plausible issuers, validity periods, key types, SANs, and repeated fingerprints for repeated server certificates. However, the inbound EHR traffic has a narrow and somewhat mechanical cipher distribution across globally scattered clients, with repeated session-resumption flags that feel overused for the visible six-hour slice.

**HTTP and proxy traffic:** The proxy dataset has realistic enterprise destinations and user agents, including Windows Update, Google Update, APT, Wget, curl, Python requests, and browser traffic. The synthetic signal is in the distribution: CONNECT responses and public web requests cluster around repeated exact sizes/statuses, while branded health checks are too sparse and irregular for their claimed agent.

**DNS behavior:** Internal DNS is mostly plausible: AD-style `.local` lookups go to `10.10.2.10`, while the proxy uses public resolvers. The suspicious `.top` domains look hand-inserted: randomized labels, clean `NOERROR`, CDN-looking answers, and no observed follow-on flows.

**Flow states and lateral movement:** The environment includes realistic internal protocols: Kerberos, SMB, LDAP, RDP, SSH, SQL, and proxy traffic. The compact scan from `10.10.3.10` around `2024-03-18T14:10:13Z` is coherent, but the sequencing and tidy outcomes make it look generated rather than naturally captured.

**Cross-source correlation:** Correlation is strong and mostly source-native. UIDs line up within each Zeek sensor, duplicated flows across core/dmz have independent UIDs as expected, and SSL/file/x509 linkage works. This supports realism, but the correlations are almost too complete for the behavioral patterns around them.

## Realism Score by Category

- **Field format accuracy:** 8 - Zeek JSON fields, UIDs, tuples, conn states, x509, and file records are mostly well formed.
- **Temporal patterns:** 5 - Some DNS/TLS sequencing is good, but health checks, scan bursts, and web-request cadence feel scripted.
- **Cross-source correlation:** 9 - Conn/http/ssl/files/x509 relationships are internally consistent.
- **Behavioral realism:** 6 - Enterprise proxy and lateral protocols are plausible, but public EHR traffic and suspicious DNS red herrings are too tidy.
- **Environmental consistency:** 7 - Topology and service mix are coherent, though some server/user-agent combinations and public traffic distributions feel curated.

## Recommendations

- Make health-check traffic periodic with realistic jitter and sustained cadence for the claimed checker.
- Add more natural web-session depth: headers, cache behavior, referrer chains, mixed asset outcomes, and repeat clients with less uniform response sizing.
- Reduce overuse of TLS resumption for one-off inbound clients and vary client TLS fingerprints more.
- For suspicious DNS, add realistic resolver paths and follow-on connections when appropriate, or allow NXDOMAIN/timeouts instead of clean CDN answers.
- Introduce more uneven background noise: retries, partial failures, idle gaps, browser preconnects, and less perfectly staged scan timing.
