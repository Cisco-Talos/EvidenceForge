# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 58  
**Synthetic-Confidence Score:** 36

## Executive Summary

The network data is broadly coherent: TCP states, DNS responses, TLS negotiation, proxy traffic, and perimeter scanning look plausible, and sampled Zeek connections align closely in time and tuple with endpoint FLOW records. I found no hard contradiction. The clearest synthetic-leaning observation is the concentrated, repeated pattern of inbound probes against one DMZ host; it remains plausible as internet background scanning, so it does not settle the verdict.

## Evidence For Synthetic

- [distribution_texture] In `zeek-dmz/conn.json`, six hours of inbound traffic to `10.10.3.10` include 1,634 external-origin connections. Several sources repeatedly probe the same host across service ports: for example, `185.220.88.13` sends 185 probes across ports 135, 139, 445, 3389, and 5985, mostly `S0`; `185.220.163.140` probes database and cache ports. The concentration and repeated port pattern could reflect constructed scan noise, though internet scanning is a realistic alternative.
- [environment_or_collection_plausibility] The firewall log has 21,606 lines, but only two explicit TCP deny entries in the quick review, while Zeek records hundreds of inbound `S0` attempts to exposed service ports on the web host. That difference may be explained by the observation point and firewall logging policy, but the supplied network logs do not establish the policy that would resolve it.

## Evidence For Real

- Zeek connection states are varied: `zeek-core/conn.json` has 9,878 `SF` and 1,936 `S0` records, plus `RSTO`, `RSTR`, `REJ`, and less common states. `zeek-dmz/conn.json` also contains a realistic mix, with 6,275 `SF` and 2,647 `S0`. Connection durations range from near-zero DNS transactions to multi-hour sessions.
- DNS contains a varied mix of `A`, `AAAA`, `PTR`, `SRV`, `TXT`, and other queries, with mostly `NOERROR` and some `NXDOMAIN`, `SERVFAIL`, and `REFUSED` responses. For example, the core DNS log includes ordinary host and directory lookups alongside failed lookups such as `printer01.meridianhcs.local` and `cdn-check-52me8yup.top`.
- TLS records show both TLS 1.2 and TLS 1.3, several plausible cipher suites, and a broad set of external services. `zeek-dmz/ssl.json` contains 1,855 TLS 1.3 and 772 TLS 1.2 records, with established and unsuccessful handshakes.
- Proxy traffic is internally consistent: `zeek-dmz/http.json` contains 1,947 `CONNECT` requests, and the corresponding connection records show clients connecting to `10.10.3.20:8080` while that host makes outbound connections. The sampled Zeek and eCAR FLOW tuples generally agree, with timestamps typically within fractions of a second.
- Perimeter scanning is not the only source of traffic. The data also includes ordinary mail flows, enterprise DNS and Kerberos, internal TLS, HTTP proxying, and application-to-database connections.

## Detailed Analysis

### Scope and timing

The network evidence includes Zeek core, DMZ, and database sensor logs, plus Snort alerts, Cisco ASA logs, and eCAR endpoint FLOW events. Zeek core and DMZ connection records cover approximately **2026-11-02 13:00–19:00 UTC**. The database sensor has 470 connection records over a similar window.

### Connection and protocol behavior

The core sensor records 12,194 connections. DNS (3,197), Kerberos (2,437), HTTP (2,070), LDAP (1,163), and SMB are prominent, fitting an enterprise network with directory, web, and file services. The DMZ sensor records 9,159 connections, dominated by TLS, HTTP, DNS, and proxy traffic. Both sensors record failed and reset connections in addition to completed sessions.

The database sensor shows 290 connections to port 3306 in its 470 records. The samples include web-server-to-database connections and database-host telemetry traffic; the excerpted records do not show a field-level contradiction.

### DNS, HTTP, and TLS

Core DNS responses include internal host records, reverse lookups, service discovery, external destinations, and some failures. I did not find a systematic ordering defect: DNS and connection records are often close in time, though cached names and concurrent activity prevent treating every connection as requiring a preceding query in the visible window.

The DMZ HTTP records are mostly `CONNECT`, with a smaller mix of `GET` and `POST`. Status codes include successful responses and ordinary failures such as `403`, `407`, `502`, `503`, and `504`. TLS traffic includes common contemporary TLS 1.3 suites as well as TLS 1.2, which is plausible for a mixed fleet.

### Sensor and endpoint correlation

I matched sampled Zeek connections against eCAR FLOW records using the five-tuple and protocol. Exact tuple matches were found for 11,527 core records, 8,464 DMZ records, and 448 database records. For those matches, eCAR and Zeek timestamps were generally close; the observed differences are consistent with distinct collection and event-reporting times. Sampled endpoint identities also fit the connection direction—for example, `MAIL-CLIN-01` reports an outbound DNS FLOW from `10.10.2.26`, matching a core Zeek DNS query from that address.

This is supporting evidence of coherent network telemetry. The close alignment itself is not treated as a synthetic indicator.

### Inbound scan traffic

The DMZ sensor records repeated internet-origin probes to `10.10.3.10`, including common web, file-sharing, remote-administration, and database ports. Many probes are `S0`, consistent with unanswered SYN attempts. Snort also raises scan and suspicious-DNS alerts. This pattern is security-relevant, but it is plausible for an internet-exposed web host and does not establish synthetic generation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | Zeek DMZ | Repeated external probes to one DMZ host across a recurring set of ports | The concentrated pattern could be constructed scan background, but also fits internet scanning. Weak evidence. |
| `environment_or_collection_plausibility` | ASA and Zeek DMZ | Many inbound `S0` probes versus two explicit TCP denies seen in the sampled ASA review | The relationship is unclear without firewall policy and sensor placement. Possible collection-policy difference; weak evidence. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled Zeek and eCAR records use coherent fields and plausible values.
- **Temporal patterns:** 7 — Durations and event timing vary; sampled endpoint FLOW timestamps are close to Zeek observations.
- **Cross-source correlation:** 8 — Sampled connection tuples correlate with eCAR, and HTTP proxy records align with observed connections.
- **Behavioral realism:** 7 — Enterprise DNS, proxy, TLS, directory, mail, and database patterns appear together; external scanning is plausible.
- **Environmental consistency:** 6 — The inbound scan pattern and its relationship to the sampled firewall denies remain underexplained.

## Recommendations

- If this were synthetic, vary the inbound scan sources, probe timing, and destination-port mix enough to avoid a repeated concentration on one DMZ host.
- If the ASA and Zeek records represent the same perimeter path, include representative firewall policy or logging context so the relationship between inbound `S0` traffic and explicit deny records can be assessed.
