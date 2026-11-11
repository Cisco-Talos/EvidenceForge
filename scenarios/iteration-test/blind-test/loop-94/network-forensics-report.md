# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 30

## Executive Summary

The examined network evidence is mostly production-like, with plausible connection states, varied DNS outcomes, proxy traffic, and coherent exact protocol pivots. No demonstrated hard contradiction emerged from 20 individually examined records; the main reservation is a small, concentrated legacy TLS population, which is readily explainable by service policy and cannot establish origin.

## Evidence For Synthetic

- [weak_signal] `zeek-db/ssl.json` contains 19 TLS sessions, all TLSv12; 11/19 use `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` and 8/19 use `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. This limited two-suite population is a possible low-entropy texture signal, but legacy internal service configurations can produce it. It receives little weight and is neither an invalid cipher nor a demonstrated protocol defect.
- No hard contradiction, required-companion gap, or source-native format defect was demonstrated in the bounded sample. High cross-source matching, compact activity, domain naming, filesystem timestamps, and absent optional telemetry were not treated as synthetic indicators.

## Evidence For Real

- `zeek-core/conn.json` spans epoch 1793624400.006178–1793645984.793219, approximately 2026-11-02 13:00–19:00 UTC. Its 12,943 connections include SF 10,406, S0 1,768, OTH 442, RSTO 162, RSTR 101, REJ 29, S3 15, S2 11, and S1 9. Core, DMZ, and database sensors have different service and state distributions rather than one identical mixture.
- DNS includes multiple ordinary query families and failures: core has A 2,398, TXT 307, AAAA 274, PTR 163, SRV 100, NS 16, SOA 4, and MX 3, with 222 NXDOMAIN, 14 SERVFAIL, and 4 REFUSED among 3,265 rows. TTLs include fixed authoritative values and smaller residual values.
- Exact HTTP/connection and TLS/connection/certificate pivots preserve identity, meaningful temporal order, and endpoint names. Their alignment supports internally coherent observations without establishing whether their origin is real.
- Core HTTP is predominantly proxy CONNECT (2,318/2,520 rows), so its HTTP volume does not imply predominantly cleartext web browsing. Visible responses include 407, 403, 502, 503, and 504 alongside success and cache/redirect responses.
- DHCP renewal-shaped observations and SMTP STARTTLS-shaped observations provide plausible infrastructure context without requiring unobserved pre-window starts.

## Detailed Analysis

### Scope and method

I read only the assigned data directory and briefing. I individually examined 20 unique JSON records: two each from core conn, DNS, HTTP, SSL, X.509, DHCP, SMTP, and SMB files (16 records), plus two joined connection records and two joined certificates (4 records). Initial representative rows were the first and middle row of each selected file. Aggregate counts across the three Zeek sensors supply denominators and service context; this was not an exhaustive per-record authenticity or intrusion audit. I did not inspect endpoint logs, scenario material, evaluators, other reports, code, packet captures, or embedded URLs.

### Exact pivot 1: HTTP CONNECT to TCP

`zeek-core/http.json` UID `CCNiAm1f7JPR2ix29e`, ts `1793624408.815497`, is `10.10.1.41:62106 -> 10.10.3.20:8080`, CONNECT `preview.redd.it:443`, HTTP/1.1, response `200 Connection Established`, zero HTTP request/response bodies. The exact UID in `zeek-core/conn.json` has the identical tuple, ts `1793624408.687071`, duration `2.967407`, service `http`, state `SF`, history `ShADadfF`, 2,065 originator bytes and 21,059 responder bytes.

The CONNECT timestamp follows TCP open by 128.426 ms and lies inside the transport interval. Connection bytes exceeding CONNECT body lengths are compatible with tunnel traffic; zero CONNECT body lengths do not contradict the connection counters. This join does not independently establish the downstream destination connection or prove tunnel decryption.

### Exact pivot 2: TLS to TCP and certificate chain

`zeek-core/ssl.json` UID `CfXsGkkuG9lcJw887K`, ts `1793635200.230940`, is `10.10.1.21:42707 -> 10.10.2.21:443`, TLSv12 with `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `resumed=false`, `established=true`, SNI `FILE-LNX-01.meridianhcs.local`. Its exact conn UID has the identical tuple, ts `1793635200.175663`, duration `14.185937`, SF, history `ShADadFf`, 762/4,082 payload bytes and 4/10 packets. The TLS row follows connection open by 55.277 ms and lies within the flow.

The referenced certificate FUID `FQKBEGjxMFg4aE9tahU` resolves in `zeek-core/x509.json` at `1793635200.238519` to leaf subject `CN=FILE-LNX-01.meridianhcs.local`, matching SAN `file-lnx-01.meridianhcs.local`, RSA 2048, SHA256-with-RSA, valid from `1762484647` through `1822619047`. The second FUID `FAg1hiFlqkGBwA3VphH`, ts `1793635200.246587`, resolves to a CA certificate whose subject exactly matches the leaf issuer: `CN=Meridianhcs Enterprise Issuing CA, O=Meridianhcs, C=US`; its validity interval also covers observation time. This is a coherent chain representation; JSON metadata alone cannot verify its cryptographic signatures.

### DNS, infrastructure, and source interpretation

The first core DNS row, UID `ClnAf4xMznbwm13HlN`, ts `1793624400.006178`, queries `DC-01.meridianhcs.local` from `10.10.2.20:58104` to `10.10.2.11:53`, A/NOERROR, answer `10.10.2.10`, TTL 300, RTT 0.469 ms. The separately sampled conn row with the same UID and tuple has duration 0.469 ms, one UDP packet each way, and 41/57 payload bytes versus 69/85 IP bytes. A domain controller answering another controller's address is ordinary DNS behavior. A middle DNS row resolves DC-02 through DC-01 with a 1.149 ms RTT, showing another ordinary internal exchange. DNS-to-application resolution was not independently pivoted, so I make no claim that every application connection has a preceding lookup; caching also prevents such a universal requirement.

The sampled DHCP rows contain REQUEST/ACK, assigned addresses matching clients, lease times 7,200 and 14,400 seconds, and transaction durations 0.488278 and 0.114502 seconds. These are compatible with renewals in a slice of time. Sampled SMTP rows on port 587 set `tls=true`, have 220 TLS transition replies, and empty mail envelopes/message fields, compatible with visibility ending at STARTTLS. Sampled SMB rows show a SYSVOL file open and a ClinicalResearch file write; neither alone establishes maliciousness or authenticity.

### Distribution context and limits

There are 12,943 core, 10,263 DMZ, and 438 database connection rows. Database traffic is chiefly port 3306 (255/438), whereas core contains DNS 3,272, Kerberos 2,607, proxy 8080 2,406, LDAP 1,136, and SMB 723. DMZ contains 3,680 port-443 and 2,634 port-8080 connections. These ratios are compatible with different observation paths; sensor names alone do not establish exact tap placement, and rows across sensors were not assumed independent.

Among TCP connections, core has 7,156, DMZ 8,739, and database 369. S0 rows number 1,492/2,494/13 respectively; none has responder packets. SF rows number 5,306/6,002/274; none has zero responder packets. Aggregate payload/IP-byte minimum checks found no IP-byte counters below payload plus 20 bytes per packet among TCP/UDP rows. These limited invariants are supportive, not proof of packet-level fidelity.

Core hourly counts from 13 through 18 UTC are 1,829, 3,443, 1,898, 1,769, 2,176, and 1,828; DMZ counts are 1,515, 2,916, 1,496, 1,534, 1,401, and 1,401. This is not perfectly flat, but a six-hour window cannot establish overnight, weekly, or business-hours realism. Connection median/95th-percentile durations are approximately 0.0317/6.30 s core, 1.016/6.61 s DMZ, and 1.399/18.91 s database. Mixed DNS, failed TCP, and application traffic make these aggregate durations poor standalone authenticity indicators.

TLS versions vary by sensor: core 214 TLSv13 and 199 TLSv12; DMZ 2,125 TLSv13, 909 TLSv12, and 4 without a version; database 19 TLSv12. Core and DMZ include AES-GCM and ChaCha20 suites and resumed/non-resumed sessions. The small database legacy-cipher concentration is the only scored reservation and can be explained by a narrow internal-service population. I did not verify unfamiliar native fields against documentation because no allegation depended on uncertain source semantics.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | Zeek TLS | Database sensor: 19 rows, 11 CBC and 8 AES-GCM, all TLSv12 | Small legacy-policy concentration; low weight because a real service policy can explain it. |

The score of 30 describes mostly realistic observations with a limited reservation. The inconclusive verdict reflects the inability of this bounded review to distinguish a coherent simulation from a well-collected production slice, rather than a claim of demonstrated synthetic defects.

## Realism Score by Category

- **Field format accuracy:** 9 — Examined JSON fields and packet/byte relationships are plausible; no demonstrated schema defect.
- **Temporal patterns:** 8 — Two exact protocol pivots have plausible ordering and offsets; the six-hour window limits broader cadence claims.
- **Cross-source correlation:** 9 — Exact UID and FUID relationships preserve tuples, names, and certificate-chain identity in the sampled pivots.
- **Behavioral realism:** 8 — Proxy CONNECT, DNS error/query diversity, STARTTLS visibility, and DHCP renewal shapes are plausible.
- **Environmental consistency:** 8 — Different sensor service mixtures are explainable; database TLS policy remains a low-weight uncertainty.

## Recommendations

- If this were synthetic, retain service-specific TLS capabilities behind the observed database sensor rather than expanding cipher diversity arbitrarily. The concrete 19-row legacy population should reflect actual modeled service policy; it does not warrant forced modern TLS on every internal service.
- No other specific change is justified by this bounded network sample. Additional night/weekend data or packet-level validation could increase assessment confidence, but their absence here is not a realism defect.
