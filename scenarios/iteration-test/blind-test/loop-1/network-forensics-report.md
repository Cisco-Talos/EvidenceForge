# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 96
**Synthetic-Confidence Score:** 78

## Executive Summary

The transport, proxy, DNS, and TLS records are generally coherent and convincingly formatted, but the DNS answers contain a strong fingerprint of manufactured cryptographic material: nine of twelve distinct advertised 2048-bit DKIM RSA public keys have trivially small prime factors. That repeated defect across multiple purported mail domains outweighs substantial evidence of realistic network modeling; a concentrated background TXT-query distribution provides a much weaker supporting signal.

## Evidence For Synthetic

- [distribution_texture] **Manufactured-looking RSA public keys in DNS TXT answers.** I decoded the twelve unique DKIM `p=` public keys, parsed their DER SubjectPublicKeyInfo/RSA modulus fields, and trial-divided the resulting integers by primes below 10,000. Nine moduli have tiny factors. For example, `zeek-core/dns.json:2239`, `2026-11-02T17:44:16.095754Z`, UID `CVaWDRJWqGIuDF9iD4`, advertises `mail._domainkey.meridianhcs.com` with a 2048-bit modulus divisible by **3, 17, and 23**. At line 2386, UID `CPNg8CGKJZHFA0Hjrz`, `selector1._domainkey.meridianhcs.com` has factors **3, 383, 577, and 929**. At line 2481, UID `CiP6P9XhYwlfFSnO9Bj`, `mta._domainkey.atlassian.net` has factors **7, 29, 73, and 521**. These are not credible results of normal RSA key generation. This finding depends on the answer bytes and integer arithmetic, not whether sanitized domain names correspond to real services.
- [weak_signal] **Background TXT lookups occupy an unusually localized interval across unrelated clients.** In `zeek-core/dns.json`, excluding queries under `westbridge-services.cloud`, there are 35 TXT queries across 19 origin IPs. Thirty-four occur between 17:41 and 18:04 UTC, with the remaining one at 18:54; none occur during the preceding approximately 4 hours 41 minutes, although A, AAAA, PTR, and SRV activity spans the six-hour window. The group mixes SPF, DMARC, DKIM, and verification requests from workstations and servers. A scheduled diagnostic or security task could explain this, so I assign it little independent weight.

## Evidence For Real

- The three sensor files contain **23,842 connection records**: core 12,801, DMZ 10,550, and DB 491. Their service distributions differ sensibly: the DB view has 273 `mysql` connections, while the core view has 2,525 `krb`, 1,128 `ldap`, and 455 `smb` connections. The DMZ view contains substantial external scan/failure traffic and proxy/TLS traffic.
- Connection outcomes are varied rather than uniformly successful. The DMZ view includes 7,407 `SF`, 2,554 `S0`, 128 `RSTO`, 69 `RSTR`, 33 `REJ`, and smaller partial/other state groups. The core view also contains substantial unsuccessful and partial traffic.
- DNS shows realistic negative answers and query diversity. Core includes 188 A/NXDOMAIN, 18 PTR/NXDOMAIN, SERVFAIL and REFUSED responses, empty successful AAAA answers, SRV, MX, NS, SOA, and TXT records. TTLs and response times vary; core DNS RTTs range from 21 microseconds to approximately 2.04 seconds.
- All inspected DNS, HTTP, SSL, SMTP, and SMB-file rows resolve to their same-sensor connection UIDs with matching endpoint tuples and timestamps inside the connection interval. HTTP request/response bodies do not exceed the corresponding connection payload totals. This supports coherent construction; completeness itself is not a synthetic indicator.
- TLS avoids a common passive-observation error: **none of the TLS 1.3 SSL records reference extracted certificate chains**. DMZ has 2,072 TLS 1.3 records, while visible TLS 1.2 full handshakes carry certificate/file evidence and resumed handshakes use abbreviated histories.
- All referenced TLS chain FUIDs resolve to both files and X.509 records; certificate SHA-1 fingerprints agree with file hashes. Across 213 distinct certificate fingerprints, repeated appearances have consistent certificate properties. No referenced certificate was outside its recorded validity interval at observation time.
- Proxy logs distinguish CONNECT control-message bytes from tunnel bytes, with explicit fields such as `byte_scope=connect-control-message`, `tunnel_cs_bytes`, and `tunnel_sc_bytes`. Zeek's CONNECT records report zero response body rather than representing the entire encrypted tunnel as an HTTP response body.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and assigned briefing. The primary analysis covered every JSON record in the three Zeek sensor directories, with additional inspection of proxy, ASA firewall, and IDS logs. The connection window is approximately **2026-11-02 13:00–19:00 UTC**. Counts below are observations per sensor; overlapping observations are not distinct end-to-end connections.

The network-source totals are 23,842 connections, 4,420 DNS rows, 5,543 HTTP rows, and 3,567 SSL rows. This is sufficient to assess structural and protocol consistency, but the six-hour daytime window does not support conclusions about weekend behavior, overnight coverage, or complete session lifecycles.

### DKIM public-key examination

The keys look superficially convincing: each distinct key is 392 base64 characters decoding to a 294-byte DER structure, has a 2048-bit positive modulus, and advertises exponent 65537. I concatenated the TXT string fragments before decoding, removing the logged `TXT <length>` delimiters rather than treating those delimiters as key material.

The following are integer-divisibility witnesses, not probabilistic judgments about textual appearance:

| Core DNS line | Timestamp UTC | Query | Small prime factors of RSA modulus |
|---|---|---|---|
| 2239 | 17:44:16.095754 | `mail._domainkey.meridianhcs.com` | 3, 17, 23 |
| 2265 | 17:45:39.173184 | `s1._domainkey.atlassian.net` | 3, 617 |
| 2301 | 17:47:19.646894 | `selector1._domainkey.duo.com` | 173, 953 |
| 2386 | 17:50:58.236426 | `selector1._domainkey.meridianhcs.com` | 3, 383, 577, 929 |
| 2467 | 17:54:03.950306 | `k1._domainkey.github.com` | 5, 11 |
| 2481 | 17:54:44.782951 | `mta._domainkey.atlassian.net` | 7, 29, 73, 521 |
| 2561 | 17:58:41.905323 | `selector2._domainkey.okta.com` | 5, 11 |
| 2572 | 17:59:07.306574 | `selector1._domainkey.microsoft.com` | 7 |
| 2574 | 17:59:20.223369 | `selector1._domainkey.sendgrid.net` | 17 |

For each listed prime `p`, the decoded modulus satisfies `n % p == 0`. Several moduli have three or four distinct tiny factors. Normal cryptographic RSA key generation does not produce these values. Mathematically, a modulus can contain small factors, so this is not an impossible ASN.1 encoding; the defect is the repeated, implausible cryptographic content. Nine of twelve unique keys displaying it is a strong distribution fingerprint consistent with constructing random odd modulus-shaped bytes instead of real RSA public keys.

The same `selector1._domainkey.meridianhcs.com` key appears in the DMZ view at `zeek-dmz/dns.json`, UID `CVIG4tXoZyiPtPjzCh`, timestamp `17:50:58.123682Z`, so the result is not caused by accidentally mixing unrelated fields during parsing. The SHA-256 digest of its decoded SPKI begins `7cdfd058fc4239df` in both observations.

An organization could publish a broken key, and a sanitization process could replace public-key contents as well as names. The briefing specifies potentially sanitized domains, not replacement cryptographic material. Those alternatives keep verdict confidence below certainty, but nine independent bad keys across this small set is substantially less plausible than synthetic key construction.

### Transport, byte accounting, and protocol timing

I checked UID existence, four-tuple equality, and whether protocol timestamps fell inside the corresponding connection intervals. DNS, HTTP, SSL, SMTP, and SMB-file checks produced no tuple or interval contradictions. There is one SMB-mapping UID without a same-sensor connection row; a slice or source-specific collection boundary can explain that isolated absence, and I did not score it.

A naive check initially identifies 172 TCP observations where `orig_ip_bytes` or `resp_ip_bytes` is less than logical payload plus a 40-byte-per-packet minimum. **Every one is explained by the record's `missed_bytes` allowance** when treated conservatively across both directions. None remains a demonstrated byte-accounting contradiction. I therefore do not count these as synthetic evidence.

Successful TCP flows have at least two packets in each direction. Protocol evidence stays within transport lifetime, including SSL handshake offsets ranging from milliseconds to approximately 0.65 seconds. SSH and RDP have substantially longer intervals than ordinary short web/database exchanges; core RDP flows have successful transport state. I found no established TLS row attached to an `S0` or `REJ` connection.

### DNS, TLS, proxy, and collection texture

DNS behavior is richer than a simple A-record lookup stream. Empty successful AAAA answers, negative PTRs, varied TTLs, and SRV discovery fit the mixed internal environment. The concentrated background TXT interval is unusual but remains explainable by a task active during part of the window; suspicious high-entropy TXT queries themselves are not authenticity defects.

TLS versions and cipher families are internally compatible in the checks performed. Certificate key types match inspected ECDSA cipher usage, TLS 1.3 does not expose unencrypted certificate chains, and certificate identity is stable across observations. The cryptographic-content defect identified above concerns DNS DKIM keys, not all certificate records.

The proxy has 4,732 access rows, and the firewall has 25,938 records with build/teardown, NAT translation, denial, and ICMP families. ASA teardown duration can reflect connection-table lifetime rather than Zeek's packet interval, so differing UDP timeout semantics are not inherently contradictory. IDS `.cloud` DNS alerts matched corresponding DNS tuples and `.cloud` query names in all 19 checked cases: 15 core and four perimeter alerts.

Core CONNECT durations cluster noticeably near one second: 996 of 2,469 CONNECT transactions reference connection durations between 0.9 and 1.2 seconds. The DMZ view shows the same general feature in overlapping traffic. A proxy timeout/application workload could produce a mode like this; without an independent contradiction or a known traffic baseline, I do not score that observation as a defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `distribution_texture` | Zeek DNS TXT / DKIM key content | Nine of twelve distinct 2048-bit public keys; multiple client hosts and purported mail domains | Dominant evidence: repeated trivially factorable modulus-shaped values are inconsistent with normal RSA key generation and strongly suggest constructed answer content. |
| `weak_signal` | Zeek DNS query timing and host distribution | 34 of 35 background TXT queries across 19 hosts occur in roughly 23 minutes, despite a six-hour observation window | Small additional weight; a scheduled diagnostic task remains a plausible explanation. |

## Realism Score by Category

- **Field format accuracy:** 9 — Native JSON shapes, TLS histories, hash references, and DER structures are convincing; syntactic correctness masks bad DKIM cryptographic content.
- **Temporal patterns:** 8 — Protocol/transport ordering is coherent and connection outcomes vary; the background TXT interval is unusually localized.
- **Cross-source correlation:** 9 — Checked tuples, UIDs, certificate references, HTTP byte bounds, and IDS DNS claims align without demonstrated contradictions.
- **Behavioral realism:** 7 — Service-specific traffic and failed connections are plausible; unrelated hosts' localized mail-policy queries are a modest concern.
- **Environmental consistency:** 6 — Network roles are generally coherent, but the prevalence of trivially factorable advertised DKIM keys is highly implausible for ordinary production mail infrastructure.

## Recommendations

- If this were synthetic, populate DKIM answers with actual cryptographically generated public keys, retained consistently for each selector/domain. Validate decoded SPKI structure, modulus size, exponent, and the key-generation method; formatting random bytes as an RSA modulus is insufficient.
- If this were synthetic, tie ordinary SPF, DMARC, DKIM, and verification lookups to the hosts and scheduled activities that perform them. For this dataset, the 19-host background TXT burst should correspond to an explicit operational reason or be distributed according to those clients' actual roles and task timing.
- Preserve the demonstrated transport/protocol timing, missed-byte accounting, TLS 1.3 visibility limits, and CONNECT byte-scope distinctions when correcting the DNS material.
