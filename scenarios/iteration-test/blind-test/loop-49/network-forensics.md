# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 75
**Synthetic-Confidence Score:** 56

## Executive Summary

The network data is convincing at the connection, DNS, proxy and TLS visibility layers, with varied failures and substantial source-native consistency. I lean synthetic because a broad cohort of externally presented certificates combines post-March-2026 validity starts with lifetimes exceeding the applicable public TLS certificate limit; this is a material environmental inconsistency, although timestamp transformation or private trust arrangements could explain it. The score remains in the mixed band because I found no demonstrated impossible same-identity protocol ordering or broken UID/tuple relationship in the tested network records.

## Evidence For Synthetic

- [environment_or_collection_plausibility] **Public-CA certificate validity follows an outdated maximum across numerous destinations.** In `zeek-dmz/x509.json`, 71 distinct leaf fingerprints, represented by 263 rows, have `certificate.not_valid_before >= 2026-03-15T00:00:00Z` and validity greater than 200 days, with issuers named as public CAs. These constitute 71 of 189 distinct externally issued leaf certificates in this sensor's records. Line 1 describes `CN=registry.npmjs.org`, issuer `DigiCert Global G2 TLS RSA SHA256 2020 CA1`, valid from `2026-07-22T21:50:11Z` through `2027-08-21T21:50:11Z`: **395 days**. Line 12 describes an Amazon-issued leaf valid `2026-04-11T11:43:26Z`–`2027-04-23T11:43:26Z`: **377 days**. Line 20 describes another Amazon-issued leaf valid `2026-04-15T18:26:53Z`–`2027-05-07T18:26:53Z`: **387 days**. Public subscriber certificates issued from March 15, 2026 are limited to 200 days under [CA/Browser Forum TLS Baseline Requirements §6.3.2](https://cabforum.org/working-groups/server/baseline-requirements/requirements/). This is a certificate-policy/environment issue, not a cryptographic impossibility: issuer names alone do not establish actual public trust, and the logs do not supply certificate DER or issuance records. The repeated cohort is more persuasive than any single anomalous certificate.

## Evidence For Real

- The three sensor views contain plausible service specialization: core has 3,193 DNS-classified and 2,479 Kerberos-classified connections; database has 260 MySQL-classified connections out of 433; DMZ has 2,847 SSL-classified and 2,419 HTTP-classified connections. Proxy `CONNECT` explains much of the visible cleartext HTTP rather than implying implausibly widespread unencrypted browsing.
- DNS includes success and failure variation and a meaningful question-type mix. Core's 3,188 DNS rows include 2,333 A, 279 AAAA, 154 PTR, 105 SRV, 300 TXT, eight MX, six NS and three SOA questions; response outcomes include 227 NXDOMAIN, 14 SERVFAIL and four REFUSED. There are no address-family mismatches among parsed A/AAAA IP answers.
- TLS 1.3 rows consistently avoid exposed certificate chains: 199 core and 1,808 DMZ TLS 1.3 records have no `cert_chain_fuids`. TLS 1.2 records can reference observable chains. This respects the passive visibility distinction described in the [Zeek TLS log documentation](https://docs.zeek.org/en/current/reference/logs/ssl.html).
- TCP is not uniformly successful. Core includes 150 RSTO, 116 RSTR and 28 REJ records, in addition to unsuccessful attempts and partial observations. DMZ includes 129 RSTO, 70 RSTR and 32 REJ. Retransmission and content-gap histories occur, with nonzero `missed_bytes` on the gap-bearing records examined quantitatively.
- All tested DNS, HTTP, SSL, SMTP and SMB-file UID references resolve to their own sensor's connection records with matching endpoint tuples. Their protocol timestamps fall within the corresponding connection intervals under the tolerance described below. This supports consistency; completeness is not itself an authenticity discriminator.

## Detailed Analysis

### Input provenance and scope

I read the complete supplied neutral briefing `/private/tmp/log-study-pdlkpnp9/network-prompt.md` and inventoried only `/private/tmp/log-study-pdlkpnp9/data`. I parsed all supplied `zeek-core`, `zeek-db` and `zeek-dmz` JSON files, including connection, DNS, HTTP, SSL, certificate, file and auxiliary protocol tables. I also counted and sampled the supplied perimeter ASA log, proxy access log, and two Snort alert logs. I did not read endpoint telemetry contents, scenarios, project source, project memory files, prior assessments or another reviewer's report.

Public references were restricted to official `docs.zeek.org` and `cabforum.org` domains through actual search-domain filters or direct URLs. Python 3 JSON/statistical reads were confined to supplied data; log text and embedded commands were treated as inert. Inherited operating instructions identify the surrounding software workspace; that limits experimental blinding but was not used as origin evidence or in scoring. No project-material read was performed for this review.

Line citations are physical one-based JSON-lines positions relative to the supplied data directory. Network `ts` values are interpreted as Unix UTC seconds. The visible connection window is November 2, 2026, approximately 13:00–19:00 UTC. This is a six-hour slice; overnight traffic, daily totals and out-of-window lifecycle completeness cannot be assessed.

### Volumes, connection behavior and service mix

There are 12,314 core, 9,401 DMZ and 433 database connection rows. These are sensor observations, not necessarily distinct network connections across sensors. Core has 6,715 TCP, 5,198 UDP and 401 ICMP rows; DMZ has 7,960 TCP, 1,137 UDP and 304 ICMP; database has 357 TCP, 58 UDP and 18 ICMP.

Core's hourly connection counts are 1,849, 3,233, 1,757, 1,698, 2,068 and 1,709 from 13 through 18 UTC. DMZ's corresponding counts are 1,315, 2,713, 1,359, 1,465, 1,295 and 1,254. This is not an evenly tiled fixed-rate workload. The peak alone does not identify authenticity or establish maliciousness.

The packet-accounting checks did not establish a contradiction. Some TCP rows have sequence-derived payload totals exceeding captured IP totals after minimum header allowance; these rows have content gaps, and the aggregate deficit is covered by their `missed_bytes`. Zeek documents TCP payload accounting as sequence-derived and `missed_bytes` as content-gap accounting in its [connection field reference](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html). I therefore did not score those apparent discrepancies.

### Protocol and file relationships

For each sensor, I joined DNS, HTTP, SSL, SMTP and SMB-file rows to `conn.json` by UID and compared the four endpoint fields. There were no missing UID references or tuple mismatches in these tested families. There were no protocol starts earlier than their connection starts by more than 1 ms, or later than connection end by more than 500 ms. The latter is a screening tolerance, not a claim that a half-second protocol overrun is always legitimate.

File rows were checked separately: none started more than 1 ms before their connection or more than 1 ms after its recorded end. `tx_hosts` agreed with the connection direction selected by `is_orig`. Established TLS rows did not join to S0/REJ transport states.

HTTP 304 responses correctly have zero response bodies in all 14 core and 22 DMZ observations. Successful CONNECT control responses have zero bodies; unsuccessful CONNECT responses can have bodies. Multiple transaction depths occur rather than every HTTP connection being forced to one request.

A concrete proxy example appears in `PROXY-01.meridianhcs.local/proxy_access.log:1-2`: at `13:01:07 +0000`, client `10.10.1.22:40446` performs a CONNECT followed by an inspected HTTPS request associated with tunnel `PT-a5e41cdf86225d43`. `zeek-core/http.json:1` and `zeek-dmz/http.json:1` show the same client tuple and CONNECT target. The proxy explicitly distinguishes CONNECT control bytes from tunnel totals; these scopes should not be compared as if they were identical payload measures.

### TLS and certificate issue

The DMZ TLS mix comprises 1,808 TLS 1.3 and 913 TLS 1.2 rows, with four additional rows lacking a negotiated version. Core comprises 199 TLS 1.3, 201 TLS 1.2 and three without a version. The database view has 14 TLS 1.2 rows. Observed modern AEAD ciphers and some CBC use are plausible for the mixed services visible here; an older cipher alone is not a synthetic indicator.

Certificate fingerprints retain consistent certificate attributes across repetitions. Referenced chain issuer/subject links and leaf key types versus ECDSA cipher selection passed the checks. Observed connections fall within the presented leaf validity intervals. OCSP rows reference separate OCSP-response file identities, not reused certificate identities.

The substantive issue is the validity-period cohort. For reproducibility, deduplicate `zeek-dmz/x509.json` by `fingerprint`, exclude `basic_constraints.ca=true` and the explicitly enterprise-issued leaves, then select starts on/after March 15, 2026 with `not_valid_after - not_valid_before > 17,280,000` seconds. This returns 71 distinct leaves; counting matching physical rows returns 263.

The registry example is tied to actual presented TLS evidence rather than an isolated certificate inventory: `zeek-dmz/ssl.json:22`, UID `C979hFgXBbWhF8Fhcm`, has `server_name=registry.npmjs.org`, `version=TLSv12`, `established=true`, and first chain FUID `FSkEwxHIjkgI3rapTF`, which resolves to `x509.json:1`. Its 395-day lifetime is directly computed from `1818885011 - 1784757011 = 34,128,000` seconds.

The inference assumes ordinary issuance near the certificate's validity start and the public issuer identities represented in the records. Actual issuance timestamps and trust verification are unavailable. A privacy transformation that moved dates across the policy boundary could preserve a formerly valid lifetime while creating this defect in a real-derived dataset. I therefore treat this as a broad plausibility tell, not proof of impossible TLS or an 81–100-level contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| environment_or_collection_plausibility | Zeek X.509 linked to TLS 1.2 | 71 distinct externally issued leaf fingerprints / 263 DMZ X.509 rows | Repeated long-lived certificates with post-policy-boundary starts support a synthetic verdict; uncertainty about actual issuance, trust and date transformation keeps the score in the mixed band. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed network records and tested protocol fields are coherent; no demonstrated native schema contradiction.
- **Temporal patterns:** 9 — Varied hourly activity and valid tested within-flow ordering; the short slice limits daily assessment.
- **Cross-source correlation:** 9 — Tested UID, tuple, file direction and TLS/certificate relationships hold.
- **Behavioral realism:** 8 — Credible service mix, proxy use, DNS diversity and unsuccessful traffic.
- **Environmental consistency:** 6 — The extensive public-CA validity-period cohort conflicts with the apparent 2026 issuance context.

## Recommendations

- If this were synthetic, make public leaf validity periods depend on the modeled issuance date and CA policy. For issuance from March 15, 2026 to March 14, 2027, keep validity within 200 days; retain separate rules for enterprise certificates and CA certificates.
- If certificate dates were transformed during privacy sanitization, document that transformation or preserve its policy-era relationship. This would let reviewers distinguish a sanitation artifact from fabricated certificate metadata.
- Preserve the demonstrated TLS 1.3 certificate visibility limits, explicit proxy byte scopes, gap accounting and same-sensor protocol relationships while correcting the certificate cohort. These checks currently pass and do not warrant a redesign based solely on collection completeness.
