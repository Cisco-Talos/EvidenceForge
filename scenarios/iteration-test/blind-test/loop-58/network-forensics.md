# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 48

## Executive Summary

The network data is largely coherent at the flow, protocol, byte-accounting and certificate-reference levels, with a credible explicit-proxy topology and a varied failure distribution. The strongest concern is repeated millisecond-separated ICMP echo exchanges assigned separate Zeek connection UIDs despite sharing the native ICMP connection key; that needs a nonstandard collection explanation and raises the score into the mixed range, but does not establish synthetic origin on its own.

## Evidence For Synthetic

- [contract_gap] **ICMP connection segmentation differs from ordinary Zeek connection ownership.** In `zeek-dmz/conn.json:2444` and `:2445`, echo traffic from `10.10.3.10` to `10.10.2.11`, type/counterpart fields `8/0`, receives UIDs `Cwbvfrms6WztDYB2X7` and `COHK9exZjuqm2jQHhq` at epochs `1793630400.210769` and `1793630400.243621`: only 32.852 ms apart. Both rows represent one request and one reply. Another pair, `zeek-core/conn.json:1355` and `:1356`, has the same key `10.10.2.11 → 10.10.3.20, 8/0`, separate UIDs, and 83.518 ms separation. Across each file independently, 22 adjacent same-key ICMP pairs in core and 11 in DMZ start less than 60 seconds apart. Standard Zeek keys ICMP on addresses, type and counterpart type, rather than echo identifier, and uses a one-minute default inactivity timeout. This looks like per-occurrence rendering instead of native connection aggregation. A custom removal policy, merged workers, or separately processed captures could explain it; the supplied records do not establish which applies. [Upstream ICMP key construction](https://raw.githubusercontent.com/zeek/zeek/master/src/packet_analysis/protocol/icmp/ICMP.cc), [documented timeout](https://docs.zeek.org/en/v9.0.1/scripts/base/init-bare.zeek.html#id-icmp_inactivity_timeout).
- [weak_signal] **The background TXT-query cohort has a sharply bounded collection profile.** Core has 362 TXT queries; 326 originate from `10.10.2.30`, including the obvious high-volume `westbridge-services.cloud` family. The remaining sources contribute small SPF/DMARC/DKIM-like cohorts beginning at `zeek-core/dns.json:2157`, `1793641298.191437` (17:41:38 UTC), with `10.10.4.10` querying `atlassian.net`. DB's three TXT rows are all between 17:41:38 and 17:54:59 (`zeek-db/dns.json:27`, `:29`, `:30`); DMZ's four are between 17:42:30 and 18:03:45 (`zeek-dmz/dns.json:689`, `:711`, `:730`, `:743`). Coordinated testing, an application rollout or a scheduled mail-domain check could explain this. I give this only a small contribution: the concern is the abruptly introduced multi-host query-family distribution, not the suspicious activity's timing or narratability.

## Evidence For Real

- All 11,950 DNS, HTTP and TLS records have a matching connection UID in their own sensor file, and their protocol timestamps fall within that connection's visible interval to a 1 ms comparison tolerance. The three sensors use different UIDs for independently observed traffic, rather than treating a UID as a universal network identifier. Completeness itself is neutral; the useful evidence is the absence of contradictory tuple/time relationships.
- The first proxy transaction is causally and volumetrically plausible. `zeek-dmz/conn.json:1` records `10.10.1.32:57530 → 10.10.3.20:8080`; `http.json:1` records `CONNECT clients6.google.com:443`. `conn.json:2` and `ssl.json:1` describe the proxy's separate egress `10.10.3.20:34135 → 142.250.190.110:443`. The proxy log's first line explicitly separates CONNECT control bytes from tunnel bytes; the latter, 4,274/34,835, match the egress connection's payload counters.
- DNS includes A, AAAA, PTR, SRV, TXT, MX, NS and SOA rather than a single generic query shape. Core has 210 NXDOMAIN, 19 SERVFAIL and three REFUSED responses. Internal AAAA NODATA responses are represented without fabricated address answers, for example `zeek-core/dns.json:20`.
- TLS has full, resumed and failed handshakes, and distinguishes passive TLS 1.3 visibility from TLS 1.2 certificate visibility. Core's final TLS rows (`ssl.json:315-316`) have TLS 1.3 history `Cs` and no plaintext certificate chain. No TLS 1.3 record in any sensor contains a certificate chain.
- TCP states include closed sessions, unanswered SYNs, refusals, resets and partial closes. Among core's 12,382 connections are 1,741 S0, 171 RSTO, 106 RSTR and 45 REJ rows. These are not all stamped with a successful application transaction.
- Packet-loss artifacts are internally reconciled. For example, `zeek-core/conn.json:130` reports responder content loss with `history=ShADadfFg` and `missed_bytes=15`; its HTTP body is 1,598 seen bytes (`http.json:21`), while the extracted file has 1,609 total, 1,598 seen and 11 missing bytes (`files.json:11`). The file/body difference is accounted for by missing content, rather than being an unexplained contradiction.

## Detailed Analysis

### Scope, provenance and method

I read the supplied neutral network briefing and files under `/private/tmp/log-study-mlpr3vwu/data`, plus official Zeek documentation and upstream Zeek source to verify protocol-field interpretation. I did not read project code, scenarios, TODO/worklogs, prior assessments or other reviewers' material. Inherited generic operating instructions were treated as an environment limitation and not as evidence of origin. Parsing used system `python3` with `/private/tmp` as its explicit working directory. File modification times and public-domain/IP mappings were not used.

I parsed every record in the three Zeek directories and inspected selected firewall, proxy, IDS and endpoint rows for observation-path context. File/line citations below are one-based and relative to the supplied data directory. I did not assume full packet capture or an unmodified default Zeek configuration.

| Sensor | Connections | DNS | HTTP | TLS | X.509 |
|---|---:|---:|---:|---:|---:|
| zeek-core | 12,382 | 3,180 | 2,223 | 316 | 197 |
| zeek-dmz | 9,629 | 980 | 2,479 | 2,709 | 1,088 |
| zeek-db | 498 | 36 | 11 | 16 | 18 |

Connection starts cover approximately 13:00–19:00 UTC on November 2, 2026. This is insufficient to judge overnight traffic or daily seasonality. I did not score their absence.

### Flow ownership and state

The sensor split fits the visible topology: core contains substantial Kerberos, LDAP, SMB and client-to-proxy traffic; DMZ contains much more outbound TLS and HTTP; DB is dominated by MySQL. DB has 329 `service=mysql` rows, compared with only 16 TLS records. Service names are not assigned to TCP rows without any payload-history evidence in the supplied data.

I checked adjacent records sharing the exact directed TCP address/port tuple within each sensor. None had an interval overlap greater than 5 ms. There were also no successful TLS handshakes, HTTP status responses or successful DNS transactions attached to S0/REJ connections. These checks directly test ownership and state compatibility rather than simply praising reference completeness.

ICMP is the exception. The two closely spaced exchanges at DMZ lines 2444–2445 would ordinarily be accumulated into the same active Zeek ICMP connection. Changing echo identifiers or payload sizes does not change the upstream key construction. The repeated pattern warrants a collection explanation, but I classify it as a contract gap rather than a hard contradiction: nondefault lifecycle policy or merged independent observation processes can split otherwise identical keys. The count of 33 pairs is a count of sensor-local adjacent record pairs, not 33 proven independent physical incidents.

### DNS and resolution

Across all three sensors I checked single-packet DNS request sizes against the DNS header, encoded question name, QTYPE and QCLASS minimum. None were too small. A/AAAA response records with a single responder packet also had enough bytes for their visible questions and address-answer minima. No query label exceeded the 63-character DNS limit in this check.

Core's DNS composition is 2,282 A, 283 AAAA, 129 PTR, 102 SRV, 362 TXT, nine NS, seven MX and six SOA. Those counts describe this slice; the conspicuous TXT family is associated principally with one source rather than evenly smeared across the environment. Internal authoritative A responses have stable per-name TTLs: both domain controllers consistently use 300 seconds, while `LOG-MON-01` uses 1,800. Constant authoritative TTLs are expected and were not misclassified as a cache-aging defect.

The small background TXT cohorts described above remain a weak distribution concern, with plausible real operational explanations. Domain sanitization makes external naming or current resolution an invalid discriminator here.

### HTTP, proxying and transferred files

CONNECT is the dominant HTTP method: 2,005 core, 2,038 DMZ and 11 DB records. It would be misleading to interpret this as thousands of plaintext web browsing sessions: these are visible proxy control exchanges for TLS tunnels. The first proxy/egress example has appropriate distinct tuples, a plausible CONNECT-to-TLS progression, and explicitly scoped byte accounting.

I summed HTTP request and response body lengths across all transactions for each UID and compared them with the corresponding connection payload counters. No UID's summed request or response body exceeded its corresponding TCP payload count. There are multi-transaction connections with depths up to seven, rather than universal one-request connections. A few HTTP file references lack a files row; given possible file-logging filters and incomplete observation, those alone are not an authenticity defect.

### TLS and certificates

The TLS distribution is 1,901 TLS 1.3 records, 1,134 TLS 1.2 and six without a negotiated version. All DB TLS records are TLS 1.2; core and DMZ are mixed. I checked every TLS row with a visible, referenced leaf certificate for negotiated ECDSA/RSA authentication compatibility and certificate validity at the handshake timestamp. None failed those checks. Repeated certificate fingerprints did not change serial, subject, issuer, validity interval or key type within a sensor. Visible certificate-chain byte totals never exceeded their connection's responder payload.

TLS 1.2 histories include full exchange `CsxknGIi` and abbreviated exchange `CsiI`; failed handshakes have shorter histories. The supplied field distinctions agree with [Zeek's SSL history definitions](https://docs.zeek.org/en/v8.2.1/scripts/base/protocols/ssl/main.zeek.html). I did not infer a TLS 1.3 certificate-visibility defect: the records appropriately omit those chains.

### Traffic texture and collection limits

Hourly core connection counts are 1,779, 3,113, 1,724, 1,856, 2,192 and 1,718 for hours 13 through 18. This is visibly uneven. There is a meaningful duration tail: `zeek-core/conn.json:5217` contains a 13,298.584111-second SSH interval, and other SSH sessions last tens of minutes. Large SMB transfers and smaller interactive/health traffic coexist. None of this proves production origin, but it prevents a finding of universally short, uniform or identically paced traffic.

I did not penalize absent QUIC, NTP, a particular endpoint collector, sparse DB HTTP, missing selected Sysmon types, complete source matching or missing out-of-window session initiators. Without a collector configuration or packet capture, those observations do not establish a required companion or a source-native contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Zeek ICMP connection records | 22 core and 11 DMZ adjacent same-key pairs less than 60 seconds apart; two illustrated below 100 ms | Main reason for a mixed score: ordinary native aggregation should preserve one active connection identity; nonstandard collection remains an alternative |
| weak_signal | DNS TXT query-family distribution | Small background TXT cohorts introduced across several hosts during a bounded late-window period | Small increase only; scheduled or coordinated real activity is plausible |

No demonstrated impossible TCP lifecycle, negotiated cipher/key mismatch, DNS wire-size impossibility or application-success/failed-flow contradiction was found. The conclusion does not rely on suspicious activity being compact or easy to reconstruct.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source shapes and checked protocol/byte constraints are strong; native ICMP aggregation needs explanation.
- **Temporal patterns:** 8 — Uneven hourly activity and substantial duration tails; narrowly introduced background TXT cohorts are a weak concern.
- **Cross-source correlation:** 9 — Protocol timing, flow ownership, proxy byte scopes and loss accounting are coherent in the checks performed.
- **Behavioral realism:** 8 — Credible proxy, directory, database, file-transfer and remote-admin traffic with varied outcomes.
- **Environmental consistency:** 8 — Sensor-specific traffic mixes fit visible roles; ICMP record segmentation could indicate an unstated collection policy.

## Recommendations

- If this were synthetic, aggregate ICMP echoes through the same native connection key and inactivity lifecycle as the intended Zeek collector. Preserve packet and byte totals across repeated echoes instead of automatically allocating a new UID per exchange. If the data is real, document the policy, worker merge or capture-processing boundary that accounts for sub-100-ms identity splits.
- If this were synthetic, give background SPF/DMARC/DKIM querying a host/application-specific schedule consistent across the visible window. Avoid introducing those query families simultaneously across otherwise unrelated hosts without a modeled operational reason. A real collection manifest or scheduled-job explanation could resolve this weak signal without changing the records.
- Retain the existing explicit proxy byte scopes, passive TLS 1.3 certificate visibility limits, and content-loss accounting; those checked details already withstand straightforward network-forensic consistency tests.
