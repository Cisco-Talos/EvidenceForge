# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 29

## Executive Summary

The inspected network evidence is mostly production-like: TCP outcomes, DNS failures and query diversity, TLS resumption and certificate reuse, and proxy byte accounting are internally plausible. Two exact pivots produced coherent transport/application relationships, and the bounded review did not demonstrate an impossible ordering or source-native contradiction; those results support a low synthetic-confidence score but cannot establish real provenance.

## Evidence For Synthetic

- No verified synthetic indicator was established in this bounded network review. In particular, complete UID alignment was not scored as suspicious, and the repeated normal TCP history strings were not treated as a generator fingerprint.
- The review does not exclude defects outside the inspected samples or defects in protocol details that require packet contents. This uncertainty is a limit, not an authenticity indicator or a scored defect.

## Evidence For Real

- `zeek-core/conn.json`, `zeek-db/conn.json`, and `zeek-dmz/conn.json` contain 23,644 combined connection rows with a mixture of `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `OTH`, and partial states. The 4,326 `S0` observations are not represented as successful data transfers; the inspected DMZ example has one SYN and no response packets.
- Across the three DNS files, 4,478 records include A, AAAA, PTR, SRV, TXT and smaller NS/SOA/MX populations. The core sensor alone has 222 NXDOMAIN, 14 SERVFAIL and four REFUSED responses among 3,265 DNS rows; the inspected `isatap` NXDOMAIN has no fabricated answer array.
- The exact core CONNECT pivot preserves source/destination tuple and records 412 client control bytes plus 1,653 client tunnel bytes, totaling the connection's 2,065 origin bytes. Its 229 server control bytes plus 20,830 server tunnel bytes total the connection's 21,059 response bytes.
- The exact DMZ TLS pivot places the handshake 106.354 milliseconds after TCP open and certificate observations shortly afterward, within a 3.544722-second flow. The leaf SAN covers the SNI and its issuer matches the intermediate's subject.
- TLS version and cipher populations vary by observation scope: DMZ has 2,125 TLS 1.3 and 909 TLS 1.2 rows, whereas all 19 DB-sensor TLS rows use TLS 1.2. Repeated leaf observations generally retain their fingerprint and validity interval rather than changing certificate identity on every connection.

## Detailed Analysis

### Scope and method

I read only the supplied briefing and assigned data directory. I inspected 18 complete raw records: eight initial Zeek records across core, DMZ and DB sensors; six additional records completing the two pivots; one unanswered SYN; one NXDOMAIN; one Snort alert; and one ASA message. Aggregate computations covered the network JSON files without expanding this into a full record-by-record audit. No repository, scenario, evaluation, provenance or other reviewer material was accessed.

The connection timestamp range is approximately November 2, 2026, 13:00–19:00 UTC. This six-hour window cannot establish overnight behavior or daily and weekly rhythms. Source names identify distinct observation scopes; their record counts were not assumed to be independent physical packets, and duplicate visibility across sensors was not penalized.

### Transport distributions and accounting

The three sensor totals are 12,943 core, 438 DB and 10,263 DMZ connection rows. Their state counts are:

| State | Core | DB | DMZ |
|---|---:|---:|---:|
| SF | 10,406 | 329 | 7,175 |
| S0 | 1,768 | 13 | 2,545 |
| OTH | 442 | 23 | 310 |
| RSTO | 162 | 38 | 118 |
| RSTR | 101 | 18 | 62 |
| REJ | 29 | 9 | 23 |
| S1/S2/S3 combined | 35 | 8 | 30 |

No connection row had payload byte counts exceeding its corresponding IP byte counts. No TCP `SF` row had zero responder packets. Those are limited consistency checks, not packet reconstruction or a claim that every history string is valid.

The inspected failed connection `CMqVDGDEGOP76UgYg`, `zeek-dmz/conn.json`, `ts=1793624416.154508`, is `10.10.3.10:36384 -> 10.10.2.30:443`, TCP `S0`, history `S`, origin packets 1/IP bytes 52, response packets and bytes zero. Its omitted duration and zero application payload are plausible for a single unanswered SYN. I did not infer that all failed connections have the same cause.

Hourly core counts are 1,829, 3,443, 1,898, 1,769, 2,176 and 1,828 for hours 13 through 18 UTC. DMZ counts are 1,515, 2,916, 1,496, 1,534, 1,401 and 1,401. These show a shared 14:00 increase rather than perfectly fixed hourly counts; aggregate counts alone do not determine the cause or provenance.

### Exact pivot 1: CONNECT application and native proxy accounting

The inspected core HTTP record at `ts=1793624408.815497`, UID `CCNiAm1f7JPR2ix29e`, is a successful `CONNECT preview.redd.it:443` from `10.10.1.41:62106` to `10.10.3.20:8080`. The same UID in `zeek-core/conn.json` opens at `1793624408.687071`, duration `2.967407`, state `SF`, with 2,065 origin bytes and 21,059 response bytes.

The corresponding native `PROXY-01.meridianhcs.local/proxy_access.log` line has source `10.10.1.41`, time `[02/Nov/2026:13:00:08 +0000]`, principal `maya.ross@meridianhcs.local`, the same CONNECT destination and user agent, and status 200. The native log lacks a source port and UID, so its attribution is an exact visible source/target/time/method/user-agent match rather than an independent unique tuple assertion. It explicitly separates CONNECT control traffic from tunnel traffic and reports `tunnel_duration_ms=2836`. The HTTP observation occurs 128.426 milliseconds after flow open; the control/tunnel byte sums agree with the conn record. Neither encrypted payload contents nor upstream server behavior was inferred from this tunnel.

### Exact pivot 2: TLS, transport and certificate chain

`zeek-dmz/ssl.json` UID `CG295AL9K2PwDjLsPO`, `ts=1793624403.783765`, describes `10.10.3.20:42181 -> 52.84.46.244:443`, established non-resumed TLS 1.2, cipher `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, SNI `data.fastreach.com`.

Its exact `conn.json` UID and tuple open at `1793624403.677411`, last `3.544722` seconds, use `SF`/`ShADadfF`, and contain 1,221 origin and 16,934 response payload bytes. The certificate references resolve in `zeek-dmz/x509.json`: leaf `FQsAdfFUiyDy4spKsce` at `1793624403.799878` has subject `CN=data.fastreach.com`, matching SAN, issuer `CN=Amazon RSA 2048 M01, O=Amazon, C=US`, and a validity interval covering the flow; intermediate `FJ3PicXF0NY6i4N00U` at `1793624403.824896` has that subject and issuer `CN=Amazon Root CA 1, O=Amazon, C=US`. This validates visible identity and temporal compatibility, not the cryptographic certificate signatures.

### DNS, infrastructure and collection limits

The initial core DNS/conn pair UID `ClnAf4xMznbwm13HlN` was inspected as two representative source-native records, not used as an additional investigative pivot. Its UDP exchange has `rtt=0.000469`, one packet each way, query `DC-01.meridianhcs.local`, answer `10.10.2.10`, TTL 300. The inspected core NXDOMAIN at `1793624510.824572` queries `isatap` and has `rtt=0.002442`; that is plausible ambient name-resolution noise.

Core destination-port populations include DNS 3,272, Kerberos 2,607, proxy 8080 2,406, LDAP 1,136 and SMB 723. DB traffic is dominated by 3306 (255 of 438 connection records); this is compatible with the apparent observation scope. Port and service names are not proof of application contents.

Aggregate UID/time checks on all 5,318 HTTP, 3,470 SSL and 4,478 DNS rows found no missing conn UID, timestamp before its conn start, or timestamp later than conn end plus 10 milliseconds. TLS includes resumed sessions without certificate-chain fields, and the initial core example is one such session. I did not test DNS-before-connection relationships across caches or shared resolvers, nor interpret missing DNS rows as defects.

The inspected Snort line reports BitTorrent traffic at `13:27:40.884851`, `10.10.2.21:46853 -> 34.104.145.3:6881`; one alert cannot establish IDS precision or frequency. The inspected ASA line at `13:00:01` records a UDP connection from DMZ proxy `10.10.3.20:49120` to inside DNS `10.10.2.10:53`; it was checked for native shape only. No additional alert/firewall correlation claim is made.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| No verified indicator | Zeek, sampled proxy/ASA/Snort | 18 inspected records, two exact pivots and described aggregates | No demonstrated contradiction supports a high synthetic score; remaining uncertainty reflects bounded inspection and unknown provenance. |

## Realism Score by Category

- **Field format accuracy:** 9 — Inspected network records use plausible native fields and state-dependent omissions; packet-level validation was unavailable.
- **Temporal patterns:** 8 — Sampled protocol timing and hourly variation are plausible; the six-hour slice limits rhythm assessment.
- **Cross-source correlation:** 9 — Both exact pivots agree on visible transport, timing, identity and byte accounting.
- **Behavioral realism:** 8 — Failure states, infrastructure traffic, DNS errors and TLS variation support realistic traffic; detailed user behavior was outside scope.
- **Environmental consistency:** 8 — Core/DMZ/DB populations differ plausibly; topology and collection policy are inferred, not independently established.

## Recommendations

No corrective recommendation is justified by a demonstrated defect in this bounded network sample. If this were synthetic, retain the visible control/tunnel byte distinction, state-dependent connection fields and scoped TLS/certificate identities. Any further realism changes should be driven by an additional concrete discrepancy rather than by demanding more sources, perfect DNS coverage, or a longer intrusion narrative.
