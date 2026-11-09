# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 91
**Synthetic-Confidence Score:** 83

## Executive Summary

The network data is broadly convincing at the protocol, topology, and activity levels, but repeated cross-sensor TCP accounting contradicts the source-native meaning of Zeek's payload-byte fields. Completed flows retain their handshake and both FINs while their reported sequence-space payload totals are reduced by exactly the sensor's `missed_bytes`; this occurs across HTTP, TLS, SSH, MySQL, and other services, making synthetic capture-loss modeling the strongest explanation.

## Evidence For Synthetic

- **[hard_contradiction] TCP capture gaps are subtracted from sequence-space byte totals.** `zeek-core/conn.json:18`, UID `C3ODY8b4myLQhgDjrP`, and `zeek-dmz/conn.json:10`, UID `CD4lGB7yqW7TRp5WZ3`, describe `10.10.1.22:59362 → 10.10.3.20:8080` at `ts=1793624469.160602` and `1793624469.045338`. Core reports `orig_bytes=449`, `resp_bytes=1197`, `missed_bytes=1`, `history=ShADadfFG`; DMZ reports `450`, `1197`, `0`, `ShADadfF`. Both report `SF`, and both histories retain SYN, SYN-ACK, and FIN in each direction. Zeek TCP `orig_bytes`/`resp_bytes` are based on sequence space, so a missed interior byte should not reduce the total when the stream boundaries remain visible. Packet/IP-byte counts can differ; these sequence-space totals should not be treated as captured-byte counters.
- **[hard_contradiction] The same issue affects encrypted and database traffic, not just HTTP export interpretation.** `zeek-core/conn.json:234` and `zeek-db/conn.json:8` describe `10.10.4.10:43168 → 10.10.2.40:443`; responder payload totals are `66845` and `66161`, exactly `684` apart, with DB reporting `missed_bytes=684`. Both are `SF` with histories `ShADadfF` / `ShADadfFg`. `zeek-dmz/conn.json:183` versus `zeek-db/conn.json:16` similarly reduces MySQL payload by `12 + 242 = 254`, exactly DMZ's `missed_bytes=254`, despite visible stream start and end in both directions.
- **[distribution_texture] The arithmetic is systematic rather than an isolated analyzer anomaly.** Among matching, completed TCP flows with `S/h/F/f`, no retransmission flags, and start timestamps less than one second apart, there are 412 core–DMZ pairs, 10 core–DB pairs, and 47 DMZ–DB pairs where one sensor is gap-free and directional payload totals differ. In **every** such pair, the total decrease equals the other sensor's `missed_bytes`. These pair counts overlap and must not be summed as independent connections. This is supporting texture of the same accounting defect, not an independently scored defect.

## Evidence For Real

- **Coherent proxy and DNS sequence:** `zeek-dmz/http.json:1` has a CONNECT from `10.10.1.22:40446` to proxy `10.10.3.20:8080` for `prod-useast-a.online.tableau.com:443` at `1793624467.079136`. Proxy DNS in `zeek-dmz/dns.json:1` starts at `1793624467.150148`, has RTT `0.071839`, and returns `44.238.150.90` / `44.238.151.90`. The first upstream connection, `zeek-dmz/conn.json:5`, starts at `1793624467.228751`, after that DNS response; `zeek-dmz/ssl.json:2` then records the matching TLS/SNI. This is a plausible proxy-resolution path rather than an incorrect demand for client-side DNS before every CONNECT.
- **Source-native TLS visibility:** Across the sensors, no TLS 1.3 row exposes a certificate chain through `cert_chain_fuids`. Visible TLS 1.2 chains resolve to file and X.509 records, and inspected ECDHE-RSA / ECDHE-ECDSA suites agree with leaf key type. `zeek-core/ssl.json:1` links the internal FILE-LNX TLS session to leaf FUID `FCR28yc3nBi076mskU`; `zeek-core/x509.json:1` gives the matching hostname, RSA key, enterprise issuer, and valid dates.
- **Plausible source distributions:** Core includes 2,479 Kerberos connections, 1,208 LDAP, 465 SMB, 79 SMTP, and 60 DHCP; the DB sensor is dominated by 260 MySQL service identifications. DMZ has 2,847 SSL and 2,419 HTTP service identifications, with HTTP largely proxy CONNECT rather than evidence of a predominantly plaintext enterprise.
- **Traffic has failures and operational variety:** Core DNS includes 227 NXDOMAIN, 14 SERVFAIL, and 4 REFUSED records; DMZ has 150 NXDOMAIN and 5 SERVFAIL. Connections include SYN-only attempts, rejections, resets, partial/other states, retransmissions, long SSH/RDP sessions, and shorter service traffic. This diversity is consistent with live collection, although it does not repair the accounting contradiction.
- **IDS spot checks agree with underlying traffic:** `snort-perimeter/snort_alert.log:1` identifies curl traffic for `10.10.3.20:37494 → 23.72.53.238:80`; `zeek-dmz/http.json:13` has the same tuple and `user_agent=curl/8.4.0`. `snort-core/snort_alert.log:1` matches the `.tk` query at `zeek-core/dns.json:19` by tuple and query content. I do not treat domain naming or real-world domain/IP mapping as authenticity evidence.

## Detailed Analysis

### Scope and method

I read only the supplied data directory and the supplied reviewer briefing. Network analysis covered every JSON row in the three Zeek sensor directories, with focused inspection of ASA, proxy, Snort, and normalized endpoint examples. File/line citations are relative to the data directory and use one-based physical lines. Unix timestamps are quoted exactly; the Zeek connection window is approximately **2026-11-02 13:00–19:00 UTC**.

| Source | conn | DNS | HTTP | SSL | files | X.509 |
|---|---:|---:|---:|---:|---:|---:|
| zeek-core | 12,314 | 3,188 | 2,159 | 403 | 678 | 225 |
| zeek-dmz | 9,401 | 1,075 | 2,431 | 2,725 | 1,686 | 1,079 |
| zeek-db | 433 | 50 | 20 | 14 | 21 | 14 |

These are sensor observations, not unique enterprise connections: several sensors observe the same traffic. I did not penalize absent pre-window initiators or post-window closures, unspecified collectors, selected endpoint event families, or completeness of source matching.

### TCP state and accounting

Core connection states are `SF=10053`, `S0=1897`, `RSTO=150`, `RSTR=116`, `OTH=29`, `REJ=28`, `S2=16`, `S3=15`, and `S1=10`. DMZ has `SF=6516`, `S0=2606`, plus resets, rejections, and other/partial states. The large SYN-only share is concentrated in particular origins: `10.10.3.10` accounts for 1,481 core S0 observations and 1,735 DMZ S0 observations. Several external sources contribute DMZ S0 traffic. This supports scanning or blocked probes; the high S0 rate alone is not an authenticity defect.

Simple per-row checks found no payload/IP-byte minimum violations for IPv4 TCP/UDP, no positive byte counts with zero corresponding packet counts, and no established TLS session linked to S0/REJ TCP. HTTP body totals and individual HTTP/SSL extracted-file `seen_bytes` did not exceed the associated directional connection bytes plus reported gaps. Thus the defect is more specific than arbitrary impossible byte counts.

The decisive distinction is **sequence-space payload size versus captured packet volume**. When SYN and both directional FINs are visible, the intervening TCP sequence range establishes the payload size even if interior packets were missed. A capture gap can reduce packet count and captured IP bytes, and can impair analyzers and extracted files. Subtracting it from `orig_bytes`/`resp_bytes` confuses those meanings.

Additional reproducible examples:

| Tuple | Files/lines | Gap-free payload `(orig,resp)` | Other payload `(orig,resp)` | Other `missed_bytes` |
|---|---|---:|---:|---:|
| `10.10.1.22:59362 → 10.10.3.20:8080` | DMZ conn:10 / core conn:18 | `(450,1197)` | `(449,1197)` | 1 |
| `10.10.2.27:60137 → 10.10.3.10:80` | core conn:20 / DMZ conn:13 | `(210,564)` | `(210,558)` | 6 |
| `10.10.1.22:38609 → 10.10.3.20:8080` | core conn:25 / DMZ conn:16 | `(11791,95986)` | `(11732,95986)` | 59 |
| `10.10.4.10:43168 → 10.10.2.40:443` | core conn:234 / DB conn:8 | `(3794,66845)` | `(3794,66161)` | 684 |
| `10.10.3.10:46413 → 10.10.4.10:3306` | DB conn:16 / DMZ conn:183 | `(3753,21472)` | `(3741,21230)` | 254 |

All these examples report SF and handshake/FIN history in both directions. The first pair also decrements originator packets from four to three and IP bytes from 666 to 609. Decreasing observed packets/IP bytes is plausible; decreasing the sequence-derived payload by one is the problem.

The core–DMZ test had 1,824 eligible completed pairs; 412 meet the affected condition, all with exact subtraction. Of these, 389 identify HTTP, 12 SSL, 5 SSH, 5 LDAP, and 1 has no service. The corresponding DB comparisons show the same arithmetic in TLS, syslog, Kerberos, MySQL, SSH, and HTTP. Between core and DMZ, the affected directional decreases are small fractions of the gap-free directional payload, with median approximately 0.64% and maximum 1.23%. This supports modeled capture degradation, but the source-native contradiction carries the weight, not merely the percentage range.

A custom postprocessor could redefine these fields as observed-byte counters in otherwise real data. No such redefinition is documented in the supplied logs. I therefore regard that as a limitation on absolute certainty, not the most likely explanation.

The following reproduces the pair-count result using only the permitted logs:

```python
from collections import Counter, defaultdict
from pathlib import Path
import json

root = Path('/private/tmp/log-study-pqiah9u3/data')

def rows(sensor):
    path = root / sensor / 'conn.json'
    return [(n, json.loads(line))
            for n, line in enumerate(path.read_text().splitlines(), 1)]

def key(row):
    fields = ('id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto')
    return tuple(row[field] for field in fields)

for left, right in [('zeek-core', 'zeek-dmz'),
                    ('zeek-core', 'zeek-db'),
                    ('zeek-dmz', 'zeek-db')]:
    index = defaultdict(list)
    for number, row in rows(right):
        index[key(row)].append((number, row))
    counts = Counter()
    for number, row in rows(left):
        candidates = index[key(row)]
        if not candidates:
            continue
        other_number, other = min(
            candidates, key=lambda item: abs(item[1]['ts'] - row['ts']))
        pair = (row, other)
        if abs(row['ts'] - other['ts']) >= 1 or row['proto'] != 'tcp':
            continue
        if any(item['conn_state'] != 'SF' for item in pair):
            continue
        if not all(char in item['history'] for char in 'ShFf' for item in pair):
            continue
        if any(char in item['history'] for char in 'Tt' for item in pair):
            continue
        counts['eligible'] += 1
        if (row['orig_bytes'], row['resp_bytes']) == (
                other['orig_bytes'], other['resp_bytes']):
            continue
        if min(row['missed_bytes'], other['missed_bytes']) != 0:
            continue
        counts['affected'] += 1
        missed = row if row['missed_bytes'] else other
        clean = other if row['missed_bytes'] else row
        decrease = sum(clean[side + '_bytes'] - missed[side + '_bytes']
                       for side in ('orig', 'resp'))
        counts['exact_subtraction'] += decrease == missed['missed_bytes']
    print(left, right, dict(counts))
```

Expected `(eligible, affected, exact_subtraction)` results: core–DMZ `(1824,412,412)`, core–DB `(41,10,10)`, DMZ–DB `(191,47,47)`.

### DNS and protocol sequencing

Every DNS, HTTP, SSL, SMB-files, SMB-mapping, and SMTP record checked has a same-sensor connection UID with an identical address/port tuple. Their logged timestamps lie within the referenced connection interval, allowing a 1 ms numerical tolerance. This is evidence of coherent construction, not proof of real provenance, and complete matching is not counted against authenticity.

Core DNS qtypes include A 2,333; AAAA 279; PTR 154; SRV 105; TXT 300; MX 8; NS 6; and SOA 3. This is richer than an A-only lookup stream. Answer/TTL vector lengths agree, NXDOMAIN records do not contain positive answers, and AAAA answers inspected contain IPv6-style addresses. Core's median DNS connection duration is roughly 3.6 ms, with a tail to 2.236 seconds; DMZ median is roughly 9.1 ms, likewise with a multi-second tail. These are plausible internal-resolver and cache-miss characteristics.

The proxy example in Evidence For Real is particularly useful because the DNS answer completes at `1793624467.221987` and upstream TCP opens at `1793624467.228751`, approximately 6.8 ms later. Comparing client CONNECT time to proxy DNS time without accounting for proxy ownership would incorrectly report a causality problem.

### TLS, certificates, and HTTP

DMZ SSL records include 1,808 TLS 1.3, 913 TLS 1.2, and 4 records without a negotiated version. Core has 199 TLS 1.3 and 201 TLS 1.2 plus 3 without a version; DB has 14 TLS 1.2. Modern AES-GCM and ChaCha20 appear alongside some CBC traffic on internal services. That internal/edge distinction is plausible without requiring obsolete protocols to create artificial diversity.

Across 211 unique visible X.509 fingerprints, certificate identity fields remain consistent across records/sensors. Referenced certificate FUIDs resolve to the relevant files and X.509 records. Visible leaf validity periods contain their session times, SNI matches visible SANs, and checked authentication key types match their TLS 1.2 suites. TLS 1.3 encrypted certificates are not exposed as passive plaintext extraction. These checks found no certificate contradiction.

Some full TLS 1.2 rows lack certificate-chain references despite certificate-like history flags: 9 core, 36 DMZ, and 1 DB. Selective extraction/export or observation gaps can explain this; the available collection context does not establish a required companion, so I do **not** score it as synthetic.

Most HTTP records are CONNECT: 1,967 core, 2,013 DMZ, and 19 DB. Therefore counting HTTP rows as plaintext browsing would misstate the environment. HTTP includes 200, 301/302/304, 403/407, and 502/503/504 outcomes. No 304 response checked has a positive response body. The proxy access examples distinguish tunnel control bytes from inner inspected HTTP bytes and identify client source ports and tunnel IDs; this is useful and plausible accounting intent.

### Timing, environment, and lateral connections

Core hourly connection counts for UTC 13–18 are `1849,3233,1757,1698,2068,1709`; DMZ counts are `1315,2713,1359,1465,1295,1254`. The visible 14:00-hour increase and uneven hourly totals do not look artificially level. Six daytime hours cannot establish business-hour/overnight or weekday/weekend realism, so those properties remain unassessed.

Matched core/DMZ observations have a median DMZ-minus-core start offset of approximately −114 ms; DB is approximately +65 ms versus core and +180 ms versus DMZ. Small sensor clock offsets can explain this, so I did not infer impossible multi-sensor causality from raw timestamp comparisons.

SSH and RDP include long-lived successful transports, short probes, and resets. Core SF SSH durations span approximately 0.22 seconds to 13,334 seconds, with median 2,111 seconds; SF RDP median is approximately 1,153 seconds, with maximum 3,427 seconds. Very short service-identified transports need not be authenticated sessions, and no successful endpoint authentication is inferred from `SF` alone. Infrastructure, proxy, DB, internal administration, and scanning observations are plausible for the visible collection paths. I do not score attack compactness, clean narrative structure, or absence of operator mistakes.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Zeek TCP conn accounting across core/DMZ/DB | 412 core–DMZ, 10 core–DB, 47 DMZ–DB affected pairs under conservative completed-flow filters; pair counts overlap | Dominant reason for score above 80: sequence-derived byte totals are treated as observed bytes despite visible start/end boundaries |
| distribution_texture | Same Zeek capture-gap representation | Every affected pair has exact payload-total subtraction equal to `missed_bytes`, across multiple unrelated services | Reinforces a systematic modeling mechanism; not scored as a separate independent defect |

## Realism Score by Category

- **Field format accuracy:** 7 — JSON, tuples, protocol fields, and certificate structures are convincing; TCP byte-field semantics contain a repeated substantive error.
- **Temporal patterns:** 9 — Within-sensor protocol ordering, variable durations, and uneven traffic are plausible; longer seasonal/overnight behavior is outside the slice.
- **Cross-source correlation:** 6 — UID/tuple/DNS/proxy/TLS relationships work well, but the same completed stream has contradictory sequence-space totals across sensors.
- **Behavioral realism:** 8 — Infrastructure traffic, proxied HTTPS, scanning, errors, and long admin sessions fit the visible environment.
- **Environmental consistency:** 8 — Sensor-specific protocol mixtures and apparent service roles are plausible, with no collection-volume defect established.

## Recommendations

- If this were synthetic, preserve TCP `orig_bytes` and `resp_bytes` as sequence-space totals when the SYN/FIN boundaries remain visible. Apply capture loss to observed packet/IP-byte counts, gap reporting, analyzer visibility, and extracted-file completeness according to their actual source semantics.
- If this were synthetic, validate paired observations of completed encrypted and plaintext TCP streams with selective packet loss. The examples above should retain compatible sequence-space totals while allowing legitimate differences in captured volume, history, file extraction, and timing.
- If these are real logs transformed after collection, document any redefinition of `orig_bytes`/`resp_bytes` rather than exporting captured-byte counters under standard Zeek field names. That would address the concrete ambiguity driving this verdict.
