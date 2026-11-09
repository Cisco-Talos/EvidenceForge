# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 74

## Executive Summary

The network data is largely coherent, with realistic protocol diversity, explicit proxy behavior, and consistent protocol-to-connection references. Two Zeek TCP records nevertheless contain a concrete accounting contradiction: responder payload retransmission is recorded while the responder IP-byte total leaves no room for any retransmitted payload. A broader population of unusually small retransmission budgets supports concern about how packet statistics were constructed, although those additional records are not individually impossible.

## Evidence For Synthetic

- [hard_contradiction] `zeek-core/conn.json:1270`, UID `Cn36WJVHCrwErEPx5O`, timestamp `1793627298.439513` (2026-11-02 13:48:18.439513 UTC), records `history="ShADadTtFf"`, `resp_bytes=4409`, `resp_pkts=5`, `resp_ip_bytes=4609`, and `missed_bytes=0`. The lowercase `t` denotes responder payload retransmission. Yet `4609 - 4409 - 5*40 = 0`: even minimum IPv4/TCP headers consume every remaining byte, leaving zero bytes for retransmission. There is no gap marker in this record.
- [hard_contradiction] The same contradiction recurs independently in `zeek-core/conn.json:4122`, UID `CtwnGoTFjO3foL3P2T`, timestamp `1793630602.715549` (14:43:22.715549 UTC): `history="ShADadTtFf"`, `resp_bytes=5012`, `resp_pkts=5`, `resp_ip_bytes=5212`, `missed_bytes=0`; `5212 - 5012 - 5*40 = 0`. This is another SMTP tuple, `10.10.2.26:38474 -> 54.240.71.115:25`, rather than a second observation of the first tuple.
- [distribution_texture] Among gap-free TCP direction records carrying their direction's retransmitted-payload flag, 214 of 2,349 sensor-direction observations have only 0–12 bytes beyond unique payload plus minimum 40-byte headers: core 90/1,105, DB 16/79, DMZ 108/1,165. For example, `zeek-dmz/conn.json:2` gives originator budget `4124 - 3832 - 7*40 = 12` despite `T`; line 4 gives `1309 - 1101 - 5*40 = 8`. Small retransmissions can happen, so this is supporting texture rather than proof. Counts include repeated visibility of some connections across sensors and must not be interpreted as 214 independent flows.

## Evidence For Real

- Protocol evidence consistently belongs to actual sensor-local connections. Across 21,137 connection records, joins of supplied DNS, HTTP, TLS, SMTP, SMB-file and extracted-file rows found no missing referenced connection UID, no tested protocol/file timestamp more than 1 ms outside its connection interval, and no extracted `seen_bytes` exceeding its corresponding connection direction's payload total.
- DNS has a credible mix of successes, failures and record types. Core DNS contains 2,204 A, 259 AAAA, 248 TXT, 154 PTR and 104 SRV queries, plus smaller NS/MX/SOA populations; its 2,979 rows include 204 NXDOMAIN and 13 SERVFAIL responses. Checked A/AAAA address answers have compatible IP versions, and negative NXDOMAIN rows do not carry positive answers.
- Explicit proxy behavior is visible in the actual tuples. `zeek-dmz/http.json:1` is a client CONNECT to the proxy at `10.10.3.20:8080`; `zeek-dmz/dns.json:1` resolves its hostname from that proxy address; `zeek-dmz/ssl.json:1` shows the proxy's separate outbound connection to the returned address `23.72.51.162:443` with matching SNI. The DNS response precedes the outbound TLS observation.
- TLS separates modern TLS 1.3 observations from TLS 1.2 certificate-bearing handshakes. An ECDSA TLS 1.2 cipher in `zeek-dmz/ssl.json:148` correctly links to an ECDSA leaf in `zeek-dmz/x509.json:80`; the RSA key of its intermediate at line 81 is compatible with an RSA-signed ECDSA leaf and is not a cipher/key contradiction.
- Connection states contain genuine-looking variation rather than only successful transactions: core has 131 RSTO, 86 RSTR, 20 REJ, 21 OTH and smaller S1/S2/S3 populations. DMZ contains 2,731 S0 observations, consistent with the visible unsolicited traffic, alongside successful flows and resets.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The principal checks covered all rows in the three Zeek sensor directories, followed by selected raw-row inspection and a limited look at endpoint FLOW records to understand the proxy path. The connection windows span approximately 13:00–19:00 UTC on 2026-11-02. This is insufficient to judge full-day business-hour or overnight behavior, so neither is scored as a defect.

Sensor-local connection counts are 11,660 core, 460 DB and 9,017 DMZ. The combined examined protocol population contains 3,959 DNS, 4,244 HTTP and 2,887 TLS rows. Sensors can observe the same physical connection, so summed counts represent observations rather than unique network activities.

### TCP accounting contradiction

Zeek's connection payload byte fields describe the stream payload quantity; retransmitted copies increase observed IP bytes without adding new unique stream payload. IPv4 and TCP require at least 20 bytes each per packet. Therefore, for a fully observed, gap-free direction with a payload retransmission, the following residual must be positive:

`direction_ip_bytes - direction_bytes - 40 * direction_pkts`

The two core SMTP examples above have a zero residual, responder retransmission marker `t`, no `g`/`G` gap history, and `missed_bytes=0`. TCP options would require additional header bytes and thus strengthen, not remove, the contradiction. I excluded gap-bearing records from this conclusion because unobserved sequence-space bytes can complicate this arithmetic.

The conclusion assumes the supplied fields retain native Zeek meanings. A downstream exporter that substitutes a different definition of payload bytes could explain contradictory fields, but would itself make these records a misleading representation of native Zeek telemetry. No such transformation is indicated in the supplied rows. These are a narrow statistical-accounting defect, not evidence that every observed connection is invalid.

The core contradiction and supporting counts can be reproduced with Python's standard library:

```python
from pathlib import Path
import json

root = Path('/private/tmp/log-study-t_42jceg/data')
for sensor in sorted(root.glob('zeek-*')):
    total = small = zero = 0
    for line, text in enumerate((sensor / 'conn.json').open(), 1):
        row = json.loads(text)
        if (row['proto'] != 'tcp' or row['missed_bytes'] != 0
                or 'g' in row['history'].lower()):
            continue
        for direction, flag in [('orig', 'T'), ('resp', 't')]:
            if flag not in row['history']:
                continue
            residual = (row[f'{direction}_ip_bytes']
                        - row[f'{direction}_bytes']
                        - 40 * row[f'{direction}_pkts'])
            total += 1
            small += residual <= 12
            zero += residual == 0
            if residual == 0:
                print(sensor.name, line, row['uid'], direction, residual)
    print(sensor.name, total, small, zero)
```

### Flow lifecycle, timing and extraction

I grouped TCP observations by the complete source/destination address and port tuple within each sensor. No consecutive connections sharing the same oriented tuple overlapped their reported duration. DNS RTT completion did not exceed the referenced connection's close time by more than 2 ms. Established TLS rows did not refer to S0 or REJ connections; HTTP response-bearing rows did not refer to zero-response-byte flows.

Extracted-file lengths fit within directional connection payload budgets in the supplied data. These checks reduce concern about common UID, lifecycle and transfer-volume defects, but cannot establish packet-level authenticity without packet captures.

### DNS, TLS and topology

The query-type and failure mix supports a heterogeneous internal environment. Internal names resolve to private addresses, while the proxy resolves external names and opens distinct outbound transports. I did not treat sanitized names or public-domain/address mismatches as authenticity evidence.

DMZ TLS comprises 1,736 TLS 1.3 and 843 TLS 1.2 observations. Core has 162 TLS 1.3, 130 TLS 1.2 and two incomplete observations; DB has 14 TLS 1.2 observations. TLS 1.3 uses AES-GCM and ChaCha20 suites, and TLS 1.2 includes modern GCM plus a smaller CBC population. The examined certificate/key relationship is valid. I did not require TLS 1.3 certificates to be visible to a passive observer, and the linked certificate extractions checked here were from TLS 1.2.

The DB sensor's 303 MySQL-service observations out of 460 connections and the DMZ's high TLS/proxy traffic are plausible for distinct observation zones. Thin or absent unrelated source families were not scored as defects.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Zeek TCP connection accounting | Two gap-free core SMTP rows, lines 1270 and 4122 | Primary reason to judge synthetic: retransmitted payload has no available IP-byte budget. |
| distribution_texture | Zeek TCP packet/byte accounting | 214/2,349 gap-free retransmission-marked direction observations have at most 12 extra bytes beyond minimum headers | Supporting concern about packet-stat construction; some observations are duplicates across sensors and individual small retransmissions remain possible. |

## Realism Score by Category

- **Field format accuracy:** 6 — JSON shapes and protocol fields are credible, but two packet-accounting combinations contradict their TCP history.
- **Temporal patterns:** 9 — Tested protocol timestamps and DNS completion fit their flows; the six-hour window limits broader timing conclusions.
- **Cross-source correlation:** 9 — Sensor-local UID and extraction joins are coherent, and the sampled proxy path agrees across layers.
- **Behavioral realism:** 8 — DNS failures, proxy errors, scanning and mixed TCP outcomes provide plausible variation; tiny retransmission budgets weaken packet-level texture.
- **Environmental consistency:** 9 — Sensor-specific protocol distributions and proxy-mediated egress fit the visible topology.

## Recommendations

- If this were synthetic, calculate connection IP-byte totals, unique payload sizes, packet counts and history flags from one coherent packet model. A payload retransmission must add its retransmitted payload and packet headers to the appropriate direction's IP-byte total.
- If this were synthetic, inspect the broader small-budget retransmission population, especially the examples at DMZ connection lines 2 and 4. Model whether the retransmission is a full segment, short application write or probe, and make packet counts, option overhead and payload accounting agree with that choice.
- Preserve the existing sensor-local UID consistency, DNS timing, proxy transport separation and TLS leaf-key compatibility while correcting the accounting defect.
