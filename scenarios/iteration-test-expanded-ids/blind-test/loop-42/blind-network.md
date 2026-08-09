# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 94  
**Synthetic-Confidence Score:** 88

## Executive Summary

The network corpus is unusually convincing in its Zeek schemas, protocol mix, certificate reuse, packet-loss texture, and internal/external traffic behavior. However, a dataset-wide proxy-tunnel byte-accounting contradiction and two highly bounded timing distributions are strong generator fingerprints that outweigh those realistic features.

## Evidence For Synthetic

- `[hard_contradiction]` Proxy CONNECT accounting is impossible across three sources. All 721 proxy CONNECT rows separately declare control-message bytes (`cs_bytes`, `sc_bytes`, `byte_scope=connect-control-message`) and tunnel bytes (`tunnel_cs_bytes`, `tunnel_sc_bytes`), but matched Zeek `conn.json` rows systematically account for only the tunnel bytes. Of 672 matched core sessions, 595 equal the tunnel counters exactly and none equal control-plus-tunnel; the DMZ sensor shows the same defect in 629 of 716 matched sessions.
- `[hard_contradiction]` At 2024-03-18 12:07:19 UTC, the proxy records 529/163 control bytes plus 1,051/26,655 tunnel bytes for `10.10.1.36 -> onenote.officeapps.live.com:443`. Zeek core UID `Cyqu34QX7FEqxrgrfF` reports exactly 1,051/26,655 bytes, omitting the visible CONNECT exchange, while ASA connection 1218660 reports 28,850 total bytes. One TCP stream cannot both contain and omit the CONNECT request/response.
- `[distribution_texture]` TLS handshake timing appears sampled from a bounded near-uniform distribution. Across all 1,595 DMZ `ssl.json` records, `ssl.ts - conn.ts` ranges only from 0.003821 to 0.652055 seconds, with successive 100 ms bins containing 220, 259, 242, 262, 241, 225, and 146 observations. Core TLS independently stops at 0.651432 seconds. The common approximately 650 ms ceiling and flat shape persist across local-to-local, outbound, and inbound paths.
- `[distribution_texture]` Recursive DNS RTTs mix native-looking microsecond precision with a large exact-millisecond population in the same Zeek source. In core DNS, 214 of 1,083 non-authoritative responses are exact millisecond values such as `0.095`, `0.022`, or `0.076`; the latter appears at timestamp `1710763641.544468` for `cdn.onenote.net`. That frequency is difficult to reconcile with packet-capture-derived Zeek RTTs while neighboring records retain six-digit precision.
- `[contract_gap]` Mirrored core/DMZ connections also show an unusually constructed observation delay: 1,714 of 1,715 matched five-tuples place DMZ observation after core by a tightly bounded 42–66 ms, with a median near 55 ms. An inter-sensor clock offset could explain one stable displacement, but not a narrow jittered band applied almost universally.
- `[environment_or_collection_plausibility]` Neither `conn.json` contains any UDP/123 traffic during the six-hour window, despite 6,051 core and 5,037 DMZ connection records, numerous domain clients, 1,022 core Kerberos connections, and 69 DHCP renewals. Filtering or an unusual time architecture could explain this, so it is secondary rather than decisive.

## Evidence For Real

- Core and DMZ connection-state mixes are contextually believable: core is dominated by successful internal traffic (`SF` 5,862/6,051), while DMZ has substantial unsolicited scan texture (`S0` 1,179/5,037) plus `RSTO`, `RSTR`, `REJ`, `S1`, `S2`, `S3`, and `OTH`.
- Packet accounting is otherwise coherent. `S0` connections have SYN-only histories and no response packets; successful TCP sessions have bidirectional packets; HTTP body totals that exceed observed payload are bounded by `resp_bytes + missed_bytes`.
- DNS has a convincing enterprise mix: A, AAAA, PTR, SRV, TXT, NS, MX, and SOA; 218 core NXDOMAINs; suffix-search names such as `wpad`, `wpad.local`, `isatap`, and `oldserver.meridianhcs.local`; and distinct authoritative versus recursive behavior.
- DHCP renewals are plausible bounded-window artifacts rather than missing acquisitions. Eight clients emit REQUEST/ACK renewals with stable lease-specific intervals and small per-renewal jitter; all DHCP UIDs resolve to connection records.
- TLS fields are internally strong: TLS 1.2/1.3 cipher selection is credible, resumed sessions omit certificate chains, non-resumed sessions reuse stable leaf and intermediate fingerprints, certificate dates are valid at observation time, and intermittent missing X.509 parsing corresponds to nonzero `missing_bytes`.
- The same `mail-clinical.meridianhcs.com` IP presents an internal-CA certificate on SMTP ports 25/587 and a public DigiCert certificate on IMAPS/993, a realistic service-specific distinction rather than random certificate churn.
- Proxy traffic includes plausible CONNECT failures, authentication failures, cache behavior, redirects, upstream errors, tunneled and bumped TLS, varied user agents, and both interactive and software-update traffic.
- External scanning is heterogeneous rather than mechanically uniform: different source populations favor SMB/RDP, Telnet, or mail ports, and include realistic mixtures of SYN timeouts, resets, ICMP, and occasional successful application sessions.

## Detailed Analysis

### Connection Patterns

`zeek-core/conn.json` contains 6,051 records over approximately six hours. Its major services are DNS (2,158), Kerberos (1,022), SMB (876), HTTP (811), LDAP (623), SSH (158), TLS (74), DHCP (69), and SMTP (67). The 96.9% `SF` rate is plausible for an interior sensor.

`zeek-dmz/conn.json` contains 5,037 records. Its 1,179 `S0` sessions largely come from internet scanners targeting `10.10.3.10`, while 3,642 sessions complete as `SF`. Scan sources show differentiated interests: `45.33.74.51` favors 445/3389/139/135/5985; `145.78.103.167` favors 23/22/2323/8080; and `38.186.148.245` favors 25/587/465/143/110. That is more realistic than one universal scanning template.

Exact five-tuples are not improperly reused during active TCP intervals. The only apparent overlaps involve ICMP records represented with pseudo-port zero, not conflicting TCP sessions.

### DNS

Core DNS has 2,151 records: 1,359 A, 277 AAAA, 266 TXT, 164 PTR, 66 SRV, plus smaller NS/MX/SOA populations. Responses include NOERROR, NXDOMAIN, SERVFAIL, and REFUSED. Authoritative answers have a much lower median RTT than recursive answers, and TTLs vary appropriately between internal values such as 300/1,800/3,600/7,200 and external CDN-like values.

The exact-millisecond recursive RTT concentration is nevertheless conspicuous. Zeek calculates RTT from packet timestamps; a mixed population where roughly one-fifth of recursive records land exactly on millisecond boundaries, while local records retain microsecond-scale values such as `0.000578`, resembles two separate generation paths.

### HTTP and Explicit Proxying

The proxy access log contains 1,420 records: 721 CONNECT, 673 GET, and 26 POST. It includes forward, tunnel, tunnel-setup, SSL-inspection, denial, authentication, and upstream-failure behaviors.

The decisive contradiction is byte ownership. For the 12:07:19 `onenote.officeapps.live.com` session:

- Proxy control message: 529 client-to-server and 163 server-to-client bytes.
- Proxy tunnel: 1,051 client-to-server and 26,655 server-to-client bytes.
- Zeek core UID `Cyqu34QX7FEqxrgrfF`: exactly 1,051 and 26,655 bytes.
- ASA connection 1218660: 28,850 aggregate bytes.

The Zeek connection must include the CONNECT exchange because its HTTP row records that exchange on the same UID at `1710763639.329480`, after the connection opens at `1710763639.226480`. Yet its TCP payload counters omit precisely those control bytes. The pattern repeats hundreds of times and therefore cannot be attributed to one capture gap.

### TLS and X.509

TLS protocol selection is plausible: DMZ records include 1,097 TLS 1.3 and 498 TLS 1.2 sessions, with current AES-GCM and ChaCha20 suites plus a smaller legacy CBC population. Certificates are consistently reused for recurring services rather than regenerated per connection. For example, all 134 observed `ehr-portal.meridianhcs.com` leaf records share one fingerprint and serial.

The timing distribution is not similarly organic. A healthy environment may have most TLS handshakes below one second, but 1,595 observations spread almost evenly across 0–650 ms and then stop abruptly. The same ceiling appearing at both sensors and across very different network paths is substantially more consistent with bounded random sampling than packet-derived latency.

### Cross-Sensor and Firewall Correlation

Mirrored flows preserve tuples, services, states, and realistic sensor-local packet-loss differences. Approximately 200 mirrored connections differ by one packet per direction, often accompanied by `G/g` history markers and nonzero missed-byte accounting; that is persuasive capture texture.

Conversely, nearly every matched DMZ timestamp occurs 42–66 ms after the corresponding core timestamp. Real sensor clock skew can create a stable offset and packet transit can create small directional differences, but this narrow always-positive jitter band across protocols and directions looks modeled.

ASA built/teardown records generally align with Zeek states and durations. The ASA totals on proxy tunnels also reinforce that the Zeek CONNECT counters are deficient rather than the proxy metadata merely being additive labels without traffic meaning.

### Infrastructure and Temporal Volume

Business-hour user bursts coexist with background scanning, mail, DHCP, authentication, and server traffic. DHCP T1-like renewal intervals are particularly credible and correctly vary by lease/client.

The complete absence of NTP is odd in this otherwise richly instrumented domain environment. Because a collection filter or centralized non-NTP time design is possible, I treat it as a moderate plausibility gap rather than an impossibility.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---:|---|
| `hard_contradiction` | Proxy, Zeek conn/http, Cisco ASA | Dataset-wide; hundreds of CONNECT sessions | Zeek TCP byte totals omit separately visible CONNECT control bytes while logging the CONNECT request on the same UID. |
| `distribution_texture` | Zeek SSL | Dataset-wide; 1,595 DMZ and 116 core TLS records | Near-uniform handshake offsets share an abrupt approximately 650 ms ceiling across sensors and network paths. |
| `distribution_texture` | Zeek DNS | Repeated; 214/1,083 core recursive responses | Mixed microsecond timestamps and unusually frequent exact-millisecond RTTs indicate separate modeled timing paths. |
| `contract_gap` | Zeek core versus Zeek DMZ | Repeated; 1,714/1,715 matched flows | Almost universal positive 42–66 ms inter-sensor offsets form a narrow synthetic-looking jitter band. |
| `environment_or_collection_plausibility` | Zeek conn | Dataset-wide absence | No UDP/123 traffic appears despite dense domain, DHCP, and authentication activity across six hours. |

## Realism Score by Category

- **Field format accuracy:** 8 — Zeek, ASA, proxy, SMTP, DNS, TLS, and X.509 shapes are strong, but CONNECT counters violate their source-native meaning.
- **Temporal patterns:** 5 — User, scan, and DHCP timing is good; TLS and inter-sensor timing show conspicuous bounded distributions.
- **Cross-source correlation:** 5 — Identity and lifecycle correlation is generally excellent, but proxy-tunnel byte accounting is materially impossible.
- **Behavioral realism:** 8 — Protocol use, scanning, proxy behavior, mail routing, and failure-state variety are credible.
- **Environmental consistency:** 7 — Host/service placement is coherent, with the main concern being absent time-synchronization traffic.

## Recommendations

If this were synthetic, the highest-impact improvement would be to make proxy CONNECT accounting obey one canonical byte contract: Zeek `orig_bytes` and `resp_bytes` must include both the CONNECT exchange and tunneled payload, while proxy and firewall counters should render their documented source-native scopes from that shared total.

Replace bounded uniform TLS-handshake delays with path- and endpoint-conditioned latency distributions that have realistic concentration, retransmission effects, and a sparse long tail. Preserve causal ordering without enforcing a shared approximately 650 ms ceiling.

Generate DNS RTTs at capture-native precision from resolver/path behavior rather than mixing millisecond-quantized external values with microsecond internal values. Model sensor clock offset separately from packet transit and capture jitter, including direction-sensitive variation where applicable.

Finally, either include low-volume NTP/MS-SNTP behavior appropriate to the visible hosts or make the collection profile visibly explain its exclusion.
