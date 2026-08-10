# Network Forensics — Authenticity Assessment

## Verdict

- Assessment: Synthetic
- Verdict Confidence: 72%
- Synthetic-Confidence Score: 64/100
- Rubric classification: Likely synthetic

## Executive Summary

The network telemetry is technically sophisticated and internally plausible, but several population-level patterns suggest coordinated generation rather than organically collected traffic.

The strongest indicator is the behavior of 1,909 flows observed by both Zeek sensors: every DMZ observation starts later than its core counterpart within an unusually narrow 41.7–66.4 ms envelope, while 1,660 pairs have all eight packet-accounting fields exactly equal. The proxy data also resembles probabilistic outcome injection: isolated `407`, `403`, and gateway failures occur across otherwise successful clients and destinations without the retry behavior normally associated with proxy authentication.

Conversely, TLS handling is unusually strong. TLS 1.3 sessions correctly lack visible certificate chains, while TLS 1.2 certificate visibility tracks full versus resumed handshakes. DNS, Zeek connection states, protocol fan-out, firewall records, and IDS alerts also contain substantial realistic variation.

## Evidence For Synthetic

### Multi-sensor timing

- 1,909 core/DMZ flows matched on the complete five-tuple within 200 ms.
- Every DMZ timestamp was later than the corresponding core timestamp.
- Start offsets were confined to 41.655–66.446 ms, with a 55.871 ms median.
- Corresponding flow end times remained in essentially the same bounded envelope.
- Duration differences had a 0 ms median and only 0.512 ms standard deviation.
- This resembles an explicit per-sensor delay model. Independent sensors would more commonly show a stable clock skew, sub-millisecond forwarding latency, packet-loss differences, capture batching, or less uniformly one-sided variation.

### Mirrored packet accounting

- Of the 1,909 matched observations, 1,660 had exact equality across:
  `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `orig_pkts`,
  `resp_pkts`, `orig_ip_bytes`, and `resp_ip_bytes`.
- Exact accounting is possible for mirrored traffic, but its combination with randomized-looking, tightly bounded timestamp offsets is more characteristic of duplicating one canonical connection into two sensor views.

### Proxy behavior

- Core HTTP contains 23 `407`, 34 `403`, and several `502`–`504` outcomes.
- The `407` responses appear as isolated terminal CONNECT transactions for users and agents that otherwise communicate successfully through the proxy, including browsers, Windows services, update agents, and security clients.
- Examples include challenges for `portal.azure.com`, `docs.google.com`, `res.cdn.office.net`, Windows Update, and Cisco Secure Client traffic.
- The distribution resembles independent per-request outcome sampling more than stateful proxy authentication, where challenges normally provoke an immediate authenticated retry or consistently affect a particular client/configuration.

### DNS population shaping

- Frequently queried external names generally expose only one or two answer sets across the entire six-hour interval. Examples include `pypi.org` with 26 queries and two sets, `api.snapcraft.io` with 17 and two, and `registry.npmjs.org` with 14 and two.
- This consistent cap across unrelated services suggests predefined answer pools.
- DNS tunneling evidence itself is coherent, but its TTLs are heavily quantized at very small integral values, especially `1.0`, and the generated-looking label components draw attention to a parameterized construction pattern.

### HTTP population texture

- All 2,172 Zeek HTTP records use HTTP/1.1.
- Many unrelated HTTPS destinations repeatedly use a single URI, commonly `/`, while failures are distributed across them in similar ways.
- User-agent diversity is good, but combinations such as `python-requests`, browsers, update agents, and management software receive broadly similar proxy error classes, suggesting shared probability rules rather than application-specific behavior.

## Evidence For Real

### TLS semantics

- DMZ TLS contains 1,112 TLS 1.3 and 523 TLS 1.2 sessions.
- All TLS 1.3 sessions lack certificate-chain visibility, which is correct for passive inspection of encrypted TLS 1.3 handshake certificates.
- The 202 certificate-less TLS 1.2 sessions align with resumed handshakes; 321 non-resumed TLS 1.2 sessions expose certificates.
- Repeated host certificates retain stable fingerprints and serials.
- Certificate chains include leaf/intermediate structure, realistic validity periods, SANs, algorithms, and key sizes.

### Zeek protocol structure

- Connection-state diversity includes `SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `S1`, `S2`, `S3`, and `OTH`.
- Histories vary meaningfully and agree with states: `S` dominates unanswered DMZ scans, while established traffic includes multiple data, teardown, and reset patterns.
- No successful TCP `SF` connection was found with zero duration or fewer than two packets in either direction.
- DNS `rtt` matches corresponding UDP connection duration and uses substantial microsecond-scale variation.
- TLS, HTTP, SMTP, SMB file, X.509, OCSP, PE, DHCP, firewall, and IDS views use source-appropriate fields rather than one flattened schema.

### DNS realism

- DNS includes A, AAAA, PTR, SRV, TXT, MX, NS, and SOA traffic.
- Responses include `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`.
- Internal authoritative answers, AD service discovery, reverse lookups, WPAD/ISATAP failures, external TTL variation, and low-volume resolver noise are represented.
- The suspicious TXT activity forms a technically plausible tunneling pattern rather than malformed DNS.

### Firewall and IDS evidence

- ASA records distinguish inbound, outbound, inside, DMZ, and outside semantics and include connection IDs, NAT views, durations, byte counts, and teardown reasons.
- DMZ scanning produces realistic `S0` Zeek histories and SYN-timeout firewall records.
- Snort alerts use plausible signatures, classifications, priorities, transport protocols, and source/destination tuples.
- Alert volume is restrained relative to the 11,541 Zeek connections rather than treating every unusual event as an alert.

### Timing and traffic mix

- The six-hour dataset is not uniformly spaced.
- Long SSH sessions coexist with short DNS, web, mail, SMB, authentication, scanning, and failed-connection traffic.
- Packet counts, byte counts, connection durations, TLS reuse, and file-transfer sizes show broad variation.

## Detailed Analysis

The core sensor records 6,200 connections; the DMZ sensor records 5,341. Core traffic is dominated by DNS, Kerberos, HTTP, SMB, and LDAP, while DMZ traffic emphasizes TLS, HTTP, DNS, MySQL, and external scans. This division is topologically plausible.

Connection lifecycle modeling is strong. The core sensor has 5,977 `SF` connections, while the DMZ sensor has 1,113 `S0` entries consistent with perimeter scanning. TCP histories and packet counters are compatible with their stated outcomes.

TLS is the most convincing subsystem. Its certificate visibility reflects passive-observation constraints rather than simply attaching a certificate to every successful session. Stable fingerprints, chain identities, OCSP responses, and certificate-derived file records reinforce this.

The authenticity concern emerges at scale. Mirrored sensor observations behave as if a canonical record was cloned and assigned a bounded sensor delay. Similarly, the proxy’s authentication and error outcomes do not demonstrate enough client-session state. DNS answers and HTTP resource selection also appear drawn from constrained pools.

These are structural generation indicators, not conclusions based on sanitized names, dataset size, file metadata, or the apparent storyline.

## Synthetic Indicator Summary

| Category | Indicator | Weight |
|---|---|---:|
| Sensor timing | All 1,909 matched DMZ observations follow core by 41.7–66.4 ms | High |
| Sensor accounting | 1,660 matched pairs have exact equality across eight accounting fields | Medium |
| Proxy state | Isolated authentication challenges across otherwise successful clients | Medium-high |
| DNS diversity | Popular unrelated names repeatedly limited to one or two answer sets | Medium |
| HTTP texture | Uniform HTTP/1.1 and heavily reused URI patterns across applications | Low-medium |

## Realism Score by Category

| Category | Score |
|---|---:|
| Zeek connection and topology realism | 8/10 |
| DNS realism | 7/10 |
| TLS/X.509/OCSP realism | 9/10 |
| HTTP and proxy realism | 6/10 |
| Firewall, IDS, and timing realism | 7/10 |

## Recommendations

- Model each sensor from packet-observation characteristics rather than applying a bounded timestamp offset to a canonical flow. Include clock drift, capture loss, batching, asymmetric visibility, and occasional packet-count differences.
- Make proxy authentication stateful per client, process, and session. A `407` should normally produce a prompt retry, persistent failure, or a client-specific configuration consequence.
- Tie proxy errors to destination policy and upstream state rather than sampling them independently per request.
- Expand DNS answer behavior with TTL-aware caching, resolver selection, CDN rotation, negative caching, and longer-lived stable mappings where appropriate.
- Add application-specific HTTP protocol behavior, including HTTP/2 where observable, richer resource trees, redirects, cookie/auth sequences, and differing retry policies.
- Preserve the existing TLS model; its TLS 1.3 visibility and TLS 1.2 resumption behavior are among the dataset’s strongest realism features.
