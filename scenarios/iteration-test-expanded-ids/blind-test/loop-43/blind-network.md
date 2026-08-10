# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 76  
**Synthetic-Confidence Score:** 67

## Executive Summary

The telemetry is technically strong: Zeek schemas, TCP state transitions, TLS chains, packet-loss artifacts, proxy behavior, and smoothly drifting sensor clocks are unusually convincing. However, repeated impossible HTTP body-length disagreements between two sensors observing identical gap-free TCP streams, combined with a thin and highly structured inbound-scan population, push the assessment toward synthetic.

## Evidence For Synthetic

- `[hard_contradiction]` Fifteen matched HTTP transactions have different `response_body_len` values between `zeek-core/http.json` and `zeek-dmz/http.json` even though their corresponding `conn.json` records report identical bytes, packets, histories, and `missed_bytes: 0`. At `2024-03-18T12:52:05.995725Z`, the transaction for `10.10.1.31:53208 -> 10.10.3.10:80`, URI `/assets/css/main.min.07b8945e.css`, reports 5,758 response-body bytes at core and 5,819 at DMZ. Both connection records report `orig_bytes=4732`, `resp_bytes=714419`, `orig_pkts=245`, `resp_pkts=494`, `history=ShADadfF`, and zero missing bytes. Two Zeek analyzers receiving the same complete TCP byte stream cannot derive different entity-body lengths for the same HTTP transaction.
- `[hard_contradiction]` The same defect repeats across unrelated clients and objects: `/assets/img/content/a9d1ac6d.jpg` is 147,136 versus 146,505 bytes at `12:52:20Z`; `/assets/img/content/e1847311.jpg` is 212,109 versus 212,603 at `13:14:44Z`; and `/assets/js/app.bundle.d8a74c0f.js` is 130,372 versus 131,677 at `17:23:02Z`. Their connection-level counters are again identical and gap-free.
- `[distribution_texture]` In `zeek-dmz/conn.json`, 944 external failed inbound attempts target `10.10.3.10`; 940 originate from only nine recurring IPs, while just four sources appear once. The dominant sources persist for nearly the full six-hour window and divide into unusually clean port-interest families: `45.33.74.51` generates 151 Windows-service probes, `37.75.195.175` generates 147 Telnet/SSH/HTTP probes, and `38.186.148.245` generates 144 mail-service probes. Real Internet background normally has a substantially longer tail of transient scanners.
- `[distribution_texture]` DHCP renewals show nearly invariant per-host periods. For example, `WS-MCHEN-01` has ten intervals averaging 1,969.687 seconds with 0.586-second standard deviation, while `WS-PPATEL-01` averages 1,692.693 seconds with 0.619-second deviation. Stable DHCP scheduling is legitimate, but the combination of individualized periods and sub-second dispersion across every visible client resembles deterministic periodic-plus-jitter generation.
- `[weak_signal]` The DMZ sensor records no successful response from any of the recurring external scanning campaigns—almost every attempt is an `S0`—while maintaining richly varied successful internal and outbound traffic. This is possible under perimeter filtering, but the binary separation adds to the templated scan texture.

## Evidence For Real

- TCP state semantics are internally coherent. Core traffic includes `SF`, `RSTO`, `RSTR`, `REJ`, `S0`, `S2`, `S3`, and `OTH`, with believable histories and packet directionality; sampled `S0` rows contain an initiating packet and no response, while `REJ` rows contain responder resets.
- The two Zeek sensors exhibit realistic independent observation behavior. Matched connection UIDs differ, and their median clock offset drifts smoothly from approximately 45.264 milliseconds during hour 12 UTC to 62.323 milliseconds during hour 17 UTC rather than using one exact offset.
- Capture-loss handling is unusually convincing. For TLS UID `CWRBzQUeOfBLToWuaKk`, `ssl.json` references two certificate FUIDs absent from `x509.json`; `files.json` explains this with incomplete certificate objects—1,468 of 1,471 bytes and 1,439 of 1,442 bytes observed. Similar incomplete-certificate cases recur with nonuniform byte deficits.
- DNS telemetry contains a plausible mix of A, AAAA, PTR, SRV, TXT, NS, MX, and SOA questions, along with NOERROR, NXDOMAIN, SERVFAIL, and REFUSED responses. RTTs range from local sub-millisecond answers to multi-second responses, and internal versus external TTL behavior is differentiated.
- TLS telemetry has a credible TLS 1.2/1.3 mix, modern AES-GCM and ChaCha20 suites, some resumed sessions, consistent SNI-to-leaf-SAN relationships, repeated fingerprints for reused certificates, and no certificates outside their validity interval.
- Proxy activity distinguishes denied requests, ordinary forwarding, CONNECT tunnels, and SSL inspection. The proxy log includes separate control-message and tunnel byte scopes, avoiding the common mistake of equating CONNECT response size with tunneled payload.
- Firewall lifecycle records agree with network behavior: for example, the opening `S0` probe from `45.33.74.51:17207` to TCP/445 receives an ASA build record followed by a 30-second, zero-byte `SYN Timeout` teardown.
- I did not treat absent initial DHCP discovery, sessions potentially crossing collection boundaries, complete UID relationships, or the compact suspicious DNS activity as synthetic indicators.

## Detailed Analysis

### Collection Window and Traffic Mix

Both Zeek connection files cover approximately `2024-03-18T12:00Z` through `17:59Z`. Core contains 6,051 connections: 3,033 TCP, 2,940 UDP, and 78 ICMP. DMZ contains 5,037 connections: 4,251 TCP, 732 UDP, and 54 ICMP. The core mix is dominated by DNS, Kerberos, SMB, HTTP proxying, LDAP, SSH, DHCP, SMTP, and TLS; DMZ adds substantial HTTPS, public HTTP, MySQL, and unsolicited inbound traffic.

The hourly volume is irregular rather than mechanically uniform. Core ranges from 921 to 1,173 connections per hour, while DMZ ranges from 703 to 1,115. The visible period maps to daytime business activity, so the lack of overnight evidence is a bounded-window property and was not scored.

### TCP Connections and Sensor Behavior

State/history combinations are source-native and varied. Core includes 5,862 `SF`, 74 `RSTO`, 54 `RSTR`, 20 `REJ`, 16 `S0`, 12 `OTH`, eight `S3`, and five `S2` connections. DMZ appropriately has far more incomplete connections: 1,179 `S0` against 3,642 `SF`.

Across 1,715 tuple-and-time-matched core/DMZ connections, the median sensor offset changes gradually by hour: 45.264, 48.739, 52.243, 56.605, 58.490, and 62.323 milliseconds. Independent UIDs plus monotonic clock skew are strong production-like details.

The strongest authenticity failure appears above this layer. For 15 exact HTTP transaction matches, connection counters and packet histories are identical and gap-free, but parsed body lengths differ. This is not explainable as separate sensor capture loss because both rows explicitly report zero missed bytes and matching stream totals. Other differing transactions do have corresponding `missed_bytes`, which makes the unexplained gap-free cases more conspicuous.

### DNS

Core has 2,151 DNS rows: 1,359 A, 277 AAAA, 266 TXT, 164 PTR, 66 SRV, ten NS, six MX, and three SOA. Result codes include 1,914 NOERROR, 218 NXDOMAIN, 16 SERVFAIL, and three REFUSED. All use the modeled resolver at `10.10.2.10`, while client distribution varies considerably.

Local records generally use stable infrastructure TTLs such as 300, 600, 1,800, and 3,600 seconds. External TTLs vary and sometimes reach very low residual values. The dense TXT sequence from `10.10.2.30` beginning near `16:44:59Z` has low TTLs and rapidly changing subdomains, but it is credible automated or malicious DNS behavior rather than an authenticity defect.

The 701 DNS records visible at both sensors retain identical semantic fields while receiving sensor-local UIDs and timestamp offsets. I found no visible case where the same DNS transaction occurs after a dependent connection in an impossible order.

### HTTP and Proxy Traffic

HTTP methods and statuses are plausible: CONNECT dominates proxy-facing traffic, while GET and POST are used for direct and inspected traffic. Core records 897 HTTP transactions, including 673 CONNECTs, with success, proxy-authentication, deny, upstream-error, cache-validation, and redirect statuses.

Persistent direct HTTP connections show realistic `trans_depth` values and asset fan-out. Proxy access rows distinguish `forward`, `tunnel`, `tunnel-setup`, and `ssl-inspect`, and supply tunnel byte counts separately from CONNECT control-message sizes.

The cross-sensor body-length contradiction affects 15 of 891 semantically matched HTTP observations where no stream-counter difference or missing data exists. Additional body-length differences accompanied by `missed_bytes` are plausible and were not counted as defects.

### TLS, Certificates, and Files

Core has 116 TLS rows; DMZ has 1,595. TLS 1.3 is dominant but TLS 1.2 remains common. Cipher selections fit a mixed modern environment, including AES-128/256-GCM, ChaCha20-Poly1305, ECDHE-RSA, and a smaller amount of CBC.

Certificate identities and validity periods are coherent. Leaf SANs match observed SNI values wherever both are available. Certificate fingerprints repeat across sessions while FUIDs remain observation-specific. Incomplete certificate files explain absent X.509 parsing, providing realistic capture-imperfection texture rather than arbitrary log omission.

### DHCP and Infrastructure Timing

The core sensor records 69 DHCP REQUEST/ACK renewals across eight clients. Initial lease acquisition could precede the window, so the absence of DISCOVER/OFFER sequences was not penalized.

Renewal intervals are host-specific and extremely stable. Examples include `WS-OHADDAD-01` at 1,787.576 ± 0.770 seconds, `WS-LNGUYEN-01` at 1,940.563 ± 0.782 seconds, and `WS-AJOHNSON-01` at 3,841.489 ± 1.120 seconds. Operating-system timers and DHCP T1 values can create regularity, so this is not a contradiction, but the repeated sub-second variance across all clients is a noticeable synthetic texture.

### External Scanning and Lateral Services

Internet-originated background probes focus on TCP/23, 25, 445, 3389, 2323, 22, 587, 465, 443, 139, 135, and 5985. Port selection is credible, and source ports and interarrival times vary. The weakness is population shape: nearly all 944 failed probes come from nine long-lived actors, each specializing in a clean service family, with almost no one-off scanner tail.

Internal sensitive-port traffic is richer and mostly successful: SMB, LDAP, SSH, RDP, Kerberos, and MySQL show varied durations and closure states. Successful SSH and RDP sessions include both short administrative activity and longer-lived sessions, consistent with a mixed enterprise environment.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Zeek HTTP/conn across core and DMZ | 15 repeated transactions | Identical complete TCP streams produce different HTTP entity-body lengths, which is not source-native behavior. |
| `distribution_texture` | Zeek DMZ inbound connections | 944 failed probes; 940 from nine recurring sources | The scanner population lacks a realistic transient long tail and divides into overly clean service-interest families. |
| `distribution_texture` | Zeek DHCP | All eight visible clients | Renewal schedules use host-specific periods with consistently sub-second dispersion, suggesting deterministic periodic jitter. |
| `weak_signal` | Zeek DMZ/perimeter firewall | Recurring external scan campaigns | Near-total `S0` outcomes are possible under filtering but reinforce the binary, templated background-noise profile. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, IDS, proxy, TLS, and X.509 records are source-native and internally detailed.
- **Temporal patterns:** 6 — Sensor drift and user traffic are convincing, but DHCP and scanner timing/population textures are conspicuously controlled.
- **Cross-source correlation:** 6 — Most relationships are excellent, but repeated gap-free HTTP body-length contradictions are decisive.
- **Behavioral realism:** 7 — Enterprise services, proxy use, Internet noise, and suspicious DNS behavior are plausible; scan-source diversity is weak.
- **Environmental consistency:** 8 — Network roles and protocol placement are coherent, with no broad topology contradiction visible.

## Recommendations

- If this were synthetic, derive each HTTP transaction’s semantic body lengths once and preserve those values across every observing sensor. Sensor-specific loss should alter parser output only when the corresponding stream explicitly records gaps or incomplete data.
- Expand unsolicited Internet noise with a larger transient-source population, overlapping scanner interests, one-off probes, short bursts, and varied campaign lifetimes while retaining a smaller number of persistent actors.
- Model DHCP renewal timing from explicit T1/T2 lease options or realistic client timer behavior. Avoid applying a nearly fixed, host-specific interval plus only sub-second jitter across every renewal.
- Preserve the existing sensor-local UIDs, clock drift, TCP history diversity, proxy byte scoping, and certificate-loss semantics; these are the dataset’s strongest production-like characteristics.
