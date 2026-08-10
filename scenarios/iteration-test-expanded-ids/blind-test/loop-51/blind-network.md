# Assessment

Synthetic

# Verdict Confidence

80/100

# Synthetic-Confidence Score

74/100 — likely synthetic

# Executive Summary

The dataset presents a sophisticated, internally coherent network environment with credible Zeek, proxy, firewall, IDS, DNS, HTTP, TLS, certificate, and endpoint relationships. It is substantially more realistic than a simple event-template corpus. However, several low-level regularities are difficult to reconcile with independently captured production telemetry. Most notably, 1,845 five-tuple matches between the core and DMZ Zeek sensors have an extremely constrained inter-sensor timestamp offset of approximately 41–66 ms, averaging 54.37 ms. This looks like bounded synthetic observation jitter rather than natural clock skew or packet-path timing. Systematic TLS artifact behavior and highly parameterized protocol/timing distributions reinforce the synthetic assessment.

# Evidence For Synthetic

- **[Cross-sensor timing] Bounded Zeek observation offsets:** 1,845 core/DMZ connections matched on complete five-tuple within one second. Every matched DMZ timestamp was approximately 41–66 ms after the core timestamp, with an average offset of 54.37 ms. The offsets densely populate this narrow bounded interval. Natural dual-sensor data might exhibit stable clock skew or path-dependent latency, but this hard, randomized-looking envelope across many protocols and flows is characteristic of modeled observation delay.
- **[Cross-sensor replication] Near-lossless duplicated flow accounting:** 1,613 of the 1,845 near-time matches had exactly identical byte and packet counts across both sensors, while timestamps were independently perturbed in the narrow window above. Exact shared flow truth combined with bounded per-source time jitter strongly suggests one canonical flow rendered into multiple sensor views.
- **[TLS/X.509 semantics] Systematic TLS-version-dependent artifact omission:** In `zeek-dmz/ssl.json`, all observed non-resumed TLS 1.3 sessions lacked `cert_chain_fuids`—including 475 AES-128-GCM, 154 AES-256-GCM, and 63 ChaCha20 sessions. Conversely, most non-resumed TLS 1.2 sessions carried certificate chains and corresponding files/X.509 records. A complete version-wide omission is more suggestive of a generator capability boundary than organically incomplete capture.
- **[TLS distributions] Small compositional history vocabulary:** The 1,657 DMZ TLS records collapse heavily into a limited family of repeated `ssl_history` strings, led by `CSOFFD` (369), `CSOXYFFD` (315), `CSIFIFD` (187), and `CSXKNGIFIFD` (174). The combinations are plausible individually, but their highly reusable, state-template-like distribution is synthetic-leaning.
- **[Protocol timing] Parameterized response timing:** Internal DNS responses frequently use microsecond-resolution RTTs, whereas many public-resolution RTTs occur at conspicuously clean millisecond values such as 0.028, 0.099, 0.105, and 0.111 seconds. This split resembles separate locally generated latency models.
- **[Firewall lifecycle] Mechanically complete lifecycle rendering:** ASA built/teardown and NAT build/teardown sequences are unusually systematic. Examples include proxy transactions receiving client-to-proxy construction, proxy NAT construction, origin-flow construction, and paired teardown records with mechanically aligned integer-second durations. This is credible but resembles canonical activity rendered into each source.
- **[Connection outcomes] Strong service-state regularity:** Core traffic contains 2,151 successful DNS, 922 successful HTTP, 914 successful SMB, 780 successful UDP Kerberos, and 512 successful LDAP connections, with relatively small failure-state populations. This does not prove synthesis, but the clean service/state composition adds weight when combined with the timing artifacts.

# Evidence For Real

- **[Network architecture] Credible routed topology:** The data consistently represents internal, DMZ, and external zones, including explicit proxy traffic through `10.10.3.20:8080`, proxy-origin egress, NAT addresses, inbound Internet scanning, and separate core/DMZ observation points.
- **[Proxy semantics] Strong transaction modeling:** CONNECT denials and successes, tunnel-control byte scope, SSL inspection/bump actions, tunneled byte counters, user identities, user agents, and proxy-origin DNS/egress behavior agree well. For example, a denied Adobe CONNECT receives a 403, while allowed browser and application requests receive tunnel setup plus corresponding proxy access records.
- **[Zeek fan-out] Internally valid UID relationships:** DNS, HTTP, TLS, files, X.509, OCSP, SMTP, and connection records generally share expected UIDs/FUIDs and protocol tuples. All 594 certificate file SHA-1 values checked matched their corresponding X.509 fingerprints.
- **[Traffic diversity] Broad, plausible workload mix:** The six-hour window includes DHCP, Kerberos, LDAP, SMB, SSH, RDP, SMTP, DNS, HTTP, TLS, OCSP, Internet scans, proxy browsing, software updates, and service traffic. Connection states include SF, S0, REJ, RSTO, RSTR, S1–S3, and OTH.
- **[Packet accounting] Plausible Zeek counters:** Packet counts, payload bytes, IP bytes, histories, and connection states are broadly protocol-compatible rather than simplistic fixed-row placeholders.
- **[IDS texture] Alerts are sparse relative to total traffic:** Core and perimeter Snort logs contain 69 and 136 alerts respectively, avoiding implausible alert saturation.
- **[Certificate realism] Detailed PKI variation:** Certificates vary by issuer, algorithm, key size, validity, SANs, chain depth, and OCSP metadata. The corpus includes both enterprise and public trust structures.

# Detailed Analysis

- **Zeek connection realism:** The core sensor contains 6,218 connections and the DMZ sensor 5,445 over approximately 21,568 seconds, or six hours. Service mixes reflect sensor placement: the core is dominated by DNS, Kerberos, SMB, LDAP, proxy HTTP, and internal administrative protocols; the DMZ is dominated by external TLS, proxy HTTP, Internet scan attempts, DNS, and MySQL. This is architecturally persuasive.
- **Cross-sensor behavior:** Matching internal-to-DMZ flows retain the same tuple and usually the same traffic accounting while receiving distinct UIDs, which is correct for separate Zeek instances. The concern is not the duplicated observation itself but the uniformly bounded 41–66 ms offset. A real deployment would more commonly exhibit near-fixed clock skew with modest noise, sub-millisecond synchronized capture, or traffic-dependent path behavior—not a dense bounded jitter band applied broadly.
- **DNS:** Records contain credible qtypes, flags, answers, TTLs, NXDOMAIN/SERVFAIL behavior, AD-style authoritative internal answers, and public recursive answers. DNS-to-connection correlation is strong. Nonetheless, RTT behavior and the repeated use of a compact set of TTL/latency regimes appear parameterized.
- **HTTP/proxy:** Core and DMZ HTTP records correctly separate client-to-proxy CONNECT traffic on port 8080 from ordinary port-80 HTTP and proxy-origin TLS. No HTTP/SSL UID overlap was found in the DMZ data, avoiding the mistake of claiming passive decryption of ordinary TLS. Proxy logs contain additional bumped-request semantics unavailable to passive Zeek, which is reasonable.
- **TLS/X.509/OCSP:** TLS versions, ciphers, resumption, SNI, certificate file extraction, X.509 fingerprints, and OCSP responses are richly modeled. Certificate SHA-1 cross-checking was fully consistent. The principal authenticity concern is the categorical absence of certificate-chain references from non-resumed TLS 1.3 sessions, coupled with heavily reused handshake-history forms.
- **Firewall:** ASA records include zone-aware direction, static and dynamic NAT, connection identifiers, protocol-specific lifecycle messages, SYN timeouts, byte counts, access-group denials, and proxy egress. These are convincing individually. Their unusually complete pairing and tight agreement with Zeek/proxy lifecycles are synthetic-leaning but are not independently decisive.
- **IDS:** Snort source/destination tuples and alert types fit surrounding DNS and perimeter scanning behavior. Alert density is plausible. The alert corpus appears curated, but narrative neatness alone was not treated as evidence.
- **Coverage caveats:** The six-hour duration, selective host/source coverage, and missing activity before the observation window were not counted as synthetic indicators. Domain sanitization, file modification times, and mere correlation completeness were also excluded from the verdict.

# Synthetic Indicator Summary

- High weight: bounded 41–66 ms core-to-DMZ timestamp jitter across 1,845 matched flows.
- High weight: canonical-looking duplicated byte/packet truth combined with independently jittered sensor timestamps.
- Medium-high weight: categorical absence of certificate-chain artifacts for non-resumed TLS 1.3.
- Medium weight: compact, repeatedly composed TLS handshake-history vocabulary.
- Medium weight: distinct quantized latency regimes in DNS.
- Low-medium weight: unusually systematic firewall/NAT lifecycle completion and service-state distributions.

# Realism Categories

1. Network topology and traffic composition: 8/10
2. DNS/HTTP/proxy protocol realism: 8/10
3. TLS/X.509/OCSP realism: 6/10
4. Cross-source correlation and lifecycle realism: 8/10
5. Timing and capture-process realism: 5/10

# Recommendations

1. Replace bounded per-sensor timestamp jitter with a sensor-clock model combining stable offset, slow drift, protocol/path-dependent delay, capture batching, and occasional discontinuities.
2. Derive each sensor’s packet and byte accounting from its own visibility conditions, including asymmetric loss, truncation, retransmission visibility, capture filters, and partial-flow observation.
3. Add TLS 1.3 certificate/file/X.509 artifacts where the modeled Zeek version and capture visibility support them; otherwise model explicit version/plugin limitations across the entire source consistently.
4. Broaden TLS handshake histories based on genuine protocol state transitions and capture loss rather than selecting from a small repeated vocabulary.
5. Use continuous, resolver-specific DNS latency processes with queueing and cache-state effects instead of visibly separate clean RTT regimes.
6. Introduce limited, source-local lifecycle gaps in firewall, NAT, proxy, and Zeek observations while preserving canonical activity truth.
