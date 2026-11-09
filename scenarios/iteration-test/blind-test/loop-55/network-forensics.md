# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 43

## Executive Summary

The network records are largely convincing: protocol references, TLS visibility, proxy byte accounting, DNS behavior, and independent sensor observations generally agree. A conspicuous lower tail in TLS flow durations and application payload returning on some nominally simplex TCP syslog sessions warrant suspicion, but I did not establish an impossible same-identity chronology or another decisive authenticity contradiction.

## Evidence For Synthetic

- [distribution_texture] **TLS flow duration has an unusually abrupt lower tail across varied traffic.** In `zeek-dmz/conn.json`, 2,704 rows have `service="ssl"` and `conn_state="SF"`; 2,703 last at least 0.828642 seconds. The sole shorter flow is line 2783, UID `C9jGcziZvfgky2OFr`, duration 0.288102. The next shortest is inbound line 4334, duration 0.828642; outbound line 5415 is 0.838543. The same boundary extends into internal observations: 257 of 258 core SSL/SF observations exceed 0.8 seconds, with the exception being the same 102/450-byte flow seen at core line 3216. These observations are not all independent flows. The absence of ordinary shorter completed TLS connections across inbound, outbound, and internal activity resembles a shared duration distribution with a floor. Application connection reuse or collection selection could also explain it, so this is a moderate distribution concern, not a protocol impossibility.
- [environment_or_collection_plausibility] **Some connections identified as plain TCP syslog carry responder application payload.** `zeek-core/conn.json` line 19 (`CesEZdyJgXxmYDkwr`, timestamp 1793624480.143864, `10.10.2.25:51228 → 10.10.2.21:514`) has `resp_bytes=98` and responder data in `history="ShADadfF"`. There are 19 such positive-responder-payload observations among 96 core TCP connections labeled syslog. Database-side examples are `zeek-db/conn.json` lines 34, 35, and 36: receiver `10.10.2.40:514` sends 171, 169, and 47 application bytes respectively. Ordinary TCP syslog is simplex; TCP ACK headers do not explain `resp_bytes`. These could be a custom acknowledged protocol or misclassified service, but that qualification is needed to reconcile the records with standard syslog semantics. [RFC 6587, sections 3 and 3.2](https://www.rfc-editor.org/rfc/rfc6587.html).

## Evidence For Real

- **Network-to-protocol timing and identities hold together.** All 4,196 DNS, 4,713 HTTP, and 3,041 SSL observations reference a connection UID present in their own sensor's connection file. Every such protocol timestamp lies within its corresponding connection interval using a 1 ms end tolerance. This establishes usable evidence consistency, although completeness itself does not distinguish real from synthetic.
- **TLS fields respect major passive-observation constraints.** Across all three sensors, the 1,901 TLS 1.3 records have no `cert_chain_fuids`; their visible history is normally `Cs`. TLS 1.2 has full-handshake and resumed forms, with certificate references on full handshakes and none on the sampled resumed examples. RSA-authenticated cipher suites do not reference ECDSA leaf keys in the checked certificate-linked records.
- **Multiple sensors retain recognizable, distinct observations.** The same client/proxy flow appears at `zeek-core/conn.json` line 3 and `zeek-dmz/conn.json` line 1 with different UIDs, identical payload counts, and slightly different durations. Its DMZ timestamp is 115.093 ms earlier, consistent with a sensor clock offset rather than an impossible causality claim.
- **DNS has meaningful variation.** Core DNS includes A, AAAA, PTR, SRV, TXT, NS, MX, and SOA; it contains 210 NXDOMAIN, 19 SERVFAIL, and 3 REFUSED observations. TTLs include both fixed authoritative values and short/cache-like remaining values. `zeek-dmz/dns.json` line 1 resolves `ocsp.pki.goog` before a connection to one returned address at `zeek-dmz/conn.json` line 5.
- **The environment has plausible separation of duties and imperfect transport outcomes.** Core traffic emphasizes DNS, Kerberos, LDAP, SMB, and proxy access; the database sensor emphasizes TCP/3306; the DMZ observes proxy egress and public ingress. TCP reset, rejection, incomplete, retransmission, and gap histories are present, and all observed gap histories have positive `missed_bytes` rather than a contradictory zero.

## Detailed Analysis

### Input provenance, method, and qualifications

I read the supplied neutral briefing at `/private/tmp/log-study-6dyv3d6d/network-prompt.md` and inventoried only its supplied data directory. I parsed all JSON files under `data/zeek-core`, `data/zeek-dmz`, and `data/zeek-db` with system `python3`, executing from `/private/tmp`. I also read initial records and counted the perimeter ASA, core/perimeter Snort, and proxy access files. I did not inspect repository files, authored scenarios, project memory, prior reports, neighboring reviewer outputs, or filesystem timestamps as authenticity evidence.

The only external material accessed was direct official Zeek documentation for connection and SSL field semantics and direct RFC Editor pages for RFC 6587 and RFC 5424. No general web search was used. Generic project-oriented instructions inherited from the host environment were not treated as input evidence about these logs.

This is an AI-assisted technical review applying the assigned network-forensics perspective. I do not claim personal incident-response employment, expert-witness credentials, or packet-capture access. No PCAP, collector configuration, Zeek version declaration, or sampling policy was supplied, which limits conclusions about service classification and duration distributions. Logged commands were treated as inert text; none was executed.

All line references below and above are one-based physical lines relative to the supplied `data` directory. Sensor duplicates are observations, not additional independent sessions.

### Inventory and observation window

| Sensor | conn | dns | http | ssl | files | x509 |
|---|---:|---:|---:|---:|---:|---:|
| zeek-core | 12,382 | 3,180 | 2,223 | 316 | 696 | 197 |
| zeek-dmz | 9,629 | 980 | 2,479 | 2,709 | 1,721 | 1,088 |
| zeek-db | 498 | 36 | 11 | 16 | 18 | 18 |

The visible connection starts span approximately 2026-11-02 13:00–19:00 UTC. Core hourly connection counts are 1,779, 3,113, 1,724, 1,856, 2,192, and 1,718. DMZ counts are 1,561, 2,701, 1,143, 1,485, 1,449, and 1,290. This is not a flat per-hour workload, and both sensors show an elevated 14:00 hour. A six-hour slice cannot establish overnight or weekly behavior; their absence is neutral.

### Transport state and accounting

Core state counts include SF 9,865, S0 1,741, OTH 420, RSTO 171, RSTR 106, and REJ 45. DMZ has SF 6,427 and S0 2,637, alongside resets, rejects, and incomplete states. I did not interpret all S0 rows as failed TCP: many core S0 records are ordinary unidirectional UDP syslog. Zeek treats UDP as flows; its state and history must be read with transport context. [Zeek connection field reference](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

The byte fields generally survive basic arithmetic scrutiny. No connection has IP bytes below its corresponding payload bytes, and no TCP direction has IP bytes below a 40-byte-per-observed-packet minimum. Clean SF TCP flows without gaps or retransmission history have header/payload differences aligned to four-byte header lengths. No observed file's `seen_bytes` exceeds its associated direction's connection payload. Minimum HTTP start-line, body, and framing lengths likewise do not exceed connection payload totals in the checked HTTP groups.

Content gaps appear in 490 core, 661 DMZ, and 49 database observations; every one has positive `missed_bytes`. The gap counts differ between sensors observing common flows, which is compatible with source-local capture loss. The counts are not a contradiction simply because a protocol could have been partially analyzed before loss.

A secondary, low-weight texture observation is that 220 of 243 clean database SF TCP flows satisfy `orig_pkts = ceil(orig_bytes/1460) + 3`. Database line 1, for example, sends 4,124 originator bytes in six packets and receives 30,340 responder bytes in 25 packets. This is compatible with small request packets and offload/ACK behavior; without PCAP it does not justify claiming impossible packetization. I have not used this observation as a separate scored synthetic indicator.

### Sensor offsets and proxy semantics

Matching exact five-tuples with starts within one second produced 4,759 core/DMZ pairs. The median DMZ-minus-core start difference was −114.227 ms with a roughly 2.61 ms standard deviation. The 359 DMZ/database pairs had a median database-minus-DMZ difference of +179.709 ms. These are recognizable sensor clock offsets, with variation, rather than evidence that DNS or transport happened after application activity.

The opening proxy transaction is particularly useful:

- DMZ connection line 1: client `10.10.1.32:57530 → 10.10.3.20:8080`, UID `C0Nhhio9UD4kCLDsXZ`, payload 4,794/35,048 bytes.
- DMZ HTTP line 1: successful CONNECT to `clients6.google.com:443` on that UID.
- DMZ connection line 2: upstream `10.10.3.20:34135 → 142.250.190.110:443`, UID `CyfuWzWe7S7ISfAaY3`, payload 4,274/34,835 bytes.
- Proxy access line 1: `cs_bytes=520`, `wire_sc_bytes=213`, `tunnel_cs_bytes=4274`, `tunnel_sc_bytes=34835`.

The client/proxy totals equal CONNECT control plus tunnel payload: 520 + 4,274 = 4,794, and 213 + 34,835 = 35,048. The upstream uses a distinct source port and UID. ASA line 1 further shows the upstream source NAT translation to `203.14.220.1/43398`. This is coherent proxy evidence, not an inappropriate assumption that the workstation itself originated the public TCP flow.

### DNS and TLS

Core DNS query-type counts are A 2,282, TXT 362, AAAA 283, PTR 129, SRV 102, NS 9, MX 7, SOA 6. A large TXT component alone is not an authenticity flaw. Internal service discovery, successful and failed lookups, and different cache lifetimes are represented. DNS RTTs are not all fixed: core median is about 4.18 ms, DMZ about 22.02 ms, with both very short and multi-second observations.

The DMZ OCSP-name example is temporally sensible: DNS line 1 has timestamp 1793624407.227488 and RTT 0.000832; connection line 5 begins at 1793624409.607864 to returned address `142.250.190.99:80`. This is a within-sensor comparison and needs no clock correction. I did not require a fresh lookup for every connection, since caches and the pre-window period exist.

DMZ SSL version counts are TLS 1.3 1,750, TLS 1.2 954, and five unnegotiated/unspecified versions. Core has 151 TLS 1.3, 164 TLS 1.2, and one unspecified. The database sensor has 16 TLS 1.2 observations. This mix is plausible for public services plus older internal software. Modern TLS 1.3 suites, ECDHE-GCM TLS 1.2 suites, and a smaller internal CBC component are not intrinsically contradictory.

For example, DMZ SSL line 1 describes a full TLS 1.2 ECDSA-authenticated handshake and links certificate files; line 2 describes TLS 1.3 with `ssl_history="Cs"` and no visible certificate chain. Database SSL line 2 describes a resumed TLS 1.2 session with `ssl_history="CsiI"` and no new certificate references. These are coherent uses of SSL history and resumption fields. [Zeek SSL field reference](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html).

The duration-tail issue remains a distribution finding about whole connections, not a claim that TLS must finish in less than 0.8 seconds or that `duration` measures handshake RTT. Successful TLS flows can legitimately remain open for seconds or minutes. What is unusual is how thoroughly the shorter completed-connection tail disappears across many unrelated sessions and directions.

### Interpretation and limits

The strongest question is about the 19 TCP syslog flows with return application bytes. RFC 6587 describes fixed sender/receiver roles and no application back channel. A local protocol extension, RELP-like arrangement on an unusual port, or service-labeling policy could explain these records, so I classify the observation as collection/environment plausibility rather than a proven hard contradiction. No application payload is supplied to resolve it.

The remaining timing and cross-source checks are favorable. That is why a confidently synthetic score would overstate the evidence. Equally, the duration distribution and syslog semantic question prevent calling the sample indistinguishable from production. The score of 43 reflects mixed evidence, while the verdict-confidence score of 82 reflects confidence that the available network data does not resolve origin decisively.

## Synthetic Indicator Summary

| Category | Source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek conn / TLS-classified flows | 2,703 of 2,704 DMZ SSL/SF observations at least 0.828642 s; comparable absence of short flows internally | Moderate suspicion of a shared bounded duration distribution; alternative collection/application explanations remain |
| environment_or_collection_plausibility | Zeek conn / TCP syslog | 19 of 96 core TCP syslog observations return application bytes; database-side examples corroborate the behavior | Moderate protocol/labeling question; ordinary simplex syslog does not explain it, but custom protocol semantics could |

No hard contradiction or generator identity leak was established. Repeated observation of a flow by multiple sensors is counted once conceptually when weighing an indicator.

## Realism Score by Category

- **Field format accuracy:** 9 — JSON types, IDs, histories, payload/header accounting, and TLS fields are generally convincing; TCP syslog classification needs explanation.
- **Temporal patterns:** 7 — Variable hourly loads and coherent sensor offsets, with an unusually absent short-duration TLS tail.
- **Cross-source correlation:** 9 — Protocol UID/timing checks and proxy/NAT accounting work; no demonstrated impossible same-identity ordering.
- **Behavioral realism:** 7 — Plausible proxy, domain-service, database, and scanning behavior, tempered by syslog response semantics and TLS duration texture.
- **Environmental consistency:** 8 — Sensor roles and service concentrations fit together; custom TCP syslog behavior is the principal unresolved environment question.

## Recommendations

- If this were synthetic, vary whole-connection duration by actual application and connection-reuse behavior, including an evidence-supported population of shorter successful TLS flows. Avoid imposing one common lower bound on unrelated inbound, outbound, and internal services.
- If this were synthetic, generate zero responder application payload for ordinary plain TCP syslog while retaining genuine TCP ACK packets and IP bytes. If acknowledged logging or another custom protocol is intended, label and document that protocol consistently rather than relying on generic syslog semantics.
- Preserve the existing distinctions between proxy control bytes and tunnel bytes, source NAT and original tuples, TLS 1.2 and TLS 1.3 visibility, and source-specific sensor clock/capture effects. These are supported strengths of the supplied records.
