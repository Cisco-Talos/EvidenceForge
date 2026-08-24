# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 47

## Executive Summary

The network telemetry is technically strong: Zeek state/history combinations, OS-specific ephemeral-port behavior, DNS response texture, TLS semantics, and multi-source tuple correlation are unusually convincing. The main counterweight is a repeated proxy-path causality defect in which upstream TLS connections precede the only visible A lookup for the same SNI and destination IP; combined with a complete absence of NTP traffic in an otherwise richly observed domain network, this leaves the dataset mixed rather than confidently production-like.

## Evidence For Synthetic

- `[contract_gap]` Several explicit-proxy bursts open upstream TCP/TLS sessions before the proxy's only visible A lookup for the destination. At 17:14:21 UTC, `PROXY-01.../proxy_access.log` records a client `CONNECT cache.rollbar.org:443`; `zeek-dmz/conn.json` then shows `10.10.3.20:53866 -> 52.84.57.248:443` at 17:14:21.844995 and `ssl.json` identifies SNI `cache.rollbar.org` at 17:14:21.921854. The proxy's A query does not appear until 17:14:25.725812, when it returns that exact IP with TTL 30. Two additional upstream connections begin at 17:14:24.555691 and 17:14:25.152613 before the lookup.
- `[contract_gap]` This is repeated rather than isolated. `customer.cloud.com` has multiple upstream TLS handshakes from 12:09:37 through 12:09:40 before the A lookup at 12:09:40.527082; `slack.com` has upstream TLS at 15:40:22.773894 before its only A lookup at 15:40:24.674511. Across 1,524 proxy-origin TLS records with SNI, 143 had no prior same-name A lookup from the proxy in the visible window but did have one later.
- `[weak_signal]` A pre-window or stale proxy cache could explain individual cases, so the ordering is not treated as an absolute impossibility. That explanation is weak for the 17:14 `cache.rollbar.org` burst, however: it occurs more than five hours into the window, no earlier proxy lookup is visible on either Zeek sensor, and the later answer has a 30-second TTL.
- `[environment_or_collection_plausibility]` Neither Zeek connection view contains any UDP/123 traffic among 14,861 connection records. The same collection observes 1,875 core DNS connections, 1,020 Kerberos connections, 611 TCP/389 connections, and 48 DHCP transactions across active Windows and Linux systems, so total absence of domain or host time synchronization is an unusual infrastructure-family gap. A capture filter, hypervisor time source, or unusually long poll interval could explain it, so this is lower impact than the DNS ordering.

## Evidence For Real

- Connection-state texture is credible and sensor-specific. Core contains 5,330 `SF`, 1,500 `S0`, 68 `RSTO`, 37 `RSTR`, 17 `REJ`, and smaller `S1`/`S2`/`S3`/`OTH` populations; DMZ has a different but plausible mix of 5,051 `SF`, 2,607 `S0`, 103 `RSTO`, 54 `RSTR`, and 19 `REJ`.
- TCP histories agree with their states: rejected connections use `Sr`, unanswered attempts use `S`, origin resets use forms such as `ShADaR`, and normal sessions contain varied teardown/data histories rather than one template. No negative durations or payload/IP-byte inversions were found.
- OS-specific ephemeral-port behavior is particularly convincing. Windows workstations `10.10.1.31` through `10.10.1.36` generated no TCP source port below 49152, with minima of 49168–49256. Linux clients `10.10.1.21`, `.22`, and `.99` used 32768–60999-style ranges, with approximately 55–58% of their source ports below 49152.
- DNS contains a realistic long tail. Core records include 1,306 A, 132 AAAA, 79 PTR, 65 SRV, and 283 TXT queries, with 1,686 `NOERROR`, 163 `NXDOMAIN`, 15 `SERVFAIL`, and 6 `REFUSED` responses. `wpad`, `isatap`, suffix-appended names, reverse lookups, SPF/DKIM records, empty successful AAAA responses, and diverse TTLs are all represented.
- DNS transaction fields are internally sound: NXDOMAIN/error responses have no answers or TTLs, answer and TTL arrays have matching lengths, RTTs are positive and varied, and successful A answers align with the destination IPs used by later TLS sessions when a prior lookup exists.
- TLS semantics are strong. DMZ contains 1,451 TLS 1.3 and 700 TLS 1.2 sessions with appropriate cipher families and 760 resumed handshakes. TLS 1.3 sessions generally omit passive certificate extraction, while non-resumed TLS 1.2 sessions frequently carry one- or two-certificate chains; all 845 certificate references resolve, sampled SNI/SAN relationships match, and no certificate is used outside its validity interval.
- DHCP renewal behavior follows lease semantics without exact clocks. For example, `10.10.1.21` renews a 3,600-second lease at gaps ranging roughly from 1,756 to 1,989 seconds, while 7,200- and 14,400-second leases renew near their respective half-life with per-client jitter.
- SMTP/STARTTLS correlation is source-native: all 31 SMTP rows marked `tls:true` have an SSL record on the same UID, while all 15 cleartext rows lack one.
- Protocol child records retain correct ownership. Every inspected DNS, HTTP, SSL, and file UID exists in the corresponding sensor's `conn.json`, tuples match, and child timestamps remain inside the connection interval.
- Firewall lifecycle texture is coherent: 6,994 parsed ASA connection identifiers each have exactly one built and one teardown record, while denials use separate message semantics. This is supportive consistency, not evidence of synthetic origin merely because it is complete.
- Long-lived sessions coexist with burst traffic: SSH connections last from minutes to over four hours, RDP sessions reach roughly 53 minutes, web activity is bursty, and high-rate scans produce heterogeneous open, reset, rejected, and silent outcomes.

## Detailed Analysis

### Connection Patterns and Timing

The six-hour view runs from approximately 12:00 to 18:00 UTC. Core has 6,980 connections and DMZ has 7,881. Median recorded TCP duration is about 2.0 seconds on core and 2.27 seconds on DMZ, but both have a substantial tail: one SSH session from `10.10.1.99` to `10.10.3.10:22` lasts 15,469.56 seconds, while several other SSH and RDP sessions last 1,400–3,600 seconds.

Unanswered scanning is represented as SYN-only `S0` traffic, while successful ports gain source-appropriate services and histories. During the internal scan near 13:44:30–13:44:42, 1,249 core `S0` records span ports 22, 80, 443, 445, and 3306 across almost the entire `10.10.2.0/24`; 1,226 source ports are unique, and inter-arrival gaps vary from microseconds to more than 100 milliseconds. This looks like believable scanner output rather than a fixed-interval loop.

The two sensors are not literal clones. Matching tuples have different Zeek UIDs and an approximately 114 ms sensor-clock offset, while some byte counts, histories, and observed record sets differ slightly. That is consistent with independent observation points.

### DNS

The single resolver at `10.10.2.10` behaves as both an authoritative server for the internal namespace and a recursive resolver externally. Authoritative internal records use `AA:true, RA:true`; external answers generally use `AA:false, RA:true`. Internal SRV answers point Kerberos and LDAP service discovery to the domain controller, and PTR records cover internal and external addresses.

RTTs range from roughly 0.1 ms to 2.01 seconds rather than occupying a narrow band. Core median RTT is about 6.6 ms; DMZ median is about 18.1 ms. TTLs range from one second through 86,400 seconds, with common internal values such as 300/3,600 and CDN-style short values in the 30–100 second range.

The principal defect is causal ordering in the proxy-origin path. The 17:14 `cache.rollbar.org` example is especially difficult to reconcile with normal resolution: three TCP opens and TLS handshakes use `52.84.57.248` before the first visible proxy lookup returns that address. Similar inversions occur in multiple browser bursts. Because a resolver cache may have been seeded before the observation window, I classify this as a repeated contract gap rather than a hard contradiction, but it materially raises the synthetic-confidence score.

### HTTP and Explicit Proxy Traffic

Core HTTP is dominated by 1,389 CONNECT requests out of 1,529 records, consistent with clients reaching an explicit proxy at `10.10.3.20:8080`. DMZ sees 1,438 CONNECT requests plus additional origin-side HTTP activity. Denies, proxy authentication failures, gateway errors, redirects, cache-related responses, and successful tunnels all appear.

Proxy access records distinguish CONNECT control bytes from tunneled bytes and include authenticated and unauthenticated clients. Ordinary tunnel metadata agrees closely with Zeek transport accounting: for the 12:02:20 `drive.google.com` tunnel, `cs_bytes=532` plus `tunnel_cs_bytes=3370` equals the core connection's 3,902 origin bytes, while `sc_bytes=242` plus `tunnel_sc_bytes=40396` equals 40,638 response bytes; its 8,583 ms tunnel duration also matches the Zeek duration.

The proxy DNS-before-origin sequencing is the main weakness. Once an answer is visible, later connections consistently use an advertised address, so the problem appears to concern initial transaction ordering or cache state rather than hostname/IP disagreement.

### TLS, Certificates, and External Traffic

The TLS version and cipher distribution is plausible for a mixed modern environment. TLS 1.3 uses AES-GCM and ChaCha20 suites, while TLS 1.2 includes RSA- and ECDSA-authenticated ECDHE suites plus a smaller AES-CBC population. Resumed sessions lack certificate chains, and TLS 1.3 certificate invisibility is represented appropriately for passive monitoring.

Certificate reuse is credible: fingerprints recur for repeated destinations, while connection-specific file identifiers differ. Leaf subjects/SANs align with SNI in the checked records, certificate chains distinguish host and CA certificates, and OCSP records contain plausible `thisUpdate`/`nextUpdate` intervals and `good` status.

Outbound traffic covers major SaaS, update, package, collaboration, and CDN destinations. Inbound DMZ traffic includes normal TLS/HTTP clients plus failed scanning on SSH, SMB, RDP, mail, and management ports. HTTPS dominates, while cleartext HTTP remains for redirects, OCSP, update infrastructure, and inbound web service traffic.

### Infrastructure and Lateral Traffic

Kerberos, LDAP, SMB, DHCP, DNS, mail, database, SSH, and RDP traffic align with visible host roles. SMB mappings and file actions use the same UID and tuple as their port-445 connections, with mappings preceding file operations. MySQL traffic primarily follows the web-to-database path, while mail submission, server-to-server SMTP, IMAPS, and STARTTLS are differentiated correctly.

The only notable infrastructure-distribution omission is NTP. Given the otherwise broad visibility of short UDP transactions and active domain/Linux systems, some UDP/123 traffic would normally be expected during six hours. This remains explainable by collection policy or alternative time synchronization and is not independently dispositive.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Zeek DNS, conn, SSL; proxy access | Repeated across several proxy browsing bursts | High: upstream TCP/TLS repeatedly precedes the only visible A lookup that returns the destination IP. Cache state prevents calling every case impossible, but the late-window 30-second-TTL example is difficult to explain organically. |
| `environment_or_collection_plausibility` | Zeek conn/infrastructure traffic | Dataset-wide | Low-medium: zero UDP/123 records despite rich DNS, DHCP, Kerberos, LDAP, and mixed-OS traffic suggests an incomplete infrastructure model or unusual collection filter. |
| `weak_signal` | Proxy resolver behavior | Repeated but cache-ambiguous | Low: 143 proxy-origin TLS records have a later but no earlier same-name A query in-window; long-lived or stale cache state could explain a subset. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, TLS/X.509, DHCP, SMTP, proxy, and ASA fields are source-native and internally consistent.
- **Temporal patterns:** 6 — Bursts, long sessions, scan timing, and lease jitter are strong, but proxy DNS ordering is repeatedly questionable.
- **Cross-source correlation:** 8 — UIDs, tuples, protocol children, firewall lifecycles, and proxy byte accounting agree without observed tuple contradictions.
- **Behavioral realism:** 8 — User browsing, SaaS traffic, scanning, mail, database, SMB, SSH, and RDP exhibit plausible role and duration distributions.
- **Environmental consistency:** 7 — Network segmentation and OS-specific source-port behavior are excellent; total absence of NTP is the main concern.

## Recommendations

- If this were synthetic, ensure the proxy performs or reuses a still-valid DNS resolution before the first upstream TCP open. Cache entries should carry explicit expiry state derived from TTLs; if stale-while-revalidate behavior is intentional, model it consistently so a later lookup is clearly a refresh rather than the apparent prerequisite.
- Add a regression check that, for a proxy-origin connection without a valid cached address, the A/AAAA transaction completes before TCP start and TLS handshake. Test multi-connection browser bursts so the first lookup precedes every sibling origin connection.
- If the collection is intended to include general infrastructure traffic, add low-volume, per-host-jittered UDP/123 polling appropriate to Windows domain members, Linux systems, and the domain controller. If NTP is intentionally filtered or replaced by another time source, make that collection boundary consistent rather than introducing artificial companion rows.
- Preserve the strong existing properties: OS-aware ephemeral-port ranges, TLS-version-dependent certificate visibility, varied Zeek state histories, lease-half-life jitter, sensor-specific UIDs/timing, and protocol-child ownership.
