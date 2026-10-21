# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 74
**Synthetic-Confidence Score:** 64

## Executive Summary

The network evidence is broadly coherent and substantially more realistic than a collection of independently invented log rows. I nevertheless lean synthetic because OCSP connections share a conspicuously narrow duration distribution across different clients and responders, while TLS companion coverage partitions almost perfectly by TCP termination state. A smaller formatting artifact reinforces that conclusion; I found no proven impossible network ordering or cryptographic contradiction.

## Evidence For Synthetic

- **[distribution_texture] OCSP connection durations cluster within 14.675 milliseconds across heterogeneous traffic.** All 23 OCSP HTTP connections last between **0.456048 and 0.470723 seconds**, with a median of **0.459690 seconds** and population standard deviation of **0.003767 seconds**. They involve all four originating hosts, four responder names, and six responder IPs. Examples are `office-span/conn.json:52`, UID `CPiBJfqbrLNrGxCJRA`, at `2026-10-20T13:19:44.339836Z`, duration `0.456048`; line 334, UID `C7GZCMuUU4kgV4I5EEx`, at `14:09:06.354909Z`, duration `0.460272`; and line 1410, UID `CO6uQEZJ7IIInADTrn9`, at `17:06:23.832515Z`, duration `0.463296`. This is a strong repeated timing texture, not an impossible individual duration.
- **[contract_gap] TLS record availability follows TCP closure state unusually sharply.** Of 950 connections labeled `service="ssl"`, all 863 `SF` connections have an `ssl.json` row. All 68 SSL-labeled reset connections—40 `RSTO` and 28 `RSTR`—lack one. Nine `S2`/`S3` connections also lack TLS rows, whereas all four `S1` connections have explicit failed TLS rows. This matters because some omitted connections contain substantial two-way data and no reported missed bytes: `office-span/conn.json:507`, UID `CxTGqJNOV4jPzy4QOg`, records `orig_bytes=7900`, `resp_bytes=13039`, `history="ShADadr"`, `missed_bytes=0` at `14:35:16.949087Z`. The collection pattern is demonstrated; an undocumented selective logging policy remains a plausible alternative explanation.
- **[schema_or_format] Some AAAA answers use an atypical textual rendering for native Zeek output.** Thirty-two of the 100 IPv6 address answers retain leading zeros in nonzero hexadecimal groups. For example, `office-span/dns.json:16` at `13:17:32.193069Z` contains `2620:1ec:cd5e:0058::1`; line 26 at `13:19:56.948505Z` contains `2606:50c0:a734:008a::1`; and line 32 at `13:21:27.169947Z` contains `2607:f8b0:d8e6:00f0::1`. These are valid IPv6 addresses, but typical Zeek address rendering would use `58`, `8a`, and `f0`. I give this limited weight because export processing could change string formatting, and the supplied records do not identify the exact exporter build.

## Evidence For Real

- **Protocol relationships survive systematic checks.** Across DNS, TLS, HTTP, NTP, SMB mapping, and SMB file records, every UID joins to a connection with the same four-tuple. None of those protocol timestamps falls before its connection start or materially beyond its recorded end. This is positive evidence of coherent construction, not evidence of synthetic origin through excessive completeness.
- **DNS includes realistic diversity and cache behavior.** The 991 DNS records contain 804 A queries, 132 AAAA queries, 55 PTR queries, and 56 NXDOMAIN responses. For the same client/resolver and unchanged answers, `office-span/dns.json:630` and `:646` show `accounts.google.com` TTLs decreasing from 955 to 815 over 140.513 seconds; lines 843 and 854 show `ssl.gstatic.com` TTLs decreasing from 1411 to 1338 over 72.778 seconds.
- **TLS certificate visibility respects protocol differences.** There are 607 TLS 1.3 and 260 TLS 1.2 observations. No TLS 1.3 record claims a visible certificate chain. The 153 TLS 1.2 rows that do reference certificate chains resolve to X.509 records with matching issuer/subject chains, appropriate leaf key types for RSA versus ECDSA cipher suites, and valid observation-time certificate dates.
- **Capture loss has consequences in downstream files.** For example, `office-span/files.json:45-46`, UID `C8Lym4Xbue3yxZcYCe`, records certificate objects missing 9 and 11 bytes. Those objects lack parsed X.509 rows. Similarly, the OCSP body at `office-span/files.json:83` has FUID `FuJSnEOShCRUJz3ZIr`, `seen_bytes=1349`, `total_bytes=1352`, `missing_bytes=3`, and no corresponding OCSP parse record. The missing bytes provide a concrete reason parsing may fail.
- **SSH sessions have credible network/authentication ordering.** `office-span/conn.json:64`, UID `C2iQaYI83sTaasDvFK`, opens `10.42.0.12:53077 → 10.42.0.31:22` at `13:20:12.758891Z`; `NS-BUILD-01.northstar.example/syslog.log:32` accepts public-key authentication at `13:20:17.723623Z`, 4.965 seconds later. The connection lasts 3540.163329 seconds, a plausible interactive-session duration.

## Detailed Analysis

### Scope and observation window

I examined the supplied evidence tree only, concentrating on all ten `office-span` JSON files and using endpoint flow and SSH records to check network ownership and authentication ordering. The network files contain 4,847 records, including 2,128 connections, 991 DNS transactions, 867 TLS observations, 369 file observations, and 292 X.509 records. Times in this report are UTC on 2026-10-20.

Connection start times span `13:02:15.251714Z` through `18:59:23.481119Z`. Four internal originators appear: `10.42.0.11`, `.12`, `.21`, and `.31`. Endpoint evidence associates them with two Macs, a Windows host, and the Linux build host, respectively. This is a six-hour slice, so it cannot establish an overnight activity profile or require complete session lifetimes.

### Connection states, services, and volume

The protocol mix is 1,079 TCP connections, 1,036 UDP connections, and 13 ICMP observations. Across protocols, states include 2,008 `SF`, 53 `RSTO`, 29 `RSTR`, 13 `REJ`, six each of `S0`, `OTH`, and `S2`, four `S1`, and three `S3`. The distribution includes ordinary failures and partial observations rather than exclusively successful flows.

Dominant destination ports are 53 (1,024), 443 (964), 445 (62), 80 (25), 22 (13), and 123 (12). The predominance of encrypted web traffic over cleartext HTTP is plausible. The small HTTP set is mostly certificate-status checking. I do not require QUIC, DHCP, LDAP, Kerberos, or multicast discovery merely because some hosts could generate them.

Traffic is bursty within the slice: per-hour connection counts are 288, 390, 367, 301, 395, and 387. Individual clients show a mixture of dense bursts and long gaps; this is not an evenly spaced connection stream. SSH durations range into tens of minutes, while SMB and HTTPS have distinct shorter distributions. Basic IP/payload accounting passes conservative minimum-header bounds, and no observed SMB transfer size exceeds the matching connection's available payload in the transfer direction.

### DNS behavior

All 991 DNS rows have matching connection tuples. Request payload sizes accommodate the visible question names; response sizes accommodate the visible A/AAAA answers under conservative DNS compression assumptions. The records include successful answers, NODATA-like empty AAAA responses, PTR lookups, and failed local-name lookups.

I checked repeated client/resolver/question/answer combinations before treating TTL changes as suspicious. Many re-queries occur after a previously short TTL expires, so a larger subsequent TTL is explainable. The cache-decay examples cited above support realism. Likewise, a connection beginning before a nearby same-name DNS query need not be causal misuse when an earlier cached answer exists; I found no proven DNS-before-connection violation.

The padded IPv6 groups remain a source-rendering concern. This is not a claim that the addresses are invalid, that domains resolve incorrectly, or that their real-world assignments disprove authenticity.

### TLS and certificate material

The TLS mix is approximately 70% TLS 1.3 and 30% TLS 1.2. There are 317 resumed observations and four explicitly unsuccessful handshakes. Cipher selections include AES-GCM and ChaCha20, with a small CBC tail. Certificate references are internally consistent; repeated fingerprints do not describe conflicting certificates. Leaf SANs cover the recorded server names, and RSA/ECDSA cipher authentication matches the referenced leaf key type.

The concern lies in lifecycle-dependent record availability. All 863 established TLS rows are attached to `SF` connections. The absent companion set includes connections with visible SYN/SYN-ACK history and meaningful data in both directions. Beyond line 507, `office-span/conn.json:1075`, UID `C4YVHvTAEJDtG2aJOk`, records an `RSTR` exchange at `16:09:27.213787Z` with 637 originator bytes, 23,691 responder bytes, and zero missed bytes. Line 940, UID `C4MApN0AQeR6xZqzF4`, records `S3`, 3,213/19,353 bytes, and zero missed bytes at `15:29:54.058738Z`.

A TCP reset does not itself erase a previously observed TLS hello or handshake. The presence of failed TLS rows at `office-span/ssl.json:18`, `:74`, `:192`, and `:446` also shows that the collection does not simply exclude every failed TLS exchange. The state partition therefore warrants explanation. I have not assumed that every SSL-labeled reset completed TLS authentication, and I excluded the six `OTH` connections from the stronger comparison because midstream observation is a reasonable explanation for them.

### HTTP and OCSP timing

I decoded all 23 OCSP request URIs from URL-escaped Base64 and checked their DER length structure. Each passed that structural check. For the 22 parsed OCSP responses, the request serial matches the response serial. HTTP payload counts also accommodate the visible request fields and response bodies.

The duration distribution is the principal authenticity concern. The 23 flows span roughly five hours, four clients, responders named DigiCert, Sectigo, Google, and GlobalSign, and response bodies from 915 to 2,500 bytes. Nonetheless, every connection closes within the same approximately 0.46-second band. Some histories include retransmissions or gaps, such as `conn.json:811` (`ShADadTtFf`) and `:1216` (`ShADadTFfG`), yet their durations remain `0.459550` and `0.461920` seconds.

A common client timeout or intermediary could impose a timing band, so this does not prove generation. The cross-client, cross-responder consistency and absence of a latency tail make a shared synthetic timing recipe a more likely explanation to me than unconstrained production traffic.

### Lateral traffic and endpoint ownership

Internal SMB connections consistently target the build host's Engineering share, and the records include both reads and writes. Samba can advertise Windows-compatible filesystem labels, so `native_file_system="NTFS"` on a Linux-hosted share is not an impossibility by itself.

SSH sessions from the other internal hosts to the build host have multi-second authentication delays and realistic session lengths. Among network FLOW rows with a visible referenced process lifecycle, I found no FLOW occurring before that process's visible creation or after its visible termination. I did not penalize missing process starts or session closes that could lie outside the collection window.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Zeek HTTP/connection | All 23 OCSP connections across four clients and six responder IPs | Highest weight: a 14.675 ms total duration range over heterogeneous exchanges suggests shared timing construction. |
| `contract_gap` | Zeek TLS/connection | All 68 SSL-labeled reset flows and nine `S2`/`S3` flows lack TLS rows; all 863 `SF` and four `S1` flows have them | Moderate weight: protocol visibility partitions by transport termination state, including substantial gap-free exchanges. Explicit filtering could explain it. |
| `schema_or_format` | Zeek DNS | 32 of 100 IPv6 answer strings | Limited weight: padded groups differ from expected native address rendering; exporter transformations remain possible. |

## Realism Score by Category

- **Field format accuracy:** 8 — Mostly coherent native-looking fields, valid hash widths and DER requests; IPv6 textual rendering is a qualified exception.
- **Temporal patterns:** 6 — Bursty client activity and plausible SSH timing, offset by the narrow OCSP duration band.
- **Cross-source correlation:** 7 — Tuple, UID, certificate, and ownership checks pass; TLS record availability has an unexplained dependence on connection state.
- **Behavioral realism:** 8 — Plausible encrypted web use, DNS cache behavior, file sharing, remote administration, and failed probes.
- **Environmental consistency:** 8 — Host roles and lateral services agree reasonably well; uncertainty centers on the TLS collection policy.

## Recommendations

- If this were synthetic, derive OCSP connection lifetimes from the same transport timing model used for comparable cleartext exchanges, including client, path, responder, retransmission, and closure effects. The current 23-flow duration range is the clearest distribution artifact.
- If this were synthetic, retain protocol observations already established before a TCP reset or one-sided close. Make missing TLS rows depend on observed handshake bytes, parser failure, or an explicit collection policy, and validate the result against the SSL-labeled connection set.
- If this were synthetic and intended to reproduce native Zeek exports, normalize IPv6 AAAA answer strings consistently with the target renderer. If a transformation intentionally preserves another representation, describe that export behavior.
- Preserve the working DNS cache decay, TLS 1.3 certificate-visibility distinction, cipher/key compatibility, capture-loss effects, and SSH transport/authentication ordering. No additional source family is required merely to make the dataset more complete.
