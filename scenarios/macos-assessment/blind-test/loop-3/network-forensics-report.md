# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 68

## Executive Summary

The network data is realistic in most respects: DNS cache lifetimes, TLS certificate relationships, shared connection identifiers, file accounting, and SSH authentication ordering hold together. My synthetic verdict rests on a repeatable source-native inconsistency in a small subset of TCP records: packet counts are lower than the distinct packets represented in their own connection histories, particularly among connections marked with content gaps. This is a localized but substantive defect; I found no basis to characterize the whole dataset as temporally or behaviorally implausible.

## Evidence For Synthetic

- [hard_contradiction] `office-span/conn.json:1219`, UID `C6xhOnMb2hjbXBGZH`, at `2026-10-20T15:45:34.503459Z`, reports `history="DdAG"` but `orig_pkts=1`. In normal Zeek history semantics, this is originator data (`D`), responder data (`d`), then an originator pure acknowledgment (`A`): at least two distinct originator packets. A single observed originator packet cannot occur on both sides of the responder's observed data. `missed_bytes=1` and the content-gap marker do not reconcile those two observed originator actions with a count of one.
- [hard_contradiction] `office-span/conn.json:589`, UID `CWHOUUAw0jRZ9JWpv`, at `2026-10-20T14:26:43.027845Z`, reports `history="ShADadrGg"` and `orig_pkts=2`. The originator's SYN (`S`), pure ACK (`A`), and data (`D`) require at least three distinct observed originator packets, even without counting any close packet. This record also has content-gap indicators, with `missed_bytes=23`.
- [contract_gap] The same class of history/count discrepancy extends to 16 of the 1,144 TCP connection records, affecting HTTP, TLS, and SMB, rather than one isolated destination or host. For example, `office-span/conn.json:48`, UID `C0pomKA1lMfEh9DrMGy`, at `13:05:57.548135Z`, has `history="ShADadfFG"` and `orig_pkts=3`: the originator's SYN, pure ACK, data, and later FIN are four separate packets, with responder traffic between the data and FIN. All 16 identified records contain `G` or `g` and nonzero `missed_bytes`. This supports a common packet-accounting defect in the treatment of gapped flows. The broader count includes FIN/reset interpretation; the two strongest examples above do not depend on that interpretation.

## Evidence For Real

- Connection outcomes have a credible range rather than being uniformly successful. Across `office-span/conn.json`, there are 2,150 `SF`, 35 `RSTR`, 35 `RSTO`, 10 `S1`, seven each `S3` and `OTH`, four each `S2` and `S0`, and three `REJ` records. Of 1,144 TCP connections, 1,039 are `SF`; the UDP and ICMP exchanges account for the other successful connections.
- DNS is substantially richer than an A-record-only fixture: `office-span/dns.json` contains 862 A, 122 AAAA, and 72 PTR transactions, including 68 NXDOMAIN responses and successful no-answer AAAA responses. Examples include `dns.json:4`, a NOERROR/no-answer AAAA query for `company.okta.com`, and `dns.json:7`, an NXDOMAIN query for `wpad`.
- There is visible DNS cache aging. `office-span/dns.json:403` and `:405` show the same client, resolver, `zoom.us` answer pair, and qtype, 26.803924 seconds apart; TTLs fall from `[1757,1757]` to `[1731,1731]`. That is a sensible cache countdown, not independent arbitrary TTL selection on these records.
- TLS behavior respects important protocol distinctions. There are 681 TLS 1.3 and 256 TLS 1.2 observations, 319 resumed connections, and ten non-established handshakes. None of the TLS 1.3 records exposes a cleartext certificate chain; the 152 TLS records that do reference certificate FUIds are TLS 1.2. Referenced certificate key types match the RSA/ECDSA authentication family of the negotiated TLS 1.2 cipher.
- Protocol references and transferred bytes are internally useful and coherent. Every DNS, TLS, HTTP, NTP, SMB mapping, and SMB file record resolves to an existing connection UID with the same tuple, and its timestamp is within the recorded connection interval. All 284 X.509 certificate fingerprints match the SHA-1 value of their corresponding `files.json` record; HTTP response-file byte counts match the corresponding HTTP response-body lengths.
- SSH endpoint evidence has sensible ordering. For UID `CHSXTfowUgvQWBCSmH`, transport begins at `13:08:27.219008Z` in `office-span/conn.json:51`; the Linux server then logs the connection at `13:08:28.602636Z`, public-key acceptance at `13:08:31.231769Z`, and PAM session opening at `13:08:31.388617Z` in `NS-BUILD-01.northstar.example/syslog.log:17-19`. The source address and source port `10.42.0.21:61411` agree.

## Detailed Analysis

### Scope and method

I examined the supplied network JSON records in full using read-only parsing and in-memory aggregation, then sampled the supplied endpoint FLOW/session and Linux SSH records to check ownership and authentication ordering. I did not consult external documentation, neighboring directories, scenario descriptions, or other assessments. All timestamps below are UTC on 2026-10-20 unless explicitly stated otherwise; line references are one-based physical lines in the supplied evidence files.

The main network window runs from `13:00:08.467170Z` through `18:59:23.359118Z` by connection start time. The evidence comprises 2,255 connection records, 1,056 DNS transactions, 937 TLS records, 38 HTTP transactions, 12 NTP observations, 381 file observations, 284 X.509 records, 27 OCSP records, 49 SMB mappings, and 89 SMB file-operation records. A few endpoint lifecycle records extend beyond the latest connection start; that is not a defect.

Four addresses originate the recorded flows: `10.42.0.11`, `.12`, `.21`, and `.31`. The supplied endpoint names and paths support two Mac workstations, a Windows workstation, and a Linux build/service host. I treated the network records as sensor observations, not as native Mac telemetry.

### TCP state, histories, and packet accounting

The overall state mix is plausible. There are 1,019 connections to TCP/443, 60 to TCP/445, 42 to TCP/80, and 13 to TCP/22. SSH has 12 completed flows and one rejected attempt; SMB has 59 completed flows and one unanswered attempt. Small internal probes include explicit rejection or no-response outcomes rather than fabricated successful application sessions. For example, `conn.json:998-1004` spans several attempts from `.31` around `15:19:39Z-15:19:55Z`, including rejected TCP/3389 and TCP/22, unanswered TCP/135, and a short successful TCP/22 probe. That mixture is technically credible. Its compactness is not an authenticity indicator.

There are also realistic partial or interrupted connections. `conn.json:93`, UID `CCF02O3Vc2ozBvxmGh`, has `conn_state="OTH"`, `history="ADad"`, a 44.443 ms duration, and small bidirectional payload totals. An observation beginning midstream is possible in a slice-of-time collection and is not itself suspicious. The presence of content gaps, retransmission indicators, or resets is likewise not a defect by itself.

The contradiction is that some individual records disagree with themselves about packets already observed. The most conservative test counted SYN/SYN-ACK, pure ACK, and data history tokens by direction. It found the two failures at lines 589 and 1219. These do not rely on assumptions about how FIN and data might be combined in one segment. In particular, `DdA` records an originator packet before responder data and another originator packet afterward, so `orig_pkts=1` is irreconcilable with that sequence under ordinary Zeek semantics.

A further conservative pass allowed immediately adjacent same-direction data and FIN/reset to share one packet, but counted close flags separately when responder traffic intervened. It identified 16 affected connection rows:

| `conn.json` line | UID | Affected direction | Recorded packets | Minimum from visible history | History |
|---:|---|---|---:|---:|---|
| 36 | `CtErpKZtAwj4Dt3Kq` | responder | 3 | 4 | `ShADadFfg` |
| 48 | `C0pomKA1lMfEh9DrMGy` | originator | 3 | 4 | `ShADadfFG` |
| 65 | `C1ArrZBELrM3GfMPLr` | originator | 4 | 5 | `ShADaDadfFG` |
| 142 | `CLZZADh0b4e1f7pWyAB` | originator | 3 | 4 | `ShADadfFG` |
| 225 | `CzbxIOpuNtRufbD9uq` | originator | 4 | 5 | `ShADaDadfFG` |
| 297 | `C4ITUlueMPsAvNe6Mai` | originator | 3 | 4 | `ShADadfFGg` |
| 314 | `CyGCshnV0UZpTroWNa` | originator | 3 | 4 | `ShADadfFG` |
| 589 | `CWHOUUAw0jRZ9JWpv` | originator | 2 | 3 | `ShADadrGg` |
| 766 | `CRCld9NJRCCjv5Tb2W` | originator | 4 | 5 | `ShADaDadfFG` |
| 988 | `CzHy5e2hHPzFbkYbTB` | originator | 4 | 5 | `ShADaDadfFG` |
| 1055 | `CcIZ12YzMs6IbHc6o7` | originator | 3 | 4 | `ShADadfFaG` |
| 1219 | `C6xhOnMb2hjbXBGZH` | originator | 1 | 2 | `DdAG` |
| 1294 | `C9m9QmL1aoB0BUiDTHW` | originator | 3 | 4 | `ShADaRG` |
| 1602 | `CUz1XHmsnSldhaRboE` | originator | 5 | 6 | `ShADaDaDadfFG` |
| 1940 | `CdWtGsgaHPUhfAPZxs` | originator | 4 | 5 | `ShADaDadfFG` |
| 2155 | `CU6tJdpCMA52Lekovs` | originator | 4 | 5 | `ShADaDadfFaG` |

These constitute about 1.4% of TCP records and 13.6% of the 118 TCP records containing content-gap history markers. All 16 have a one-packet deficit under this test. Packet loss can explain missing data or missing flags; it does not naturally explain retaining the history of an observed packet while removing that packet from the same connection's observed packet count. A nonstandard exporter or damaged postprocessing of real telemetry remains an alternative explanation, so I do not claim that this establishes an identifiable generator or proves the provenance of every source.

### DNS behavior

The DNS records contain distinct resolver configurations by client: `.11` uses `8.8.8.8` and `8.8.4.4`, `.12` uses `1.1.1.1` and `1.0.0.1`, `.21` uses `208.67.222.222`, and `.31` uses the Cloudflare address pair. This is possible in an unmanaged or mixed small environment. The logs do not establish a requirement for a central directory resolver, and I did not penalize the absence of Kerberos, LDAP, DHCP, or mDNS merely because those protocols could exist in such an environment.

There are 988 NOERROR and 68 NXDOMAIN responses. The no-answer AAAA cases and PTR outcomes add appropriate protocol variety. NXDOMAIN records include both short names and suffixed names; for example, `dns.json:23` contains `wpad.northstar.example`, while `:27` contains `wpad`. I did not treat the exact domain-to-IP assignments as authenticity evidence because sanitization is allowed.

All 1,056 logged DNS transactions have one request and one response in their corresponding connection records, with the connection duration equaling the logged RTT. That is consistent with isolated UDP query/response transactions and is not, by itself, evidence of synthetic generation. I checked a conservative DNS message-size lower bound using question lengths and A/AAAA/PTR answer counts and found no undersized corresponding response.

For 912 TLS records I could find a preceding DNS answer from the same host matching the SNI and destination IP. One connection starts approximately 38 ms before the latest matching DNS response would arrive: `dns.json:873`, `ssl.json:782`, UID `CfIuF4CyKuduXWydps`. This is not an impossible causal relationship, because the connection could use an earlier cached address while another lookup was in flight; there is no supplied request-level dependency that proves the latest DNS response initiated that connection. I did not score it as a defect.

The explicit cache-aging example at lines 403 and 405 is a useful positive sign. Across repeated identical client/resolver/query/qtype/answer groups within 120 seconds and within the earlier TTL, I found one comparable pair and no large cache-countdown inconsistency.

### TLS, certificates, HTTP, OCSP, and files

The predominance of TLS over HTTP is reasonable for contemporary workstation traffic. The visible TCP destination-port totals are 1,019 for 443 and 42 for 80; application logs include 937 TLS observations and 38 HTTP transactions. HTTP is largely certificate-status retrieval or redirects: 28 HTTP transactions have hostnames beginning with `ocsp`, and ten transactions return 301/302. That is a credible cleartext subset; it is not necessary for cleartext HTTP logs to expose application activity inside encrypted sessions.

TLS 1.3 accounts for 72.7% of TLS records. TLS 1.2 records use ECDHE with RSA or ECDSA authentication, primarily GCM, with two CBC selections. The records have successful, resumed, and unsuccessful handshakes rather than forcing every row into a completed full handshake. I found no TLS-version/cipher-family contradiction.

The cleartext certificate material also respects visibility. No TLS 1.3 row has `cert_chain_fuids`. The 152 TLS 1.2 rows with certificate references link to existing X.509 records. Where a leaf and issuer are supplied, issuer and subject names agree, and RSA/ECDSA leaf key types agree with the handshake authentication family. SANs cover the corresponding SNI names in the referenced records. Grouping X.509 records by fingerprint, serial, or subject did not reveal conflicting certificate fields for the same identity. Ten successful nonresumed TLS 1.2 rows lack explicit certificate references, but source retention, extraction gaps, or deduplication are plausible; I did not count that absence alone as a synthetic tell.

The 381 file records comprise 303 SSL, 40 SMB, and 38 HTTP observations. Their connection references exist, their timestamps lie inside the relevant connection intervals, and their observed file sizes do not exceed the supplying direction's connection payload bytes. All 284 X.509 SHA-1 fingerprints equal their corresponding file SHA-1 value. All 38 HTTP response-file lengths match `response_body_len`.

I also decoded the base64 OCSP request paths in memory. Their nested ASN.1 sequence lengths were consistent with the supplied bytes, and the visible request issuer hashes and serial numbers agreed with the corresponding logged OCSP response records when both were linked. For example, `http.json:5` identifies the serial `3C26E7082081805285E5C6A7737D6E62` and issuer hashes that reappear in `ocsp.json:1`, FUId `F3ShpDfDEg5mZwDOdF8`. This is a positive consistency check, not proof that the certificates themselves existed outside this dataset.

### Timing, host roles, and lateral activity

The hourly connection counts are 257, 543, 468, 481, 265, and 241 from 13:00 through 18:59 UTC. That is not a flat per-hour fixture. Within-host DNS interarrival times also have a substantial tail: `.12` has a median of about 2.91 seconds and a maximum of about 1,323 seconds; `.11` has a median of about 4.23 seconds and a maximum of about 1,138 seconds. Dense bursts and long quiet gaps are compatible with workstation activity. A six-hour daytime slice cannot establish overnight, weekend, or full-day realism, and I did not extrapolate those properties.

SSH connection durations range from a 62 ms probe to a 3,663.993447-second session. The long sessions have low-to-moderate byte totals consistent with interactive use rather than every session being a large transfer. The explicit public-key/PAM example above has transport before acceptance and session opening. Additional normalized endpoint examples agree: the `.21:56542` to `.12:22` transport at `15:07:44.568779Z` in `conn.json:843` precedes the inbound FLOW at `15:07:45.423Z` and SSH login at `15:07:50.586Z` in `NS-MAC-02.northstar.example/ecar.json:399` and `:403`.

SMB activity toward the Linux service host is supported by server-side `/usr/sbin/smbd` and SMB session evidence, rather than inferred merely from the destination port. For example, `conn.json:2`, UID `CpDmnkLMDmtmUXfsMxy`, carries the `.21:52674` to `.31:445` transfer; `smb_mapping.json:1`, `smb_files.json:1-2`, and `files.json:1` agree on the Engineering share, filename, direction, and 878,226-byte observed file. The Linux server's normalized SMB login for that tuple appears at `13:02:16.947Z` in `NS-BUILD-01.northstar.example/ecar.json:18`. Samba can present an NTFS-style native filesystem identifier, so `native_file_system="NTFS"` alone is not a Linux contradiction.

The NTP sample is small: 12 Windows-originating observations to one time service, with poll interval 2,048 seconds and variable actual spacing. I did not interpret small differences between sensor time and NTP payload timestamps as impossible ordering: payload clocks and the capture clock need not be synchronized. Likewise, I did not demand host lifecycle initiators or terminators outside the visible window.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `hard_contradiction` | Zeek-style TCP connection records | Two unambiguous packet/history conflicts at `conn.json:589` and `:1219` | Main reason the assessment favors synthetic: observed SYN/pure-ACK/data history requires more packets than the record reports. |
| `contract_gap` | TCP connection history, packet counters, and content-gap accounting | 16 TCP records across TLS, HTTP, and SMB; all gap-marked, all one packet below the conservative history minimum | Recurrence across clients/services suggests a shared accounting defect rather than one malformed row. This is an extension of the same root issue, not an independent second defect family. |

No domain-realism, collection-completeness, missing-Sysmon, intrusion-narrative, or out-of-window lifecycle argument contributed to the score. The high quality of the other correlations limits the score to the likely-synthetic band rather than the confidently-synthetic band.

## Realism Score by Category

- **Field format accuracy:** 7 — JSON, protocol fields, certificates, and references are strong, but a small TCP subset has self-contradictory packet/history fields.
- **Temporal patterns:** 9 — Bursts, idle gaps, service-dependent durations, cache aging, and sampled transport-before-authentication relationships are credible within the visible window.
- **Cross-source correlation:** 9 — Tuples, UIDs, certificate hashes, transferred file sizes, and sampled SSH endpoint relationships agree; no demonstrated cross-source impossibility was found.
- **Behavioral realism:** 8 — Workstation TLS, certificate-status HTTP, SMB file activity, interactive SSH, and mixed scan outcomes are plausible; the six-hour scope limits assessment of the longer tail.
- **Environmental consistency:** 8 — Client-specific resolvers and observed Mac/Windows/Linux roles are coherent, with a plausible Linux SMB/SSH service host and no required-source coverage contradiction established.

## Recommendations

- If this were synthetic, derive TCP histories and directional packet counters from the same observed packet sequence, including any modeled loss. A packet removed from observation must not remain represented as an observed SYN, pure ACK, data packet, or close packet in that connection's history.
- If this were synthetic, add a conservative directional packet-count check covering the two strongest cases: `DdA` requires at least two originator packets, and `ShAD` requires at least three. Extend it to FIN/reset chronology while allowing legitimately combined flags in a single segment.
- If this were synthetic, apply that check across the whole content-gap family rather than correcting only the two smallest rows. The 16 affected records span HTTP, TLS, and SMB and would benefit from one consistent observation/accounting rule.
- If these were production-derived exports, preserve or document any exporter transformation that intentionally gives `history` and `orig_pkts` different observation scopes. Without such a documented distinction, their ordinary source-native meanings conflict in the cited records. Raw packet comparison would be the appropriate next verification if such evidence became available; no packet capture was supplied here.
