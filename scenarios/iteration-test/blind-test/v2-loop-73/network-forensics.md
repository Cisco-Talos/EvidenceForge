# Network Forensics Analyst — Authenticity Assessment
## Verdict
**Assessment:** Synthetic
**Verdict Confidence:** 81
**Synthetic-Confidence Score:** 64

## Executive Summary
The network corpus is highly realistic at the transport and sensor-projection layers, but it is
more likely synthetic than sanitized production data. The conclusion does not rely on narrative
cleanliness, source completeness, filesystem timestamps, or the mere fact that records correlate.
It rests mainly on two repeated, log-visible artifacts: implausible SYSVOL/NETLOGON file semantics
and request-by-request byte variation for nominally immutable, content-hashed web assets. An
isolated OCSP relationship for a self-signed, non-CA leaf is a further contract concern.

The counterevidence is substantial. Across 20,495 Zeek `conn.json` rows, state, packet, byte,
duration, and protocol fields are internally sound. Independent sensors retain different UIDs,
stable but nonidentical clocks, and realistic asymmetric packet loss. Cisco ASA connection IDs,
NAT records, teardown reasons, durations, and byte counters align closely with Zeek. TLS chains,
SMTP relays, DNS behavior, file-transfer direction, and repeated-file hashes are also unusually
well constructed. This is therefore a likely-synthetic verdict in the lower half of the
“likely synthetic” band, not a finding that the corpus is obviously fabricated.

## Evidence For Synthetic
- **[environment_or_collection_plausibility] Systematic SYSVOL/NETLOGON content is not
  production-like.** `zeek-core/smb_files.json` contains 40 file-transfer actions on the two DCs'
  `SYSVOL`/`NETLOGON` shares; 10 exceed 1 MiB and 7 exceed 2 MiB. Concrete examples include a
  5,340,705-byte `\\DC-01\NETLOGON\Scripts\2025\policy-draft.ini` at
  `1710775256.150916` (`smb_files.json:116`), a 4,185,454-byte
  `\\DC-01\SYSVOL\Policies\scheduledtasks.bat` at `1710766725.728628` (line 25), a
  3,482,783-byte `\\DC-02\SYSVOL\Policies\groups-final.ini` at `1710781766.832209`
  (line 204), and a 1,602,352-byte `policy-draft.pol` at `1710764256.207646` (line 15).
  The corresponding `files.json` records identify the `.bat` and `.ini` objects as `text/plain`
  and confirm those full sizes (`zeek-core/files.json:105` and `:568`). The corpus also places
  GPO-like names in simplified, non-GUID paths and uses future-year components (`2025`, `2026`,
  `2027`) in a March 2024 capture. Any one object is possible; the repeated size/path/type pattern
  is not plausible normal Group Policy or logon-script storage texture.

- **[distribution_texture] Content-addressed static objects change size on nearly every successful
  retrieval.** In `PROXY-01.meridianhcs.local/proxy_access.log`, 54 content-hashed URL/status
  groups are fetched more than once; 53 groups (144 of 146 repeated rows) have more than one
  `sc_bytes` value. The same user and user agent retrieve
  `https://js.clearstream.io/assets/js/app.19dd8a46.js` six times from 15:33:21 through 15:34:00,
  all with status 200, but with 114055, 114105, 114073, 113975, 114010, and 114049 bytes (lines
  1208, 1218, 1235, 1243, 1254, and 1266). Four status-200 fetches of
  `main.ceed2288.css` within 36 seconds similarly report 9353, 9308, 9447, and 9467 bytes (lines
  1207, 1221, 1228, and 1258). Some response-counter variation can come from header accounting,
  compression, or access-log semantics, but the near-universal one-value-per-request pattern over
  hash-versioned assets is much closer to randomized response sizing than a small set of stable
  entity or encoding variants.

- **[contract_gap] A self-signed non-CA leaf receives a parsed “good” OCSP result through an
  unrelated public responder path.** `zeek-dmz/x509.json:17` records serial
  `4193A2239818BABF2B4BB485BBCD46B6` with both subject and issuer `CN=20.205.79.152`, no SAN,
  and `basic_constraints.ca=false`. Five seconds later, `zeek-dmz/http.json:50` requests an OCSP
  object from `ocsp.sectigo.com`; `zeek-dmz/ocsp.json:3` returns `certStatus="good"` for that exact
  serial and self-derived issuer hashes. A hostile endpoint can serve malformed or untrustworthy
  PKI material, so this is not physically impossible, but a normal client has no meaningful
  issuer trust path on which to perform that validation. It looks like generic OCSP companion
  generation was applied to a raw-IP/self-signed certificate.

- **[schema_or_format, weak_signal] Proxy byte-field semantics are ambiguous.** All 130 status-304
  proxy rows report a nonzero main byte count and identical nonzero `sc_bytes`; examples include
  54 bytes for `postman.css` at 12:01:09 (line 5) and 210 bytes for
  `main.dc9c6c59.css` at 12:10:40 (line 62). This is correct if the field means total response
  bytes including headers, but inconsistent with an Apache/Nginx-style entity-body byte field.
  Zeek's own 32 status-304 rows across core and DMZ all have `response_body_len=0`. Because the
  proxy format does not declare its counter semantics, this is only a low-weight format signal.

## Evidence For Real
- **Independent sensor observations are source-native rather than copied.** There are 4,230
  core/DMZ connections with the same five-tuple and start time within five seconds, but zero UIDs
  reused across sensors. Their median core-minus-DMZ start offset is 0.114164 seconds (standard
  deviation 0.001091 seconds), all 4,230 agree on state and service, and only 3,817 have identical
  byte pairs; the differences track vantage-specific `missed_bytes`. For the first proxy flow,
  DMZ UID `C7hyv1K36YYxlCdKo` starts at `1710763217.915740` while core UID
  `CkySQwoaET9ioEmmv` starts at `1710763218.031005`; both see the same tuple and payload, and
  each sensor's HTTP child uses its own UID (`zeek-dmz/conn.json:3`,
  `zeek-core/conn.json:1`, and both `http.json:1`).

- **Long-session reconstruction is convincing.** The SSH session
  `10.10.3.10:46342 -> 10.10.2.30:22` lasts about 13,321.28 seconds. Core sees 25,710 responder
  bytes with no loss (`zeek-core/conn.json:4958`); DMZ sees 25,462 responder bytes and
  `missed_bytes=248` (`zeek-dmz/conn.json:3976`). ASA connection 1685021 is built at 14:14:58 and
  torn down at 17:56:59 after `3:42:01`, with 29,807 bytes (`cisco_asa.log:8737` and `:19502`).
  That ASA total equals the loss-free core IP-byte total, while the DMZ deficit is explainable by
  its recorded loss.

- **Firewall lifecycle and counters look operational.** The ASA file has 7,431 TCP/UDP builds and
  7,430 teardowns, sequential connection IDs, no teardown-before-build case, and one unmatched
  build near the collection tail. Teardown reasons include 4,221 `TCP FINs`, 2,092
  `SYN Timeout`, 103 `TCP Reset-O`, and 43 `TCP Reset-I`; 7,398 of 7,430 matched Zeek flows have
  duration agreement within 1.1 seconds. The first external SMTP delivery is visible as Zeek UID
  `C8aqzEKlQwVPGJxoRT` at `1710763946.438916` (`zeek-core/conn.json:296`), a parsed SMTP message
  (`zeek-core/smtp.json:3`), ASA build 1681735 at 12:12:26, and teardown three seconds later with
  5,900 bytes (`cisco_asa.log:477` and `:481`); 5,900 is exactly the two Zeek IP-byte counters.

- **Connection distributions have production texture.** Core contains 11,712 connections
  (9,446 `SF`, 1,954 `S0`, plus resets, rejects, and incomplete states), DMZ 8,345 (5,498 `SF`,
  2,620 `S0`), and DB 438. Core includes 5,074 UDP, 6,224 TCP, and 414 ICMP rows; DMZ includes
  7,026 TCP, 1,008 UDP, and 311 ICMP rows. Core 15-minute counts range from 285 to 2,083 rather
  than forming a flat cadence. DB application traffic has 314 MySQL flows but a bursty
  interarrival coefficient of variation of about 1.64. No same-sensor UID is duplicated, no
  overlapping reuse of the same TCP five-tuple was found, and no state/packet/byte lower-bound
  contradiction was found.

- **DNS is diverse and internally consistent.** The three sensors contain 3,959 DNS rows with no
  malformed JSON, answer/TTL length mismatch, invalid AAAA answer, or reused exact transaction
  tuple. Core alone has 845 distinct queries and a realistic mix of 2,167 A, 254 AAAA, 146 PTR,
  97 SRV, 286 TXT, and smaller MX/NS/SOA volumes; outcomes include NOERROR, NXDOMAIN, SERVFAIL,
  and REFUSED. The suspicious `westbridge-services.cloud` TXT activity is not itself an
  authenticity defect: its 250 queries vary from 0.006 to 49.169 seconds apart, use both internal
  resolvers, and include NOERROR, NXDOMAIN, SERVFAIL, and REFUSED rather than a mechanically clean
  one-result stream.

- **TLS/X.509 relationships are strong.** All 2,628 SSL rows have matching connection UIDs and
  tuples, occur within their connection interval, and use plausible TLS 1.2/1.3 cipher suites.
  Every one of 558 inspectable SNI/leaf pairs matches the CN or SAN; all 517 two-certificate chain
  links have leaf issuer equal to parent subject; no leaf validity interval exceeds its issuer's;
  and all 88 OCSP serials exist in the corresponding X.509 data. Certificate fingerprints are
  stable across repeated observations, with sensor-local FUIDs. The isolated self-signed OCSP case
  above is the exception rather than the general rule.

- **File and application children preserve Zeek semantics.** Every DNS, HTTP, SSL, and file UID
  reference resolves to a same-sensor connection, with matching tuple and in-interval timestamp.
  File direction is correct for SMB reads and writes, and `seen_bytes + missing_bytes = total_bytes`
  wherever total size is present. Repeated SMB content retains identity: `Q1-budget.xlsx` is read
  at `1710777940.760280` and `1710781259.886393` with the same 937,984-byte size and SHA-256
  `37b81986...f5674` (`smb_files.json:147`, `:182`; `files.json:426`, `:546`); a written then read
  `pipeline-manifest.json` likewise keeps size 72,395 and SHA-256 `44d6d2f6...93aae`
  (`smb_files.json:83`, `:191`; `files.json:233`, `:550`).

- **IDS timing has believable separate clocks.** All 171 Snort alerts match a Zeek tuple within
  five seconds. Snort-core minus Zeek-core medians are approximately 0.257 seconds for UDP and
  0.293 seconds for TCP; perimeter medians are approximately 0.238 seconds for UDP,
  0.247 seconds for ICMP, and 0.269 seconds for TCP. The bounded spread is consistent with
  sensor-clock/processing differences. The JA3 alert at 12:11:37.475714
  (`snort-perimeter/snort_alert.log:1`) maps to the TLS flow and self-signed leaf discussed above,
  while ASA connection 1681718 preserves the exact tuple and a plausible one-second lifecycle
  (`cisco_asa.log:430`, `:433`).

## Detailed Analysis
**Connection states, durations, and volume.** The visible window is approximately 12:00-18:00 UTC
on 18 March 2024. The three Zeek sensors show distinct but coherent visibility domains: core is
almost entirely internal (11,678 of 11,712 rows have both local flags true); DMZ contains 4,894
internal, 1,859 outbound, and 1,592 inbound rows, with 512 unique external destinations and 246
unique inbound sources; DB contains 438 internal-only rows. Median observed duration is 0.043624
seconds on core, 1.674408 on DMZ, and 2.094018 on DB, with realistic long SSH/RDP tails. The 2,620
DMZ `S0` rows correspond naturally to the ASA's 30-second SYN timeouts. Nonzero loss is present and
sensor-specific; packet counts, IP-byte overhead, payload limits, and state histories do not show
an impossible combination.

**DNS ordering and diversity.** All 3,959 DNS rows link to sensor-local DNS connections; DNS
timestamps range from the connection start to 4.166 ms later and never precede the connection or
occur after its close. Core median RTT is 3.44 ms, with a 99th percentile of 469.945 ms and a
2.454832-second maximum. TTLs mix internal values (300, 600, 1,800, 3,600, 7,200, 86,400) with
short public/cache values, and internal authoritative answers appropriately combine AA with
recursive RD/RA behavior. PTR responses are sparse rather than universal. The attack-like TXT
burst is visible and reconstructable but has sufficiently irregular timing and error outcomes that
it is not evidence of synthesis by itself.

**HTTP and proxy behavior.** Zeek has 3,704 HTTP rows: 3,100 CONNECT, 568 GET, and 36 POST. Every
row matches its connection and stays inside the transport interval; multi-transaction UIDs have
contiguous transaction depths up to six, and no HTTP body count exceeds its connection payload.
The proxy adds 2,697 records with 1,572 CONNECT, 1,097 GET, and 28 POST. All 720 inspected tunnel
IDs have a prior tunnel setup, all have at least one inner request, identities remain stable, and
inner byte sums do not exceed tunnel totals. Those are strong contracts. The main defect is the
dataset-wide mutable-byte texture for content-hashed objects, compounded by ambiguous 304 byte
semantics.

**TLS, certificates, and OCSP.** DMZ TLS is 1,539 TLS 1.3 and 689 TLS 1.2 sessions; core is 201
TLS 1.3 and 188 TLS 1.2; DB has 11 TLS 1.2 sessions. Resumption is present (904 of 2,628 rows), SNI
is diverse on the DMZ sensor (443 unique values including null), and certificate omission on
resumed/TLS 1.3 traffic is plausible. Public-like leaf validity periods remain within 398 days,
key types match negotiated RSA/ECDSA ciphers, and issuer hashes are stable per issuer. The raw-IP
self-signed certificate followed by a good OCSP response is a localized semantic blemish against
an otherwise convincing PKI model.

**IDS, firewall, and cross-source timing.** Snort contains 171 alerts spanning DNS TLD policies,
STUN, P2P, user-agent policy, JA3, HTTP/SSH scans, and ICMP. Alert tuples are reconstructable in
Zeek with separate clock offsets, not copied timestamps. ASA provides NAT build/teardown records,
denials, ICMP lifecycles, and correct syslog priority/severity framing. Of 7,431 parsed ASA TCP/UDP
builds, 7,430 have an exact Zeek tuple near the rounded firewall timestamp; the only unmatched
build is an SSH flow created at 17:31:19 and still lacking an ASA teardown at the tail, which is
consistent with a bounded collection window rather than forced lifecycle closure.

**Internal lateral movement and file sessions.** Zeek core contains 688 TCP/445 connections,
132 SMB share mappings, 230 SMB file actions, and 106 SMB-derived `files.json` entries. Every
mapping uses a port-445 connection and occurs inside it. SMB writes are client-to-server and reads
server-to-client; repeated content preserves hashes. Share-role distribution is broadly plausible
(`Finance`, `Users`, `Shared`, `ClinicalResearch`, `SYSVOL`, and `NETLOGON`). The DC policy-share
paths and object-size distribution are the exception and are the most analyst-visible environment
artifact in this review.

## Synthetic Indicator Summary
No defensible `hard_contradiction` was established in connection ordering, packet arithmetic,
five-tuple reuse, or ordinary protocol lifecycle. The verdict is based on converging repeated
artifacts rather than one impossible packet.

| Indicator | Label | Scope | Weight |
|---|---|---:|---:|
| Multi-megabyte, simplified/future-dated GPO-like objects on SYSVOL/NETLOGON | `environment_or_collection_plausibility` | 40 transfers; 10 >1 MiB | High |
| Nearly every repeated content-hashed URL/status group has a different response-byte count | `distribution_texture` | 53/54 groups; 144/146 rows | High |
| Good OCSP status for a self-signed non-CA raw-IP leaf via a public responder path | `contract_gap` | One certificate/transaction | Medium |
| Nonzero 304 byte counts without declared header/body counter semantics | `schema_or_format`, `weak_signal` | 130 proxy rows | Low |

## Realism Score by Category
- **Field format accuracy:** 9 — Zeek JSON, UID/FUID use, ASA framing, Snort fast-alert syntax,
  X.509 fields, packet arithmetic, and protocol fields are overwhelmingly source-native; proxy
  byte semantics and one OCSP case prevent a 10.
- **Temporal patterns:** 9 — Bursts, long tails, expected DHCP renewal cadence, irregular DNS
  activity, incomplete states, and stable per-sensor clock offsets look operational rather than
  uniformly sampled.
- **Cross-source correlation:** 10 — Sensor-local UIDs, independent clocks and packet loss, exact
  tuple reconstruction, ASA counters, SMTP relays, tunnel identity, and file hashes correlate
  without collapsing distinct observation semantics.
- **Behavioral realism:** 7 — Proxy browsing, mail relay, scanning, DB, DNS, and lateral traffic
  are convincing, but immutable-object byte jitter and DC-share content reduce credibility.
- **Environmental consistency:** 7 — Host/subnet roles and firewall paths are coherent; the
  SYSVOL/NETLOGON vocabulary and sizes, future-year paths, and isolated self-signed OCSP workflow
  are notable environment-level artifacts.

## Recommendations
1. Model SYSVOL and NETLOGON as source-specific storage, not generic SMB shares. Use canonical
   domain/GPO GUID directory structures, keep `gpt.ini`, registry-policy, XML preference, and logon
   script sizes within type-appropriate distributions, and reserve multi-megabyte objects for
   binaries or explicitly justified deployment payloads.
2. Give cacheable web objects durable content identity keyed by URL/version and content encoding.
   Repeated 200 responses for a hash-versioned JS/CSS/image should reuse entity length and hash;
   represent compression variants as a small stable set. Keep per-request transport/header bytes
   separate from entity-body bytes.
3. Define proxy counters explicitly. If `sc_bytes` includes response headers, name or document it
   as an on-wire/message counter and emit a separate zero entity-body count for 304 responses. If
   it is intended as body bytes, set it to zero for 204/304.
4. Gate OCSP generation on a valid issuer/AIA contract. Self-signed leaves should not receive a
   normal trusted-issuer OCSP companion; malformed hostile OCSP should be represented as such and
   should not look like ordinary status validation.
5. Preserve the current sensor-specific behavior: independent UIDs/FUIDs, stable clock offsets,
   viewpoint-specific packet loss, ASA/Zeek byte accounting, partial lifecycle visibility, and
   hash continuity are the strongest authenticity features in the corpus.
