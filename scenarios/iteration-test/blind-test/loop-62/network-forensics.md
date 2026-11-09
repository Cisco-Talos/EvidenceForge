# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 72

## Executive Summary

The network evidence is substantially realistic: protocol records correlate coherently with transport tuples, modern TLS is present, and DNS and connection-state distributions have plausible variety. The strongest contrary evidence is a localized but reproducible inconsistency between HTTP file loss, HTTP body accounting, and the same Zeek sensor's TCP gap accounting; identifier-length distributions provide a weaker secondary signal. These defects support a likely-synthetic verdict without suggesting that the entire network corpus is implausible.

## Evidence For Synthetic

- [contract_gap] Five HTTP 200 response files claim more missing bytes than their entire owning TCP connection reports missing. Four are on `zeek-core` connections with `missed_bytes=0` and no content-gap history flag: `files.json:58`/`conn.json:947` (374 versus 0), `files.json:390`/`conn.json:6574` (2,166 versus 0), `files.json:467`/`conn.json:7370` (1,284 versus 0), and `files.json:682`/`conn.json:10994` (1,693 versus 0). These are exact `conn_uids` joins, not inferred activity matches.
- [hard_contradiction] A particularly strong direction-and-count contradiction occurs in `zeek-dmz/files.json:526`: responder file `Fge76RvJNVLm2g9JYQE`, UID `CPYL9PEH7d2mXzcIZU`, has `is_orig=false`, `seen_bytes=140204`, `total_bytes=141609`, and `missing_bytes=1405`. The same UID in `zeek-dmz/conn.json:4300` reports only 31 missed bytes and history `ShADadfFG`, whose sole gap marker is uppercase `G`, indicating originator-side loss. The sensor subsequently parses response transactions 4–7 (`http.json:793–796`), making this an in-window discrepancy within an ongoing, successfully parsed connection.
- [schema_or_format] HTTP body lengths repeatedly behave like captured file-byte counts rather than Zeek's gap-aware HTTP message length. Among 23 HTTP 200, depth-zero response files with nonzero `missing_bytes`, 18 have `http.response_body_len == files.seen_bytes < files.total_bytes` (7 core, 11 DMZ); five retain the total length. For example, `zeek-dmz/http.json:792` reports 140,204 bytes for the gapped JavaScript response above. Standard Zeek increments the HTTP body length across a recognized body gap before exporting it. This is closely related to the previous loss-accounting finding and is not treated as an independent dataset-wide defect.
- [weak_signal] Connection UID lengths follow almost the same unusual 17/18/19-character mixture on all three sensors: core 1,237/7,500/3,752; DMZ 898/5,646/2,795; DB 52/288/128. Example 19-character UID `Cg1WlSiUAaTOdI2YN9F` appears at `zeek-core/conn.json:6`. Zeek supports configurable UID bit lengths, so 19 characters alone is not an error. The repeated approximately 10%/60%/30% mixture looks more like a chosen string-length distribution than the distribution from one fixed bit-length setting; identifier remapping or collector customization could explain it. This carries little weight.

## Evidence For Real

- Every examined DNS, HTTP, SSL, SMB and SMTP UID resolves to a connection on its own sensor, with matching endpoint addresses and ports. Across the 12,614 records checked in those protocol families, none precedes its connection start by more than 1 ms or extends beyond the recorded connection duration by more than 1 ms. This is positive consistency evidence, not an authenticity penalty for completeness.
- DNS is not restricted to successful A lookups. Core has A 2,303, TXT 310, AAAA 277, PTR 174, SRV 103, plus SOA/NS/MX; its response codes include 208 NXDOMAIN, 13 SERVFAIL and 4 REFUSED. `zeek-core/dns.json:24` (`wpad`) and `:127` (`wpad.meridianhcs.local`) are credible Windows-related negative-query examples, while SRV discovery targets the domain controllers.
- TLS versions and cipher/key relationships are internally plausible. DMZ has 1,877 TLS 1.3 and 789 TLS 1.2 rows, with four incomplete handshakes lacking a version; the DB sensor's 22 TLS observations are TLS 1.2. Among available referenced certificates, no checked ECDHE_RSA/ECDHE_ECDSA leaf-key mismatch or validity-window violation was found.
- Incomplete certificate observations are handled conservatively. All 78 SSL file records with nonzero file gaps across the sensors lack both a corresponding X.509 record and a complete-file SHA-1 hash. For example, `zeek-core/files.json:23–24` records truncated certificate files without inventing parsed certificates or full hashes.
- HTTP browsing includes multiple transactions on one UID, 304 cache responses, 206 partial responses, mixed resource types and nontrivial page assets. `zeek-dmz/http.json:790–796` includes a page, JavaScript, an image, favicon, CSS and a cached SVG, with a common client tuple and appropriate transaction depths.
- Firewall NAT and lifecycle records have meaningful structure. `fw-perimeter/cisco_asa.log:4,6,8–9` joins a dynamic translation from `10.10.3.20:40671` to `203.14.220.1:43574`, an outbound connection to `204.79.197.202:443`, its teardown and translation removal. Snort includes DNS, STUN, scanning and application-policy signatures rather than a single repeated alert type.

## Detailed Analysis

### Input provenance and examination method

Actual local inputs were `/private/tmp/log-study-yflye15q/network-prompt.md` and files under `/private/tmp/log-study-yflye15q/data`. I inventoried the supplied data directory, parsed all JSON records in its three Zeek sensor directories using system `python3` with working directory `/private/tmp`, and inspected supplied firewall, Snort and proxy records. No project code, authored scenario, roadmap, worklog, earlier result or other reviewer's report was accessed. Generic inherited operating instructions were not used as origin evidence. Official upstream Zeek sources were consulted to verify native field semantics; no task-project web pages or general web searches were used.

All file/line references below are relative to the supplied data directory and use one-based physical line numbers. There was no packet capture or collection configuration available, so judgments about analyzer customization and capture policies remain qualified.

### Volume, observation window and flow states

The three sensors contain 12,489 core, 9,339 DMZ and 468 DB connection records. Core connection starts span 2026-11-02 13:00:03.414812–18:59:28.340331 UTC; DMZ and DB lie within essentially the same six-hour interval. Duplicate visibility between sensors was not counted as distinct enterprise activity.

Core states are SF 9,995; S0 1,685; OTH 471; RSTO 156; RSTR 106; REJ 32; S2 21; S3 15; S1 8. DMZ has SF 6,321; S0 2,462; OTH 326; RSTO 106; RSTR 71; REJ 30; S1/S3 8 each and S2 7. This is a credible mix of successful traffic, unanswered attempts, resets and partial activity. The 14:00 UTC hour contains much more unsuccessful activity than adjacent hours: core S0 rises to 1,298 and DMZ S0 to 1,486. I do not interpret those counts as uniform background failures or penalize an active scan simply because it is concentrated in time.

No TCP SF row lacked both directional FIN markers; no row had positive payload bytes in a direction reporting zero packets; none violated the basic minimum header-byte floor checked against packet counts. These tests cannot substitute for packet-level reconstruction, but they remove several simple transport-accounting objections.

The six-hour slice is insufficient to assess overnight traffic, daily periodicity or weekend variation. Missing out-of-window beginnings and endings were not scored.

### Protocol mix and environment

Core destination ports include DNS/53 (3,196), Kerberos/88 (2,464), explicit proxy/8080 (2,071), LDAP/389 (1,278), SMB/445 (714), HTTPS/443 (664), SSH/22 (379), syslog/514 (352) and HTTP/80 (350). DMZ is dominated by 443 (3,280), 8080 (2,291), DNS (1,018), HTTP (663) and MySQL/3306 (587). On the DB sensor, 286 of 468 flows target MySQL, predominantly from `10.10.3.10` to `10.10.4.10`, which is compatible with a web/application-to-database path.

Most HTTP rows are CONNECT requests: core 2,005 of 2,209, DMZ 2,059 of 2,430 and DB 21 of 28. Thus the raw HTTP-row count should not be interpreted as predominantly cleartext web browsing. The proxy logs explicitly distinguish CONNECT control traffic from tunnel byte totals and separately identify inspected HTTPS requests; `PROXY-01.meridianhcs.local/proxy_access.log:6–7` illustrates a CONNECT/inspected-GET pair sharing `tunnel_id=PT-d303501621658dc3` and `client_src_port=38363`.

Port placement, private address roles and proxy behavior are broadly consistent. No penalty is assigned for absent QUIC, absent native macOS network logging, or lack of a particular optional Zeek protocol file.

### DNS and TLS

DNS rows have matching transport tuples; no checked A/AAAA answer was an IP address of the wrong address family. Question and basic A/AAAA response sizes fit the associated UDP payload counts. RTTs range from submillisecond local lookups to seconds for slower cases rather than one fixed latency. Hostname-only SRV targets and `TXT <length> <text>` summaries are legitimate Zeek output conventions, confirmed in the [upstream DNS script](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/dns/main.zeek); they were not mistaken for malformed resource records.

TLS 1.3's predominantly `Cs` history and lack of exposed certificates is compatible with passive observation of encrypted handshakes. TLS 1.2 has full and resumed histories, and available leaf certificates match the authentication algorithm implied by their cipher. Certificate identities stay consistent when the same fingerprint recurs. Domain names and external address/domain associations were treated as potentially sanitized.

### HTTP gap semantics: the decisive inconsistency

The main finding is about contradictory source-local observations, not the amount of source coverage. The strongest single example is:

| File and line | Relevant fields |
|---|---|
| `zeek-dmz/conn.json:4300` | UID `CPYL9PEH7d2mXzcIZU`; `10.10.1.33:58995 → 10.10.3.10:80`; `ts=1793631884.675523`; `missed_bytes=31`; `history=ShADadfFG`; SF |
| `zeek-dmz/http.json:792` | Same UID; `ts=1793631886.251349`; depth 3; GET `/assets/js/vendor.757467b6.js`; status 200; body 140,204; response FUID `Fge76RvJNVLm2g9JYQE` |
| `zeek-dmz/files.json:526` | Same FUID and UID; responder file; `seen_bytes=140204`; `total_bytes=141609`; `missing_bytes=1405`; `timedout=false` |
| `zeek-dmz/http.json:793–796` | Later response transactions on the same connection continue to be parsed |

For the JavaScript response on this persistent HTTP connection, 1,405 missing responder file bytes cannot be explained by 31 missing originator TCP bytes. The [upstream connection script](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/conn/main.zeek) defines the gap byte count and directional history letters. A custom file-analysis omission policy could cause application-local gaps without TCP capture loss, so I do not assume every file gap must imply packet loss. But the body counter is still inconsistent with the standard recognized-gap path: [Zeek's HTTP analyzer](https://raw.githubusercontent.com/zeek/zeek/master/src/analyzer/protocol/http/HTTP.cc), `HTTP_Entity::Undelivered`, adds recognized body-gap lengths, and the [HTTP logging script](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/http/main.zeek) exports that message body length.

An independent same-stream comparison reinforces the issue. `zeek-core/http.json:957` reports 385,100 bytes for `/assets/img/hero.webp` and `files.json:390` reports 2,166 missing bytes from a 387,266-byte file. Its `conn.json:6574` nevertheless has no missed bytes or gap flag. The DMZ sees the same tuple and transaction at `http.json:1076` and `files.json:752` with the full 387,266 bytes. Both connection records retain identical responder payload and IP byte totals, packet counts and normal shutdown state (`zeek-dmz/conn.json:5154`). A server-side truncated response is therefore an inadequate explanation for this pair.

There are legitimate distinctions among file completeness, TCP reassembly, analyzer skipping and HTTP message statistics. The report's finding is the combination of mismatched counters, direction and successful subsequent parsing, rather than a blanket assertion that any incomplete HTTP file is impossible. The native version and any custom transformation policy would be the next evidence needed to overturn it.

### Identifier texture and uncertainty

The configurable default in [Zeek's initialization script](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/init-bare.zeek) is 96 UID bits. Its [UID implementation](https://raw.githubusercontent.com/zeek/zeek/master/src/UID.cc) converts fixed-size integer segments to base 62. The observed length mixture is unusual for that process and repeats across sensors, but configuration changes, combined sources or export remapping remain possible. I consequently give this much less weight than the exact HTTP/FUID/UID contradictions and make no claim that a nondefault UID length is inherently invalid.

The verdict also allows for a real dataset that has undergone a faulty normalization or anonymization step. Such a process could explain apparently synthetic source-native counter behavior. With only the supplied records, that explanation is less convincing than synthetic construction but cannot be excluded.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affects the score |
|---|---|---|---|
| `hard_contradiction` | DMZ Zeek HTTP/files/conn | One especially clear persistent connection, UID `CPYL9PEH7d2mXzcIZU` | Responder file loss exceeds total transport gaps and contradicts the only gap direction; later transactions remain parsed. Highest-weight example. |
| `contract_gap` | Core Zeek HTTP/files/conn | Four HTTP 200 response files | File losses of 374–2,166 bytes coexist with zero connection gaps; same-stream DMZ comparison rules out server truncation for a cited case. |
| `schema_or_format` | Core and DMZ HTTP message lengths | 18 of 23 gapped, depth-zero HTTP 200 response files | Body lengths collapse to captured file bytes rather than the native recognized-gap message length. Related to the preceding loss-accounting issue, so not double-counted as a separate broad defect. |
| `weak_signal` | Zeek connection identifiers | All three sensors | Repeated 17/18/19 length proportions are atypical for a fixed UID-bit configuration; export customization is a plausible alternative. Small contribution only. |

## Realism Score by Category

- **Field format accuracy:** 8 — Native formats and protocol fields are largely credible; HTTP gap/body statistics are the clearest exception.
- **Temporal patterns:** 9 — Variable timing, concentrated unsuccessful activity and source-local protocol ordering are convincing within the six-hour window.
- **Cross-source correlation:** 7 — Tuples and references align well; HTTP/file/transport loss accounting has demonstrable exceptions.
- **Behavioral realism:** 8 — Proxy use, cached/ranged resources, mail TLS, database traffic and infrastructure protocols form a plausible mix.
- **Environmental consistency:** 9 — Sensor traffic roles and NAT/proxy paths are broadly coherent; no demonstrated platform-placement contradiction was found.

## Recommendations

- If this were synthetic, make each source-local HTTP response derive file completeness, HTTP message length, TCP content gaps and history direction from one coherent observation model. Test the cited five UIDs, including cases where a later HTTP response is parsed on the same persistent connection.
- Preserve the distinction between captured file bytes and HTTP message body length across recognized gaps. Verify the intended behavior against the actual Zeek version and analyzer policy instead of copying `seen_bytes` into `response_body_len`.
- If application-local omission is intentional, ensure the exported fields accurately reflect that mechanism and document the collection policy; do not imply responder packet loss through file metadata while recording only originator transport loss.
- Check the UID bit configuration or any identifier remapping against the observed length distribution. Preserve a real native distribution when rendering native-looking Zeek identifiers; this is a lower-priority concern than loss accounting.
