# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 74  
**Synthetic-Confidence Score:** 66

## Executive Summary

The network telemetry is technically sophisticated: TCP lifecycles, DNS behavior, proxy-to-TLS sequencing, certificates, and cross-sensor correlations are mostly production-plausible. I nevertheless assess it as synthetic because several repeated source-native inconsistencies—particularly analyzer bookkeeping in `files.json` and implausible SMB/SYSVOL file characteristics—look more like generation defects than ordinary operational noise.

## Evidence For Synthetic

- `[schema_or_format]` In `zeek-core/files.json`, 87 SMB records contain `md5`, `sha1`, and `sha256` values while declaring only `analyzers: ["MIME"]`. For example, FUID `Fop8BNCiKLAKuJaJtM` at `2024-03-18T12:04:06.791175Z` has all three hashes for `Projects\2023\action-items.xlsx` but lists no hash analyzer. Other protocols in the same dataset correctly declare `MD5`, `SHA1`, and `SHA256`, making the SMB-specific behavior internally inconsistent.

- `[schema_or_format]` All three records in the `pe.json` files have corresponding `files.json` rows that list only `["SHA1"]`, despite a PE analysis record being present. Examples include FUID `FBIuvO94TpjzZKfkQn` at `17:30:28.488457Z` and `FWAJpACCLhSB7rXrG1` at `17:30:34.736523Z`.

- `[environment_or_collection_plausibility]` SMB traffic contains numerous extremely large operational files under SYSVOL/NETLOGON-style paths. Examples include `Machine\2025\groups.xml` at 5,469,156 bytes, `User\registry-final.ps1` at 4,858,601 bytes, `Policies\scheduledtasks.bat` at 4,185,454 bytes, and `User\gpt-v2.ini` at 3,154,871 bytes. Multi-megabyte GPO scripts, INI files, and XML preferences at this frequency are highly unusual.

- `[distribution_texture]` SMB filenames repeatedly combine templated modifiers and years extending well beyond the observed 2024 date: `Team\2026\action-items-draft.pdf` at `12:04:53.483651Z`, `Machine\2025\groups.xml` at `14:28:50.122642Z`, `Policies\2027\gpt-approved.ini` at `14:47:14.556257Z`, and `User\2027\startup-review.ini` at `16:50:06.752626Z`. Future planning documents are plausible individually, but the repeated year/modifier construction across user documents and operational GPO files resembles a shared vocabulary generator.

- `[distribution_texture]` HTTP redirects sometimes appear to inherit the requested asset’s MIME type mechanically. Thirteen DMZ redirects show patterns such as a `301` response for `/assets/main.css` with `text/css`, or a `302` for `/favicon.ico` with `image/x-icon`. The first such CSS example occurs at `12:03:45.769431Z`. These responses are legal, but their repeated extension-derived texture is atypical.

- `[contract_gap]` A small number of protocol records reference absent file records: four HTTP FUIDs and two SMB FUIDs do not resolve into the corresponding `files.json`, including SMB FUID `FLj...` for a 5,465,191-byte `Templates\team-roadmap.pdf`. The low frequency prevents this from being decisive, but it is a visible coverage inconsistency.

- `[weak_signal]` Every examined Zeek JSON stream is strictly sorted by its `ts` value, including `conn.json`. Native Zeek connection rows are normally written at termination while retaining connection-start `ts`, so long-lived sessions commonly introduce ordering inversions. Export-time sorting could explain this, so it carries little independent weight.

## Evidence For Real

- TCP state and history combinations are internally credible. `S0` flows contain only originator setup activity, `REJ` flows contain responder rejection, and successful `SF` sessions have realistic bidirectional histories. Packet and byte accounting also respects expected invariants.

- Connection states are diverse rather than uniformly successful. Core traffic contains 9,269 `SF`, 1,935 `S0`, 142 `RSTO`, 114 `RSTR`, 30 `REJ`, and smaller populations of `OTH`, `S1`, `S2`, and `S3`.

- Host source-port behavior is OS-plausible. Windows-like clients predominantly use ports 49152–65535, Linux-like systems use approximately 32768–60999, and the scanner shows the broader source-port behavior expected from crafted probes.

- DNS traffic has realistic breadth: A, AAAA, PTR, TXT, SRV, MX, NS, and SOA queries; NOERROR, NXDOMAIN, SERVFAIL, and REFUSED responses; Windows-style suffix-search failures involving `wpad` and `isatap`; and plausible response-time tails.

- DNS answers and subsequent TLS destinations agree. Among 1,589 outbound DMZ TLS sessions with an observed DNS name, no destination IP fell outside that name’s observed answer set.

- TLS behavior is modern and heterogeneous. The DMZ contains 1,521 TLS 1.3 and 861 TLS 1.2 sessions, while the database segment is TLS 1.2-only. Cipher selection, leaf-key type, SNI, certificate identity, validity periods, and chain relationships are mutually coherent.

- Proxy behavior has convincing timing. Of 1,587 successful HTTP CONNECT transactions, at least 1,576 pair with a subsequent outbound TLS session within 15 seconds; the median delay is approximately 0.20 seconds and the 95th percentile approximately 0.61 seconds.

- Cross-source UID integrity is strong without reusing the same UID across sensors. DNS, HTTP, TLS, SMTP, and SMB records all resolve to same-sensor connection records, and protocol timestamps remain within their parent connection intervals.

- The internal scan at approximately `13:40Z` behaves like a real network scan: `10.10.3.10` probes 254 hosts across ports 22, 80, 443, 445, and 3306, with ICMP and a realistic mixture of unanswered, rejected, reset, and successful results.

- The TXT-query sequence from `10.10.2.30` between `16:45:06Z` and `17:00:02Z` is not mechanically periodic. Its 219 queries have a median interval of 2.11 seconds, a long-tailed maximum near 51 seconds, and 214 distinct millisecond-rounded intervals.

## Detailed Analysis

### Connection and Transport Behavior

The dataset contains 20,723 connection records: 11,553 from the core sensor, 8,663 from the DMZ sensor, and 507 from the database sensor. Protocol and service distributions fit the represented zones: the core emphasizes DNS, Kerberos, LDAP, SMB, HTTP, and syslog; the DMZ emphasizes HTTP, TLS, DNS, and MySQL; and the database view is dominated by MySQL.

TCP connection-state semantics are particularly strong. No `S0` record shows responder traffic, rejected sessions have responder rejection histories, and established flows have plausible teardown or reset patterns. I found no overlapping reuse of an identical TCP four-tuple while an earlier connection remained active.

The port scan around `13:40Z` produces a marked but bounded traffic burst. Responses vary according to apparent host availability and service state rather than assigning one result uniformly across all targets.

### DNS Behavior

Core DNS contains 3,013 records: 2,241 A queries, 256 AAAA, 256 TXT, 150 PTR, 94 SRV, and a small population of MX, NS, and SOA requests. Its response codes include 2,759 NOERROR and 230 NXDOMAIN results. The DMZ contains 1,054 DNS records, including 856 A, 125 AAAA, and 61 PTR requests.

Median DNS response time is approximately 2.9 milliseconds in the core and 9.5 milliseconds in the DMZ, with credible slower tails. Address families match query types, NXDOMAIN responses do not contain fabricated answers, and observed suffix-search failures resemble normal Windows resolver behavior.

DNS-to-TLS correlation is unusually well implemented but not contradictory. Observed destination addresses consistently belong to the relevant DNS answer sets, including multi-address service responses and TTL countdown/reset behavior. Cached or pre-window resolution plausibly accounts for sessions lacking a visible query.

### HTTP, Proxy, and TLS

HTTP transaction depth is contiguous within persistent connections, response bodies do not exceed the corresponding connection payloads, and `304` responses correctly have empty bodies. CONNECT-to-TLS timing closely resembles an explicit forward-proxy environment.

The principal HTTP anomaly is repeated asset-derived MIME typing on redirects. Although HTTP permits bodies on 301 and 302 responses, repeated `text/css`, `application/javascript`, and `image/x-icon` redirect entities matching the requested extension look like response metadata selected from URL templates instead of server-specific redirect behavior.

TLS and certificate modeling is otherwise excellent. SNI-to-certificate matching succeeds for every examined certificate-bearing session: 94 of 94 in core, 560 of 560 in DMZ, and 15 of 15 in the database zone. Certificate validity, issuer relationships, key type, and TLS 1.2 cipher selection agree. Sessions without visible certificates are explainable through TLS 1.3 encryption or capture gaps reflected by `X` histories and `missed_bytes`.

### SMB and File Analysis

The clearest authenticity problems occur in SMB file telemetry. Hash-bearing SMB records omit the corresponding hash analyzer names, unlike TLS and SMTP file records elsewhere in the same collection. The three PE-analysis records exhibit the same bookkeeping problem for the `PE` analyzer.

The file content model is also environmentally weak. Ordinary documents can certainly be several megabytes, but repeated multi-megabyte `.ini`, `.bat`, `.ps1`, and GPO XML files under SYSVOL-like paths are not representative of routine domain-policy traffic. Their sizes appear insufficiently conditioned on extension and operational role.

The filenames draw repeatedly from the same compositional vocabulary—years, `draft`, `final`, `approved`, `review`, and `v2`—across otherwise unrelated paths. This effect becomes more conspicuous when future years appear inside GPO-oriented paths, rather than only in planning documents.

### Collection and Cross-Sensor Consistency

Matching flows seen by multiple sensors use independent Zeek UIDs while preserving tuples, states, byte relationships, and transaction identifiers. This is correct behavior for independent sensors. Their timestamps exhibit stable offsets—approximately 114 milliseconds between core and DMZ and 64 milliseconds between core and database—which is compatible with modest clock skew.

All examined protocol records occur within their parent connection interval, and no impossible DNS, HTTP, TLS, or SMB ordering was found. The few unresolved FUIDs are small in proportion to total volume and could reflect extraction or analyzer policy, although their presence slightly weakens the otherwise consistent file-observation model.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `schema_or_format` | Zeek SMB/files | 87 hash-bearing records | Analyzer declarations contradict populated hash fields, unlike other file protocols in the same dataset. |
| `schema_or_format` | Zeek PE/files | 3 of 3 PE records | Parsed PE metadata exists without `PE` in the associated analyzer list. |
| `environment_or_collection_plausibility` | SMB/SYSVOL | Repeated records | Multi-megabyte scripts, INI files, and GPO XML files are implausible as routine policy artifacts. |
| `distribution_texture` | SMB filenames | Dataset-wide SMB sample | Recurrent year-plus-modifier construction, including 2025–2027 GPO paths, suggests shared templated vocabulary. |
| `distribution_texture` | DMZ HTTP | 13 redirects | Redirect MIME values repeatedly track requested file extensions in a generator-like pattern. |
| `contract_gap` | HTTP and SMB file references | 6 unresolved FUIDs | Small but concrete gaps between protocol file references and file-analysis records. |
| `weak_signal` | All Zeek sources | All inspected files | Strict start-time sorting is atypical for native connection-log write order but may result from export processing. |

## Realism Score by Category

- **Field format accuracy:** 7 — Most Zeek fields and protocol semantics are accurate, but analyzer declarations conflict with populated SMB hash and PE fields.
- **Temporal patterns:** 8 — Traffic is bursty, lifecycle ordering is valid, and protocol delays are plausible; universal timestamp sorting is the main reservation.
- **Cross-source correlation:** 9 — UID relationships, proxy/TLS sequencing, DNS destinations, certificate chains, and multi-sensor tuples are exceptionally coherent.
- **Behavioral realism:** 7 — Scanning, DNS, proxy, and TLS behavior are strong, while SMB filename and file-size distributions look templated.
- **Environmental consistency:** 7 — Network roles and service placement are plausible, but the SYSVOL/NETLOGON file population is difficult to reconcile with normal operations.

## Recommendations

- If this were synthetic, derive the `analyzers` array from the analyzers that actually produced each populated field. Hash-bearing rows should declare the relevant hash analyzers, and PE records should declare `PE`.

- Condition SMB file sizes on extension, share, and operational role. SYSVOL scripts, INI files, and Group Policy preference XML should generally be much smaller than ordinary office documents or transferred binaries.

- Use separate naming models for business documents, user shares, NETLOGON scripts, and Group Policy files. Reduce cross-context reuse of year, workflow-state, and version suffixes.

- Model HTTP redirects from server behavior rather than the requested asset extension. Redirect entities should usually be empty or use a consistent small HTML/plain-text body and corresponding MIME type.

- Ensure every emitted HTTP or SMB file reference has a corresponding `files.json` record when the modeled observation profile indicates file analysis was available.

- Preserve native Zeek write order when exporting raw logs, or clearly label the output as normalized and timestamp-sorted.
