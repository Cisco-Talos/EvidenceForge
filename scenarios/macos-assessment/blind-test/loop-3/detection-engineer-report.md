# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 67

## Executive Summary

This is largely usable, carefully correlated telemetry, but several recurring source-native field semantics and one conspicuous timestamp pileup make synthetic data more likely than production data. The strongest concerns are the SMB mapping `service` values, the NTP reference identifiers, and 13 distinct Windows process creations sharing one `UtcTime` millisecond; I did not find an impossible visible process lifecycle in the identifiers tested.

## Evidence For Synthetic

- **[schema_or_format] SMB share name substituted for service type.** All 49 rows in `office-span/smb_mapping.json` have `service="Engineering"`, `share_type="DISK"`, and a path ending in `\Engineering`. For example, line 1, UID `CpDmnkLMDmtmUXfsMxy`, is timestamped `2026-10-20T13:02:15.508175Z`. In native Zeek SMB mapping semantics, `service` represents the SMB service-type value, such as `A:` for a disk service, rather than another copy of the share name. An unavailable service field can also be absent, particularly for SMB2. Repeating the share label in this field across the entire family resembles a semantic mapping error. A custom normalized exporter could explain it, but that would make these records a transformed representation rather than a faithful native Zeek view.
- **[schema_or_format] NTP reference identifier uses reference-clock display notation at stratum 2.** All 12 rows in `office-span/ntp.json` pair `version=4`, `mode=4`, and `stratum=2` with `ref_id=".GOOG."`. Line 1, UID `CHk3C6dFeEhRvHofkw`, occurs at `2026-10-20T13:09:42.519645Z`; line 2 repeats the combination at `13:44:12.488354Z`. The reference identifier is a four-octet protocol field. Reference-clock ASCII identifiers belong to the stratum-1 interpretation; a secondary server's identifier has the upstream-address/hash interpretation. The six-character dotted label is also characteristic of a human-oriented NTP display. This repeated combination is a source-semantic concern, not an objection to using Google time servers. An undocumented display transformation remains a possible explanation.
- **[distribution_texture] Fourteen Windows creations are compressed into two event-time milliseconds.** In `NS-WIN-01.northstar.example/windows_event_sysmon.xml`, EventRecordIDs `606893`–`606906` contain 14 Event ID 1 rows: 13 have `UtcTime="2026-10-20 13:05:56.148"` and one has `.149`. The group includes Sublime Text opening three different files, two VS Code launches, two Postman launches, Notepad++, and several Windows components. In `NS-WIN-01.northstar.example/ecar.json`, lines 81–92 independently put 12 process creates at exactly `13:05:56.251Z`. Their Security 4688 counterparts are spread from `13:05:56.2087497Z` to `.7794792Z`. Startup restoration or batching could produce a burst, but the concentration of separate application creations at the exact same native occurrence millisecond is stronger than ordinary clustered activity. It is a distribution artifact, not proof of impossible ordering.
- **[environment_or_collection_plausibility] Browser-looking HTTP is systematically owned by a service process.** All 10 Windows-origin HTTP rows with `Chrome/119.0.0.0` in `office-span/http.json` map by their connection tuples to `svchost.exe -k netsvcs`, PID 5620, principal `NETWORK SERVICE`, in Windows eCAR. For example, HTTP line 1 connects `10.42.0.21:54996` to `23.45.126.50:80` for `www.citrix.com`; eCAR line 57 assigns that tuple to PID 5620, and Security record `244811` corroborates the same PID and device path. The same pattern covers ordinary browsing and page-resource destinations, including Reddit, Hacker News, and Google at HTTP lines 29–31. A service using a browser user agent, or a local mediation service, is possible, so this is supporting evidence rather than a hard contradiction. Its consistency across all 10 browser-style Windows HTTP requests suggests a generic process-ownership fallback.

## Evidence For Real

- **Windows event structure is generally accurate and SIEM-friendly.** Both XML documents parse, their namespaces and provider/channel identities are coherent, Security success/failure keywords are distinguished, and decimal Sysmon PIDs correspond to hexadecimal Security PIDs. The eight observed Security event types and eight observed Sysmon event types have recognizable source-specific fields.
- **Negative DNS results use the Windows status namespace correctly.** Sysmon Event ID 22 has 96 successful rows with `QueryStatus=0` and seven negative rows with `QueryStatus=9003`, rather than substituting DNS wire response code 3. Record `606871`, at `13:05:02.3382446Z`, records `wpad`, status 9003, and `QueryResults="-"`.
- **The explicit-credential sequence preserves meaningful identity distinctions.** Security records `245420`–`245423` and Sysmon records `607476`–`607477` show `runas /netonly`, the original local principal, the outbound account `nora.ellis-admin`, a Type 9 logon, and a new LUID `0x1053ddd9` for the child `cmd.exe`. This is considerably more realistic than replacing the child's local user with the outbound credential name.
- **Visible process lifecycles are coherent.** Across all four eCAR files, I found no actor-dependent event before that actor's visible creation or after its visible termination, and no termination before its matching visible creation. Sysmon `UtcTime` checks also found no visible process create/terminate inversion or parent/source/target use outside a matched visible lifecycle.
- **Network references and transport timing hold together.** Every DNS, HTTP, TLS, NTP, SMB file, and SMB mapping row joins to a connection with the same UID and endpoint tuple. Their timestamps lie within the corresponding visible connection intervals, and DNS response RTTs fit within those intervals. Packet/IP-byte counters meet the tested minimum IPv4 header-accounting bounds.
- **TLS and OCSP contain substantial coherent detail.** TLS 1.2 cipher authentication types agree with linked certificate key types; repeated server certificates retain their fingerprints and serials. Decoded OCSP GET request identifiers agree with their linked response issuer hashes and serial numbers. Certificate extraction gaps are accompanied by connection-level missed bytes rather than appearing as unexplained missing X.509 rows.
- **macOS records preserve source distinctions.** The supplied native ES fork records use eight-word audit tokens and preserve parent/child PID relationships and credential transitions. Unified Log records use consistent per-host boot UUIDs and coherent wall-clock/Mach-clock progress. I did not interpret normalized eCAR network flows as native Endpoint Security network events.

## Detailed Analysis

### Scope and parsing

I inspected only the supplied evidence directory and used read-only, in-memory analysis. All 9,318 JSON/NDJSON records parsed, as did the two Windows XML documents containing 582 Security events and 458 Sysmon events. The normalized endpoint files contain 1,422 Windows, 664 Linux build-host, 893 first-Mac, and 1,204 second-Mac records. The visible activity spans approximately `2026-10-20 13:00`–`19:00 UTC`.

I treated eCAR as normalized telemetry with its own string-valued properties, not as a native operating-system schema. I did not score absent event families, thin native Mac exports, unavailable domain-controller telemetry, filesystem modification times, domain authenticity, or lifecycle endpoints outside the collection window.

### Representative native event checks

The following checks cover 20 representative records or event groups. Windows record IDs refer to the corresponding XML file under `NS-WIN-01.northstar.example/`.

| Record | Fields checked and result |
|---|---|
| Security 4688, record `244784`, `13:00:54.3688714Z` | Version 2, Task 13312, hexadecimal new/parent PIDs, Subject SID/LUID, elevation token and mandatory label are structurally appropriate. New PID `0x1740` equals Sysmon PID 5952. |
| Security 4624, record `244785`, `13:00:56.1505593Z` | Version 2; local interactive Type 2, `User32`/`Negotiate`, absent remote address, and explicit target LUID `0x10372067` are mutually plausible. |
| Security 4689, record `244788`, `13:01:00.5954559Z` | Version 0; exit status `0x0`, PID `0x174c`, process path, SID and logon ID are well shaped. |
| Security 4648, record `244791`, `13:02:12.9417729Z` | Version 0; explicit credential subject, target account/server, caller PID and logon GUID fields are present. I did not assume its IP field necessarily denotes the target server. |
| Security 5156, record `244792`, `13:02:15.2739408Z` | Decimal PID 5968, NT device application path, protocol 6, outbound `%%14593`, and ALE connect layer fields are coherent. |
| Security 4672, record `244808`, `13:04:50.7998471Z` | Version 0; subject SID/LUID matches the preceding successful network logon and privilege names are string-valued. |
| Security 4634, record `244816`, `13:05:45.7990858Z` | Type 3 and target LUID `0x10379f7a` match the earlier record `244807`; logout follows login. |
| Security 4625, record `244835`, `13:05:56.1714664Z` | Audit-failure keyword `0x8010000000000000`; `Status=0xc000006d`, `SubStatus=0xc000006a`, and `FailureReason=%%2313` form a plausible bad-password result. |
| Sysmon 1, record `606850`, `13:00:54.1773146Z` | Version 5; process/parent GUIDs, millisecond `UtcTime`, decimal PIDs, image metadata, hashes, user and integrity fields have recognizable shapes. |
| Sysmon 5, record `606854`, `13:01:00.3689099Z` | Version 3; process GUID/PID and user identify the terminating `userinit.exe`; the visible creation precedes it. |
| Sysmon 7, record `606867`, `13:04:09.6660713Z` | Image and loaded-image identities are separate; signature, signature-status, hash and user fields are present. The unusual DBeaver DLL name alone was not treated as proof of a nonexistent binary. |
| Sysmon 22, record `606871`, `13:05:02.3382446Z` | Windows DNS status 9003 is used for the negative lookup; image, process GUID and PID remain attached. |
| Sysmon 3, record `606878`, `13:05:55.1011611Z` | Version 5; UDP protocol, Boolean-looking native strings, source/destination address families, ports and `Initiated=true` are consistent. |
| Sysmon 10, record `606923`, `13:08:04.4153043Z` | Source/target GUID/PID/image pairs, source thread, `GrantedAccess=0x1000`, call trace and two user fields are distinct and well formed. |
| Sysmon 11, record `607031`, `13:37:19.7690941Z` | Version 2; creator image, target filename and creation time are present; the named PowerShell process exists first. |
| Sysmon 13, record `607035`, `13:37:44.7879498Z` | Version 2; `EventType=SetValue`, expanded user-SID registry path, value details and process identity are recognizable. |
| `office-span/smb_mapping.json`, line 1, `13:02:15.508175Z` | Endpoint tuple and UID join correctly, but `service=Engineering` appears to duplicate the share name rather than preserve native SMB service-type semantics. |
| `office-span/ntp.json`, line 1, `13:09:42.519645Z` | Client/server tuple, mode, timing fields and converted poll interval are plausible; the stratum/reference-ID combination is the concern described above. |
| `NS-BUILD-01.northstar.example/syslog.log`, lines 17–20, `13:08:28.602636Z` onward | RFC 5424 framing, SSH source tuple, accepted-publickey message, PAM open and logind session creation occur in a sensible order with stable SSH PID 50042. |
| `NS-MAC-02.northstar.example/macos_endpoint_security.ndjson`, line 3, `15:07:49.936834000Z` | Declared message version 10 and fork notification shape; parent PID 45520/pid-version 35 and child PID 45521/pid-version 36; child parent token agrees with the actor, and credentials retain UID 501/GID 20. |

### Timing and lifecycle analysis

The Windows creation pileup is localized rather than a claim that the entire dataset has uniform timing. The 14 Sysmon creations involve materially different process images and command lines, including `sublime_text.exe webpack.config.js`, `sublime_text.exe Dockerfile`, `sublime_text.exe app.config`, and two `Code.exe --folder-uri` processes. Thirteen rows share `.148` even though the source includes higher-precision `TimeCreated` values. Their matching eCAR group has its own single-millisecond plateau. That combination is consistent with events being moved to a common scheduling boundary or timestamp floor. Production batching and startup restoration remain alternatives, so I classify this as distribution texture rather than a hard contradiction.

Conversely, the first visible SSH connection has sensible lifecycle relationships. `office-span/conn.json` line 1 starts tuple `10.42.0.11:56613 -> 10.42.0.31:22` at `13:00:08.467170Z`, with duration `3663.993447` seconds. The build-host eCAR login is at `13:00:12.445Z`, its shell PID 49217 is created at `13:00:12.904Z` on line 5, and that shell terminates at `14:01:13.327Z` on line 164, just after transport closure at approximately `14:01:12.461Z`. This is credible transport-before-session timing and source-local close latency.

I excluded the well-known Windows service LUIDs `0x3e7`, `0x3e5`, and `0x3e4` from naïve one-login-per-ID reasoning. Repeated service logons using those fixed identities do not establish a later creation of the operating system's service identity. Missing pre-window parent creates and long-running processes surviving the window were likewise not counted as defects.

### Network schemas, certificate evidence, and packet accounting

The network logs contain 2,255 connections, 1,056 DNS records, 937 TLS records, 38 HTTP records, 381 file records, 284 X.509 records, and 27 OCSP response records. These volumes alone do not establish either provenance.

I checked UID/tuple relationships for DNS, HTTP, TLS, NTP, SMB files and SMB mappings. No mismatched tuple was found. Every tested protocol timestamp falls inside its connection's visible start/duration interval. DNS transaction response times also fit. No connection's directional IP-byte count fell below application bytes plus minimum IPv4 transport-header accounting for the observed packet count.

The TLS certificate check did not reveal RSA/ECDSA cipher/key mismatches. For example, TLS line 51 uses `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` for `drive.google.com`, and its linked X.509 leaf, line 23, has `certificate.key_alg=id-ecPublicKey`, `certificate.key_type=ecdsa`, and a 256-bit key. Its RSA certificate signature is not contradictory: an RSA issuer can sign an EC subject public key.

Ten established, non-resumed TLS 1.2 handshakes lack `cert_chain_fuids`. I investigated rather than scoring that absence. For UID `CulV4CdQUhH9a6boBa`, TLS line 83 joins connection line 239 with `missed_bytes=51` and a gap marker in history; file lines 48–49 report incomplete certificates with 9 and 8 missing bytes. The other such handshakes also have connection/file loss evidence. This makes their absent parsed certificate chains explainable.

OCSP request/response correspondence is a further positive. HTTP line 5's decoded request and OCSP response line 1 agree on issuer-name hash `14dcb315ede798d6239ad75e2196634149e19286`, issuer-key hash `82cab9f7aea444c2a0bd066ac3020a56d7e01a77`, and serial `3C26E7082081805285E5C6A7737D6E62`. The same comparison held for the 27 HTTP responses linked to OCSP records.

The SMB `service` and NTP `ref_id` concerns therefore stand apart from reference integrity: their rows join properly, but particular source-native field meanings appear to have been replaced with convenient labels. I do not flag the Linux Samba server's `native_file_system=NTFS`; Samba can advertise that value independently of its underlying local filesystem.

### Endpoint ownership and Mac interpretation

For browser-style Windows HTTP, the suspicious feature is the declared owner, not the presence of browsing. The ten Chrome-style requests all resolve to the same NETWORK SERVICE `svchost.exe`, and the WFP evidence agrees with eCAR rather than naming a browser process. The dataset does contain Chrome process creations with file version `120.0.6099.225`, but a user agent is configurable and I do not treat that one-version discrepancy as a hard contradiction. A service legitimately fetching web resources could explain individual requests; the complete repeated pattern across news, general browsing, analytics and application sites increases its weight.

The native Mac records did not supply an equivalent demonstrated schema error. In the three fork notifications, PID 45501 first has an unset audit user, then audit user 501/session 100000 while retaining effective root credentials. PID 45520 subsequently appears with UID 501/GID 20 before forking PID 45521. Those are meaningful distinctions between audit identity, effective identity, process creation, and later execution. The notification result does not establish an authorization denial, and I did not interpret it that way.

The native and normalized exports have different timestamps; a normalized create appearing later than an ES fork was not automatically treated as impossible causality. Similarly, two loginwindow Unified Log records per Mac do not establish that all Unified Log subsystems were collected. Their limited coverage was not scored negatively.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `schema_or_format` | Zeek-like SMB mappings | All 49 records | Strongest semantic concern: share name copied into the service-type field. Custom transformation is a possible alternative. |
| `schema_or_format` | Zeek-like NTP | All 12 records | Repeated stratum-2/reference-clock-display mismatch; moderate weight because exporter presentation is not documented. |
| `distribution_texture` | Windows Sysmon and eCAR process creation | One 14-process native burst; 12 eCAR creates share a millisecond | Strong localized timestamp-floor/batching texture involving separate application launches. No impossible ordering alleged. |
| `environment_or_collection_plausibility` | Windows eCAR/WFP plus HTTP | All 10 Windows browser-style HTTP requests | Repeated service ownership of browser-looking traffic; supporting weight with service/proxy alternatives retained. |

The score is below 81 because I did not demonstrate an impossible field value or lifecycle ordering within the tested identifiers, and much of the cross-source construction survives detailed checking. It is above 60 because the concerns recur across whole protocol families and across native/normalized Windows timing views rather than resting on a single unusual record.

## Realism Score by Category

- **Field format accuracy:** 7 — Parsing and Windows shapes are strong; SMB service semantics and NTP reference-ID presentation weaken native fidelity.
- **Temporal patterns:** 6 — Lifecycle ordering is credible, but the 13-process single-millisecond plateau is a pronounced localized artifact.
- **Cross-source correlation:** 9 — UID/tuple integrity, process references, TLS keys, certificate hashes, OCSP identifiers and visible interval checks are strong.
- **Behavioral realism:** 7 — Varied endpoint and network activity is plausible; the application-creation pileup and repeated service-owned browser HTTP remain unusual.
- **Environmental consistency:** 8 — Platform paths and identities are mostly coherent, including Mac credentials and Linux Samba; systematic browser/service attribution needs explanation.

## Recommendations

- If this were synthetic, populate SMB mapping `service` from the protocol service-type value, or leave it absent when the protocol observation does not supply one. Keep the share name in the UNC path and any separately declared normalized share-name field.
- If this were synthetic, make NTP reference identifiers depend on the stratum and address-family semantics. Preserve protocol-derived values in the native export and keep any dotted reference-clock display label in a separately documented presentation field.
- If this were synthetic, preserve individual process occurrence times through scheduling and source rendering. Avoid moving multiple previously distinct application creations onto one timestamp floor; use an explicit ingest timestamp if batching needs to be represented.
- If this were synthetic, assign browser HTTP flows to the process that owns the socket. If a service intentionally mediates browsing, make that relationship explicit in available normalized metadata instead of silently using a generic NETWORK SERVICE owner for every browser-style request.
- Preserve the existing coherent loss handling, local-versus-outbound credential distinctions, process lifecycles, certificate reuse and OCSP request/response relationships while making those changes.
