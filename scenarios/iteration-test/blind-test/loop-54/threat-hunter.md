# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 77
**Synthetic-Confidence Score:** 62

## Executive Summary

The operational evidence is unusually competent: Windows credential abuse, remote administration, Linux SSH activity, file staging and proxy traffic generally support workable investigative pivots with plausible lifecycle ordering. My synthetic verdict rests on a specific repeated discrepancy, rather than the storyline: 57 unambiguous same-request joins report conflicting client User-Agent values between Zeek and the proxy, including browser-versus-service identities, across eight client IPs. This is a likely shared-truth defect, but unknown proxy enrichment or normalization prevents a definitive hard-contradiction finding.

## Evidence For Synthetic

- [contract_gap] **The same apparent client HTTP requests have incompatible client identities.** Joining `zeek-core/http.json` to `PROXY-01.meridianhcs.local/proxy_access.log` on UTC second, client IP, method and exact URI, retaining keys unique in both files and requiring equal status, yields 1,712 pairs; 57 pairs (3.33%) disagree on User-Agent. The affected client IP counts are `10.10.1.34=22`, `.32=17`, `.33=7`, `.36=5`, `.42=2`, `.35=2`, `.31=1`, and `10.10.2.10=1`. For example, Zeek line 352 (`CxkSt62W4FfOaTxV4l`, `2026-11-02T14:05:02Z`, `10.10.1.34:63485 → 10.10.3.20:8080`, CONNECT `ctldl.windowsupdate.com:443`) reports Chrome/120, while proxy line 526 reports `Microsoft-CryptoAPI/10.0`. This is an actual field disagreement, not an objection to complete matching.
- [contract_gap] **Some disagreements cross product families and conflict with the endpoint pivot.** Zeek line 581 (`CIRNmUDbSuFEm2Gh9X`, `14:45:04Z`, `10.10.1.31:58429`) reports an Edge/120 CONNECT to `clients6.google.com:443`; proxy line 848 reports `GoogleDriveFS/97.0.1.0 Windows`. `WS-MCHEN-01.meridianhcs.local/ecar.json:303` identifies the same source tuple with `msedge.exe`, supporting the Zeek product attribution. On macOS, Zeek line 940 (`CDShuVIK5RkdMWdYdC`, `15:48:46Z`, `10.10.1.42:49519`) reports Chrome/155, whereas proxy line 1440 adds `Edg/155.0.0.0`; `MAC-MROSS-02.meridianhcs.local/ecar.json:294` associates that tuple with Google Chrome PID 21393. These are examples of the same issue family, not additional independent score multipliers.

## Evidence For Real

- The supplied slice has substantial differentiated noise: 37,394 normalized endpoint records, 19,411 Windows Security events, 12,058 Sysmon events, 22,509 Zeek connection records across three sensors, 4,291 Linux syslog lines, and 3,551 proxy access records. These volumes provide a meaningful haystack; suspicious commands are not the only content.
- SSH transport, authentication and shell activity are temporally coherent in the inspected pivots. `APP-INT-01` connects to `DB-PROD-01` from source port 41315; Zeek core line 10979 opens at `18:15:17.717837Z`, target endpoint FLOW is line 590 at `18:15:19.641Z`, target syslog lines 202–204 accept/open the root session around `18:15:30Z`, and endpoint line 592 starts its shell at `18:15:32.235Z`.
- The apparent multipart diagnostics upload contains realistic sensor-specific loss. The request-body difference between Zeek core HTTP line 1275 and DMZ line 1433 is exactly 13,524 bytes; the corresponding core gzip file record explicitly reports `missing_bytes=13524`. Treating those two HTTP lengths as contradictory would be incorrect.
- Windows account identifiers are consistent across the checked domain logons. For example, `MERIDIANHCS\aisha.johnson` carries SID `S-1-5-21-1524654518-2022274387-1755902678-1007` on both domain controllers and her workstation. Local/system identities are distinguishable from domain identities.
- The Mac policy message is not followed by fabricated successful execution of the named application in the supplied Endpoint Security events. That respects the distinction between a policy observation and evidence of execution.

## Detailed Analysis

### Scope, method and input provenance

All file references below are relative to `/private/tmp/log-study-0sx5q8_q/data`; line references are one-based. I read only the supplied reviewer briefing and this data directory, using system `python3` from `/private/tmp` for inert parsing. I did not execute any logged commands. I did not inspect repository files, authored scenarios, prior assessments, other reviewers' material or neighboring inventories. Generic inherited operating instructions were present, but were not used as evidence of origin.

The visible endpoint scope is 23 hosts: ten Windows hosts, eleven Linux/syslog hosts, and two Macs. Endpoint records cover approximately `2026-11-02T13:00:01.077Z` through `18:59:57.382Z`. Addressing suggests a client segment (`10.10.1.*`), an internal server segment (`10.10.2.*`), a DMZ/proxy segment (`10.10.3.*`) and a database segment (`10.10.4.*`). Sensor and hostname roles are inferences from the records rather than supplied organizational facts.

I inventoried all 117 files; parsed normalized endpoint records and Windows XML; surveyed process activity, native source distributions and source tuples; followed selected suspicious and ordinary activity across endpoint, native host, network and proxy logs; checked endpoint process-parent lifecycle ordering; and compared client-side HTTP observations. This is a bounded investigation, not an exhaustive validation of every native field or every session.

One external primary reference was consulted, using the actual search domains filter restricted to `docs.zeek.org`: the [Zeek HTTP field reference](https://docs.zeek.org/en/v8.0.11/scripts/base/protocols/http/main.zeek.html). It defines `user_agent` as the client User-Agent header and the body-length fields as actual transferred uncompressed content sizes. Those definitions support interpreting the observed fields; they do not establish the dataset's provenance.

### Hunting pivots and operational coherence

`WS-AJOHNSON-01` contains credible credential-access and staging leads. Endpoint line 833 records PID 5956 running `ms-index-service.exe` with `privilege::debug` and `sekurlsa::logonpasswords` arguments at `16:45:05.122Z`. The naming alone does not prove successful credential theft. Later, lines 1126–1134 show a `runas /netonly` process and its command-shell child, followed by file enumeration/copying under a consistent local process identity. Retaining the local principal with alternate outbound credentials is technically plausible for `/netonly`.

Lines 1174, 1191 and 1210 collect files from Windows and Linux SMB shares. At `18:02:15.115Z`, line 1222 launches compression; line 1229 records creation of `C:\ProgramData\Microsoft\cache_7f3a.zip` by that process. At `18:25:19.879Z`, line 1295 launches curl with that archive and an explicit proxy; line 1302 reads the same archive identity; line 1304 supplies the source tuple `10.10.1.35:54609 → 10.10.3.20:8080`. Proxy line 3245 logs the matching upload URL and `proxy_action=ssl-inspect ssl_bump=bump`, with `client_src_port=54609`. Therefore a proxy-visible HTTPS POST is supported by the collection record's explicit inspection mode. Its presence is not a TLS visibility contradiction.

On `DC-01`, endpoint lines 3570 and 3578 show PSEXESVC and its command child near `17:00Z`. Native Security 4697 at `17:00:00.0433845Z` names PSEXESVC and a domain subject. Later native 4720 at `17:15:13.4024131Z` creates `svc_dirsync`; 4728 at `17:15:17.6947687Z` adds the same SID to Domain Admins. The corresponding endpoint commands are lines 3778–3802. I treat those as command/effect correlations, without assuming every malicious command succeeded merely because it was logged.

The Linux database pivot is similarly usable. `DB-PROD-01/ecar.json:593` runs mysqldump at `18:15:36.100Z`; line 594 creates `/tmp/rpt_0318.sql`; line 595 terminates the dump before gzip begins at line 596. Root shell-history lines 1–2 include the output redirection missing from the child's argv, which is normal shell behavior. Gzip creates the compressed archive at line 597, terminates at line 599, and scp begins at line 600. The reverse SSH transport uses `10.10.4.10:56155 → 10.10.2.30:22` in `zeek-core/conn.json:11017` and `zeek-db/conn.json:433`; the receiver's authentication appears in `APP-INT-01/syslog.log:217–219`, and its file creation is `APP-INT-01/ecar.json:942`. This is a functioning pivot rather than loosely similar narrative labels.

### Collection effects that must not be scored as defects

The diagnostics upload is particularly useful as a negative control. `WS-LNGUYEN-01/ecar.json:319` runs a two-part form upload. Core HTTP line 1275 reports `request_body_len=1559734`; DMZ HTTP line 1433 reports `1573258`. Core `files.json:404–405` contains the 50-byte metadata component and gzip component with `seen_bytes=1559340`, `missing_bytes=13524`. DMZ `files.json:973–974` observes the same 50-byte metadata and the full `1572864`-byte gzip file. Core connection line 7712 explicitly has `missed_bytes=13527` and history `ShADadfFG`, whereas DMZ connection line 6309 has no missed bytes. The body difference is thus accounted for rather than evidence that independent sources invented different upload sizes.

I also checked visible endpoint process parents against their recorded creation and termination times. No child CREATE had a known same-object parent creation more than two seconds later or known parent termination more than two seconds earlier. No scored finding rests on absent pre-window parents, absent post-window termination, intentionally omitted Sysmon types, thin Unified Log coverage, sanitized DNS names, or filesystem modification times.

`MAC-MROSS-01/macos_unified_log.ndjson:2` reports an AppleSystemPolicy message about MeetingAssist at `15:41:38.930666Z`. I found no corresponding successful MeetingAssist exec in the supplied ES events. I therefore do not infer child execution, persistence, or successful effects from that policy message. I did not attempt to assert a release-specific ES schema defect without the necessary platform verification.

### Why the HTTP identity finding affects authenticity

The strongest examples are client-to-proxy observations, not comparisons between the proxy's inbound and outbound rewritten requests. Browser version differences recur systematically, while the Edge-versus-GoogleDriveFS and Chrome-versus-CryptoAPI examples change the apparent application family. The same product identities appear in endpoint pivots, making this relevant to a hunter's attribution rather than cosmetic text variation.

There are limits: proxy software and its log-format specification are not supplied, and packet payloads are unavailable. A proxy that enriches or normalizes its User-Agent column could explain some discrepancies in real data. Consequently I classify the issue as a repeated cross-source contract gap and keep the score near the lower boundary of “likely synthetic,” rather than claiming impossible packets or a dataset-wide generator fingerprint. The several examples share one probable root issue and are not counted as independent defects.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| contract_gap | Zeek HTTP versus proxy access logs | 57/1,712 unique same-request pairs; eight client IPs | Principal scored indicator: client User-Agent identity diverges on apparently identical inbound requests. |
| contract_gap | Endpoint FLOW attribution versus proxy application identity | Selected Windows and Mac pivots within those 57 pairs | Strengthens the interpretation of the same issue; does not add an independent defect count. |

No demonstrated hard contradiction, generator identity leak, or distribution-only finding is used in the score.

## Realism Score by Category

- **Field format accuracy:** 8 — Native and normalized records are broadly usable; an exhaustive release-specific schema audit was outside this review.
- **Temporal patterns:** 9 — Inspected transport/authentication/process/file ordering is workable; scheduled system noise has plausible regularity.
- **Cross-source correlation:** 7 — Strong tuple, session and artifact pivots, with a repeatable HTTP User-Agent disagreement.
- **Behavioral realism:** 8 — Credential abuse, remote administration, staging and ordinary troubleshooting commands have technically coherent surrounding evidence.
- **Environmental consistency:** 8 — Mixed OS roles, domain identity and source-volume differences fit the visible environment; no missing-source penalty was applied.

## Recommendations

- If this were synthetic, preserve one observed client User-Agent for each inbound HTTP request across network and proxy renderings. Check both browser versions and application-family attribution using the 57 reproducible mismatches above.
- If the proxy column intentionally represents an enriched or rewritten value, describe that collection semantics explicitly and distinguish it from the original client header; otherwise analysts cannot tell a logging transformation from an attribution defect.
- Retain the coherent SSH lifecycle, shell-redirection treatment, explicit TLS inspection mode and sensor-specific missing-byte accounting demonstrated here. These are useful realism strengths, not issues requiring extra noise or invented failures.
