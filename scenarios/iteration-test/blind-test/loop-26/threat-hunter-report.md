# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 64

## Executive Summary

The dataset supports credible hunting across Windows, Linux, macOS, network sensors, and an inspecting proxy, and the sampled activity generally preserves account, session, and transport relationships. My synthetic verdict rests principally on repeated high-resolution timestamp fractions across separate interactive-shell command launches on both Macs, with a weaker background-command vocabulary pattern supporting that judgment. I did not establish a hard contradiction in the suspicious activity, and realistic collection or automation could explain some of the remaining regularity, which limits both scores.

## Evidence For Synthetic

- [distribution_texture] Three groups of separate native macOS fork notifications preserve an identical microsecond fraction while advancing by exact whole seconds. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 35, 38, 41, and 44 occur at `13:48:41.198588000Z`, `13:49:08.198588000Z`, `13:49:43.198588000Z`, and `13:50:02.198588000Z`. Their immediately following exec notifications identify curl, bash, ls, and id, respectively. The same file's lines 55, 58, and 61 repeat `.487145000Z` at `14:37:50`, `14:38:28`, and `14:38:57`, for bash and two cat commands. These are separate child processes of the interactive zsh, rather than several fields describing one event.
- [distribution_texture] The pattern independently occurs on the second Mac: `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, lines 86, 89, and 92, records forks at `15:30:55.965208000Z`, `15:31:17.965208000Z`, and `15:31:58.965208000Z`; exec lines 87, 90, and 93 identify dscl, find, and du. Across both Macs, 10 of 54 fork notifications whose parent image is `/bin/zsh` belong to these three repeated-fraction groups. Ordinary fork-to-exec timestamps elsewhere retain varied microseconds. This localized preservation of fine-grained fractions across command groups is more suggestive of inherited scheduling anchors than organic interactive launch timing. It is one underlying indicator, not three independent defects.
- [weak_signal] Administrative sudo activity across 11 Linux hosts repeatedly draws from a common vocabulary and a very small working-directory set. There are 107 successful sudo command-message records with 60 distinct command strings, but every `PWD` is one of `/home/deploy`, `/etc`, `/var/log`, `/home/ops`, `/srv/app`, `/home/admin`, and `/tmp`. Examples include APP-INT-01 at `13:07:43.261481Z` running journalctl from `/home/ops`, DB-PROD-01 at `13:13:25.383320Z` running free from `/home/admin`, and MAIL-EDGE-01 at `13:05:49.921901Z` checking dovecot from `/home/admin`. Shared operator practices and standardized fleets are plausible explanations; this is supporting texture with little independent weight, not an impossible environment.

## Evidence For Real

- Local and remote account semantics are handled credibly. On WS-AJOHNSON-01, Security record `131022` at `18:00:45.8375845Z` records Type 9 logon `0x27c9918` with local identity `aisha.johnson` and outbound identity `marcus.chen`. FILE-SRV-01 subsequently records the SMB session from `10.10.1.35:49678` as `marcus.chen`, Type 3, record `273596` at `18:01:13.8217402Z`. The differing endpoint and file-server principals are appropriate for the visible `runas /netonly` command.
- All eight visible successful Windows Type 10 logons checked have matching TCP/3389 tuples in `zeek-core/conn.json`, with `SF` connection states and transport starts before authentication. For example, UID `CD2Ae4MMzp1GQsM1Xb` matches `10.10.1.99:57338` into WS-AJOHNSON-01; the Security logon at `16:01:25.7620464Z` occurs approximately 7.121 seconds after transport start and within its 887.866-second interval.
- The database-to-application transfer has useful pivots: DB-PROD-01 shows mysqldump, creation of `/tmp/rpt_0318.sql`, gzip, and scp; Zeek observes `10.10.4.10:49550 -> 10.10.2.30:22`; APP-INT-01 records acceptance of that source tuple and creation of the receiving archive. The receiver authentication follows transport establishment.
- The proxy distinguishes CONNECT control traffic from inspected HTTPS requests. `PROXY-01.meridianhcs.local/proxy_access.log`, lines 4044–4045, connects a curl upload to the same tunnel ID `PT-e1698317f3ded0de`, client source port `56287`, authenticated principal, and destination, while separately accounting for control-message bytes and upload bytes. This is a practical pivot rather than merely a repeated hostname.
- Network observations include unsuccessful and incomplete connections, rather than just successful application transactions. The core sensor has 1,670 `S0` connections, 156 `RSTO`, 104 `RSTR`, and 44 `REJ`, alongside 9,787 `SF`; database and DMZ sensors also show mixed states. Native Linux records include denied sudo commands and failed local authentication.
- In an automated pass over all eCAR records, I found no actor-dependent event more than one second before that actor's visible process creation or more than one second after its visible termination, where those boundaries were present. This bounded check supports lifecycle plausibility without claiming that every possible source-native relationship was verified.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory after reading the reviewer briefing. I inventoried 115 files under 23 endpoint directories and the network/collection directories. The endpoint mix is ten Windows hosts, eleven hosts with Linux-style records, and two Macs. Names and observed traffic suggest directory controllers, Windows and Linux file servers, application and database servers, several mail systems, a web-facing server, a proxy, monitoring infrastructure, and user workstations.

The eCAR window is `2026-11-02T13:00:01.033Z` through `18:59:51.224Z`. Visible internal addresses occupy `10.10.1.*`, `10.10.2.*`, `10.10.3.*`, and `10.10.4.*`; external client and destination addresses are also present. I treated domain names as potentially sanitized and made no external DNS-validity judgment.

Parsed volumes include 37,414 eCAR records, 17,780 Windows Security events, 11,606 Sysmon events, and 23,141 Zeek connection observations across the three sensors. Sensor observations are not necessarily distinct physical connections. The core sensor has 12,230 connection rows, DMZ 10,481, and database 430. There are also 4,379 proxy rows, 25,529 firewall lines, 899 web access lines, and 145 IDS alerts. These volumes provide background in which to investigate; I do not infer synthetic origin from the suspicious activity being understandable.

I used process identities and timestamps to check eCAR lifecycle ordering, parsed Windows XML, checked RDP source tuples, followed SSH/file-transfer records, and joined Zeek protocol rows to their own sensor's connection UIDs. I read native macOS process notifications separately from normalized eCAR rows and shell histories.

### Native macOS timing: strongest authenticity concern

The first repeated-fraction group contains four distinct child PIDs: `29678`, `29725`, `29784`, and `29816`. Their fork times advance by precisely 27, 35, and 19 seconds, preserving all six meaningful fractional digits. Their subsequent exec notifications occur at `13:48:41.201976000Z`, `13:49:08.207155000Z`, `13:49:43.205524000Z`, and `13:50:02.207561000Z`, so the entire file was not simply rounded to one shared fractional value.

A second group on the same host retains `.487145` for bash, cat `/etc/resolv.conf`, and cat `/etc/hosts`, with 38- and 29-second separations. The second Mac's dscl/find/du group retains `.965208`, with 22- and 41-second separations. Each group has shell ancestry and distinct executable invocations. The shell histories corroborate the command vocabulary; they do not establish that a human personally typed every command.

A scheduled interactive automation system could deliberately launch commands at these intervals. However, repeated matching to the microsecond in multiple otherwise different command groups, while adjacent native notifications vary at that precision, is a substantial distribution artifact. This is not a claim that any individual timestamp is impossible, that the macOS message schema is invalid, or that a compact suspicious sequence is inherently synthetic. It is the primary reason the synthetic-confidence score enters the low 60s.

The two native Endpoint Security files contain fork, exec, and exit observations. Their lack of file notifications is not a defect by itself: normalized file observations need not share that native export's selected scope. Likewise, the `MeetingAssist` security-policy message does not establish denial or successful execution, and I did not use it to infer subsequent effects.

### Account-boundary and SMB pivot

The Windows collection contains a useful credential-boundary test. WS-AJOHNSON-01 eCAR line 972 records `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"` at `18:00:42.319Z`. The subsequent Type 9 Security event preserves `aisha.johnson` as the local token identity and identifies `marcus.chen` as the outbound account. eCAR then associates the command shell and collection commands with local logon ID `0x27c9918`.

FILE-SRV-01's record `273596` assigns `marcus.chen` to the incoming Type 3 SMB session from WS-AJOHNSON-01's address and port. Record `273599`, Event 5145 at `18:01:14.0455140Z`, references `Q1\FY24\Q1-forecast.xlsx` on the Finance share using the same server logon ID `0xf885aa0`. A later collection command uses source port `52518`; the server establishes another `marcus.chen` session `0xf885bd2` and records corresponding file access.

This is operationally coherent. Treating the local `aisha.johnson` process identity and remote `marcus.chen` identity as a contradiction would misread the explicit netonly boundary.

### Remote-session ordering

The eight RDP Type 10 logons checked consume successful transport intervals rather than rejected or reset placeholders. Their observed authentication offsets range from approximately 7.121 to 8.856 seconds after the corresponding core-sensor connection starts. That band is fairly narrow, but common client behavior and a shared environment can explain it; I did not give it independent synthetic-indicator weight.

Examples include FILE-SRV-01's `14:45:25.5674484Z` logon from `10.10.1.35:61426`, matching UID `CiDi47kWJbCAt2BRD8`, and DC-01's `18:10:16.8201921Z` logon from `10.10.1.31:58141`, matching UID `CD7ygDiatXu09qjsfA`. Both authenticate within visible successful TCP intervals.

For the later Linux transfer, `zeek-core/conn.json` line 10909 records UID `CoQeNZSBHFcAaYbn4G`, starting at epoch `1793643344.306524`, with a 23.395479-second duration. APP-INT-01 syslog lines 220–221 identify the same `10.10.4.10:49550` source, with connection and successful public-key messages at `18:15:49.697537Z` and `18:15:50.937493Z`. DB-PROD-01's scp invocation is visible before that transport; the destination file creation is visible afterward. The eCAR receiving-file row lands just after the sensor close, which can follow source observation latency; it is not sufficient evidence of an impossible operation.

### Proxy and protocol pivots

At `18:25:17.759Z`, WS-AJOHNSON-01 eCAR identifies curl posting the collected ZIP through `10.10.3.20:8080`. Proxy lines 4044–4045 at `18:25:21 +0000` show CONNECT and an inspected POST to `/upload/telemetry/7f3a2b19`, with the same tunnel ID and source port. The POST row reports `cs_bytes=18783258`; its companion tunnel row reports larger client tunnel traffic, `tunnel_cs_bytes=18809860`, rather than confusing the small CONNECT request with the archive body. I did not require plaintext HTTP evidence from uninspected TLS flows.

The multipart support upload on WS-LNGUYEN-01 also has client/proxy and proxy/server observations. The core HTTP row at line 1396 carries an absolute-form proxy URI and both JSON and gzip request MIME types. DMZ rows 1578–1579 distinguish the client-facing proxy hop from the outgoing server hop and use origin-form on the latter. This is a credible source-specific representation.

All HTTP, DNS, SSL, SMTP, and SMB-file rows checked resolved to a connection UID within their own sensor, with protocol timestamps no more than one second outside the associated interval. One SMB-mapping row lacked a visible connection UID; I did not score that absence because this is a collection-window slice. I found no HTTP success response attached to an `S0` or `REJ` connection. Basic per-direction payload/IP-byte/packet bounds also held across all Zeek connection rows. These checks do not establish authenticity, but they remove several common causes of unusable synthetic hunting pivots.

### Background and limitations

The mixture includes periodic service activity, administrative SSH sessions, DNS and Kerberos traffic, web scanning, failed connections, failed local authentication, and denied commands. The shared Linux sudo vocabulary and seven-directory PWD pool look somewhat templated, but are not compelling alone. Uniform operational procedures could produce some of this repetition.

I did not score missing Sysmon families, absent pre-window processes or sessions, the completeness of cross-source coverage, thin Unified Log exports, sanitized destination names, file modification times, or the apparent narrative completeness of suspicious actions. I did not validate unfamiliar macOS schema details against outside material, and therefore make no native-schema error allegation. No hard contradiction was established by this review.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Native macOS Endpoint Security process notifications | Three command groups across two hosts; 10 of 54 shell-parent forks retain group-identical microsecond fractions over exact whole-second gaps | Primary indicator. Fine-grained timestamp inheritance across distinct launches is unusually specific; adjacent exec times show that the export retains finer variation. Strong enough to favor synthetic origin, but automation remains possible. |
| `weak_signal` | Linux sudo/syslog administrative activity | 107 successful command-message rows across 11 hosts, 60 command strings, seven PWD values | Minor supporting influence only. Shared vocabulary and directory selection suggest a reusable background pool; standardized administration is a credible alternative. |

The two rows are not equivalent evidence. The verdict is driven by native process timing, not the weak administrative-vocabulary observation. There is no demonstrated hard contradiction, so an 81–100 score would be unjustified.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed XML and JSON records and sampled text formats preserve useful source-specific structures; no demonstrated native-format defect.
- **Temporal patterns:** 6 — Remote-session ordering is plausible, but repeated microsecond fractions across different shell launches are a strong timing artifact.
- **Cross-source correlation:** 9 — RDP, SSH, netonly SMB access, proxy uploads, and sensor-local protocol references support practical pivots.
- **Behavioral realism:** 8 — Credential boundaries, collection commands, compression, transfers, failures, and administrative noise are technically credible; the shared background command vocabulary is somewhat narrow.
- **Environmental consistency:** 8 — The mixed fleet and four internal address groups support plausible service relationships; standardized administrative working directories are a mild concern rather than a contradiction.

## Recommendations

- If this were synthetic, give each native process launch a separately resolved high-resolution time. Preserve causal and intentional scheduling relationships, but avoid copying one fractional timestamp into multiple otherwise separate interactive command forks. Recheck the three cited macOS groups and analogous batches.
- If this were synthetic, derive sudo working directories from a host/account/session working-directory state and its actual command context. Broaden background command selection where appropriate to the visible server roles, rather than repeatedly selecting from the same seven generic directories across the Linux fleet.
- If this were synthetic, retain the demonstrated distinctions between local and outbound netonly identities, successful RDP transport intervals and target authentication, and CONNECT control bytes versus inspected request bytes. These concrete relationships currently make the hunting pivots credible and should survive timing improvements.
