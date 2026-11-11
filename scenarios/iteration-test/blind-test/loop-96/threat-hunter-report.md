# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 30

## Executive Summary

The bounded sample is mostly production-like: two independently selected suspicious activities support usable endpoint/network/application pivots with compatible identities, account ownership, and visible lifecycle ordering. I found no demonstrated contradiction or generator fingerprint in the 20 representative records examined; that supports a low synthetic-confidence score, but this small sample cannot establish production provenance.

## Evidence For Synthetic

- No supported synthetic indicator was established in the bounded review. Apparent extra Windows path escaping in displayed JSON disappeared after decoding: the examined eCAR and native Sysmon command lines are exactly equal, 196 characters, with no doubled path separators. This is not an authenticity defect.
- The repeated scheduled command pool is measurable but not a scored indicator: `/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'` and `debian-sa1 1 1` each occur in 360 of 2,749 eCAR PROCESS/CREATE records. A recurrent sysstat task can legitimately repeat. This aggregate alone does not establish unrealistic timing or distribution.

## Evidence For Real

- The SCP pivot preserves exact process identity `a689ee9c-c74d-4545-bcdd-00cca3c16a77`, PID 1089180, principal `root`, and tuple `10.10.4.10:37862 -> 10.10.2.30:22` across endpoint and network evidence. Remote sshd public-key acceptance precedes the target endpoint login; source termination follows transport closure.
- The curl pivot preserves PID 6932, parent PID 6784, principal `aisha.johnson`, and `10.10.1.35:53885 -> 10.10.3.20:8080`. The proxy records the same client source port and upload URL, with `proxy_action=ssl-inspect ssl_bump=bump`, giving a concrete reason for HTTPS request visibility.
- The source mix contains 19,623 Windows Security events, 12,162 Sysmon events, 39,151 eCAR records, 23,644 Zeek connection records across sensors, 4,463 syslog lines, 4,316 proxy rows, and 160 Snort lines. Security events include successful and failed authentication, Kerberos traffic, process lifecycle, network policy, and file access. These counts do not demonstrate an implausibly empty background for the visible 23-host, approximately six-hour collection.
- Different sensors retain different UIDs and modest observation-time offsets for the same transport tuple. The inspected records preserve matching packet/byte totals without requiring identical timestamps.

## Detailed Analysis

### Scope and method

I read only the supplied briefing and assigned data directory. The review inspected 20 representative raw records, supplemented by file inventory, event-family counts, command-frequency aggregates, and decoded comparisons of already-inspected records. It is not an exhaustive audit. The eCAR timestamp span is 2026-11-02 13:00:00.756 through 18:59:50.485 UTC. There are 23 host directories, Windows Security/Sysmon, Linux syslog and histories, two Mac endpoint exports, normalized eCAR, three Zeek sensor directories, proxy, firewall, web, and IDS sources.

Counts above are records for NDJSON/line sources and parsed Event elements for Windows XML; XML line counts were not treated as event counts. Multiple sensors can observe a single connection, so the Zeek total is not a unique-session denominator. The solitary Mac ES representative record was insufficient to judge the native Mac collection; I make no Mac schema or lifecycle finding.

### Exact pivot 1: database SCP to application host

`DB-PROD-01.meridianhcs.local/ecar.json:477` creates `/usr/bin/scp`, PID 1089180, under `/bin/bash`, root, at 18:16:05.383. The command copies `/tmp/rpt_0318.sql.gz` to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. Line 479 attaches the same process UUID and PID to outbound TCP source port 37862 at 18:16:08.968.

`zeek-core/conn.json:11643`, UID `CKrloaHiL9PiHXUDkx`, observes the exact tuple at 18:16:08.360165, with SSH service, SF state, 18.830982-second duration, 931,308 originator bytes and 29,855 responder bytes. `zeek-db/conn.json:375`, UID `CFUyTxkZcnCp5VrbXx`, observes it approximately 72 ms later with compatible duration and identical byte/packet totals.

`APP-INT-01.meridianhcs.local/syslog.log:225` records sshd PID 2984040 receiving that exact source tuple at 18:16:13.796468. Line 227 records successful public-key authentication for root at 18:16:16.277719. Target eCAR line 917 records a successful root SSH login at 18:16:17.975 with the same IP/port, target session 475 and logon ID `0x153beedd`. Source eCAR line 481 terminates the exact SCP process at 18:16:27.911, after the core transport's approximately 18:16:27.191 close.

This is a feasible transfer sequence. The independent target login/session identity need not equal the source process's session 321. The evidence establishes transport, accepted authentication and process lifecycle, not independently verified archive contents or ultimate persistence of the destination file.

### Exact pivot 2: Windows upload through inspecting proxy

`WS-AJOHNSON-01.meridianhcs.local/ecar.json:1430` creates curl PID 6932 at 18:25:01.980, process UUID `f3083f8e-f1d7-4731-a48c-b65aed9b1b35`, parent cmd PID 6784, user aisha.johnson, logon ID `0x27c9a29`. Native Sysmon EventRecordID 31678, Event ID 1, records the same PID, command, parent, user, session 3 and logon ID at 18:25:01.795025. This subsecond difference is compatible with source observation timing.

The command submits `C:\ProgramData\Microsoft\cache_7f3a.zip` as an archive to `https://api.westbridge-services.net/upload/telemetry/7f3a2b19` using proxy `10.10.3.20:8080`. eCAR line 1438 binds its exact process UUID to client source port 53885 at 18:25:06.264.

`zeek-core/conn.json:11947`, UID `Cgdvm7K8zNtDYIZySOH`, sees the exact client/proxy tuple at 18:25:05.894129, SF, duration 4.098444 seconds, 18,810,324 originator bytes. The DMZ sensor also sees that tuple with a separate UID and slightly earlier observation. `PROXY-01.meridianhcs.local/proxy_access.log:3965` records the same URL, user `MERIDIANHCS\aisha.johnson`, client port 53885, curl/8.4.0, HTTP 200, `cs_bytes=18783258` and tunnel ID `PT-b27ab0df9e91e7fa` at 18:25:06 UTC. Request-layer bytes being slightly below TCP-originator bytes are directionally plausible; the sources measure different layers.

The archive upload is a hunt lead, not proof that every archived byte is sensitive. A separately sampled Linux support-diagnostics curl command carries a ticket number, component metadata and a log archive, illustrating why an upload should be assessed against account and destination context rather than classified solely by tool name.

### Interpretation limits

Complete joins and a compact suspicious sequence were not scored as synthetic. Neither source absence nor out-of-window lifecycle endpoints were penalized. No commands or URLs from the records were executed. The score describes the observed surface: mostly realistic with substantial unexamined scope. Confidence in an inconclusive provenance verdict is separate from that surface score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| None demonstrated | Examined endpoint, SSH, Zeek and proxy records | 20-record bounded sample and two exact pivots | No upward adjustment for a concrete defect |
| Unscored observation | eCAR scheduled process commands | Two recurring command strings, 360 creations each out of 2,749 | Repetition is explainable by scheduled collection; insufficient to call distribution_texture |

## Realism Score by Category

- **Field format accuracy:** 9 — Examined native Sysmon, syslog, Zeek and proxy fields are usable; unfamiliar Mac details were not scored as errors.
- **Temporal patterns:** 8 — Both inspected activity chains have feasible order and duration; broad timing distributions were not audited.
- **Cross-source correlation:** 9 — Exact process identities, tuples, users and client ports support both pivots without a demonstrated ownership conflict.
- **Behavioral realism:** 8 — SCP and proxy curl activity technically fit their visible accounts and transport; intent and content remain unproven.
- **Environmental consistency:** 8 — Mixed host/source coverage and background event families are plausible at the observed scale; service placement and long-tail behavior were not exhaustively verified.

## Recommendations

- If this were synthetic, preserve the demonstrated separation of source and destination SSH sessions, transport-before-authentication ordering, and source-specific observation timing. No corrective change is justified by the inspected chains.
- Preserve explicit proxy inspection context and client-port fields: they explain the HTTPS POST visibility and allow an exact join without assuming decryption from the URL alone.
- No defect-driven realism remediation is supported by this bounded review. Additional sampling would be required before changing command distributions or platform coverage based on these results.
