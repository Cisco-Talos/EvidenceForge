# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 20

## Executive Summary

The bounded sample is production-like: an SSH file transfer and an explicit-proxy upload can both be followed through endpoint and network records with consistent identities, tuples, timing, and byte direction. I found no demonstrated authenticity defect in the sampled records; that supports a low synthetic-confidence score, but twenty records and two pivots cannot distinguish actual production telemetry from a capable generator.

## Evidence For Synthetic

- No substantiated synthetic indicator in the bounded review. In particular, successful cross-source joins, a legible transfer command, similar file timestamps, and potentially sanitized domains do not count as synthetic evidence.
- No hard contradiction, required-companion gap, or quantified implausible distribution was established. This is a finding about the sampled evidence, not a claim that the full collection has none.

## Evidence For Real

- The DB-PROD-01 `scp` process (eCAR line 477, PID 1089180, objectID `a689ee9c-c74d-4545-bcdd-00cca3c16a77`) and FLOW (line 479) agree on identity, command and destination. The exact tuple `10.10.4.10:37862 → 10.10.2.30:22` matches Zeek SSH UID `CFUyTxkZcnCp5VrbXx` and APP-INT-01 sshd's root public-key acceptance from the same source port.
- The WS-LNGUYEN-01 multipart curl process (eCAR line 502, PID 2981051) connects to the configured proxy rather than directly to the HTTP origin. The exact socket matches Zeek, and proxy line 2641 records the same account, request target, curl agent, successful response and 1,573,700 client bytes.
- That HTTP upload's byte direction fits its command: Zeek records 1,573,700 originator bytes and 306 responder bytes; proxy records `cs_bytes=1573700 wire_sc_bytes=306`, while the ordinary response body size is 96. These distinct body/wire values are plausible and useful to an investigator.
- Baseline process creation includes service and user activity: across all 2,683 process-create rows, common commands include `smbd --foreground --no-process-group` (91), `taskhostw.exe /Run` (76), `-bash` (75), `WmiPrvSE.exe -secured -Embedding` (64), and `-zsh` (58). These are descriptive counts, not independent authentication of the data.

## Detailed Analysis

### Scope and sampling limits

I read only the supplied briefing and assigned data directory. I inspected twenty individual records: five initial orientation records, nine selected process-create records, two FLOW records, two Zeek connection records, one proxy request and one sshd acceptance. Aggregate scans counted records and command frequencies without treating every row as an individually reviewed sample. The review intentionally stopped after two exact pivots.

The data directory contains 118 files and 23 endpoint directories with eCAR. Available source families include Windows Security/Sysmon XML, Linux syslog and shell histories, macOS Endpoint Security/Unified Log exports and zsh histories, normalized eCAR, three Zeek sensor locations, proxy/web access, ASA and Snort. eCAR's aggregate visible range is 2026-11-02 13:00:00.756–18:59:50.485 UTC, approximately six hours; this does not establish identical boundary times for every source. Visible IPs in the pivots include `10.10.1.*`, `10.10.2.*`, `10.10.3.*`, and `10.10.4.*`; directory names alone do not prove subnet masks or full topology.

Aggregate line counts include 39,151 eCAR rows, 23,644 Zeek conn rows, 4,478 DNS rows, 5,318 HTTP rows, 3,470 SSL rows, 4,463 syslog lines, 4,316 proxy lines, 786 web access lines and 25,085 firewall lines. XML line counts are not event counts and are not used to infer Windows activity volume. The eCAR mix is dominated by FLOW/CONNECT (28,678), with PROCESS/CREATE (2,683), PROCESS/TERMINATE (2,541), USER_SESSION/LOGIN (1,007) and LOGOUT (532). Different source visibility, sensor overlap and the slice boundary preclude treating those unequal totals as gaps.

### Exact pivot 1: SSH transfer and destination authentication

1. `DB-PROD-01.meridianhcs.local/ecar.json:477` creates `/usr/bin/scp` as root at **18:16:05.383 UTC**, PID **1089180**, parent PID **1089071** (`/bin/bash`). Command: `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`.
2. The same file at line **479** records FLOW/CONNECT at **18:16:08.968 UTC**, actorID equal to that process objectID, with tuple **10.10.4.10:37862 → 10.10.2.30:22**.
3. `zeek-db/conn.json:375` records that exact tuple and UID **CFUyTxkZcnCp5VrbXx** at **18:16:08.431932 UTC**. It is a successful `SF` SSH connection lasting **18.831904 seconds**, with **931,308** originator and **29,855** responder bytes. The network start precedes the endpoint observation by about 0.536 seconds; this is compatible with separate collection delays.
4. `APP-INT-01.meridianhcs.local/syslog.log:227` records **18:16:16.277719 UTC**, sshd PID **2984040**: `Accepted publickey for root from 10.10.4.10 port 37862 ssh2`.

The exact source port avoids conflating unrelated root logons. The order is technically feasible: process starts, transport opens, authentication succeeds while the transport is still active. Two Zeek sensor matches existed for the socket; I individually inspected one and do not count overlapping visibility as two transfers. I did not inspect target file creation, shell readiness, server configuration or terminal rows and therefore do not claim the transfer's destination-file outcome or root-login policy was independently proven. Direct root SSH is sensitive but possible; it is not an authenticity defect by itself.

### Exact pivot 2: multipart HTTP upload through an explicit proxy

1. `WS-LNGUYEN-01.meridianhcs.local/ecar.json:502` creates curl at **16:42:28.821 UTC**, PID **2981051**, objectID **0b3fc5cd-087b-4bc9-a399-b05840db0208**, principal **lina.nguyen**. Its command uses `--proxy http://proxy.meridianhcs.com:8080`, multipart JSON metadata for ticket **MHS-48217**, and an attachment `/tmp/mhs-support-48217.tar.gz` directed to `http://support.valeworks-health.net/api/v1/cases/MHS-48217/attachments`.
2. The same file at line **510** records FLOW/CONNECT at **16:42:46.308 UTC**, actorID matching the process, tuple **10.10.1.21:36016 → 10.10.3.20:8080**. This is a proxy-facing socket, consistent with the command.
3. `zeek-core/conn.json:8484` records the exact tuple at **16:42:45.162754 UTC**, UID **C09WEMTz1u8lKh5iYYK**, service HTTP, `SF`, duration **19.152601 seconds**, and **1,573,700/306** originator/responder bytes.
4. `PROXY-01.meridianhcs.local/proxy_access.log:2641` records client **10.10.1.21**, user **lina.nguyen@meridianhcs.local**, **16:42:45 UTC**, a POST to that exact attachment URL, status **200**, agent **curl/7.81.0**, `cs_bytes=1573700 wire_sc_bytes=306 proxy_action=forward`.

This pivot joins the process and socket exactly, then joins the application request using client/account/target/time and the uncommon byte pair. The proxy log does not expose source port, so its join is strongly supported but not a proxy-native exact five-tuple join. Approximately 16 seconds from process creation to connection is possible; the visible logs do not show enough preparation detail to label it impossible. I cannot identify the archive contents or classify the upload as authorized support traffic versus exfiltration from the command alone.

### Background texture and platform boundaries

`debian-sa1 1 1` occurs 360 times, exactly 36 times on each of ten Linux-labelled endpoints over six hours. Paired `/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'` occurs another 360 times. A ten-minute scheduled system-activity collector explains those counts; fixed scheduled-job counts are not by themselves an implausible human-behavior distribution. I did not score this as synthetic.

The initial macOS samples show separate Endpoint Security fork evidence (child PID 41136), a normalized eCAR process row for that PID, and a loginwindow Unified Log message. I did not turn unfamiliar version-11 fields or the limited Unified Log count into schema or collection defects. I did not inspect enough native macOS lifecycle rows to judge their full semantics. A sampled WEB-EXT syslog UFW block of inbound TCP/3389 represents network filtering; it does not demonstrate an RDP service on that Linux host. Windows-native record semantics, source-family long tails and platform-specific process termination were outside the twenty-record inspection.

No absent pre-window initiator or post-window terminator was penalized. I did not execute commands or follow domains appearing in logs.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| None substantiated | Sampled eCAR, Zeek, syslog, proxy, initial macOS exports | Twenty records; two bounded pivots | No demonstrated defect raises the score. A score of 20 reflects production-like sampled telemetry with substantial untested scope. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled tuple, command and HTTP fields are plausible; native Windows and complete macOS schema correctness remain unverified.
- **Temporal patterns:** 9 — Both pivots preserve process/transport/auth or application ordering with plausible source offsets; broad activity distributions were not audited.
- **Cross-source correlation:** 9 — Two useful exact endpoint-to-Zeek socket joins; receiver SSH and proxy semantics support them, with the proxy source-port limitation stated.
- **Behavioral realism:** 8 — scp transfer and multipart support upload are technically plausible; authorization, file contents and ultimate effects remain unknown.
- **Environmental consistency:** 8 — Proxy routing, Linux collector jobs and destination SSH observations fit the visible environment; full roles and collection policies were not supplied or inferred beyond evidence.

## Recommendations

No specific realism improvement is supported by the observed evidence. If this were synthetic, I would not change the demonstrated transfer or proxy behavior on this review alone.
