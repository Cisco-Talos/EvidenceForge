# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 75
**Synthetic-Confidence Score:** 20

## Executive Summary

The bounded sample is production-like: two exact cross-source pivots preserve account, endpoint, transport, application, and timing relationships without a demonstrated contradiction. I cannot determine origin from this sample; the low synthetic-confidence score describes the observed telemetry, while the verdict confidence describes confidence that the available evidence does not support an origin determination.

## Evidence For Synthetic

- No qualifying synthetic indicator was demonstrated in the inspected sample. In particular, neither high cross-source agreement nor the visibility of suspicious commands establishes synthetic origin.
- The aggregate recurrence of scheduled commands was considered and rejected as an indicator: `WS-LNGUYEN-01` has 36 creates each for the `debian-sa1` wrapper and child, and `LOG-MON-01` has the same counts over approximately six hours. A common ten-minute schedule explains that count; the aggregate alone does not show implausible timing or human behavior.

## Evidence For Real

- The SSH pivot retains the exact tuple `10.10.1.41:55417 → 10.10.2.30:22`, with a successful Zeek transport, endpoint attribution to `maya.ross`, and later target authentication/session opening. Source timestamps differ in a plausible way rather than requiring exact equality.
- The upload pivot distinguishes application body bytes from proxy wire bytes: Zeek reports a 1,573,258-byte POST body and 96-byte response body; proxy access records 1,573,700 client bytes and 306 server wire bytes with a 96-byte response. These are compatible measurements at different protocol boundaries.
- Native and normalized Mac samples distinguish a `fork` from a later `exec`, retain audit and execution identities, and represent a long-running parent whose start precedes collection. I found no reason to interpret the pre-window parent as a missing initiator.
- The collection contains substantial routine traffic, scheduled monitoring, DNS, authentication, file sharing, and background process evidence across a mixed fleet. Suspicious command lines are a small portion of the source volumes; their mere visibility is not an authenticity defect.

## Detailed Analysis

### Scope and method

Only the assigned data directory and supplied briefing were examined. This was a bounded hunt, not an exhaustive audit: I inspected 20 complete representative records, used selected-field command discovery and aggregate counts, and followed two exact cross-source pivots. No embedded command or URL was executed or followed.

The data exposes 23 endpoint directories with normalized eCAR records, Windows Security/Sysmon XML, Linux syslog and shell history, two Mac endpoint/Unified Log collections, three Zeek sensor directories, proxy/web access, firewall, and IDS sources. The normalized endpoint window is approximately November 2, 2026, 13:00–19:00 UTC. The eCAR source contains 39,151 records: 28,678 FLOW/CONNECT, 2,683 PROCESS/CREATE, 2,541 PROCESS/TERMINATE, 1,007 USER_SESSION/LOGIN and 532 USER_SESSION/LOGOUT, among other objects. These counts do not themselves prove missing lifecycles: collection boundaries, account semantics, and source identity matter.

The combined Zeek connection count is 23,644, proxy access count 4,316, and firewall count 25,085. Windows XML was parsed as events rather than treating XML line count as record count: the supplied Security files contain 12,800 event 5156 records, 2,087 event 4769 records, 935 event 4688 records, 863 event 4624 records and 28 event 4625 records, among others. Sysmon contains 8,226 event 3, 1,193 event 22, 934 event 1 and 795 event 5 records, among others. I do not infer that omitted or less numerous event families should exist under an unspecified collection policy.

### Exact pivot 1: Mac SSH to an application server

The relevant records are:

- `MAC-MROSS-01.meridianhcs.local/ecar.json:387`: timestamp `1793638886001` (17:01:26.001 UTC), FLOW/CONNECT, PID `69926`, principal `maya.ross`, command `/usr/bin/ssh maya.ross@APP-INT-01.meridianhcs.local`, source `10.10.1.41:55417`, destination `10.10.2.30:22`.
- `zeek-core/conn.json:8958`: timestamp `1793638883.889877` (17:01:23.889877 UTC), UID `CvyGmX1UNCL7WtEJOm`, identical tuple, service `ssh`, state `SF`, duration `574.955112`, 43,600 originator payload bytes and 64,930 responder payload bytes.
- `APP-INT-01.meridianhcs.local/syslog.log:170–173`: sshd PID `2975359` observes the same source tuple at 17:01:27.841416; accepts a password for `maya.ross` at 17:01:40.000447; PAM opens the session at 17:01:40.108028; logind creates session `410` at 17:01:40.710813.

The transport precedes accepted authentication in both network and endpoint observations. The password acceptance precedes PAM opening and logind session creation. The source's local username need not share the target's numeric UID: target PAM identifies UID `2176`, which is not a contradiction with Mac audit UID `501` in the independently sampled Mac execution record. This exact pivot supports operational coherence. I did not audit every SSH continuation or close and make no claim about those uninspected records.

### Exact pivot 2: support attachment through an explicit proxy

The relevant records are:

- `WS-LNGUYEN-01.meridianhcs.local/ecar.json:502`: 16:42:28.821 UTC, PROCESS/CREATE UUID `0b3fc5cd-087b-4bc9-a399-b05840db0208`, PID `2981051`, principal `lina.nguyen`. The curl command specifies proxy `http://proxy.meridianhcs.com:8080`, a JSON metadata part with ticket `MHS-48217`, and archive `/tmp/mhs-support-48217.tar.gz`, directed to `/api/v1/cases/MHS-48217/attachments`.
- `PROXY-01.meridianhcs.local/proxy_access.log:2641`: 16:42:45 UTC, client `10.10.1.21`, authenticated principal `lina.nguyen@meridianhcs.local`, matching POST URL, status 200, `curl/7.81.0`, response size 96, `cs_bytes=1573700`, `wire_sc_bytes=306`, `proxy_action=forward`.
- `zeek-core/http.json:1587`: 16:42:45.314036 UTC, UID `C09WEMTz1u8lKh5iYYK`, client `10.10.1.21:36016` to proxy `10.10.3.20:8080`, identical absolute URI, user agent, method and status; request body 1,573,258 bytes and response body 96 bytes. The record exposes JSON and gzip MIME types and archive filename `mhs-support-48217.tar.gz`.

A process beginning roughly 16 seconds before the observed HTTP request is plausible; no timing contract requires immediate request transmission. A plain-HTTP explicit proxy request uses the proxy as transport responder while preserving the destination in the HTTP host/absolute URI. Two MIME parts with only one filename are compatible with an unnamed JSON metadata part. These details support a usable hunt pivot without establishing whether the attachment is legitimate or malicious, and without treating source completeness as suspicious.

### Additional representative evidence and interpretation limits

The remaining samples cover a DNS connection, Linux rsyslog queue status and its normalized outbound log-forwarding flow, Mac fork and loginwindow records, a Mac SSH exec, a DB-host scp process and an unrelated inbound database flow, a privileged Windows PowerShell process, and a Mac browser CONNECT proxy entry. The Mac ES fork at 13:00:06.950823 uses parent PID 1 with an October 21 start time and child PID 41136; the normalized sample labels that activity as `operation=fork`. A separately sampled Mac `PROCESS/MODIFY` at 14:24:59.622 labels `operation=exec`, retains object UUID `fe3cd3c2-784a-4a83-8fe9-ebcace00c39a`, and moves from zsh to ssh. I did not verify the entire ES native schema against OS documentation and do not claim exhaustive native-format validation.

`DB-PROD-01/ecar.json:477` shows root running scp for `/tmp/rpt_0318.sql.gz` to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. This is a hunt lead, not proof that the transfer succeeded; the adjacent record 478 is a different tuple on port 3306 and cannot be used as its corroboration. `DC-01/ecar.json:5576` shows a SYSTEM PowerShell EncodedCommand with a download expression; that is a separate lead, not proof of payload execution or subsequent effects. I did not penalize the absence of unsearched companions or infer account privileges from command text alone.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| No demonstrated indicator | Inspected endpoint, syslog, proxy and Zeek records | 20 representative records; two exact pivots; limited aggregates | Supports a low appearance score of 20 within the reviewed scope; does not establish production provenance |

No hard contradiction, contract gap, schema defect, or substantiated distribution defect was established. Common scheduled counts and cross-source completeness were excluded from the indicator set.

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled fields are usable and internally consistent; native schema validation was limited.
- **Temporal patterns:** 9 — The exact SSH and upload sequences are plausible; six hours and 20 records do not support broad temporal claims.
- **Cross-source correlation:** 9 — Two exact pivots preserve tuple/application identity and source-specific byte/timing semantics.
- **Behavioral realism:** 8 — Commands and privilege boundaries support plausible hunt leads; success and effects were not inferred from intent alone.
- **Environmental consistency:** 9 — Mixed-fleet source roles and observed volumes are plausible within the collection slice; topology and policy were not independently available.

## Recommendations

No evidence-backed corrective recommendation follows from this bounded review. If this were synthetic, preserve the demonstrated separation of transport opening, authentication, PAM/session lifecycle, explicit-proxy addressing, and body-versus-wire accounting. Further quality work should validate the exact DB scp transfer and privileged PowerShell lead before changing behavior; the reviewed record set does not establish defects in either.
