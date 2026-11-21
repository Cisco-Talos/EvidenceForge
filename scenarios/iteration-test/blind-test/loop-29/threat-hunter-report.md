# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 65
**Synthetic-Confidence Score:** 28

## Executive Summary

I lean toward real, sanitized enterprise telemetry, with moderate confidence: the strongest evidence is operationally coherent process, authentication, network, and file activity across a mixed fleet. I found a weak repetitive-command texture on the two Macs, but did not demonstrate a hard contradiction or a compelling cross-source lifecycle failure in the checks described below; this remains a probabilistic assessment, not proof of origin.

## Evidence For Synthetic

- [weak_signal] The two Mac shell histories have a relatively narrow diagnostic vocabulary. `MAC-MROSS-02.meridianhcs.local/zsh_history/maya.ross.zsh_history` contains 19 commands but only 12 distinct command strings, including three repetitions each of `du -sh /Users/maya.ross/Documents` and `ps aux`; the other Mac has 24 commands and 18 distinct strings, including four `id` invocations. In its eCAR stream, MROSS-02 repeats the Documents size check at 14:12:40.600, 15:31:59.440, and 17:32:42.091 UTC. This could reflect a small activity pool, but the same named operator uses both machines, and troubleshooting is an adequate production explanation. It has only a small effect on my score.
- I identified no sufficiently demonstrated `hard_contradiction`, `contract_gap`, or `schema_or_format` finding to add to the score. In particular, the presence of a well-supported intrusion sequence is not itself evidence of synthesis.

## Evidence For Real

- The source mix is substantial and differentiated: 37,414 normalized endpoint rows on 23 hosts, 23,141 Zeek connection observations across three sensors, 4,379 proxy requests, 899 web access rows, 25,529 firewall rows, and 145 IDS alerts. The apparent six-hour window contains routine traffic and maintenance as well as suspicious activity; malicious commands are not the only meaningful workload.
- Cross-source SSH pivots preserve endpoint addresses and source ports while allowing source-specific timestamps. For example, `zeek-core/conn.json` line 2420 records `10.10.1.41:62772 → 10.10.1.42:22`, starting at 14:24:26.141893 UTC; the target eCAR stream records the same inbound tuple at 14:24:26.553 and the successful `maya.ross` SSH session at 14:24:36.023. Native target process observations place the SSH service startup and session shell in the intervening interval.
- Native Mac process evidence distinguishes fork from exec, maintains PID continuity through exec, changes audit-token PID versions, and represents the setuid behavior of `/usr/bin/login`. These details support plausible operating-system behavior rather than merely matching names between sources.
- The support upload has distinct client-to-proxy and proxy-to-upstream legs, proper absolute versus origin-form request targets, two request MIME entities, and a file created before it is read for upload. This is an operationally credible pivot across endpoint, proxy, and Zeek data.
- Routine DHCP evidence is internally useful rather than decorative: Linux clients log request/ACK/bound sequences and subsequent renewals consistent with their announced timers and the sensor's different lease durations.

## Detailed Analysis

### Orientation and method

I examined only the supplied data directory. The endpoint scope comprises 11 Windows hosts, 10 Linux hosts, and two Macs, with role names suggesting workstations, domain controllers, file services, mail services, application/database servers, a proxy, and monitoring. The main visible interval is November 2, 2026, approximately 13:00–19:00 UTC, across the `10.10.1`, `10.10.2`, `10.10.3`, and `10.10.4` networks.

I inventoried all supplied source families, parsed the endpoint JSON, Windows XML, Mac native JSON, and Zeek JSON, and followed selected suspicious and routine activities across formats. I also performed dataset-wide bounded consistency checks: visible eCAR process actor references against creation/termination, native Mac process starts and post-exit references, HTTP body sizes against connection byte totals, and Zeek protocol timestamps against their associated connection intervals. These tests establish the specific properties tested, not the authenticity of every field.

### Operational lifecycle coherence

Across all 23 eCAR files, the actor-reference check found no event preceding the same actor's visible process creation or following its visible termination. This deliberately excludes absent pre-window births and absent post-window exits. Process creation after an explicitly visible logout of the same logon ID was not found either. These results are positive operational evidence, not a claim that complete matching itself establishes reality.

The Mac native streams contain 144 and 163 records respectively: MROSS-01 has 46 fork, 53 exec, and 45 exit notifications; MROSS-02 has 51 fork, 62 exec, and 50 exit notifications. There were no future `start_time` values or notifications using an already exited exact `(pid, pidversion)` identity in the checked native records.

On MROSS-01, `/usr/bin/login` executes at 13:07:32.867172 UTC, with its target audit token changing effective UID from the calling user's 501 to 0 while retaining real UID 501. Its file mode is 35181 decimal, consistent with a setuid executable. The subsequent `/bin/zsh` execution at 13:07:32.886423 runs as UID 501. MROSS-02 similarly represents `login -fpl ... ShellLauncher --launch_shell`. This matters because a superficially plausible terminal tree can otherwise erase the privilege transition or confuse exec with a new process.

I did not infer successful execution of MeetingAssist from the MROSS-01 Unified Log message at 15:42:09.009673 stating that security policy “would not allow” the process. That message alone does not prove a completed executable image, a denial outcome, or downstream effects. Likewise, inventory plist creation and removal are separate observations from service execution.

### SSH pivots

For the MROSS-01 to MROSS-02 session, the network sensor sees the TCP/22 connection before target authentication. Native target ES records then show launchd forking PID 99697 at 14:24:31.083276, its progression through xpcproxy, the SSH wrapper and sshd, and the eventual zsh execution at 14:24:35.428147. Target eCAR records successful authentication at 14:24:36.023 with source port 62772. Source-specific offsets explain why the normalized and native timestamps are not identical; the transport-before-auth relationship remains usable.

The reverse session also works as a pivot: `zeek-core/conn.json` line 6610 records `10.10.1.42:54545 → 10.10.1.41:22` at 16:02:02.087110. MROSS-02 eCAR line 296 attributes that tuple to `/usr/bin/ssh -tt maya.ross@MAC-MROSS-01.meridianhcs.local`; target eCAR line 323 records the matching inbound flow at 16:02:04.360, preceding target login at 16:02:10.018. The target Unified Log public-key acceptance at 16:02:08.243284 and native shell execution at 16:02:08.397555 provide further independent-looking session context.

### Downloads and support upload

MROSS-01's history records downloading `connector-check.sh`, then running it with bash. Native ES records curl's exec at 13:48:41.201976 and exit status 0 at 13:48:59.520345; eCAR line 95 records the download-path file creation at 13:48:42.960, followed by bash execution at 13:49:09.687. A file opened during transfer, a successful curl exit, and later execution form a workable sequence. Domain spelling was not used as an authenticity indicator.

The Linux upload is especially useful for assessing tradecraft and pivots. In `WS-LNGUYEN-01.../ecar.json`, line 435 launches tar at 16:31:34.993, line 436 creates `/tmp/mhs-support-48217.tar.gz`, and line 439 launches curl with two form fields: inline JSON metadata and the gzip diagnostics file. Line 443 reads that same artifact at 16:32:04.432.

`zeek-core/http.json` line 1396 records a POST from `10.10.1.21:42549` to proxy `10.10.3.20:8080`, with the absolute URI, request body length 1,573,258, and `application/json` plus `application/gzip` MIME types. The connection reports 1,573,700 originator bytes, which can contain the body plus headers. `zeek-dmz/http.json` lines 1578–1579 distinguish the client-facing request from the forwarded request to `52.44.186.73:80`; the latter uses `/api/v1/cases/MHS-48217/attachments`. Proxy access line 2221 agrees on the user, request, HTTP 200 outcome, and 96-byte response body. The file entities need not have equal-length filename and MIME arrays: the inline metadata part has no filename.

### Suspicious activity and background workload

There is a credible investigation trail without needing to assume that every unusual action is malicious. WEB-EXT-01's access log line 509 shows a POST to `/ehr/admin/upload.php` at 14:20:17. Its eCAR line 960 shows apache2 launching a base64-decoding bash pipeline as `www-data` at 14:20:27.968. Later root-session discovery commands and scanning warrant investigation, but I do not infer a particular privilege-escalation mechanism from temporal proximity alone.

On DC-01, Sysmon records PSEXESVC at 17:00:14.791, later WMI-parented commands add `svc_dirsync`, add it to Domain Admins, and configure DeviceSyncSvc and a scheduled task. Security events 4720 at 17:15:05.8149075 and 4728 at 17:15:13.8607171 retain the new account's SID ending `-2188`; event 4726 at 18:50:30.3730345 deletes the same SID. The visible administrative commands and audited effects are technically intelligible. Their compactness or completeness does not influence my score.

Background traffic is role-differentiated: the DB sensor has 273 MySQL connections among 430 total, while the core sees substantial DNS, Kerberos, LDAP, SMB, and web/proxy traffic. Linux sysstat jobs repeating 36 times over six hours fit a ten-minute scheduled task and are not suspicious uniformity by themselves. DHCP adds further lifecycle detail: WS-LNGUYEN's 13:01:19.740490 bound message announces renewal in 1,885 seconds, and the next request is at 13:32:45.563468, approximately the predicted interval. Zeek records that client's one-hour lease, versus a four-hour lease for WS-OHADDAD.

### Limits and alternative explanations

All checked HTTP request/response body lengths fit their associated directional connection byte totals. The checked HTTP, SSL, DNS, SMTP, and matched SMB timestamps lie within the associated sensor-local connection intervals, allowing 10 ms comparison tolerance. One SMB mapping (`zeek-core/smb_mapping.json` line 93, UID `C4bqaKVpaYQLPkuTrz`, at 17:35:24.871449) lacks a connection row in the slice. A connection can be logged only after it closes beyond the slice, or be independently dropped by collection, so I did not score that absence as synthetic.

The restricted Mac command vocabulary is the main residual concern. It could be templated baseline activity, but the records also show SSH, a support script, application activity, and file access; repeated diagnostics by one operator are not enough to outweigh the coherent lifecycle evidence. Normalization, deliberate source selection, and sanitization also limit the strength of either origin claim. I did not penalize filtered Sysmon event types, thin Unified Log coverage, complete cross-source matching, or absent out-of-window initiators.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `weak_signal` | Mac zsh history and normalized process telemetry | Two hosts operated by the same named user; 43 history commands total | Repeated diagnostic vocabulary slightly increases suspicion of a small activity pool; plausible troubleshooting prevents a stronger conclusion. |
| No demonstrated high-impact indicator | Cross-source lifecycle, native process, and network checks described above | Broad checks plus targeted pivots | No confirmed impossible ordering, impossible field value, or generator identity leak was established. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source records and inspected native process/audit fields are coherent; not every native field was independently validated.
- **Temporal patterns:** 9 — Transport, authentication, process, file, and DHCP relationships examined are plausible, with source-specific offsets.
- **Cross-source correlation:** 9 — SSH and proxy upload pivots work at tuple, identity, artifact, and protocol levels without a demonstrated contradiction.
- **Behavioral realism:** 8 — Administrative and suspicious behavior is technically intelligible; the Mac interactive vocabulary is somewhat narrow.
- **Environmental consistency:** 9 — Service-oriented source mixes, mixed-platform paths, identities, maintenance, and collection boundaries are credible.

## Recommendations

- If this were synthetic, broaden the two Macs' routine interactive command vocabulary only where the intended operator workload supports it; the repeated Documents size checks and generic host diagnostics are the clearest remaining texture worth reviewing.
- Preserve the demonstrated source-specific timing, privilege transitions, SSH tuples, proxy-leg distinctions, and file identity continuity. I found no evidence-based reason to add arbitrary source families, more attack mistakes, or additional event types solely to change the apparent authenticity.
