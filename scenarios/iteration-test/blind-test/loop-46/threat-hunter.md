# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 79
**Synthetic-Confidence Score:** 38

## Executive Summary

The supplied six-hour slice is operationally credible across Windows, Linux, macOS, network sensors and the explicit proxy. My strongest authenticity concern is localized scanner texture, with a secondary, less certain question about process ownership in normalized endpoint records; I did not establish an impossible visible lifecycle or a native-format contradiction sufficient to call the dataset synthetic confidently.

## Evidence For Synthetic

- [distribution_texture] The Nikto-labeled scan in `WEB-EXT-01.meridianhcs.local/web_access.log` contains 316 requests, 315 distinct `Test:` identifiers, and identifiers ranging from 103598 to 995913. The requests cover only 40 base paths. Identical requests repeatedly acquire unrelated-looking identifiers: `GET /config.php` at lines 53, 166, 227, 237 and 372 carries `562442`, `156850`, `799377`, `847902` and `564902`, respectively. A changing test identifier is legitimate for different tests, so this is a texture concern rather than proof; the almost fresh arbitrary identifier per request weakens the scanner's apparent tool fidelity.
- [weak_signal] `WEB-EXT-01.meridianhcs.local/ecar.json:840` records PID 2702825 as the Apache-child Bash process executing a decode-and-pipe-to-Bash wrapper; line 841 attributes its outbound TCP/8443 connection to that same PID and wrapper command. Ordinarily a pipeline and the nested shell execution would put the socket in a descendant execution. There is no corresponding descendant or exec transition in the visible endpoint rows. This may be an action/ancestor attribution convention in the normalized feed, so I give it little weight without that feed's ownership contract. It is not a demonstrated contradiction in native endpoint telemetry.

## Evidence For Real

- A meaningful hunt is possible without a supplied narrative. At `WEB-EXT-01.meridianhcs.local/web_access.log:419`, an external client posts to `/ehr/admin/upload.php` at 14:19:57. Apache-child shell creation follows in `ecar.json:840` at 14:20:06.317, and the outbound tuple in line 841 matches `zeek-dmz/conn.json:1625`: `10.10.3.10:41647 -> 45.33.32.30:8443`. The network row has no fabricated TLS service merely because the destination port is 8443.
- The database-to-application-server transfer has credible account, transport and receiver relationships: `DB-PROD-01.meridianhcs.local/ecar.json:536-539` and `APP-INT-01.meridianhcs.local/ecar.json:775-779` agree on TCP source port 58586, sender `10.10.4.10`, receiver `10.10.2.30`, root authentication and the target archive path. Receiver syslog lines 200-203 contain connection, accepted-key, PAM and logind evidence before the target file event.
- The explicit proxy produces distinct client and upstream legs, rather than treating the external service as the workstation's direct TCP peer. The support attachment is visible in `PROXY-01.meridianhcs.local/proxy_access.log:2017`, `zeek-core/http.json:1253`, and `zeek-dmz/http.json:1416-1417`, with appropriately different UIDs, tuples and absolute versus origin-form request URIs.
- Mac process records preserve forked-image inheritance and exec changes instead of making every exec a new PID. Checks of the 126 and 157 native Endpoint Security records found no visible process use after its exit or image change lacking an intervening exec in those streams.
- Background transport is materially mixed: core Zeek has 10,053 `SF`, 1,897 `S0`, 150 `RSTO`, 116 `RSTR` and smaller populations of other states. DMZ and database sensors have different state and service mixes. The result is not simply successful flows surrounding isolated suspicious rows.

## Detailed Analysis

### Input provenance and scope

I read the complete neutral briefing `/private/tmp/log-study-6xx3sa0s/threat-prompt.md` and examined files only beneath `/private/tmp/log-study-6xx3sa0s/data`. I did not access project directories, source, authored scenarios, TODO/worklogs, previous assessments, parent inventories or other reviewers. General project operating instructions were inherited in the environment; I did not use them as evidence of the data's origin. I also consulted the public primary references linked below to check narrow Bash, Nikto and Zeek semantics. Suspicious commands were treated as inert text and were not executed.

The endpoint directories represent 23 hosts: ten with Windows Security/Sysmon XML, eleven with Linux-style syslog, and two with macOS Endpoint Security and Unified Log exports. Normalized eCAR records accompany all 23. Three Zeek sensor directories, two IDS feeds, an ASA perimeter feed, web/proxy access logs and shell histories provide additional pivots. The visible timestamps run approximately 13:00-19:00 UTC on 2 November 2026. Hostnames, IPs and traffic imply workstation, directory, file, proxy, web, application, database, monitoring and mail roles across addresses beginning `10.10.1`, `10.10.2`, `10.10.3` and `10.10.4`; I do not assume their configured prefix lengths from the names alone.

I parsed all eCAR files, all ten native Sysmon XML files and both native macOS Endpoint Security files for visible process relationships. I examined additional native Windows Security, Linux syslog, access, IDS and firewall records and cross-referenced selected network/file transfers. This is a targeted hunt and consistency assessment, not a claim that every field in every source has been manually validated.

### Initial compromise and process attribution

The upload-to-shell-to-egress sequence is technically plausible at the host/account level: Apache runs as `www-data`, its shell child also uses `www-data`, and egress comes from the web host's DMZ address. The network observation at `zeek-dmz/conn.json:1625` starts at epoch 1793629209.585467, lasts 29.415661 seconds, and records 620 originator and 1,840 responder payload bytes. Its plain TCP interpretation is consistent with a shell-channel hypothesis; the row alone does not prove what commands were exchanged.

The process ownership limitation matters because endpoint pivots should identify whether the reported PID owns the socket or initiated the activity. The [GNU Bash pipeline documentation](https://www.gnu.org/s/bash/manual/html_node/Pipelines.html) describes separate process execution for pipeline components, subject to the `lastpipe` qualification. The visible wrapper has nested shell execution, but the feed represents only the wrapper PID for this connection. I cannot establish whether this is a simplification or an intentional normalized attribution policy from these records alone. Accordingly, I do not label it `hard_contradiction`, and I do not count absent descendant rows alone as a collection failure.

The later root SSH access is independently visible rather than inferred from the original shell. `WEB-EXT-01.meridianhcs.local/syslog.log:351-353` reports source `10.10.1.34:57673`, root public-key acceptance and PAM session opening at 14:39:48-14:39:54. Endpoint discovery commands appear under that separate root shell in eCAR lines 916-928. A `www-data` reverse shell does not itself establish the root account transition, and I have not treated the two as a proven privilege-escalation chain.

### SSH, staging and transfer pivots

A useful positive check is the Mac-to-Mac SSH session. `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:45` shows client exec at 14:24:27.438759; its eCAR line 91 carries source port 49252. `zeek-core/conn.json:2497` observes the same tuple to `10.10.1.42:22`, with a 621.618998-second successful connection. The receiver's Unified Log line 2 records keyboard-interactive/PAM acceptance at 14:24:44.399410, followed by the native shell exec at Endpoint Security line 61. The native receiver shell and session processes terminate at lines 71-73 around 14:34:59, close to client exit at native source line 46. These are plausible source-specific times, not a requirement for identical timestamps.

For database staging, eCAR lines 530-535 show a database-dump process, `/tmp/rpt_0318.sql`, gzip creation of `/tmp/rpt_0318.sql.gz`, and termination before scp begins. Sender line 537 gives the transfer tuple; receiver line 778 gives the target file `/tmp/.cache/rpt_0318.sql.gz`. `zeek-core/conn.json:11098` and `zeek-db/conn.json:385` preserve the same tuple with sensor-local UIDs and slightly different timestamps. These relationships make the pivot feasible. I cannot infer actual patient/claims contents from command and path names alone, nor do I require pre-window origins for long-lived daemons.

### Proxy upload and source-specific timing

The diagnostic upload is not intrinsically malicious. `WS-LNGUYEN-01.meridianhcs.local/ecar.json:399` shows archive creation from two connector-log paths, and line 403 shows curl posting metadata plus an archive through the proxy. The HTTP client leg has a 1,573,258-byte body. File records `zeek-core/files.json:377-378` split that body into a 50-byte JSON entity and a 1,572,864-byte gzip entity, leaving plausible multipart overhead. The gzip FUID and request UID agree with the HTTP row.

On the DMZ sensor, the proxy's upstream request uses `10.10.3.20:51963 -> 52.44.186.73:80`, while the workstation speaks to `10.10.3.20:8080`. The upstream response body is 95 bytes and the client-side body is 96; a proxy can alter the response. I do not penalize that difference as an identity contradiction. I also do not interpret `files.ts + duration` as an exact application commit timestamp: Zeek describes duration as a file-analysis interval, and its [file framework](https://docs.zeek.org/en/lts/frameworks/file-analysis.html) distinguishes analysis metadata from endpoint effects. Across all three sensors, my scan found no file interval beginning before its associated connection or ending more than 10 ms beyond the connection interval.

### Scanner texture, noise and collection boundaries

The Nikto concern is about tool-specific field behavior, not the fact that scanning is repetitive or easy to recognize. [Nikto's configuration documentation](https://github.com/sullo/nikto/wiki/Config-Variables) defines `@TESTID` as a test identifier. The supplied scan puts a nearly unique six-digit value on nearly every request, even repeated method/path combinations. Different tests can target the same path, and an attacker can forge a user agent; those are real alternatives. Nevertheless, the fresh identifier pattern across a small path vocabulary is the clearest localized texture artifact I found. Stable response lengths for repeated static error pages are not independently suspicious.

Source volumes fit a selected six-hour security slice sufficiently well that I do not score absolute thinness. Core Zeek contains 12,314 connections, DMZ 9,401 and database 433; these are sensor observations, so summing them would double-count some traffic. Proxy access has 3,524 rows and web access 757. Native Windows Security and Sysmon include short-lived and persistent processes and heterogeneous authentication/transport activity. A programmatic check found no negative visible Sysmon process lifetime, native child creation after its known parent's termination, or same-GUID dependent event outside its visible process interval.

The Mac Unified Log warning for MeetingAssist at `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:2` is not proof that the app executed. I found no corresponding native MeetingAssist exec, and I do not turn the policy message into an execution or effects claim. Similarly, a plist file event is not by itself evidence of launch-item activation. These are appropriate limits on attribution, not missing-artifact penalties.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Web access / scanner user-agent fields | 316 Nikto-labeled requests, 40 base paths, 315 distinct test identifiers | Modest upward weight: tool-like labels appear substantially more random than their intended test semantics suggest; custom/spoofed scanning remains possible. |
| `weak_signal` | Normalized Linux eCAR process/flow attribution | One visible Apache-child decode/pipeline shell and associated connection | Small upward weight only: likely descendant socket ownership is collapsed into the wrapper PID, but normalized attribution semantics are unknown. |

No verified `hard_contradiction` or demonstrated native macOS schema error drove the score. Strong cross-source matching is useful investigative evidence, not an authenticity penalty.

## Realism Score by Category

- **Field format accuracy:** 8 — Common native/normalized shapes are credible; scanner test identifiers have questionable tool fidelity.
- **Temporal patterns:** 8 — Visible process and selected SSH ordering are coherent, with plausible source-specific offsets.
- **Cross-source correlation:** 8 — Endpoint, authentication, transport, proxy and file pivots work; normalized socket ownership remains uncertain in one shell case.
- **Behavioral realism:** 7 — Mixed administrative activity, failures and scanning support a credible hunt, with a localized scanner-texture concern.
- **Environmental consistency:** 8 — Host roles, multiple address ranges and explicit-proxy paths mostly agree with observations.

## Recommendations

- If this were synthetic, tie scanner `Test:` identifiers to concrete tests and request variants; validate repeated method/path combinations against an actual scanner pattern rather than assigning almost every request a new arbitrary-looking identifier.
- If this were synthetic and eCAR FLOW PID means socket owner, represent the pipeline's relevant descendant/exec ownership so the flow points to the actual networking process. If it means root activity initiator, document that convention so hunters do not mistake it for native socket attribution.
- Preserve the distinction between proxy client/upstream legs, shell exec transitions, native SSH authentication and endpoint file effects. These relationships already support realistic investigation and should remain independently timed and correctly scoped.
