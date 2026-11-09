# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 34

## Executive Summary

This is mostly convincing telemetry: the suspicious activity supports practical pivots between endpoint identity, remote sessions, network transports, and file movement, and the visible lifecycle checks did not produce a hard contradiction. There are mild signs of small activity vocabularies and generic administrative-command substitution, but these are explainable in real data and do not establish synthetic origin. The score reflects mostly realistic data with limited behavioral texture concerns, not certainty about its provenance.

## Evidence For Synthetic

- [distribution_texture] The two Mac shell histories have a small, overlapping command vocabulary despite spanning several hours: `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` contains 20 entries but 13 distinct command strings; the corresponding `MAC-MROSS-02` file contains 21 entries and 13 distinct strings. On the first host, `/usr/bin/id` appears at lines 1, 13, and 15, while the same Documents PDF search occurs at lines 10 and 18. This is a mild repeated-menu texture signal, not an impossible behavior; a user doing repeated troubleshooting could produce it.
- [weak_signal] The administrative history on APP-INT-01 repeatedly substitutes related software names into generic inspection commands: `bash_history/marcus.chen.bash_history` line 6 is `ss -ltnp | grep cifs-utils`, line 26 is `systemctl status cifs-utils`, line 30 is `systemctl status smb-client`, and line 38 is `journalctl -u smbclient -n 100`. This resembles a generic service-inspection vocabulary rather than demonstrated service-specific troubleshooting. The records do not show command output or the unit inventory, so this is a small concern about command semantics, not proof that the commands failed or that the environment is impossible.
- [weak_signal] Several server syslogs contain substantial volumes of recurring maintenance/debug-style messages: snapd plus irqbalance account for 100/235 APP-INT-01 lines, 153/276 LOG-MON-01 lines, and 251/1446 WEB-EXT-01 lines. Examples include APP-INT-01 `syslog.log` lines 2 and 13 and LOG-MON-01 lines 9–14. A deliberately verbose collection configuration can explain this; the concern is the recurring maintenance-heavy vocabulary across different roles, not missing coverage of other products. I assign this little weight.

## Evidence For Real

- The database collection and transfer sequence has coherent visible ordering and identities. DB-PROD-01 `ecar.json` lines 593–603 show mysqldump, its output file, termination, gzip, compressed output, termination, scp, transport, file read, and scp termination. Gzip begins after the dump ends; scp begins after gzip ends.
- The scp transfer has a usable destination-side pivot: source `10.10.4.10:56155` to `10.10.2.30:22` appears in `zeek-db/conn.json` line 433, `zeek-core/conn.json` line 11017, APP-INT-01 `syslog.log` line 216, and APP-INT-01 `ecar.json` line 940. The application session is associated with the same source port and root account.
- Sensor disagreement in the support upload is explained by observed capture loss rather than an unexplained content contradiction. `zeek-core/http.json` line 1275 reports a smaller request than `zeek-dmz/http.json` line 1433; the 13,524-byte difference exactly matches the core gzip file observation's `missing_bytes` in `zeek-core/files.json` line 405.
- Windows credential-access evidence preserves source process identity and timing. WS-AJOHNSON-01 Sysmon shows PID 5956 / GUID `{fd907e59-be11-6ae8-d902-0000e1b233e0}` launching the renamed credential tool, accessing LSASS, creating a remote thread, and exiting; Security 4688/4689 and eCAR retain compatible process/account evidence.
- Mac observations distinguish a policy-rejected application attempt from successful execution. MAC-MROSS-01 `macos_unified_log.ndjson` line 2 reports that policy would not allow MeetingAssist; I found no corresponding successful MeetingAssist exec in the supplied native Endpoint Security records. I did not infer execution or persistence effects from that message.
- The source mix has differentiated roles and noise: 12,382 core, 9,629 DMZ, and 498 database connection observations; SMB records at core; SMTP activity; web-facing connection/block activity; and platform-specific endpoint sources. Nothing in those volumes alone establishes an unrealistic collection profile.

## Detailed Analysis

### Scope, method, and provenance

I examined only the supplied briefing and `/private/tmp/log-study-kl_ep_px/data`. The data directory contains 117 files, including eCAR telemetry for 23 hosts, Windows Security and Sysmon XML, Linux syslog and shell histories, two Mac native Endpoint Security exports with Unified Log excerpts and zsh histories, three Zeek sensor views, proxy and web access logs, ASA records, and IDS alerts. The principal visible window is 2026-11-02 approximately 13:00–19:00 UTC. The internal addresses expose several segments, including 10.10.1.x clients, 10.10.2.x servers, 10.10.3.x web/proxy infrastructure, and database address 10.10.4.10.

The eCAR files contain 37,394 records: 27,630 FLOW, 5,137 PROCESS, 2,466 MODULE, 1,515 USER_SESSION, and smaller file, registry, thread, and service families. There are 40 distinct nonempty principal strings; this includes service/system identities and is not a claim of 40 human users. The directory and file names are used only as source identifiers. Filesystem modification times and domain registration/resolution were not used as authenticity evidence.

I parsed the JSON and XML, compared process identities and lifetimes, checked network/application timing, and followed selected suspicious pivots. Parsing was read-only from `/private/tmp` using Python; I switched to explicit `/usr/bin/python3` after the initial `python3` invocation resolved to the installed Homebrew interpreter. No project code, authored scenario, prior assessment, worklog, or other reviewer report was read, and no web search was used. Generic inherited operating instructions were not treated as evidence of data origin.

### Operational hunt: remote access and collection

WEB-EXT-01 `ecar.json` line 1139 records root SSH access from `10.10.1.22:54014` at 14:39:31.856. Lines 1141–1150 then show interface/hosts/resolver inspection, a search for credential-related names, and network discovery; line 1407 shows a TCP connect scan of selected ports. This is suspicious activity with useful host-to-network pivots. Its compactness and apparent progression are not counted as authenticity indicators.

APP-INT-01 subsequently records root SSH access from WEB-EXT-01's `10.10.3.10` at 15:15:28.538 (`ecar.json` line 279). Later, DB-PROD-01 records root access from `10.10.2.30:41315` at 18:15:30.192, line 591. The database-side network observation (`zeek-db/conn.json` line 431) starts at 18:15:17.788810 and lasts 1,790.100754 seconds. The transport therefore precedes authentication and remains open throughout the visible dump/compression activity.

At 18:15:36.100, DB PID 1089075 starts `mysqldump --single-transaction ehr patients insurance_claims`; the file `/tmp/rpt_0318.sql` is observed at 18:15:37.710, and the process ends at 18:15:41.259. Gzip starts at 18:15:42.568 and ends at 18:16:09.576. Scp starts at 18:16:10.176, with outbound transport at 18:16:13.812 and termination at 18:16:38.714. These are compatible visible relationships rather than an output artifact preceding its producer.

The reverse SSH transfer uses the tuple `10.10.4.10:56155 → 10.10.2.30:22`. Database Zeek line 433 reports start 18:16:12.984775, duration 25.280434, `SF`, and 204,902 originator payload bytes. APP-INT-01 syslog line 216 records the incoming connection at 18:16:18.246883; eCAR line 940 records the root session at 18:16:22.032. The sensor and endpoint observations differ in timestamp but preserve the essential transport-before-auth relationship. I do not require bit-identical timestamps from separate collectors.

### Windows credential-access pivot

At 16:45:05.060, Sysmon's embedded `UtcTime` records `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` as PID 5956, high integrity, parent cmd.exe PID 5864, user `MERIDIANHCS\aisha.johnson`. The relevant command line is at WS-AJOHNSON-01 `windows_event_sysmon.xml` line 12705; Security's compatible 4688 command line is at line 19294 of `windows_event_security.xml`.

Sysmon then shows access to winlogon with `0x1010`, LSASS PID 4292 with `0x1FFFFF` at 16:45:08.584, and a remote thread into the same LSASS identity at 16:45:08.712. The source GUID remains constant. Its termination is recorded at 16:45:14.912. This supports a credential-access hunt without requiring that the command succeeded in returning usable credentials. The records themselves do not establish the tool's output.

Across all supplied Windows Sysmon files, I compared embedded event timestamps for visible process GUIDs against their create/terminate records, including source and target GUID references. I found no reference predating that GUID's visible creation or following its visible termination. A separate eCAR pass found no child more than one second before its visible parent creation and no actor reference more than two seconds after its visible termination. These are bounded consistency results, not assertions that every possible lifecycle relationship was exhaustively validated.

### Proxy/file accounting and collection boundaries

The support attachment is a useful test because both cleartext HTTP and file-analysis records are present. WS-LNGUYEN-01 history lines 39–40 contain the multipart curl submission; eCAR line 319 starts that curl process at 16:32:52.252. Core HTTP line 1275 records the POST at 16:33:05.798729 using source port 52146 and request-body length 1,559,734. DMZ HTTP line 1433 observes the same client/proxy tuple, method, absolute URI, and filename with request-body length 1,573,258. Their difference is 13,524 bytes.

Core files line 405 reports the gzip part with `seen_bytes=1559340`, `missing_bytes=13524`, and no asserted `total_bytes`. This provides a direct observation-based explanation for the smaller parsed core request. The DMZ's proxy/server leg, HTTP line 1434, preserves request-body length 1,573,258 with the origin-form URI. Proxy access line 1972 records `proxy_action=forward`, `cs_bytes=1573700`, and response body 96. Request wire bytes exceeding body bytes are coherent with headers and multipart framing. I therefore did not score the differing body counts as a contradiction.

For HTTP, SSL, DNS, SMTP, and SMB-file rows with matching connection UIDs, I checked whether their timestamps lay outside the same sensor's connection interval by more than 0.5 seconds. None did. I also checked SSH eCAR LOGIN rows with matching source IP/port transport observations; the matched observations did not authenticate before transport opening or after transport closure. Out-of-window starts/ends were not penalized.

### Mac interpretation and behavioral texture

The Mac files are recognizably distinct record families, not interchangeable telemetry. Endpoint Security records have native process/audit-token and exec-target structures; eCAR is a normalized view; Unified Log rows carry messages; and shell histories show entered commands. For example, MAC-MROSS-01 native ES lines 1–3 show a launchd fork and xpcproxy/Terminal exec transitions. I did not apply Windows process-creation semantics to these transitions or count every exec as a newly forked process.

The MeetingAssist policy message is insufficient to infer execution, child activity, or launch-item activation. Likewise, the real SSH acceptance evidence is more specific: MAC-MROSS-01 Unified Log line 3 records public-key authentication for maya.ross from `10.10.1.42:55377` at 16:01:39.035681. I treated the local Mac account and directory identities on other machines as potentially distinct accounts.

The strongest remaining concern is comparatively modest: both Mac histories repeatedly cycle through a small set of host-identification, Documents-listing, PDF-search, process-listing, and disk-space commands. This affects behavioral variety, not causal feasibility. APP-INT-01's repeated inspection of similarly named SMB-related software adds a second small vocabulary concern. These do not overcome the substantial coherent evidence sufficiently to call the data synthetic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Mac zsh histories | Two hosts; 41 entries, 13 distinct commands on each | Mild upward contribution from repeated command-menu texture; ordinary repeated troubleshooting remains plausible. |
| weak_signal | Linux shell history | APP-INT-01 administrative session | Small contribution from generic service-inspection substitutions; no command-output evidence establishes an error. |
| weak_signal | Linux syslog | Several server roles | Very small contribution from recurring maintenance-heavy vocabulary; verbose collection is a viable explanation. |

No hard contradiction or demonstrated required-companion gap is included in the score. The suspicious activity's linearity, completeness, number of intrusion phases, and ease of narration were not used as indicators.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source structures and identity fields support practical pivots; no demonstrated native-format defect was found in the reviewed records.
- **Temporal patterns:** 9 — Visible process and sampled application/transport relationships remain compatible; separate sensors retain small timing differences.
- **Cross-source correlation:** 9 — SSH, credential access, support upload, and file-transfer evidence correlate without a demonstrated contradiction.
- **Behavioral realism:** 7 — Technical actions are plausible, but repeated small command vocabularies reduce organic texture.
- **Environmental consistency:** 8 — Mixed-platform roles and sensor coverage are plausible; maintenance-heavy server noise warrants some caution.

## Recommendations

- If this were synthetic, expand the repeated Mac command vocabulary with host/session-specific task parameters and meaningful task variation, while retaining the coherent SSH and process transitions. The concrete target is the two histories' 13-command vocabularies, not the absence of a particular endpoint product.
- If this were synthetic, make service-inspection commands reflect the actual installed units/processes for APP-INT-01 instead of rotating `cifs-utils`, `smb-client`, and `smbclient` through generic commands. If they are intended unsuccessful operator commands, preserve that interpretation rather than treating them as evidence of running services.
- If this were synthetic, tie recurring snapd/irqbalance maintenance messages to explicit host-specific state and verbosity so the maintenance-heavy server texture varies with the observed role. This is a low-priority texture improvement; I would not add arbitrary log families merely to increase volume.
- Preserve the explicit capture-loss accounting in the multipart upload and the existing process/session/transport ownership. Those details prevent misleading authenticity findings and make the evidence useful for a real hunt.
