# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 43

## Executive Summary

The sampled activity is operationally coherent and supports practical pivots across endpoint, authentication, network, shell-history, and proxy evidence. One specific SSH transfer has inconsistent session identifiers between Linux syslog and normalized endpoint telemetry, but the broader checks did not establish enough independent defects to confidently determine origin. This is a bounded assessment, not an exhaustive certification of every record.

## Evidence For Synthetic

- [contract_gap] The same root SCP receiver session has conflicting session identifiers. In `APP-INT-01.meridianhcs.local/syslog.log:213–218`, sshd PID `2983988` accepts public-key authentication from `10.10.4.10:45342` at `18:15:59.228037Z`, followed by logind session `378852` at `18:16:00.041792Z` and removal of `378852` at `18:16:17.498823Z`. In that host's `ecar.json:677–682`, the matching PID, root account, source tuple and file transfer instead carry session `378837` on LOGIN and LOGOUT. A normalization convention could explain differing identifier namespaces in isolation, but 70 of the other 71 uniquely time/account-matched Linux session starts agreed; this particular transfer is the exception. This is evidence of a correlation defect, not proof that the raw telemetry was generated.

## Evidence For Real

- The root database operation has a workable sequence: transport before authentication, shell before commands, SQL export before compression, and compression before transfer. `DB-PROD-01.meridianhcs.local/ecar.json:587–604` and `bash_history/root.bash_history:1–6` preserve the source account, commands, filenames and relevant process ancestry.
- The SSH transfer can be followed across two hosts and two network sensors without inventing a connection: `10.10.4.10:45342 → 10.10.2.30:22` appears in source `ecar.json:602`, receiver `ecar.json:675`, `zeek-core/conn.json:10571`, and `zeek-db/conn.json:404`. The sensors report compatible byte totals and approximately 21.65 seconds of transport life.
- A separate web compromise pivot is supported by source-native web access plus endpoint and network evidence: `WEB-EXT-01.meridianhcs.local/web_access.log:501` records the external POST, endpoint `ecar.json:923–924` shows Apache spawning bash and the subsequent outbound connection, and `zeek-dmz/conn.json:1498` records the matching outbound tuple.
- The visible process graph has lifecycle discipline. A UUID-based scan of all 35,313 normalized endpoint records found no actor-linked event preceding that actor's visible PROCESS CREATE or following its visible PROCESS TERMINATE. This checks only visible UUID relationships; it does not establish completeness or validate every process attribution.
- The window contains substantial background evidence and useful ambiguity: ordinary web requests/scans around the malicious POST, database administration by multiple accounts, service traffic, and both successful and failed connections. I found no concrete volume or family-mix contradiction warranting a synthetic penalty.

## Detailed Analysis

### Orientation and scope

I inventoried only the supplied data directory. There are 23 endpoint directories with normalized eCAR data, covering Windows, Linux, and two Macs; network sources include three Zeek sensors, firewall, IDS, and proxy logs. The normalized records span `2026-11-02 13:00:01.077Z` through `18:59:59.925Z`, with 39 distinct non-null principal strings, 26,307 FLOW records and 2,184 PROCESS CREATE records. Principal strings include service identities and are not a headcount.

I read representative records from each broad source family, parsed two Windows hosts' Security/Sysmon XML, performed bounded suspicious-command searches, checked normalized actor lifecycle ordering, and followed selected web, Windows persistence, database export, SSH transfer, and proxy-upload pivots. The inventory totals include 21,463 Zeek connection rows across sensors, 4,201 syslog rows, and 3,353 proxy rows. Overlapping sensor observations mean these totals are not independent activity counts. Missing initiators before the window, closures after it, absent product families, and deliberately selected Sysmon types were treated as neutral.

### Web intrusion pivot

At `14:19:57`, `web_access.log:501` shows `185.70.41.45` posting to `/ehr/admin/upload.php`, receiving HTTP 200. This status alone would not establish execution, but endpoint `ecar.json:923` independently shows `/usr/sbin/apache2` PID `23966` spawning bash PID `2702804` as `www-data` at `14:19:57.838Z`, with an encoded shell command. The outbound FLOW at line 924 uses `10.10.3.10:37640 → 45.33.32.30:8443` at `14:20:01.832Z`; Zeek DMZ line 1498 observes the same tuple at epoch `1793629201.694975`, state `SF`, duration `14.957469` seconds. The shell terminates at `14:20:20.651Z` in endpoint line 928, after the observed transport interval. These observations form a technically plausible local pivot. Their completeness and narrative clarity were not scored as synthetic indicators.

### Windows execution and persistence

DC-01's normalized lines 3673, 3681, 3687 and 3694 show WMI-parented cmd processes creating a service and scheduled task. PID `5056` (`0x13c0`) launches PID `5060` (`0x13c4`) for `sc.exe create DeviceSyncSvc`; the service creation follows at normalized line 3701. Native Security XML includes the corresponding command at line 186273, and native Sysmon XML at line 117195. The process IDs, parent command and SYSTEM target context agree across these representations. WMI provider execution and child account need not be identical because remote-management impersonation can change execution context; I did not treat that difference alone as a defect.

On WS-AJOHNSON-01, normalized lines 1069–1088 show PowerShell collecting files and creating `C:\ProgramData\Microsoft\cache_7f3a.zip`; Security/Sysmon represent the compression process as PID `6716`, logon `0x27cb216`. A later curl process reads that archive at line 1160. Proxy lines 2993–2994 and `zeek-core/http.json:1873` provide a practical pivot through client source port `61054` to the CONNECT request for `api.westbridge-services.net`. A visible archive-read operation and upload path are stronger evidence than interpreting a downloaded or merely named file as executed.

### SSH export and the identifier disagreement

The root database session starts from APP-INT-01 source port `41321`: normalized DB lines 588–590 show inbound FLOW at `18:14:53.441Z`, root LOGIN at `18:15:03.361Z`, and bash at `18:15:05.032Z`. The export command begins at `18:15:11.587Z`; the shell history includes the output redirection that is correctly absent from the child program's own argv-style command line. Gzip begins only after the export process terminates, and SCP begins after gzip terminates. I therefore did not flag absent redirection in the child command line as an impossible action.

For the subsequent SCP connection, Zeek core line 10571 starts at `18:15:53.101079Z` and lasts `21.647156` seconds. Receiver SSH authentication and file creation are inside that interval, while close and process-cleanup records occur near its end. The real disagreement is identity: syslog calls the receiver's logind session `378852`, while eCAR calls the matching login/logout `378837`. To bound the issue, I compared Linux syslog `New session N of user U` messages with a unique eCAR LOGIN for the same account within five seconds: 71 matched starts, one disagreement. This is a localized problem rather than evidence of a fleet-wide broken session model. It could arise in synthetic construction or real normalization, and that uncertainty limits the verdict.

### Limits

I did not verify every native macOS message against operating-system headers, infer authorization outcomes from notification records, or require missing macOS/Windows event families. I also did not claim that every suspicious command succeeded. No authenticity inference relies on filesystem timestamps, sanitized domains, linearity of the activity, or complete source alignment.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Linux syslog ↔ normalized eCAR | One root SCP receiver session; 1 disagreement in 71 uniquely matched starts | Raises the score above mostly production-like confidence because an important hunt pivot carries two session identifiers; bounded scope and possible normalization explainability prevent a confident synthetic verdict. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled XML, JSON, syslog, shell histories and network fields are usable; native macOS schema details were not exhaustively verified.
- **Temporal patterns:** 8 — Representative transport, authentication, execution, export and cleanup ordering works; a six-hour window limits broader periodicity conclusions.
- **Cross-source correlation:** 7 — Several actionable pivots work, with one specific SSH session-ID conflict.
- **Behavioral realism:** 8 — Commands, parentage, identities and effects generally support technically workable activity amid background events.
- **Environmental consistency:** 8 — Mixed host roles and traffic are plausible; no demonstrated source-volume or collection-profile contradiction emerged from the bounded checks.

## Recommendations

- If this were synthetic, preserve the same receiver logind session identifier across SSH syslog and normalized LOGIN/LOGOUT for the `10.10.4.10:45342` transfer, or explicitly identify a separate normalized identifier namespace. Add a check that compares account, tuple, sshd PID and session identifier through receiver closure.
- Preserve the working transport-before-authentication, process ancestry, shell-history redirection, file progression and proxy source-port pivots shown in these examples. The current evidence does not justify adding arbitrary source volume, retries, or extra failure events merely to make the activity appear messier.
