# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 62

## Executive Summary

The dataset supports practical investigation across a mixed Windows, Linux, and macOS environment, with credible remote-session, process, file-transfer, and proxy pivots. I lean synthetic because a concentrated, repeated process-start timing pattern appears in native Windows telemetry across five hosts; this is a distribution artifact, not a demonstrated impossible lifecycle. Most of the operational chains examined are coherent, so the verdict is qualified and the score stays near the lower end of the likely-synthetic band.

## Evidence For Synthetic

- [distribution_texture] Native Sysmon Event 1 records contain 16 visible parent-linked `smss.exe` → `winlogon.exe` creation pairs across nine hosts. Ten pairs across five hosts have a gap of 499–501 ms, including eight at exactly 500 ms. The other six gaps range from 140 to 1,445 ms. Examples in `DC-01.meridianhcs.local/windows_event_sysmon.xml` are `14:45:22.642` → `14:45:23.142`, `17:40:54.852` → `17:40:55.352`, and `18:10:09.902` → `18:10:10.402`, all on 2026-11-02. This sharp common offset across separate machines is the main reason for the verdict.
- [distribution_texture] The same timing cluster includes all three visible pairs on `MAIL-FIN-01` and both on `DC-02`, as well as one pair each on `WS-AJOHNSON-01` and `FILE-SRV-01`. These are additional instances of the same finding, not independent defects. Corresponding normalized eCAR records preserve the cluster, so it cannot be explained solely as coarse formatting in one normalized view.

## Evidence For Real

- The source mix is operationally varied: 23 endpoint directories, three Zeek sensor directories, two Snort sources, a perimeter ASA log, an explicit proxy, a web server, native Windows XML, Linux syslog and histories, and macOS Endpoint Security and Unified Log records. Counts include 38,189 eCAR records, 11,647 Sysmon events, 17,730 Security events, 23,502 Zeek connections, 4,229 syslog lines, and 4,920 proxy records. This is substantial background activity for a six-hour slice; suspicious activity is not the only source of records.
- The database-export chain has concrete prerequisites and effects. `DB-PROD-01/ecar.json` records a root SSH session at `18:15:02.898`, a shell at `18:15:04.376`, `mysqldump` at `18:15:09.423`, creation of `/tmp/rpt_0318.sql` at `18:15:10.754`, compression at `18:15:34.668`, and `scp` at `18:16:02.870`. Receiver and later SMB evidence continue the same file trail.
- Native Sysmon lifecycle checks found no process-associated row earlier than its visible same-ProcessGuid create, or later than its visible same-ProcessGuid termination, across the ten supplied Windows Sysmon files. A separate eCAR actor-identity check likewise found no actor use before its visible create or non-process actor use after its visible termination. These are bounded checks, not proof that every possible lifecycle relationship is correct.
- The macOS script download is distinguishable from execution: `MAC-MROSS-01/macos_endpoint_security.ndjson` has curl exec at `13:48:41.201976`, followed by `/bin/bash .../connector-check.sh --check-config` at `13:49:08.207155`. Its shell history agrees on the commands, and the proxy records the intervening download. I did not infer script effects merely from the download.
- Suspicious Windows service execution has plausible service ownership. On `DC-01`, the visible `PSEXESVC.exe` file and service creation precede SYSTEM execution and its command child; Security 4697 attributes service installation to `aisha.johnson`. This preserves the distinction between the installing account and the service execution account.
- Public web noise includes ordinary asset requests and application API calls alongside probes against `xmlrpc.php`, SQL-injection-shaped requests, and an upload request. Statuses vary, including 403, 404, 500, and 200. This provides competing investigative leads grounded in actual records.

## Detailed Analysis

### Scope and review method

The main window is 2026-11-02 approximately 13:00–19:00 UTC. The 23 endpoint directories comprise ten Windows hosts, eleven hosts with Linux-style syslog and bash histories, and two Macs with native macOS sources. Visible addresses span `10.10.1.*` client systems, `10.10.2.*` internal services, `10.10.3.*` infrastructure/DMZ systems, and a database at `10.10.4.10`; these are inferred roles, not an externally supplied topology.

I inspected the available files, counted source records, read the supplied shell histories, parsed all ten Windows Sysmon XML files and the Windows Security files, and pivoted between selected eCAR, native endpoint, Zeek, SMB, proxy, and web records. The broad parsing checks were supplemented by specific investigations; I did not manually inspect every record. Filesystem timestamps, domain resolvability, missing selected Sysmon event types, collection completeness, and the narrative shape of suspicious activity did not contribute to the score.

### Repeated Windows session-bootstrap timing

I matched each visible `winlogon.exe` create to its parent using `ParentProcessGuid` and `ProcessGuid` in Sysmon Event 1, rather than pairing nearby process names. The complete observed gap distribution in milliseconds was:

`140, 363, 499, 500, 500, 500, 500, 500, 500, 500, 500, 501, 1004, 1173, 1225, 1445`.

The cluster spans:

| Host | Native Sysmon parent → child times, UTC | Gap |
|---|---|---:|
| DC-02 | 13:57:45.835 → 13:57:46.336 | 501 ms |
| DC-02 | 14:59:06.827 → 14:59:07.327 | 500 ms |
| DC-01 | 14:45:22.642 → 14:45:23.142 | 500 ms |
| DC-01 | 17:40:54.852 → 17:40:55.352 | 500 ms |
| DC-01 | 18:10:09.902 → 18:10:10.402 | 500 ms |
| MAIL-FIN-01 | 13:54:11.525 → 13:54:12.024 | 499 ms |
| MAIL-FIN-01 | 14:45:32.972 → 14:45:33.472 | 500 ms |
| MAIL-FIN-01 | 17:56:34.680 → 17:56:35.180 | 500 ms |
| WS-AJOHNSON-01 | 16:01:21.390 → 16:01:21.890 | 500 ms |
| FILE-SRV-01 | 14:45:01.283 → 14:45:01.783 | 500 ms |

For example, the first DC-01 pair links parent GUID `{83eb9c06-a202-6ae8-c102-000032124086}` to the child's `ParentProcessGuid`. Its eCAR counterpart is `14:45:22.761` → `14:45:23.262`, preserving essentially the same offset despite different source timestamps.

A common Windows implementation or a collection transformation could conceivably create a narrow mode. I cannot rule that out from these files. Nevertheless, eight exact 500 ms gaps plus two adjacent-millisecond gaps across independently timed sessions and several hosts is a stronger synthetic signal than generic observations about regular scheduled activity. It is not an impossible field value or proof of malicious activity, and I do not count the native and normalized observations twice.

### Database extraction, SSH, and SMB pivots

The database chain is technically followable. `APP-INT-01` is `10.10.2.30`; the outgoing SSH flow uses source port `60193` toward `10.10.4.10:22`. Database syslog records the same source tuple, root password acceptance at `18:15:02.609734`, and PAM session opening at `18:15:02.711018`. The normalized session and shell then appear before the dump process.

The dump process terminates at `18:15:33.584`, before gzip starts at `18:15:34.668`; gzip creates the compressed artifact at `18:15:38.617` and terminates at `18:16:01.160`, before scp starts. The original shell history includes the output redirection to `/tmp/rpt_0318.sql`, while the process command omits that shell redirection, which is a reasonable distinction.

The scp transport is independently visible in `zeek-core/conn.json`: UID `Cck9iddc9AdlOl7GIa3`, source `10.10.4.10:35330`, destination `10.10.2.30:22`, start epoch `1793643365.447511`, duration `28.971380`, state `SF`, originator payload 40,073 bytes. The database-side sensor observes the same tuple with its own UID and a slightly different timestamp. APP-INT syslog accepts root public-key authentication at `18:16:11.433936`; APP-INT eCAR later records creation of `/tmp/.cache/rpt_0318.sql.gz`.

A later SMB hop uses a different account boundary: root on APP-INT invokes `smbclient` with directory credentials `svc_mhsync`. `zeek-core/smb_files.json` records UID `CTCvBm57j95LYwdcp`, tuple `10.10.2.30:43385` → `10.10.2.21:445`, and `SMB::FILE_WRITE` to `Integration\\DB-Staging\\rpt_0318.sql.gz` with size 10,129. `FILE-LNX-01/ecar.json` records the receiver write under `svc_mhsync` at `18:18:59.005`. Treating these separate local and directory identities as a contradiction would be incorrect.

### Windows remote service and outbound upload

At DC-01, `PSEXESVC.exe` file creation occurs at `17:00:12.672`, followed by service creation at `17:00:12.940`, service process PID 4932 at `17:00:15.150`, and command child PID 4936 at `17:00:15.503`. Native Security 4697 at `17:00:13.0067755` names `aisha.johnson`, logon ID `0x555493f`, service `PSEXESVC`, and `LocalSystem` service execution. This supports a concrete remote-execution hypothesis, while allowing source timestamp differences.

On `WS-AJOHNSON-01`, PID 6912 starts curl at `18:25:17.759` with a multipart upload of `C:\ProgramData\Microsoft\cache_7f3a.zip`, reads that file at `18:25:21.017`, and the proxy logs the destination upload at `18:25:22`. The proxy records user `MERIDIANHCS\aisha.johnson`, URI `/upload/telemetry/7f3a2b19`, and request bytes 18,783,258. This is a useful endpoint-to-proxy pivot rather than a claim that the domain's spelling establishes maliciousness or synthetic origin.

### macOS and legitimate-looking support activity

The macOS Endpoint Security records explicitly identify message version 11 and have separate fork, exec, and exit shapes. `MAC-MROSS-01` has 45 fork, 52 exec, and 44 exit records; `MAC-MROSS-02` has 55 fork, 65 exec, and 54 exit records. I treated these as selected notification observations and did not assume complete endpoint coverage or assess unfamiliar version-specific fields from memory.

The Mac support-script download connects to a proxy tunnel and an inspected GET at `13:48:44`, returning 18,695 body bytes, before the visible bash execution. The similarly named Linux tool is downloaded on `WS-LNGUYEN-01` and later executed after chmod. A separate support archive is created by tar at `16:37:08.727`, read by curl at `16:37:56.762`, and uploaded through the proxy as a multipart POST with ticket `MHS-48217`. These are credible hunting leads with sufficient evidence to distinguish file retrieval, execution, and upload.

A Unified Log message saying policy “would not allow” MeetingAssist does not by itself establish an enforcement outcome. I did not use it to infer a denied execution, successful child execution, or an impossible subsequent effect.

### Signal-to-noise and limits

The collection contains meaningful host and network background alongside the investigated activity. I found no basis to score the number of sources, successful pivots, or compactness of suspicious actions as defects. The substantial background volumes and absence of detected visible process-identity inversions weigh against a high synthetic-confidence score.

The timing concentration is narrower than a dataset-wide generator fingerprint, and I found no independently demonstrated hard contradiction in the chains examined. That limits both verdict confidence and the synthetic-confidence score; a plausible collector explanation for the 500 ms cluster would materially weaken this assessment.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native Windows Sysmon process creation, corroborated by normalized eCAR | 10 of 16 visible parent-linked smss → winlogon pairs, across five hosts, at 499–501 ms; eight exactly 500 ms | Main synthetic indicator: repeated common timing offset across hosts and sessions. Strong enough for a qualified synthetic lean, but no impossible ordering established. |

## Realism Score by Category

- **Field format accuracy:** 9 — Native XML and JSON parse successfully; inspected event shapes and identifiers support practical pivots, with no proven format contradiction.
- **Temporal patterns:** 6 — Investigated causal sequences are ordered plausibly, but the cross-host 500 ms process-bootstrap cluster is conspicuous.
- **Cross-source correlation:** 9 — SSH tuples, service installation/execution identities, SMB paths, and proxy uploads connect coherently in the reviewed chains.
- **Behavioral realism:** 8 — Commands, shell redirection, service execution accounts, and local versus directory credential use mostly make technical sense.
- **Environmental consistency:** 8 — Client, server, proxy, database, and mixed-OS evidence generally fit their visible activity and source volumes.

## Recommendations

- If this were synthetic, replace the repeated 500 ms `smss.exe` → `winlogon.exe` offset with evidence-based timing variation appropriate to Windows session creation. Preserve parent identity and causal ordering; avoid merely adding independent timestamp jitter that could reverse the relationship.
- If this were a production-derived export with transformed timestamps, document the transformation responsible for the 499–501 ms concentration so an assessor can distinguish collector behavior from fabricated process timing. The explanation should address its occurrence across five hosts and why the remaining six pairs have substantially different gaps.
