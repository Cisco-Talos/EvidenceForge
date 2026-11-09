# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 38

## Executive Summary

The supplied six-hour slice supports credible investigation across Windows, Linux, macOS, network sensors, proxy and firewall records. I found some unusual process ancestry and a narrow texture in macOS file-access behavior, but did not establish an impossible same-identity lifecycle or a decisive source-native contradiction. These observations warrant scrutiny without outweighing the operationally coherent remote-session, file-transfer and proxy evidence.

## Evidence For Synthetic

- [environment_or_collection_plausibility] An interactive credential-switch operation has an unusual direct parent: `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml:17086–17107` records `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"` at `18:01:15.709`, running as `MERIDIANHCS\aisha.johnson`, with parent PID `5796`, `winlogon.exe`, parent user `NT AUTHORITY\SYSTEM`. The matching normalized row is `ecar.json:1126`. This is an atypical launcher for an operator-issued runas command, although custom session-launch code or parent manipulation could explain it. It is not an impossible parent-child relationship.
- [distribution_texture] On `MAC-MROSS-02`, all ten visible normalized FILE/READ rows use two command forms: eight `/bin/cat` commands and two `/bin/ls -la` commands. The eight cat targets are PDFs or Office documents, including `project-plan.pdf` at `ecar.json:75`, `service-review.xlsx` at line 320, `onboarding.docx` at line 458 and `onboarding-approved.xlsx` at line 609. Repeatedly dumping binary documents to a terminal is an unusual texture for ordinary document work. A scripted read test or deliberately selected telemetry could explain it; this observation carries limited weight and does not establish what other activity occurred outside this export.
- [weak_signal] Several present Sysmon CreateRemoteThread rows pair unrelated Windows system processes with generic thread-bootstrap functions: `DC-02/windows_event_sysmon.xml:8095` has NETWORK SERVICE `WmiPrvSE.exe` creating a thread in SYSTEM `svchost.exe` at `kernel32.dll!BaseThreadInitThunk`; `WS-SMARTINEZ-01/windows_event_sysmon.xml:6051` has SYSTEM `taskhostw.exe` targeting a user's `RuntimeBroker.exe` at `ntdll.dll!RtlUserThreadStart`. Directory names in these abbreviated citations include the common `.meridianhcs.local` suffix. These are unusual enough to investigate as possible generic background-event texture, but are not inherently impossible or proof of synthetic origin. No absent module-load event was used against them.

## Evidence For Real

- The runas evidence preserves a meaningful identity distinction: the Type 9 session retains local `aisha.johnson`, while outbound credentials identify `marcus.chen`. `WS-AJOHNSON-01/ecar.json:1133–1134`, `FILE-SRV-01/ecar.json:1226–1227` and `FILE-LNX-01/ecar.json:1194–1197` show this distinction rather than incorrectly requiring the same account everywhere.
- The RDP transport precedes the target login and has a substantial successful interval. `zeek-core/conn.json:7269` records `10.10.1.99:44098 -> 10.10.1.35:3389`, `SF`, beginning at epoch `1793636449.183295`; `WS-AJOHNSON-01/ecar.json:662` records the associated Type 10 login at `16:20:54.791`. The session subsequently logs out at `ecar.json:1409`. Transport disconnection and final user logoff are distinct facts, so their different times are not a contradiction.
- The DB-to-application transfer has plausible credential, process, transport and receiving-file evidence: `DB-PROD-01/ecar.json:593–603`, `APP-INT-01/syslog.log:216–220`, `APP-INT-01/ecar.json:940–945` and `zeek-db/conn.json:433`. Root on the two Linux hosts need not be a directory identity.
- Proxy routing is represented as separate client-to-proxy and proxy-to-origin legs. For the diagnostic upload, `zeek-dmz/http.json:1433–1434` shows the client absolute-form URI and origin relative-form URI; `files.json:974` and `:976` retain the same archive filename and observed payload size. This is useful, technically meaningful pivot support.
- The corpus includes failed authentication, failed network attempts, ordinary sysstat jobs, administration commands and multiple simultaneous account/session contexts. For example, `WEB-EXT-01/ecar.json:981` and `:985` are failed inbound attempts interspersed with other activity, and Windows Security exports contain actual 4625 failures on several workstations. I did not treat completeness of matching as an authenticity clue.

## Detailed Analysis

### Input provenance and method

I read the supplied neutral briefing and files only beneath `/private/tmp/log-study-mlpr3vwu/data`, using system `python3` from an explicit `/private/tmp` working directory. I did not read project files, scenarios, prior assessments, other reviewers' reports or filesystem timestamps as origin evidence. Generic inherited project operating instructions were an environment limitation and were not used to infer provenance. The only outside reference consulted was Microsoft's official Sysmon documentation, through a `learn.microsoft.com` domain-filtered search; it was used to constrain interpretation of existing Event 8/10 records.

Line references are one-based physical file lines. Host abbreviations below retain the directory suffix `.meridianhcs.local`. I parsed all endpoint normalized JSON records and Windows XML records, inspected native Linux/macOS records and shell histories, and pivoted selected activities through network/proxy files. This is a bounded authenticity assessment, not a claim that every suspicious action succeeded or that every record has been exhaustively manually inspected.

### Environment and collection scope

There are 23 endpoint directories: ten with Windows Security/Sysmon exports, eleven with Linux-style syslog, and two with macOS Endpoint Security and Unified Log exports. The apparent environment includes workstations, two domain controllers, Windows and Linux file servers, application/database/web servers, mail servers, a proxy and monitoring infrastructure. Internal observations cover at least `10.10.1.0`, `10.10.2.0`, `10.10.3.0` and `10.10.4.0` address groups; these are observed address groupings, not asserted subnet masks.

The normalized endpoint records span approximately `2026-11-02 13:00–19:00 UTC`. The exports contain 37,394 normalized rows, 19,411 Windows Security events, 12,058 Sysmon events, 22,509 Zeek connection rows across three sensors, 4,291 Linux syslog lines and 3,551 proxy-access lines. The two macOS ES files contain 299 records total. XML physical line counts were not mistaken for event counts. The volume mix is compatible with the visible collector choices: network authorization rows dominate many Windows Security exports, while DCs carry substantial ticket activity. Thin native macOS Unified Log coverage was treated as a collection choice, not evidence against authenticity.

### Threat pivots and practical investigation feasibility

At `WEB-EXT-01/ecar.json:984`, Apache PID `23966`, principal `www-data`, launches a base64-decoding bash pipeline at `14:19:52.737`. Its payload describes a reverse shell to `45.33.32.30:8443`; line 987 records an outbound flow to that address/port associated with the same process identity, after creation and before termination at line 990. This is suspicious executable behavior with a usable process-to-network pivot. It does not alone prove the cause of the web compromise, successful command-and-control, or the dataset's origin.

On `WS-AJOHNSON-01`, `ecar.json:833` records `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` at `16:45:05.122`. The native Sysmon record gives High integrity, and subsequent Event 10 records show access to LSASS with `GrantedAccess=0x1FFFFF`. There is also a remote-thread observation at `windows_event_sysmon.xml:12794`. The records justify a credential-access investigation. They do not reveal returned passwords, and the filename alone cannot establish that this is an unmodified, specific tool build. I therefore did not assert that a particular command-line implementation could not have produced the additional thread activity.

The later explicit-credential chain is especially coherent. At `18:01`, runas requests outbound `marcus.chen` credentials. The resulting Type 9 session is `0x27cb381`, cloned from the `aisha.johnson` Type 10 session `0x2702395` (`ecar.json:1133`). Its child command shell and PowerShell processes remain locally attributed to aisha. Remote file-server accesses are attributed to marcus. That difference is expected under the visible `/netonly` semantics, not an ownership mismatch.

`WS-AJOHNSON-01/ecar.json:1174` copies a bounded set of finance files into `VaultCache`; lines 1183–1189 show the destination creations. Further clinical and research copies precede the archive process at line 1222 and ZIP creation at line 1229. The upload process at line 1295 precedes its file read at line 1302. `PROXY-01/proxy_access.log:3244–3245` then records the CONNECT and inspected POST to `/upload/telemetry/7f3a2b19`, with `tunnel_id=PT-a7cf09e64d39df67`. `zeek-core/conn.json:11300` and `zeek-dmz/conn.json:8884` contain the matching client tuple `10.10.1.35:54609 -> 10.10.3.20:8080`, around 18.8 MB of originator data, and a successful close. This provides a concrete egress pivot without incorrectly requiring passive Zeek to recover encrypted POST contents from a CONNECT tunnel.

### Linux sessions and transfer lifecycle

`DB-PROD-01/syslog.log:201–204` shows connection, accepted password, PAM session opening and logind session `279146` for root from `10.10.2.30:41315`. `zeek-db/conn.json:431` places transport opening before authentication and supplies a roughly 1,790-second successful connection interval. The shell appears before mysqldump, gzip and scp in the normalized endpoint stream.

The scp process reads `/tmp/rpt_0318.sql.gz` at `DB-PROD-01/ecar.json:602`. The separate receiver session at APP-INT uses source tuple `10.10.4.10:56155`, accepts a root public key (`syslog.log:216–218`), and creates `/tmp/.cache/rpt_0318.sql.gz` (`ecar.json:942`). The receiving endpoint and network sensor have small timestamp differences. I did not equate normalized observation timestamps with exact kernel-operation times or classify those small differences as impossible transfer ordering.

The later Samba write to `/srv/samba/ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz` is attributed to `svc_mhsync`, with its own SMB session and source tuple (`FILE-LNX-01/ecar.json:1247–1250`; `syslog.log:480–482`). Reuse of a filename supports a staging hypothesis, but the supplied metadata does not establish a byte-for-byte content identity with the earlier dump. I retained that distinction.

### Lifecycle and identity checks

Across normalized endpoint records, I checked references to processes with visible CREATE and TERMINATE rows. I found no actor/source reference more than one second before its visible creation or after its visible termination. I also checked visible process creation against prior logout for the same recorded logon identity and found no post-logout creates in that check. These checks do not penalize processes or sessions whose starting or ending boundary lies outside the slice.

For native Sysmon records, I compared available process-GUID references with visible process-create identities and checked timestamps against visible create/terminate boundaries. I found no mismatch in the checked PID/image references or impossible ordering. Native SSH Accepted rows with matching Zeek tuple observations did not precede transport opening or fall beyond the observed transport interval. Some SSH sessions lack an exported closed connection row; collection-window boundaries make that neutral rather than a defect.

DNS byte-length and duration sanity checks also found no matched Zeek DNS query whose minimum query size exceeded connection originator bytes, and no recorded DNS RTT exceeding the corresponding connection duration. These narrow checks do not establish complete protocol validity but rebut simple cross-source accounting failure hypotheses.

### Remaining texture and uncertainty

The three synthetic-leaning observations are deliberately limited. The runas parent is unusual but technically explainable. The macOS binary-document cat pattern is concrete and repetitive but could be scripted activity rather than a fabricated user. Remote-thread rows are actual claims of cross-process thread creation: Microsoft's [Sysmon documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon) distinguishes Event 8 from Event 10 process access and explains that start-module/function values are inferred. I did not assume that every suspicious-looking system process pair must be impossible, nor infer target module absence from selected Event 7 coverage.

These issues keep the sample from being indistinguishable from production for this reviewer, but none demonstrates fabrication. The synthetic-confidence score remains in the mostly-realistic band because the strongest tested operational relationships held. The Inconclusive verdict reflects the inability to infer provenance confidently from this bounded, potentially filtered export.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| environment_or_collection_plausibility | Windows Sysmon and normalized endpoint processes | One runas launch on WS-AJOHNSON-01 | Direct winlogon parent is atypical for an operator credential-switch command; modest weight, explainable |
| distribution_texture | macOS normalized FILE/READ activity | All ten visible MAC-MROSS-02 file reads; eight binary-document cat commands | Narrow, unusual command texture; limited by possible scripting/selection |
| weak_signal | Windows Sysmon Event 8 | Selected system-process pairs on several hosts | Generic bootstrap functions and unusual source/target pairs merit investigation, not a finding of impossibility |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source structures and inspected identities were usable; no demonstrated native field-format contradiction.
- **Temporal patterns:** 9 — Checked transport/authentication and process lifecycle ordering held; timestamps include plausible source differences.
- **Cross-source correlation:** 9 — RDP, netonly identity use, SCP receiving evidence and explicit proxy paths support practical pivots.
- **Behavioral realism:** 7 — Plausible suspicious and administrative behavior, with repetitive binary-document reads and unusual runas ancestry.
- **Environmental consistency:** 8 — Host roles and source-family mix generally fit the observations; unusual remote-thread relationships remain uncertain.

## Recommendations

- If this were synthetic, validate the intended launcher for the visible runas command. Preserve `winlogon.exe` as its parent only when the modeled mechanism actually starts that command through winlogon; otherwise reflect the real operator shell or launcher.
- If this were synthetic, make the eight binary-document cat operations represent an explicit scripted read workload, or use the actual document-opening/read behavior intended by the activity. The improvement concerns the visible commands and targets, not adding unspecified collection sources.
- If this were synthetic, validate each existing Event 8 source/target/start-routine combination against the actual mechanism producing a remote thread. Keep memory-reading Event 10 activity distinct from remote-thread activity, and preserve inferred/unknown module fields where the mechanism cannot substantiate an export name.
