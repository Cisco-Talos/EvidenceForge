# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 45

## Executive Summary

The records are highly usable as detection telemetry: the sampled Windows event shapes, network tuples, process identities and visible lifecycle ordering mostly withstand direct checks. A notable Windows process-duration floor and a small repeated macOS timing interval suggest modeled timing, but I found no demonstrated impossible same-identity ordering or native-schema contradiction sufficient for a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] All **733 matched, in-window Sysmon process-create/terminate pairs across ten Windows hosts last at least 3.004 seconds**, despite including command utilities. Examples: DC-01 `cmd.exe /c whoami && hostname`, ProcessGuid `{83eb9c06-c1a8-6ae8-3000-000099bc6b7e}`, runs from `17:00:24.212` to `17:00:27.329` (3.117 s), in `DC-01.meridianhcs.local/windows_event_sysmon.xml`, lines 116622/116667; WS-AJOHNSON-01 `whoami /all` runs 5.557 s, lines 9687/9898. This is a suspicious missing lower tail across a substantial sample, rather than an impossible individual runtime. Process filtering and endpoint overhead remain possible explanations.
- [weak_signal] Both Mac hosts show exactly **1.000 ms** between an early command exit and the next fork: MAC-MROSS-01 ES lines 10–11 (`13:07:36.743865` → `.744865`) and MAC-MROSS-02 ES lines 13–14 (`13:12:29.417779` → `.418779`). Other adjacent exit/fork intervals vary, so this is a small repeated scheduling texture, not a dataset-wide fixed cadence or hard contradiction.

## Evidence For Real

- Windows schema details are strong: hexadecimal Security process IDs coexist correctly with decimal Sysmon IDs; Event 4688 version 2 includes creator/target sections and `MandatoryLabel`; Event 4624 version 2 includes linked logon, virtual account and elevated-token fields. Source-specific timestamps have plausible differing precision.
- There are **zero detected same-GUID Sysmon observations before visible creation or after visible termination**, and no parent PID/image mismatch where the parent's creation is visible. These checks used GUIDs, rather than treating PID reuse as identity reuse.
- There are **zero detected 4634 records whose user/LUID has a visible 4624 but only a later initiating logon**. A concrete NTLM network session on DC-02 has a consistent user, LUID, source port and share access, described below.
- Across all three Zeek sensors, every protocol record carrying a `uid` resolves to a connection with the same endpoint tuple. The tested protocol timestamps fall within the corresponding connection interval with the stated tolerance; repeated X.509 fingerprints have stable certificate metadata.
- Network outcomes have a credible mixture: core connections include 10,053 `SF`, 1,897 `S0`, 150 `RSTO`, 116 `RSTR`, plus smaller incomplete/reset/rejected classes. This is not a collection of exclusively successful flows.
- The Mac process evidence differentiates fork from exec, preserves the PID across exec while changing its PID version, and models different Terminal and iTerm launch chains. I found no event using a process audit-token identity after its observed exit.

## Detailed Analysis

### Scope and actual input provenance

I read the full supplied `detection-prompt.md`, inventoried only its supplied `data` directory (117 files), and used Python standard-library parsers against the copied telemetry. I parsed all 30,815 Windows XML events, all 35,805 eCAR rows, all 38,537 Zeek JSON rows and all 283 Mac Endpoint Security notifications. I inspected the six Unified Log rows and samples from Linux syslog, proxy, firewall and IDS files. Bash/zsh histories were inventoried but were not substantively reviewed; their commands were never executed. Text-log samples were not exhaustively audited.

No repository files, scenario files, worklogs, prior assessments or other reviewers' reports were opened. Generic project metadata inherited in the operating context is a limitation of the review environment and was excluded from origin reasoning. External references were limited to the primary Microsoft, Zeek and Apple documentation identified below. All data paths below are relative to `/private/tmp/log-study-p29dfwbp/data`; XML line numbers identify the opening `<Event>` and its uniquely stated record ID.

### Twenty concrete record checks

For compactness, `DC2-Sec` means `DC-02.meridianhcs.local/windows_event_security.xml`, and `DC2-Sys` means the same directory's `windows_event_sysmon.xml`. `FS-Sec` means `FILE-SRV-01.meridianhcs.local/windows_event_security.xml`.

| # | Record / location | Checked fields and interpretation |
|---|---|---|
| 1 | DC2-Sec line 3, 5156 | `ProcessID=5272`, UDP `Protocol=17`, inbound `Direction=%%14592`, destination `10.10.2.11:53`; decimal process ID and source/destination semantics agree with the DNS listener. |
| 2 | DC2-Sec line 360, record 25377478, 4624 | Version 2, `LogonType=5`, `LOCAL SERVICE`, SID `S-1-5-19`, LUID `0x3e5`, absent remote IP represented by `-`; service logon is coherent. |
| 3 | DC2-Sec line 2402, record 25377573, 4634 | `lina.nguyen`, LUID `0xcb5d4ec`, `LogonType=3`; follows matching network logon at line 2267. |
| 4 | DC2-Sec line 4730, record 25377656, 4688 | Version 2; new PID `0x1bdc` (7132), creator PID `0x13fc` (5116), `dllhost.exe`, `MandatoryLabel=S-1-16-16384`; aligns with Sysmon PID 7132. |
| 5 | DC2-Sec line 2476, record 25377578, 4768 | Version 0, machine account `WS-MCHEN-01$`, service `krbtgt`, `TicketEncryptionType=0x12`, `PreAuthType=2`, mapped IPv4 address and empty certificate fields are coherent. |
| 6 | DC2-Sec line 85339, record 25380784, 4771 | `maya.ross`, `Status=0x18`, `PreAuthType=2`, source `::ffff:10.10.1.41`; failed preauthentication rather than a successful TGT. |
| 7 | DC2-Sec line 3360, record 25377604, 4776 | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, machine account/workstation `FILE-SRV-01`, `Status=0x0`; credential validation shape is plausible. |
| 8 | DC2-Sec line 129904, record 25382687, 4625 | `Status=0xc000006d`, `SubStatus=0xc0000072`, `LogonType=3`, source `WEB-EXT-01`; disabled-account failure has a plausible mapped source IP. |
| 9 | DC2-Sec line 181670, record 25384834, 4697 | `DirectoryCacheSvc`, `ServiceType=0x10`, `ServiceStartType=3`, `ServiceAccount=LocalSystem`; valid service-install field shape. |
| 10 | FS-Sec line 146, record 271776, 4656 | `HandleId=0x1b169349`, `ProcessId=0x4`, `ObjectType=File`, file path and requested `AccessMask=0x12019f`; handle creation has the appropriate context. |
| 11 | FS-Sec line 199, record 271777, 4663 | Same handle/user/path, `AccessMask=0x2`, `AccessList=%%4417`; write access is a subset of the requested access and occurs before handle close at line 240. |
| 12 | DC2-Sys line 2490, record 1368617, event 1 | `ProcessId=7132`, parent 5116, system logon, full command/image/hash fields; matches the Security process-creation record. |
| 13 | DC2-Sys line 3, record 1368530, event 3 | `Initiated=false`, DNS process 5272, UDP tuple matches inbound WFP evidence. |
| 14 | DC2-Sys line 158, record 1368536, event 5 | Process GUID/PID, image, UTC time and user form a valid termination shape; a missing pre-window creation is neutral. |
| 15 | DC2-Sys line 83, record 1368534, event 10 | Source/target GUIDs and PIDs, `GrantedAccess=0x1010`, pipe-delimited `CallTrace`, and separate users suit ProcessAccess. |
| 16 | DC2-Sys line 249, record 1368539, event 22 | `_kerberos._tcp.meridianhcs.local`, `QueryStatus=0`, SRV-style results `0 100 88 ...`; query shape and requested service agree. |
| 17 | `zeek-core/dns.json` line 1 | UID `Cuq507OFNo7MpYfALL`, UDP tuple, numeric `qtype=33`, `qtype_name=SRV`, array answers/TTLs; matches `conn.json` line 1 and its duration/RTT. |
| 18 | `zeek-core/ssl.json` line 1 | TLS 1.2 and compatible RSA cipher, SNI `FILE-LNX-01.meridianhcs.local`, certificate FUIDs present; `x509.json` lines 1–2 provide leaf and issuing CA. |
| 19 | MAC-MROSS-01 `macos_endpoint_security.ndjson` line 2 | Notification with `version=11`, `event_type=9`, actor PID 42152/PID-version 10, exec target same PID/version 11, target xpcproxy; fork immediately precedes it. |
| 20 | MAC-MROSS-01 `macos_unified_log.ndjson` line 3 | `16:01:38.551396+0000`, `/usr/libexec/sshd-session`, accepted public key for maya.ross, source `10.10.1.42:54395`; writer and message agree. |

The representative 4624 and 4688 shapes match Microsoft's documented versioned fields and header semantics. I do not infer a version defect solely from the presence of the older 4768 form: patch level is not established by a base executable version. [Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [Microsoft 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688), [Microsoft 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768).

### Identity and lifecycle checks

Sysmon checks indexed visible event 1 and event 5 records by ProcessGuid and compared dependent event times using their `UtcTime`. Source/target ProcessAccess and remote-thread identities were included. Where a parent creation was visible, its PID/image agreed with the child's parent fields. All rendered MD5, SHA1, SHA256 and IMPHASH strings had their expected lengths. These are meaningful detection-ingestion checks, although they do not prove genuine origin. Microsoft's documented Sysmon event meanings support using these GUID-based relationships. [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

For the DC-02 NTLM session, line 2267 starts lina.nguyen's Type 3 logon at `13:05:20.4895083Z`, source `::ffff:10.10.1.21:48351`, LUID `0xcb5d4ec`; line 2322 accesses SYSVOL at `13:05:20.5498706Z`; line 2402 logs off at `13:05:28.7368298Z`. There is no demand for a fresh Kerberos TGT for this explicitly NTLM session.

eCAR JSON records have consistent top-level object/action/property structure and numeric millisecond timestamps. I found no event referring to an objectID before that object's visible PROCESS/CREATE timestamp. This check is limited: I did not validate against a deployment-specific eCAR schema or certify every property as mandatory/optional.

### Network and observation semantics

The connection indexes contain 12,314 core, 9,401 DMZ and 433 DB records. For every protocol row with a singular `uid`, I tested the four tuple fields against the same sensor's connection and tested `conn.ts - 1 ms <= protocol.ts <= conn.ts + duration + 1 s`; no failures occurred. This is a bounded timing check, not a claim of nanosecond causal proof, and the plural DHCP `uids` and files `conn_uids` references were not included in that particular test. Zeek's documented connection fields and UID semantics agree with this interpretation. [Zeek conn.log](https://docs.zeek.org/en/lts/reference/logs/conn.html).

The TLS mix includes 14 TLS 1.2 DB sessions and mixed TLS 1.2/1.3 elsewhere. None of the supplied TLS 1.3 rows expose `cert_chain_fuids`, a useful distinction from observable TLS 1.2 certificate chains. CONNECT tunnel requests have zero HTTP response-body lengths, while the proxy's inspected GET records show body bytes under the same tunnel identifier; those are separate observation layers, not contradictory plaintext claims. [Zeek TLS logging](https://docs.zeek.org/en/current/reference/logs/ssl.html).

### macOS and collection limitations

ES fork/exec/exit notifications were evaluated independently from normalized eCAR PROCESS/FLOW records. The version-11 data contain nested audit tokens, parent/responsible identity, signing metadata, file stats and execution arguments; the sequence of PID-version changes is internally coherent. Apple's public event documentation was consulted, but its browser-accessible detail was limited, so I make no exhaustive claim that every version-11 serialized field is certified against eslogger's exact implementation. [Apple Endpoint Security](https://developer.apple.com/documentation/endpointsecurity), [Apple exec event](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t).

The `ASP: Security policy would not allow process` message at MAC-MROSS-01 Unified Log line 2 does not, by itself, prove a denied execution. I therefore did not infer a denial/child-execution contradiction. Six Unified Log rows are also insufficient to establish broad native collection coverage; their low count was not scored as an authenticity defect.

### Timing texture and alternative explanations

The 733 paired Windows lifetimes range from 3.004 to 17,585.906 seconds; only two millisecond-rounded durations repeat twice. Thus the issue is a lower-bound shape rather than quantization of all lifetimes or a lack of variability. Among common images, taskhostw has 152 pairs (minimum 3.095 s), dllhost 105 (3.061 s), conhost 106 (3.073 s), and userinit 22 (3.004 s). Slow security tooling or selected process coverage could skew this sample, so I treat the floor as moderate evidence, not as a native impossibility.

The two 1 ms Mac intervals carry little weight independently: there are 25 and 28 adjacent exit/fork transitions respectively, and only one such exact interval on each host. A workload script or timestamp normalization could explain that observation in real collected data.

## Synthetic Indicator Summary

| Category | Affected family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Windows Sysmon process lifecycle | 733 matched visible pairs, ten hosts; minimum 3.004 s | Main reason the score reaches the mixed band: no short-duration lower tail despite command utilities. Collection filtering remains an alternative. |
| weak_signal | macOS Endpoint Security timing | One exit→fork pair per host, exactly 1 ms | Small supporting increment only; too limited to establish a fixed timing generator. |

No hard contradiction or confirmed schema defect was established. Completeness of matching, intrusion narratability, absence of attacker mistakes, sanitized names and file modification times contributed nothing to the score.

## Realism Score by Category

- **Field format accuracy:** 9 — Representative native event shapes, IDs, hashes and address forms are strong; exhaustive Mac serialization certification was unavailable.
- **Temporal patterns:** 7 — Visible identity ordering is sound, but the Windows lifetime lower tail is suspicious.
- **Cross-source correlation:** 9 — Tested tuple, GUID, LUID and process relationships are coherent within the slice.
- **Behavioral realism:** 8 — Varied process lifetimes and connection failures are credible; fast utility runtimes are underrepresented.
- **Environmental consistency:** 9 — OS-specific paths, domain roles, DNS listeners and remote-authentication writers are coherent in checked records.

## Recommendations

- If this were synthetic, replace the apparent Windows process-duration floor with workload-specific completion timing, including subsecond command utilities where appropriate. Preserve the already coherent process GUID and parent relationships.
- If this were synthetic, review the two exactly 1 ms Mac exit→fork transitions against the intended shell scheduling semantics; do not introduce random changes merely to eliminate a plausible individual coincidence.
- For either origin, supply the actual collection/filter configuration alongside the data. It would distinguish a genuine process-duration bias from selection effects and establish the precise ES/eslogger serialization contract without guessing from the records.
