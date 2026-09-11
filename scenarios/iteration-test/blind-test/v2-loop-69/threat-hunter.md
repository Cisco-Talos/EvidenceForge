# Threat Hunter — Authenticity Assessment

## Verdict

- Assessment: Inconclusive
- Verdict Confidence: 79/100
- Synthetic-Confidence Score: 44/100

## Executive Summary

The reviewed telemetry is highly realistic in structure, environmental variation, and end-to-end
investigative utility. Process lifecycles, Windows Security/Sysmon/eCAR alignment, independent Zeek
sensor views, protocol-child timing, account changes, remote administration, staging, and exfiltration
can all be followed through source-native records without relying on perfect one-to-one duplication.
The strongest real-looking feature is not merely cross-source agreement: different sensors retain
different UIDs, sub-second clock offsets, source-specific timestamp ordering, and selective collection
gaps while preserving the same underlying activity.

The evidence is not fully clean. A failed SQL connection to `10.0.2.50:1433` occurs approximately
12.1 seconds before the only process creation naming that destination. Two remote-service chains also
bind their Windows network logons to source ports that do not match the observed SMB transports that
immediately drive the service installations. Those are concrete lifecycle/contract defects and carry
more weight than aesthetic impressions. A single incomplete SMB file-operation lifecycle and two weak
distribution/schema patterns add limited support for synthesis.

On balance, the corpus falls in the requested 41–60 mixed/inconclusive band. It is substantially more
authentic-looking than most generated corpora, but the process-before-network inversion and repeated
authentication/transport port discontinuity prevent an assessment of Real.

## Evidence For Synthetic

- **[hard_contradiction] SQL transport precedes its apparent initiating process.** In
  `WS-MCHEN-01.meridianhcs.local/ecar.json`, a failed FLOW from
  `10.10.1.31:50931` to `10.0.2.50:1433` is timestamped
  `2024-03-18T13:42:46.992Z`. `zeek-core/conn.json` records the same tuple at
  `2024-03-18T13:42:47.087020Z` as an `S0` TCP connection. The endpoint does not create PID 7516,
  `sqlcmd.exe -S 10.0.2.50 -Q "SELECT COUNT(*) FROM dbo.Orders WHERE OrderDate > GETDATE()-7"`,
  until `2024-03-18T13:42:59.191Z`; Sysmon Event 1 records it at
  `2024-03-18T13:42:59.0924782Z`, and Security Event 4688 records it at
  `2024-03-18T13:42:59.3242173Z`. The network attempt is therefore 12.104 seconds before the earliest
  process record. No other record in the reviewed data identifies a contemporaneous process or command
  for that unique destination. An unrelated precursor cannot be disproved, but the exact destination
  match makes the inversion a strong synthetic indicator.

- **[contract_gap] Remote-service authentication and transport disagree on source port in two separate
  chains.** On `DC-01`, Security Event 4624 at `2024-03-18T15:59:42.9931329Z` records
  Aisha Johnson, Logon ID `0x5553170`, from `10.10.1.35:58966`. The SMB transport immediately used for
  the operation is instead `10.10.1.35:51393 -> 10.10.2.10:445`: source eCAR at
  `15:59:43.256Z`, Zeek UID `Ccqv5hAIY2PtMEFgw` at `15:59:43.866116Z`, and target eCAR at
  `15:59:44.219Z`. That chain then creates `C:\Windows\PSEXESVC.exe` at `15:59:44.960Z` and logs
  Security Event 4697 under `0x5553170` at `15:59:45.2940988Z`. The only observed use of source port
  58966 by `10.10.1.35` is an earlier UDP DNS request to `10.10.2.11:53` at
  `13:12:11.474Z`/`13:12:12.280961Z`.

- **[contract_gap] The same port discontinuity recurs on another service-install path.** On `DC-02`,
  Security Event 4624 at `2024-03-18T16:24:46.9096329Z` records Marcus Chen, Logon ID `0xcd640a6`,
  from `10.10.2.10:49988`. The observed SMB transport is
  `10.10.2.10:52568 -> 10.10.2.11:445` in `DC-01.meridianhcs.local/ecar.json` at
  `16:24:50.194Z`, Zeek UID `CykRcLfMU40T2sZ0PC` at `16:24:49.985100Z`, and target eCAR at
  `16:24:50.800Z`. Security Event 4697 creates `DirectoryCacheSvc` under the same Logon ID at
  `16:24:51.9168623Z`. A missing parallel authentication connection is possible in production, but the
  repeated mismatch on two concise remote-service sequences is suspicious.

- **[contract_gap] One SMB file lifecycle begins with a read rather than an open.** In
  `zeek-core/conn.json`, UID `CSOZNbs25zmLakgNG1` starts at
  `2024-03-18T15:57:07.946208Z`, `10.10.1.34:61010 -> 10.10.2.21:445`, state `SF`, duration
  `3.554749`, and `missed_bytes: 0`. `zeek-core/smb_mapping.json` maps `Shared` at
  `15:57:08.057208Z`, but the only `zeek-core/smb_files.json` operation is `FILE_READ` for
  `Templates\team-roadmap-final.txt`, size 100562, at `15:57:08.498054Z`; there is no preceding
  `FILE_OPEN` or corresponding `files.json` entry. This was the only such ordering defect among the
  inspected SMB file UIDs, so it is a limited indicator and could reflect analyzer behavior or a
  durable handle.

- **[schema_or_format, weak_signal] RDP disconnects omit client names uniformly.** All 20 Security
  Event 4779 records have `ClientName: -`, including
  `MAIL-FIN-01.meridianhcs.local/windows_event_security.xml` at
  `2024-03-18T12:24:52.4792664Z`. Its matching Event 4624 at
  `2024-03-18T12:14:09.2584751Z`, Logon ID `0xd6e27ec`, identifies workstation
  `WS-AJOHNSON-01` and source `10.10.1.35:54470`. Windows can omit this field, so the pattern is not a
  contradiction; its uniformity is only weak evidence.

- **[distribution_texture, weak_signal] Successful RDP authentication latency is unusually narrow.**
  Across 19 successful Zeek RDP transports with matched target logins, transport-to-login delay spans
  only 5.592–7.271 seconds, with a 6.656-second median. For example, the MAIL-FIN session above begins
  in `zeek-core/conn.json` at `2024-03-18T12:14:02.282993Z` and reaches Event 4624 at
  `12:14:09.2584751Z`, a 6.975-second delay. A stable LAN and fixed protocol path can produce this,
  so it receives little weight.

## Evidence For Real

- **Independent sensor perspective is preserved.** Core and DMZ Zeek sensors share 4,122 connection
  tuples, but every matched observation uses a different UID. Their median timestamp offset is
  -114.227 ms; byte counts match exactly in 3,761 cases while durations match exactly in only 1,503.
  For one concrete example, the same `WS-OHADDAD` to `WEB-EXT:80` connection appears under different
  core and DMZ UIDs with a -115.472 ms offset. Core/database and DMZ/database observations similarly
  show median offsets of +61.939 ms and +178.820 ms. Those stable-but-imperfect views are consistent
  with separate collection points and clocks.

- **Protocol records obey transport lifecycles.** Every inspected Zeek DNS, HTTP, TLS, files, SMB, and
  SMTP record had a parent connection UID on the same sensor. No child protocol timestamp preceded its
  connection, and none exceeded connection close by more than 0.5 seconds. HTTP transaction depth was
  sequential for all 24 multi-transaction UIDs. For DMZ UID `C3sx3xhLg4ejTEXV4U`, requests progress
  from `/about` at `13:20:30.460982Z` (`trans_depth: 1`) to a 304 JPEG request at
  `13:20:32.177890Z` (`trans_depth: 2`, zero response body) and a WebP response at
  `13:20:32.777890Z` (`trans_depth: 3`, 99,016 response-body bytes).

- **Host process state is internally disciplined.** Across the 21 eCAR host files, there were no
  duplicate process creations or terminations, no termination-before-creation, no post-termination
  actor use, and no overlapping reuse of the same PID. Pre-window processes that terminate during the
  window and processes still active at the end account for the expected boundary cases.

- **Windows process views correlate without being implausibly identical.** Joining eCAR process
  creation to Security Event 4688 and Sysmon Event 1 by host, PID, and time produced no image, parent
  PID, or command-line disagreements for matched records. Small source-specific gaps remain: two of
  152 `DC-01` eCAR process creations lack Sysmon Event 1, and isolated Sysmon or Security gaps occur on
  `MAIL-FIN-01`, `WS-AJOHNSON-01`, `WS-PPATEL-01`, and `WS-SMARTINEZ-01`. That is credible collection
  texture rather than blanket mirroring.

- **A credential-access pivot has realistic host-native ordering.** On `WS-AJOHNSON-01`, Sysmon Event
  1 at `2024-03-18T15:45:04.4711687Z` creates PID 6604,
  `ms-index-service.exe -accepteula -o C:\ProgramData\out.txt`, from PowerShell PID 6392; Security
  Event 4688 follows at `15:45:04.7639336Z`. Sysmon Event 10 at `15:45:08.1893444Z` records PID 6604
  opening `lsass.exe` PID 4292 with `GrantedAccess: 0x1FFFFF`, followed by Sysmon Event 8 at
  `15:45:08.3218150Z` creating a remote thread in LSASS with start module `sechost.dll` and function
  `LsaICLookupNamesWithCreds`. eCAR terminates the process at `15:45:09.429Z`. The chain is concise,
  pivotable, and source-native.

- **Remote execution remains coherent apart from the source-port issue.** The PSEXEC chain proceeds
  from the SMB and RPC transports to target file creation, Event 4697, and then process creation:
  `C:\Windows\PSEXESVC.exe` starts on `DC-01` at `15:59:52.185Z`, and its child runs
  `cmd.exe /c whoami && hostname` at `15:59:52.569Z`. The observed evidence supports a complete hunt
  from source host, through network, to target service and command execution.

- **Account manipulation and persistence form a credible administrative sequence.** On `DC-01`,
  Security Event 4720 creates `svc_dirsync` at `16:15:11.9587961Z`, Event 4724 resets its password at
  `16:15:12.9346763Z`, Event 4738 changes it at `16:15:14.4632282Z`, and Event 4728 adds it to Domain
  Admins at `16:15:17.3924203Z`. Event 4697 creates `DeviceSyncSvc` at
  `16:20:03.2291048Z`, and Event 4698 registers a detailed scheduled task at
  `16:20:05.8737054Z`. Event 4726 deletes the account at `17:49:35.4547944Z`.

- **Exfiltration is operationally traceable through endpoint, proxy, and perimeter data.** On
  `WS-AJOHNSON-01`, PowerShell stages `C:\ProgramData\Microsoft\cache_7f3a.zip` at
  `17:01:02.374Z`; curl reads it at `17:25:30.900Z` and opens
  `10.10.1.35:51904 -> 10.10.3.20:8080` at `17:25:31.313Z`. Core and DMZ HTTP logs record a CONNECT to
  `api.westbridge-services.net` with `curl/8.4.0`; the client-proxy connection carries 18,783,242
  origin bytes. The proxy resolves the host at `17:25:31.868Z`, connects to `45.33.32.30:443` at
  `17:25:31.943112Z`, and emits TLS SNI at `17:25:32.127442Z`, with 18,809,726 origin bytes on the
  outbound leg. The small size difference and staged timing are realistic proxy behavior.

- **Log clearing has unusually persuasive Windows event semantics.** On `DC-01`, Security Event 4688
  at `17:42:23.6324512Z` launches `cmd.exe /c wevtutil cl Security` with EventRecordID 28261259; its
  child `wevtutil.exe` follows at `17:42:24.0686113Z` with EventRecordID 28261260. Event 1102 from
  `Microsoft-Windows-Eventlog` appears at `17:42:34.7208375Z` with `LogFileCleared` and EventRecordID
  1, and the next Event 4689 at `17:42:35.0577854Z` has EventRecordID 2. This is a strong source-native
  lifecycle detail.

- **Environmental texture is not globally templated.** Windows Filtering Platform application paths
  use different device-volume numbers by host—for example `HarddiskVolume6` on `DC-01`,
  `HarddiskVolume3` on `DC-02`, `HarddiskVolume8` on `WS-DRAMIREZ-01`, and `HarddiskVolume4` on
  `WS-PPATEL-01`. TLS versions and ciphers are compatible, certificate validity covers every observed
  TLS timestamp, Zeek states include successful, reset, and SYN-only traffic, and bash-history volume
  and cadence vary materially by user and host.

## Detailed Analysis

The assessment covered the actual JSON, XML, and shell-history records under the supplied directory:
33,662 eCAR records, 33,508 Zeek records across core/database/DMZ sensors, 30,499 Windows Security and
Sysmon events, and 308 bash-history entries. Filesystem timestamps were not used. Domain names were
treated as potentially sanitized, and neither missing event families nor incomplete source coverage was
scored as synthetic on its own.

Operationally, the dataset is highly huntable. The web-entry sequence on `WEB-EXT` is a good example:
eCAR creates an Apache-child shell at `2024-03-18T13:19:41.450Z` with a base64-decoding command;
at `13:19:45.139Z` that process opens `10.10.3.10:49708 -> 45.33.32.30:8443`; DMZ Zeek sees the same
tuple at `13:19:45.214177Z`, state `SF`, duration 8.926 seconds, with 620/1,840 application bytes; the
process terminates at `13:20:05Z`. An inbound TLS connection from `185.70.41.45` to the web server at
`13:19:36Z` overlaps the execution, while the lack of a plaintext HTTP URI is consistent with encrypted
traffic. This is a usable progression from ingress to execution to callback, not a loose collection of
indicators.

The workstation-to-domain sequence is similarly dense but coherent. A long-running PowerShell process
on `WS-AJOHNSON-01` begins at `15:20:00.909Z`, performs identity and domain-group discovery between
`15:20:01.981Z` and `15:20:07.084Z`, accesses LSASS at `15:45:08Z`, and later participates in remote
service execution. The account, service, task, staging, proxy, and cleanup records give a hunter viable
pivots by PID, process GUID, Logon ID, IP tuple, Zeek UID, file path, service name, and user SID.

Signal-to-noise is credible. The attack records sit among thousands of ordinary DNS, Kerberos, LDAP,
SMB, browser, update, mail, process, and host-service events. Network failures, resets, empty root shell
histories on some hosts, pre-window state, end-window state, and selective Windows-source gaps avoid the
appearance of an attack-only transcript. At the same time, no broad impossibility was found in TLS,
certificate, DNS, HTTP status/body, WFP direction, or process-state semantics.

The decisive issue is therefore not overall polish or correlation completeness. It is whether the three
specific contract defects could arise through collection loss or fusion. The lone SMB read can. The two
remote-logon port mismatches could reflect unobserved parallel connections, although their repetition in
short, tightly correlated service-install chains is concerning. The SQL SYN preceding the named client
process by more than 12 seconds is hardest to reconcile because the destination is distinctive and the
endpoint, Sysmon, Security, and Zeek times otherwise agree closely. One strong inversion plus repeated
port discontinuity raises the synthetic score into the mixed band, but does not outweigh the large body
of source-native realism enough for a Synthetic verdict.

## Synthetic Indicator Summary

| Category | Concrete indicator | Weight |
|---|---|---:|
| hard_contradiction | SQL SYN to `10.0.2.50:1433` occurs 12.104 seconds before the earliest matching `sqlcmd.exe` creation | High |
| contract_gap | PSEXEC logon uses source port 58966 while its observed SMB transport uses 51393 | Medium-high |
| contract_gap | DirectoryCacheSvc logon uses source port 49988 while its observed SMB transport uses 52568 | Medium-high |
| contract_gap | One complete SMB connection has a `FILE_READ` but no preceding `FILE_OPEN` or `files.json` extraction | Low-medium |
| distribution_texture | Nineteen matched successful RDP sessions cluster in a 1.679-second login-delay band | Low |
| schema_or_format | All 20 Event 4779 records have `ClientName: -`, including sessions whose Event 4624 has a workstation | Low |
| environment_or_collection_plausibility | No independent high-weight synthetic indicator found; host and sensor variation mostly supports authenticity | Counterweight |
| weak_signal | The RDP delay and Event 4779 uniformity are weak only and are not contradictions | Low |

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 9/10 | Windows XML, Sysmon fields, Zeek semantics, TLS/certificate values, paths, IDs, and protocol fields are overwhelmingly source-native; uniform 4779 client omission is the main reservation. |
| Temporal patterns | 8/10 | Most lifecycle ordering and sensor offsets are excellent, but the SQL flow/process inversion is material and RDP authentication delay is narrowly distributed. |
| Cross-source correlation | 8/10 | Correlation is rich and sensor-specific rather than copied; two repeated source-port discontinuities and one SMB child-lifecycle gap reduce the score. |
| Behavioral realism | 9/10 | Discovery, credential access, lateral movement, account changes, persistence, staging, proxy exfiltration, and cleanup form operationally credible chains amid substantial benign activity. |
| Environmental consistency | 9/10 | Host-specific device paths, topology, service roles, certificate validity, connection outcomes, and collection gaps are mutually plausible; no broad environment contradiction was found. |

## Recommendations

1. Reconcile the `10.0.2.50:1433` FLOW with its owning process. If the SYN belongs to PID 7516, move
   the connection after process creation and retain the same actor/process identity across endpoint and
   network views. If it belongs to another process, record that process explicitly so the chronology is
   explainable.
2. For remote-service activity, preserve the exact authenticated TCP source port through Security 4624,
   endpoint FLOW, Zeek `conn`, and the service-install continuation. If authentication legitimately uses
   a separate connection, emit or retain that separate tuple and distinguish it from the subsequent SMB
   file/service-control channel.
3. Ensure SMB file I/O has source-plausible open/close semantics when the analyzer has complete traffic.
   If a durable handle or parser limitation explains an open-less read, include surrounding evidence that
   makes that interpretation testable rather than silently presenting an isolated operation.
4. If this is synthetic telemetry, broaden RDP handshake/login timing according to endpoint load,
   authentication path, reconnect state, and network conditions, and populate Event 4779 `ClientName`
   selectively when its paired session metadata supports it. Do not randomize these fields independently.
5. Preserve the existing strengths: source-specific clocks and UIDs, realistic EventRecordID reset after
   log clearing, host-specific device paths, bounded-window lifecycle behavior, selective collection
   gaps, and high-value pivots across process, identity, network, file, and service evidence.
