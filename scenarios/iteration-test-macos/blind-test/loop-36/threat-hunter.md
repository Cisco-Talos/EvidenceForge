# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 77
**Synthetic-Confidence Score:** 57

## Executive Summary

The collection is highly usable for hunting, with credible transport-before-authentication relationships, durable process identities, and coherent proxy and endpoint pivots. I lean synthetic because one native Windows process is credited with explicit credential use despite a command line that should fail parameter binding, with a smaller supporting signal from repeated command timing on the two Macs. The score remains in the mixed band because broad checks did not uncover widespread lifecycle or network contradictions.

## Evidence For Synthetic

- [contract_gap] On `WS-MCHEN-01.meridianhcs.local`, native Security event 4688, record **948955**, at **14:13:58.1777320Z**, creates PID **0x1d70 / 7536** running `powershell.exe -NoProfile -Command "Get-CimInstance Win32_OperatingSystem -ComputerName 'MAIL-FIN-01' -Credential 'marcus.chen-admin'"`. Standard `Get-CimInstance` does not have a `-Credential` parameter; that command should fail parameter binding before performing explicit remote credential use. Nevertheless Security **4648 record 948958**, at **14:14:01.4080780Z**, attributes use of `MERIDIANHCS\marcus.chen-admin` against `MAIL-FIN-01` to that exact PID, and **4689 record 948959**, at **14:14:03.9740045Z**, gives its exit `Status=0x0`. These records' `EventRecordID` elements are at XML lines **5603, 5739, 5781**, respectively. The process is independently represented in `WS-MCHEN-01.meridianhcs.local/ecar.json:228`. This is the main scoring issue: the command and its asserted effect do not fit ordinary Windows PowerShell semantics. An undocumented replacement function or instrumentation alteration could explain it, but the supplied data provides no such evidence.
- [distribution_texture] The two Mac shell histories share a small rotated command vocabulary and repeated inter-command timing. `MAC-MROSS-01.../zsh_history/maya.ross.zsh_history:1-3` contains `id`, `sw_vers`, `uname` at epochs **1793624867, 1793624888, 1793624936**, gaps **21 and 48 seconds**. The corresponding `MAC-MROSS-02...` file, lines **1-3**, contains `sw_vers`, `uname`, `pwd` at **1793625110, 1793625131, 1793625179**, again **21 and 48 seconds**, despite the commands being shifted. MAC-01 lines **4-6** then run `pwd`, `ls`, `du` with **30 and 50 second** gaps; MAC-02 lines **4-5** run `ls`, `du` with another **30 second** gap. This looks like repeated activity blocks rather than fully independent workstation behavior. It is a small supporting signal because the same user operates both machines and could be following a checklist.

## Evidence For Real

- Remote-session pivots are technically coherent. I joined **61** successful SSH or Type 10 login records in endpoint eCAR to Zeek connections using source IP and source port, choosing the nearest matching transport occurrence. Every matched login occurred after transport open and before transport close. For example `DC-02.../ecar.json:690` is Aisha's login from `10.10.1.35:51720` at **13:50:26.017Z**; `zeek-core/conn.json:1544` starts its transport roughly **7.047 seconds** earlier and lasts **1017.542919 seconds**.
- Native Windows Sysmon process lifecycle evidence is consistent across the ten supplied Windows hosts. I compared visible Event 1/5 identities with dependent ProcessGuid/SourceProcessGUID/TargetProcessGUID evidence and parent identities. I found no dependent event after a visible same-GUID termination, no dependent event before a visible same-GUID creation, and no process creation after its visible parent GUID had terminated. This does not assume that pre-window creation records must exist.
- All supplied Zeek HTTP, SSL, SMTP, DNS and SMB UID references checked against their own sensor's `conn.json` had a matching connection. Their timestamps fell within the matching connection interval with a 200 ms tolerance. HTTP request/response body lengths did not exceed their respective connection payload byte counts. This is evidence of technical coherence, not an authenticity penalty for complete matching.
- The collection contains plausible failures and distractors. The public web host has scans blocked by its own host firewall while the perimeter firewall records the accepted perimeter connection and eventual SYN timeout: `WEB-EXT-01.../syslog.log:2` and `fw-perimeter/cisco_asa.log:1,3` concern `185.220.163.140:26982 -> 10.10.3.10:6379`. Those observations can coexist because they are different enforcement points.
- Proxy evidence distinguishes allowed tunnels, TLS inspection, gateway errors, and explicit denials. `PROXY-01.../proxy_access.log:4` records a 504 for `sdk.statuspage.net`; lines **2881, 3126, 3449** record denied CONNECT requests from the DC to `45.33.32.30:443`. The denial records remain HTTP control exchanges rather than being described as successful application requests.
- Security-log clearing is handled plausibly. On DC-01, Event 1102 at **18:42:26.0007020Z** has `EventRecordID=1`; subsequent Security records restart at low IDs rather than continuing the pre-clear sequence near **28261379**.

## Detailed Analysis

### Orientation and collection scope

The supplied data covers approximately **2026-11-02 13:00–19:00 UTC**. There are **23 endpoint directories**: ten with native Windows Security/Sysmon XML, eleven Linux-like endpoints with syslog, and two Macs with Endpoint Security NDJSON, Unified Log NDJSON and zsh history. All endpoints have normalized eCAR, totaling **35,814 records**. The visible network spans workstation `10.10.1.0/24`, server `10.10.2.0/24`, DMZ `10.10.3.0/24`, and a database address in `10.10.4.0/24`, with three Zeek sensor directories, two Snort alert streams and perimeter ASA telemetry.

The apparent roles fit much of the activity: DCs dominate authentication and network auditing, a public web server attracts inbound scanning, a proxy concentrates outbound HTTP/TLS traffic, and file servers provide SMB content. Zeek connection volumes are **12,279 core**, **9,287 DMZ**, and **464 database** rows. Those cannot be added as independent enterprise flows because sensors can observe the same connection. I did not score sparse native Mac Unified Log coverage, selected Sysmon event coverage, or absent ancillary products as defects.

### Hunting pivots and tradecraft

Several suspicious clusters are visible, but I did not assume they necessarily belong to a single intrusion. `WEB-EXT-01.../ecar.json:811` records an Apache-parented `www-data` bash process at **14:20:06.215Z** whose encoded command decodes to an interactive bash connection to `45.33.32.30:8443`. `zeek-dmz/conn.json:1743` supplies the matching outbound transport from `10.10.3.10:54918` at epoch **1793629209.625084**, with `SF`, **620/1840 payload bytes**, and **1.305672 seconds** duration. The bash process terminates at **14:20:21.163Z** (`ecar.json:814`). A short connected transport is observable; this alone does not establish a durable shell or subsequent privileged action.

A later remote login to Aisha's Windows workstation is explicit: `WS-AJOHNSON-01.../ecar.json:541` records Type 10 from `10.10.1.99:48154` at **16:00:34.089Z**. Discovery commands from PowerShell appear around **16:20Z** in the same interactive session. At **18:00:28.391Z**, line **1019** runs `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"`; line **1027** creates a Type 9 context that correctly preserves **local principal Aisha** while naming **outbound principal Marcus**. Line **1032** places the resulting cmd process in that new credential context. I did not mistake different local and remote identities here for a contradiction.

Subsequent file-collection commands name Finance, ClinicalExports and ClinicalResearch shares and a local archive. `WS-AJOHNSON-01.../ecar.json:1199` records the curl multipart upload at **18:24:54.488Z**. `PROXY-01.../proxy_access.log:3388` provides the application-level POST at **18:24:58Z** to the same URL, user, client address and curl user agent, with `cs_bytes=18783090`; `zeek-dmz/conn.json:8487` provides a corresponding large outbound proxy-side TLS transport with **18,809,754 orig_bytes**. The unequal endpoint HTTP and external TLS byte counts are plausible protocol-layer differences. I did not score the visibility or completeness of this trail as synthetic.

The DC-01 records also support service/persistence investigation: eCAR line **3545** installs PSEXESVC at **16:59:44.828Z**; lines **3870, 3877, 3885** show command, sc child and DeviceSyncSvc installation around **17:19:40–44Z**, followed by service execution at line **4096**. Those are meaningful pivots. Their compactness or apparent narrative structure is not part of my authenticity score.

### The credential-use inconsistency

The strongest issue is separate from the main suspicious sequence. PID 7536 on WS-MCHEN is explicitly created with the standard Windows PowerShell path and `-NoProfile`; its only supplied command is a `Get-CimInstance` invocation with an unsupported `-Credential` argument. A supplied username is not by itself a credential-use event: parameter binding would need to succeed before the cmdlet could reach a credential API. The native 4648 names exactly this PID, account and target roughly 3.23 seconds after creation, and the exit record claims zero status.

This matters to a hunter because an apparently credible credential-use pivot is attributed to an action that ordinarily cannot perform it. The logs do not show a successful MAIL-FIN remote session for this operation, and I make no claim that they do. The contradiction is between the visible command and the same-process 4648/exit outcome. A custom shadowing function is a possible but unsupported alternative explanation; it is why I characterize this as a high-impact localized contract gap rather than claiming a dataset-wide impossible state.

### Distribution and limitations

The repeated Mac command blocks are suggestive but less decisive. Their common actor makes copied checklists or deliberate comparisons plausible, and timestamped histories have second-level precision. I score only the repeated command/cadence texture, not the absence of native macOS events I would like to have, unfamiliar ES message fields, or normal workstation traffic observed by network sensors.

Broad technical checks were reassuring: visible endpoint process-parent lifetimes, native Sysmon GUID lifetimes, remote authentication order, per-sensor UID existence, HTTP body-versus-flow byte bounds, and connection IP-byte lower bounds all passed the checks described above. These checks reduce the justification for an 81–100 synthetic score. Conversely, a small number of technically incompatible source records can still make a largely convincing synthetic collection more likely than real production output.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | WS-MCHEN native Security 4688/4648/4689, corroborating eCAR process command | One identified credential-use operation, PID 7536 | Main issue: unsupported cmdlet parameter is followed by explicit credential use and zero exit status for the same process. |
| `distribution_texture` | Both Mac zsh histories | Repeated initial command blocks and intervals | Small increase: rotated command vocabulary preserves identical 21/48-second gaps and another 30-second gap; same-user checklist remains plausible. |

## Realism Score by Category

- **Field format accuracy:** 9 — Native records and normalized views are generally credible; no demonstrated widespread serialization or parser problem.
- **Temporal patterns:** 8 — Sampled and systematic lifecycle checks pass; repeated Mac shell-command cadence is a localized texture issue.
- **Cross-source correlation:** 9 — Remote sessions, process identities and network references support reliable pivots; one command-to-credential-effect contract is inconsistent.
- **Behavioral realism:** 7 — Most administrative and suspicious commands fit their hosts and purposes; the invalid CIM credential invocation materially weakens executable realism.
- **Environmental consistency:** 9 — Host roles, segments, firewall layers and proxy semantics largely agree with the observed activity and source distribution.

## Recommendations

- If this were synthetic, correct the WS-MCHEN credential operation to use an executable command path that can actually consume credentials, and ensure its 4648 and exit status follow that path's real behavior. If retaining the current command, represent its parameter-binding failure rather than attributing explicit credential use to it.
- If this were synthetic, diversify the two Macs' repeated command blocks and their inter-command timings, or add visible evidence that the user is executing a repeated diagnostic/checklist procedure. The improvement should address the observed repeated intervals, not add unrelated noise.
- Retain the coherent Type 9 local/outbound identity distinction, transport-before-authentication order, per-source UID relationships, log-clear record-ID reset, and separate proxy control-message versus application byte accounting.
