# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 82/100  
**Synthetic-Confidence Score:** 44/100

The collection is substantially more production-like than obviously synthetic. It supports a
credible, multi-stage hunt through independent source-native pivots and contains no verified hard
temporal or lifecycle contradiction. Two repeatable defects—systematic loss of RDP client-process
attribution and conflicting curl version fingerprints for nearly simultaneous executions of the
same binary—prevent a confident Real verdict.

## Executive Summary

This bounded six-hour collection covers 21 hosts, ten Windows Security/Sysmon pairs, three Zeek
sensors, endpoint/EDR-style JSON, Linux syslog and shell history, proxy, firewall, IDS, and web
telemetry. The suspicious activity is discoverable without an explicit narrative or attack label.
A hunter can begin with failed remote authentications or an anomalous scan, pivot through source
IP, host, account, LogonID, process identity, network tuple, Zeek UID, file, service, and destination,
and reconstruct a coherent chain spanning initial access, discovery, credential access, lateral
movement, persistence, collection, staging, exfiltration, and cleanup.

The strongest evidence for authenticity is the quality of the source-native contracts. Exact
process joins showed 969 of 970 Windows endpoint process creates represented in Security 4688 and
963 of 970 in Sysmon Event ID 1, with zero joined command-line disagreements. Every checked Zeek
DNS, HTTP, TLS, SMTP, and SMB companion record joined an existing `conn` UID and occurred after its
connection open. Of 24,239 endpoint FLOW records, 23,405 (96.56%) matched a Zeek connection by exact
five-tuple within five seconds. Process and session lifecycles were ordered correctly, including
1,689 exact process create/terminate pairs with no reversed pair.

The corpus is not mechanically flat. Endpoint flow volume has a five-minute coefficient of
variation of 0.63; Zeek connection volume has a coefficient of variation of 1.32. The largest burst
is attributable to a visible `nmap` process and source host rather than unexplained record
duplication. Shell history is also varied: 168 of 212 commands are unique, and the most frequent
exact command occurs only four times.

No `hard_contradiction` was validated. The remaining doubts are a source-specific `contract_gap`, a
localized `schema_or_format` inconsistency, and unusually thin Windows process-volume
`distribution_texture`. These defects are notable but can also arise from filtering, enrichment
policy, or source configuration in real deployments. The correct blind conclusion is therefore
Inconclusive, leaning Real rather than Synthetic.

## Evidence For Synthetic

1. **`contract_gap` — RDP client process attribution is systematically absent.** Fourteen Windows
   `mstsc.exe` launches could be joined to outbound TCP/3389 FLOW records 2.2–3.9 seconds later, but
   only 2 of 14 FLOW rows retained the initiating actor/process identity. For example,
   `WS-AJOHNSON-01` launched `mstsc.exe /v:DC-01` at 14:56:47.861 and opened the matching flow at
   14:56:51.637 without an actor or PID. `WS-MCHEN-01` did the same at 16:10:32.463/16:10:35.751.
   This is systematic rather than a single dropped event. It also contrasts with the same endpoint
   source family's SSH behavior: all 27 matched SSH/SCP client process-to-port-22 flows retained
   actor attribution. The initial RDP source, `LT-MRIVERA-02`, likewise exposes three RDP flows but
   no visible client process identity. This weakens a hunter's ability to move backward from remote
   authentication to the initiating tool and principal.

2. **`schema_or_format` — one executable presents incompatible default curl versions.** On
   `WS-AJOHNSON-01`, two `C:\Windows\System32\curl.exe` processes under the same principal were
   created only 547 ms apart. Exact endpoint-flow/Zeek-HTTP tuple joins report `curl/7.88.1` for one
   and `curl/8.4.0` for the other. Neither captured command line specifies `-A` or `--user-agent`.
   A per-process configuration or a binary replacement could theoretically explain this, but the
   collection contains no supporting configuration or file-change evidence. The discrepancy looks
   more like independent field generation than one host-native application identity.

3. **`distribution_texture` — Windows process telemetry is unusually sparse relative to network
   telemetry.** The ten Windows hosts produce only 970 joined process creates over six hours—about
   16.2 creates per host-hour—while the same hosts produce 7,435 Sysmon network connections and
   11,605 Security 5156 events. This may reflect a deliberately filtered endpoint collection, but
   the files otherwise appear to be broad Security and Sysmon feeds. The low process churn makes
   benign endpoint activity less dense than expected and gives suspicious command bursts more
   contrast than they would often receive in production.

## Evidence For Real

- **Exact joins preserve identity rather than merely timestamp proximity.** Across the ten Windows
  hosts, 969/970 endpoint process creates joined Security 4688 and 963/970 joined Sysmon Event ID 1
  by host, PID, and time. All joined command lines agreed exactly. The small unmatched residue is
  more credible than universal source duplication.

- **Lifecycle ordering is sound.** There are 1,689 endpoint process create/terminate pairs by exact
  object identity, with no terminate-before-create result and no duplicate starts or ends. Another
  5,438 dependent events whose actor resolved to a visible process all occur after that process was
  created. Successful network-logon sessions generally have matching logoffs; residual unmatched
  sessions are concentrated at collection boundaries or in long-lived service/interactive types.

- **Zeek protocol contracts are internally coherent.** Every checked DNS, HTTP, TLS, SMTP, SMB
  mapping, and SMB file row has a matching connection UID, and none precedes its connection open.
  This holds across core, database, and DMZ sensors rather than only one capture point.

- **Cross-source network agreement is strong but imperfect.** Exact five-tuple matching connects
  23,405/24,239 endpoint FLOW events to Zeek within five seconds. The median endpoint-minus-Zeek
  offset is 176 ms, with bounded source-specific skew rather than bit-identical timestamps. That
  permits practical pivots while retaining realistic observation delay and gaps.

- **The highest-volume anomaly has a defensible cause.** At 13:40, `WEB-EXT-01` runs
  `nmap -sn 10.10.2.0/24`, followed by `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24`. Zeek records
  roughly 247–249 `S0` targets per tested port plus approximately 245 ICMP probes. Endpoint FLOW
  rows attribute the burst to the visible root-owned `nmap` PID. The cardinality, timing, and
  connection states look like tool behavior rather than arbitrary volume injection.

- **The principal attack path is correlated without being pre-assembled.** The hunter must combine
  target authentication, endpoint sessions, process telemetry, network tuples, file operations,
  service events, and proxy/TLS observations. There is no common attack ID or conspicuous global
  correlation key joining the entire story.

- **Background traffic has useful hunting friction.** Kerberos, LDAP, DNS, SMB, proxy/TLS, service
  accounts, failed logons, recurring Linux jobs, and routine remote administration provide benign
  lookalikes. Five-minute traffic counts are bursty rather than fixed, and shell commands are not
  dominated by a small repeated pool.

- **Cleanup has source-native consequences.** Clearing the Security log on `DC-01` is followed by a
  Security 1102 event and an EventRecordID restart, explaining the only record-ID discontinuity.
  Account deletion and service cleanup also leave separate command, process, and Security-event
  evidence instead of disappearing cleanly.

## Detailed Analysis

### Scope and Quantitative Method

The assessment treated the directory as an unknown-origin telemetry export and inspected only its
contents. Checks were performed on complete source files, not hand-selected samples. The principal
tests were:

- per-source event counts, timestamp bounds, and five-minute volume distributions;
- exact endpoint process-object lifecycle joins;
- dependent-event-to-actor and target-process causality checks;
- endpoint process-to-Security 4688 and process-to-Sysmon 1 joins by host, PID, command line, and
  tight time tolerance;
- endpoint FLOW-to-Zeek `conn` joins by complete five-tuple and time;
- Zeek application-record-to-connection joins by UID and timestamp order;
- successful authentication-to-session/logoff checks by host and LogonID;
- source-native reconstruction of suspicious process, authentication, network, file, service,
  proxy, and TLS activity.

The observed time window is approximately 12:00–18:00 UTC on 2024-03-18. Boundary-only missing
initiators or terminators were not treated as authenticity defects.

### Hunt Reconstruction and Pivotability

| Time (UTC) | Hunt phase | Source-native evidence and useful pivots |
|---|---|---|
| 13:40 | Reconnaissance | `WEB-EXT-01` process telemetry exposes two root-owned `nmap` commands. PID/actor pivots reach endpoint FLOW; tuple pivots reach Zeek `S0` and ICMP fan-out. |
| 14:59–15:01 | Initial access | `WS-AJOHNSON-01` records failed attempts associated with users Aisha Johnson, Diego Ramirez, and Sophia Martinez from `10.10.1.99`/`LT-MRIVERA-02`, followed by a successful Type 10 Aisha session (`0x26dad90`). Source-host FLOW telemetry independently exposes the TCP/3389 attempts. |
| 15:19 | Discovery | Under the established Aisha LogonID, `whoami /all`, `net user /domain`, `net group "Domain Admins" /domain`, and `net view /domain` occur within seconds. The command burst is easy to query but requires session/process joins to connect to initial access. |
| 15:44 | Credential access | `ms-index-service.exe` runs `privilege::debug` and `sekurlsa::logonpasswords`; endpoint THREAD `REMOTE_CREATE` targets the visible `lsass.exe` process. Sysmon/Security process evidence provides independent corroboration. |
| 15:59 | Lateral movement | Aisha's workstation opens SMB to `DC-01`; Zeek sees an `SF` connection with substantial request bytes. `DC-01` then creates `C:\Windows\PSEXESVC.exe`, installs `PSEXESVC`, launches the service, and executes `cmd.exe /c whoami && hostname`. Source tuple, target file, service name, PID, and timestamps form a credible multihop pivot. |
| 16:14–16:29 | Persistence | `DC-01` creates `svc_dirsync`, resets its password, changes account attributes, adds it to Domain Admins, creates `DeviceSyncSvc`, and creates a scheduled task. `DC-02` separately installs `DirectoryCacheSvc`. Security 4720/4724/4738/4728/4697/4698 records track the process evidence. |
| 17:00–17:19 | Collection and staging | A Type 9 session on Aisha's workstation identifies outbound credentials as Marcus Chen. PowerShell stages a ZIP. On Linux, SSH, `mysqldump`, `gzip`, `scp`, and `smbclient put` form a second collection path whose process, FLOW, Zeek, bash, and target-file evidence can be joined. |
| 17:25 | Exfiltration | `curl.exe` reads the staged ZIP, connects to `PROXY-01`, and generates an HTTP CONNECT. The client leg carries 18,783,277 originator bytes; the proxy-to-origin TLS leg begins within the same second and carries 18,786,007 bytes to `45.33.32.30` with SNI `api.westbridge-services.net`. The small byte delta and two-leg timing are strong proxy-contract evidence. |
| 17:42–17:53 | Cleanup | `wevtutil` clears the `DC-01` Security log, `svc_dirsync` is deleted, the `DC-02` service is removed, and Linux history is cleared. The resulting 1102, account/service events, process rows, and history/file effects remain separately discoverable. |

### Analyst Workflow Realism

The chain supports several independent entry points. A SOC analyst could start with the
workstation's failed-to-successful RDP pattern, a credential-dumping command line, remote thread
creation into LSASS, `PSEXESVC` installation, privileged account creation, the large proxy upload,
or the perimeter scan. None requires knowledge of the complete storyline.

The best pivots are operationally familiar:

1. source IP and workstation name from authentication failures;
2. target LogonID into the discovery and credential-access process chain;
3. process object/PID into flow tuples;
4. tuple into Zeek UID and application metadata;
5. SMB destination into file/service creation on the remote host;
6. archive path into FILE READ and outbound proxy transfer;
7. proxy client leg into proxy-origin TLS SNI and external IP.

The collection does not make all pivots equally convenient. RDP's missing actor identity forces a
time/tuple join where SSH preserves a direct process link. That asymmetry is the most material hunt
contract weakness, but it does not make the chain undiscoverable.

### Identity and Lifecycle Continuity

User identity remains stable across domain-style names, host-local session records, Windows
LogonIDs, and endpoint principal objects. The collection also distinguishes the local interactive
identity from the outbound Type 9 credential identity during staging. On the target side, remote
execution frequently appears under service/system context, which is source-native behavior and
requires the analyst to retain the network and caller-side chain rather than assuming the target
principal names the original operator.

The two successful RDP sessions remain logged on after their corresponding transport flows close.
That is not a contradiction: an RDP session can disconnect while remaining active. Similarly,
process termination shortly before final network close is compatible with operating-system socket
teardown. No lifecycle pair in the exact process-object checks ran backward in time.

### Signal-to-Noise and Distribution Texture

The suspicious chain is visible, but it is embedded among substantial background activity. The
endpoint corpus contains 32,991 records, including 24,239 FLOW records and 1,924 process creates.
Windows Security contains 18,232 events and Sysmon contains 11,542. Zeek contains 19,833 connection
records before counting DNS, HTTP, TLS, file, SMB, mail, and certificate companions.

Traffic is neither uniform nor simply random. Endpoint FLOW counts in five-minute buckets have a
mean of 336.65, standard deviation of 212.20, and coefficient of variation of 0.63. Zeek connection
counts have a mean of 275.46, standard deviation of 364.71, and coefficient of variation of 1.32.
The observed maxima correspond to explainable operational bursts. Exact process lifetimes are also
varied: among 1,689 complete pairs, the most common non-service exact duration appears only three
times, while long-running provider processes legitimately share four-hour-scale durations.

The main texture concern is not flat traffic but the light Windows process baseline. Sixteen
creates per host-hour is low for apparently broad host telemetry and gives command-based detections
less benign contention than many production estates. Because real pipelines commonly filter
process events, this remains a moderate indicator rather than a contradiction.

## Synthetic Indicator Summary

| Indicator | Classification | Affected family | Scope | Weight |
|---|---|---|---|---|
| RDP client flows usually omit the visible initiating process/actor, unlike SSH | `contract_gap` | Endpoint FLOW + RDP/authentication | 12 of 14 matched Windows `mstsc` flows; all three visible initial-source RDP flows also lack a client process | High |
| Same System32 curl path reports two default version fingerprints 547 ms apart | `schema_or_format` | Endpoint process + Zeek HTTP/proxy | Two exact process/flow/HTTP joins on `WS-AJOHNSON-01` | Medium |
| Windows process creation volume is thin relative to network/security coverage | `distribution_texture` | Sysmon/Security/endpoint process telemetry | Ten Windows hosts across the full six-hour window | Medium-low |
| No impossible event order, duplicate lifecycle identity, or irreconcilable exact join was found | `hard_contradiction` | All checked families | Corpus-wide quantitative checks | None observed |

## Realism Score by Category

| Category | Score | Assessment |
|---|---:|---|
| Field format accuracy | 8/10 | Source-native fields are broadly usable; the curl fingerprint inconsistency is the main exception. |
| Temporal patterns | 9/10 | Millisecond-scale source skew, lifecycle ordering, burst behavior, and proxy/transport timing are credible. |
| Cross-source correlation | 8/10 | Exact joins are strong and not universal; systematic RDP attribution loss reduces the score. |
| Behavioral realism | 8/10 | The attack and background behaviors form plausible, multistage operational chains without an explicit master key. |
| Environmental consistency | 8/10 | Host roles, protocols, identities, and remote execution semantics generally agree across sources; process volume is somewhat sparse. |

## Recommendations

1. **Repair RDP attribution at the owning event/collection layer.** Preserve the initiating client
   process, PID, actor, and principal on outbound TCP/3389 FLOW records whenever the process is
   visible. Apply the same contract to non-Windows clients such as `xfreerdp`/Remmina where endpoint
   telemetry is present. Add a regression check that RDP and SSH client attribution policies do not
   diverge without an explicit collection reason.

2. **Use one canonical application identity for executable and protocol fingerprints.** Derive the
   curl User-Agent version from the actual process/binary identity and reuse it in HTTP/proxy
   rendering. If `.curlrc`, environment, or command-line overrides are intended, expose enough
   evidence to explain the difference and test simultaneous same-path invocations.

3. **Increase benign Windows process texture or make filtering explicit.** Add routine interactive
   and background process churn, parent/child variation, and normal administrative commands in
   proportion to network activity. If the source is intentionally filtered, include source metadata
   that lets an analyst distinguish collection policy from an implausibly quiet endpoint.

4. **Preserve the existing high-value contracts.** Maintain exact LogonID/process identity, Zeek UID
   causality, process lifecycle ordering, SMB service/file sequencing, and two-leg proxy byte/timing
   relationships. These are the collection's strongest realism features.

5. **Keep suspicious activity discoverable through normal pivots, not global labels.** The current
   chain appropriately requires joins across authentication, process, network, file, service, and
   proxy/TLS evidence. Future changes should retain multiple independent detection entry points and
   benign lookalikes while avoiding a corpus-wide scenario or attack identifier.
