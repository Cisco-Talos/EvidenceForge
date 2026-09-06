# Threat Hunter — Authenticity Assessment

## Verdict

- **Assessment:** Inconclusive — slight synthetic lean
- **Verdict Confidence:** Moderate (78/100)
- **Synthetic-Confidence Score:** 55/100

The dataset is operationally convincing. It presents a huntable, technically feasible intrusion
whose pivots can be reconstructed across endpoint, Windows Security, Linux authentication, Zeek,
SMB, proxy, and file telemetry. I found no hard contradiction in event ordering, process lifecycle,
session lifecycle, or network tuples. The slight synthetic lean rests instead on two concrete
ownership discontinuities at important pivots and a repeated command-vocabulary pattern across
unrelated Linux hosts. Those are meaningful but not decisive: each could also result from endpoint
collection gaps, remote-management semantics, or a shared operations playbook.

## Executive Summary

The clearest malicious sequence starts on `WS-AJOHNSON-01` at 15:45 UTC with a high-integrity
process running `privilege::debug` and `sekurlsa::logonpasswords`, followed by opens of `winlogon`
and `lsass.exe` and a remote thread into LSASS. It progresses through PsExec-like service execution
on `DC-01`, WMI-parented domain-account and Domain Admins changes, service and scheduled-task
persistence, service execution on `DC-02`, an SSH pivot from `APP-INT-01` to `DB-PROD-01`, database
dumping and compression, SCP staging back to the application host, SMB movement to
`FILE-LNX-01`, and Windows/Linux cleanup. The timestamps, identities, ports, lifecycle transitions,
and source-native delays are mostly compatible.

The surrounding environment is not just an attack transcript. It contains failed and reset network
connections, NXDOMAIN and SERVFAIL responses, ordinary web-resource bursts, proxy denials,
scheduled services, package activity, SSH failures, user typos, development commands, and varied
alert traffic. This noise gives the hunter plausible competing hypotheses and useful negative space.

The strongest synthetic concern is that some decisive remote-execution stages are richly represented
on their targets but lack a corresponding source-side initiating process or accountable principal.
Most notably, the 16:14 WMI sequence on `DC-01` follows SMB traffic from `WS-AJOHNSON-01`, yet the
visible target logon is the workstation machine account and the malicious commands execute as
SYSTEM; no matching source-side WMI client is visible. Likewise, the application-to-file-server SMB
relay exposes a source FLOW and FILE READ without a PID, actor, or principal. These are collection
or correlation gaps, not impossible events, so they do not support a confident synthetic verdict.

## Evidence For Synthetic

**[contract_gap] Remote-execution ownership is discontinuous at a key domain-controller pivot.**
At 16:14:23, `WS-AJOHNSON-01.meridianhcs.local/ecar.json` records a System/PID 4 SMB FLOW from
`10.10.1.35:62221` to `10.10.2.10:445`. On `DC-01`, the subsequent successful Type 3 session at
16:14:24.856 is attributed to `WS-AJOHNSON-01$`, after which `WmiPrvSE.exe` under NETWORK SERVICE
parents SYSTEM-context commands to create `svc_dirsync` and add it to Domain Admins. The resulting
Security events—4720, 4724, 4738, and 4728—also name SYSTEM with logon ID `0x3e7`. Yet the source
endpoint contains no visible `wmic.exe`, PowerShell WMI invocation, or equivalent client process for
this operation. A real WMI action can execute as SYSTEM and machine-account traffic is normal, but
the combination leaves the attacker-to-action handoff unusually clean on the target and opaque on
the source despite otherwise detailed process telemetry.

**[contract_gap] The final SMB relay loses source-side process and principal ownership.**
After `DB-PROD-01` sends `/tmp/rpt_0318.sql.gz` to `APP-INT-01` over SCP, the application host
records an outbound SMB FLOW from `10.10.2.30:33478` to `10.10.2.21:445` at 17:35:04.486 and a
FILE READ at 17:35:04.507. Those application-host records have no accountable PID, actor ID, or
principal. In contrast, `FILE-LNX-01` records the receiving `smbd` process, an inbound flow, a
`svc_mhsync` login, and a write to
`/srv/samba/ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz`. The transfer is feasible and
the tuple correlates, but the missing sender process makes the most important staging handoff look
partially assembled from target-side evidence.

**[distribution_texture] Distinct Linux hosts reuse conspicuously exact interactive command
strings.** The exact command `sysctl -a 2>/dev/null | grep net.ipv4.ip_forward` appears for different
users on `APP-INT-01`, `LOG-MON-01`, and `MAIL-CLIN-01`; `tail -f /var/log/syslog &` appears on
`APP-INT-01`, `MAIL-CLIN-01`, and `MAIL-EDGE-01`; and `systemd-analyze blame | head` appears on
`FILE-LNX-01`, `LOG-MON-01`, and `MAIL-EDGE-01`. Exact reuse can reflect a shared runbook, shell
snippet, or small operations team, so this is only a low-to-moderate indicator. In aggregate, however,
the cross-host command vocabulary is more recycled than the otherwise heterogeneous user activity.

**No hard contradiction found.** I found no visible create-after-terminate process, logout-before-login
session, impossible transport/authentication ordering, irreconcilable source/destination tuple, or
other log-visible violation that independently establishes synthetic origin.

## Evidence For Real

**[cross_source_correlation] Credential access has credible endpoint depth and source-native timing.**
`WS-AJOHNSON-01.meridianhcs.local/ecar.json:708` records
`ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` at 15:45:21. The process
runs as `aisha.johnson` at High integrity with logon ID `0x26db80d`; shortly afterward, eCAR records
opens of `winlogon` and LSASS PID 4292 with access `0x1FFFFF`, then a remote thread into LSASS.
Sysmon Event 1 occurs at 15:45:21.431 and Security 4688 at 15:45:21.682, a small but credible
source-dependent delay rather than a single duplicated timestamp.

**[causal_ordering] PsExec-like movement to `DC-01` follows a feasible transport-to-service chain.**
Zeek core `conn.log` records `10.10.1.35:49576` to `10.10.2.10:445` at 15:59:49.037 with 152,277
origin bytes, `SF` state, and 0.825-second duration, followed by RPC/135 at 15:59:50.176. Target eCAR
then records creation of `C:\Windows\PSEXESVC.exe` at 15:59:50.193, service creation at
15:59:50.460, service execution at 15:59:51.050, and child command
`cmd.exe /c whoami && hostname` at 15:59:56.121. Security Event 4697 at 15:59:50.528 corroborates
the service installation. The order and inter-source latency are technically credible.

**[causal_ordering] Persistence and further lateral movement retain parent, service, and identity
semantics.** On `DC-01`, WMI-parented commands create `DeviceSyncSvc` and an hourly SYSTEM task
named `\Microsoft\Windows\Maintenance\DeviceSync`; Security Event 4698 contains corresponding task
XML with a `PT1H` interval and command path. The service later executes under `services.exe`. On
`DC-02`, a Type 3 login for `marcus.chen` from `10.10.2.10:50651` at 16:25:05.989 precedes creation
of `DirectoryCacheSvc` at 16:25:11.002/16:25:11.010 and service execution at 16:25:13.447. This is
a plausible progression from credential access to durable control of multiple domain controllers.

**[cross_source_correlation] The database collection and two-hop staging sequence is especially
strong.** `APP-INT-01` records `ssh -A root@DB-PROD-01`; Zeek observes
`10.10.2.30:47571 -> 10.10.4.10:22` starting at 17:14:21.454 with a 2,208.9-second `SF` session.
`DB-PROD-01` syslog then records connection, accepted-password, PAM-open, and logind-session events
between 17:14:25 and 17:14:33. Endpoint activity proceeds from database discovery to `mysqldump`,
creation of `/tmp/rpt_0318.sql`, gzip compression, hashing, and SCP. The reverse SSH connection
from `10.10.4.10:56481` to `10.10.2.30:22` is visible in Zeek at 17:34:53.426, while the application
host records inbound FLOW, `sshd`, root login, and file creation. The subsequent SMB write is visible
in Zeek SMB/files telemetry and as `smbd`, session, and file activity on `FILE-LNX-01`.

**[causal_ordering] Cleanup behavior is represented as action plus consequence.** On `DC-01`, eCAR
shows WMI-parented `cmd.exe /c wevtutil cl Security` at 17:42:13.038 and child `wevtutil.exe` at
17:42:13.191. Security Event 1102 follows at 17:42:17.067 under SYSTEM/`0x3e7`; both processes then
terminate. Later evidence includes deletion of `svc_dirsync`, stopping and deleting
`DirectoryCacheSvc` on `DC-02`, and `history -c && cat /dev/null > ~/.bash_history` on
`APP-INT-01`. These are huntable anti-forensics rather than unexplained terminal markers.

**[environmental_noise] The background has useful operational texture.** Core Zeek connection states
include 8,639 `SF`, 1,952 `S0`, 118 `RSTO`, and 86 `RSTR`, while DNS includes 210 NXDOMAIN,
18 SERVFAIL, and 3 REFUSED outcomes. Linux records contain cron, rsyslog, resolver, package,
systemd, SSH, and user-shell activity, including typos such as `catt` and `dff`. Web and proxy logs
show resource fan-out, 200/304 mixtures, CONNECT tunnels, denials, varied user agents, and byte
counts. Snort traffic includes suspicious TLD, STUN, BitTorrent, and CONNECT alerts. This supports
realistic hunting because the malicious chain is embedded in competing routine and suspicious noise.

## Detailed Analysis

**Kill-chain reconstruction.** The likely chain is credential dumping on `WS-AJOHNSON-01`,
PsExec-like execution on `DC-01`, WMI-based account creation and privilege escalation, service/task
persistence, a second domain-controller service deployment, SSH access to the production database,
database collection and compression, SCP staging, SMB placement on a file server, and log/history
cleanup. Each major phase offers multiple pivots: process UUID/PID and logon ID at the endpoint;
source IP, source port, destination tuple, and Zeek UID on the network; service/task names in Windows;
and path/hash/session identity during staging.

**Tradecraft.** The actor mixes conspicuous credential-dumping syntax and PsExec naming with more
blended persistence names (`DeviceSyncSvc`, `DirectoryCacheSvc`) and a Microsoft-like task path.
Use of WMI parents, SYSTEM execution, SSH agent forwarding, root login, `mysqldump`, compression,
hashing, SCP, SMB, Event Log clearing, and shell-history clearing forms a credible if somewhat
demonstrative intrusion. It is realistic enough for training, though the sequence covers many
high-value techniques in a compact six-hour window and exposes unusually convenient telemetry at
nearly every target.

**Pivots and attribution.** The best pivots are robust: the initial endpoint process leads to LSASS
access; the workstation-to-DC SMB/RPC tuple leads to PSEXESVC; the DC-to-DC source address and login
lead to service creation; and the APP/DB SSH tuples lead to shell and file activity. The weakest
pivots are the 16:14 WMI initiator and the APP-side SMB sender. A hunter can infer what occurred but
cannot assign those actions to a visible source process or interactive identity without relying on
target-side consequences.

**Noise and collection.** Collection is broad but not perfectly uniform. Windows Security is heavily
populated by filtering-platform connections, while endpoint JSON provides richer process context.
Linux and network sources provide enough failures, background services, browsing, and administrator
activity to avoid a sterile attack-only environment. I do not treat absent selected Sysmon event
types, source-volume imbalance, sanitization, timestamps, or mere cross-source completeness as
authenticity evidence. The cited concerns depend on specific required ownership transitions, not on
thinness alone.

**Alternative real-world explanation.** EDR products often fail to attribute kernel-owned SMB flows,
remote-management execution can cross machine-account and SYSTEM contexts, sensors can drop the
short-lived client process while retaining the target action, and administrators can share exact
runbook commands. Those explanations keep the dataset within the plausible range for sanitized real
telemetry. Conversely, a deterministic generator can readily produce the strong target-side chains
while omitting a source actor contract or drawing interactive commands from a shared pool. The
evidence therefore supports only a slight lean.

## Synthetic Indicator Summary

| Indicator type | Count | Severity | Effect on verdict |
|---|---:|---|---|
| Hard contradictions | 0 | None observed | Prevents a confident synthetic classification |
| Remote-execution ownership gap | 1 | Moderate | Weakens attribution for the 16:14 WMI/domain-change pivot |
| Source-side transfer ownership gap | 1 | Moderate | Weakens the APP-to-FILE-LNX staging contract |
| Repeated cross-host command vocabulary | 1 pattern family | Low–Moderate | Adds synthetic distribution texture but has a credible runbook explanation |
| Strong technically feasible correlations | Multiple | Strong counterevidence | Substantially lowers synthetic confidence |
| Realistic operational noise and failures | Multiple families | Moderate counterevidence | Supports real or high-quality synthetic origin |

The synthetic case is based on three soft indicator families and no hard contradiction. The real case
is stronger on local technical feasibility; the synthetic case is stronger on how cleanly the overall
narrative is exposed and where source ownership disappears at selected bundle boundaries.

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field and format fidelity | 9/10 | Source-native XML, JSON, Zeek, syslog, SMB, proxy, and IDS records have credible fields and vocabulary |
| Temporal realism | 8/10 | Ordering and inter-source delays are generally plausible; no lifecycle inversion was found |
| Cross-source correlation | 8/10 | Excellent tuple, service, session, process, and file continuity, reduced by two ownership gaps |
| Behavioral and tradecraft realism | 8/10 | Coherent intrusion phases and cleanup, though dense and intentionally huntable |
| Environmental noise | 9/10 | Rich routine, failed, suspicious, user, service, web, DNS, and network activity |
| Distribution texture | 7/10 | Good overall variation, with exact Linux command reuse across unrelated hosts |
| Collection plausibility | 7/10 | Broad but heterogeneous coverage; key remote initiators are absent where target evidence is unusually complete |
| **Overall realism** | **8/10** | Convincing and technically feasible, with soft construction artifacts rather than decisive contradictions |

## Recommendations

If this dataset is synthetic, improve the two source-to-target ownership contracts rather than adding
more evidence overall. For the WMI pivot, emit or preserve the actual source-side client process,
principal, credential context, and source port, then make the target WMI execution inherit a traceable
remote-session identity. For the APP-to-file-server relay, attach the outbound SMB flow and source
file read to the responsible process and account, and preserve that identity through the receiving SMB
session.

Increase per-host and per-person command diversity. Shared runbooks are realistic, but exact command
strings should recur according to role, team, shell history, and task context rather than appearing as
a broadly reusable host-independent pool. Keep some genuine repetition for scheduled tasks and common
operational procedures.

Preserve the existing strengths: source-native timestamp offsets, complete local process/session
lifecycles, target-side service semantics, transport-authentication ordering, realistic connection and
DNS failures, and abundant non-attack activity. Do not make the attack less correlated merely to appear
real; make correlation emerge from accountable initiating actions and allow realistic collection gaps
to occur coherently at sensor or lifecycle boundaries.
