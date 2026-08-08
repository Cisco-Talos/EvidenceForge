# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment: Synthetic**

**Verdict Confidence: 98/100**

**Synthetic-Confidence Score: 96/100**

## Executive Summary

The endpoint corpus is confidently synthetic. This conclusion is not based on sanitized names, source coverage, cross-source completeness, filesystem metadata, or the cleanliness of the apparent narrative.

Two independently decisive defects dominate the assessment:

1. Windows inbound Event 5156 records systematically insert the remote client’s PID into the receiving host’s `ProcessID` field while naming the receiving application. Across 3,029 tuple-matched inbound connections, 2,972 Event 5156 PIDs equal the remote endpoint’s eCAR PID, while 2,528 disagree with the receiving endpoint’s local eCAR PID.
2. Linux process PIDs are effectively a mathematical function of wall-clock time: exactly two PIDs per second on both servers for six hours, with regression \(R^2 > 0.99999999\). Real PID allocation advances on process creation, not elapsed time.

A third substantial defect is the accumulation of concurrent instances of singleton Windows services: 74 captured `svchost.exe` starts have no termination in Security, Sysmon, or eCAR, producing 56 simultaneously live instances across 21 duplicate service-command groups.

The corpus otherwise demonstrates excellent correlation engineering. Security 4688, Sysmon 1, and eCAR process records generally agree; process GUID and actor lifetimes are coherent; hashes are stable by image/version; and SSH/RDP transport evidence precedes same-source session evidence. These strengths make the data useful for correlation exercises, but they do not outweigh the concrete host-semantic contradictions.

## Evidence For Synthetic

- **[hard_contradiction] Remote PID leakage into receiving Windows Event 5156 records.** Of 3,029 inbound TCP/UDP events with matching local and remote eCAR FLOW observations, 2,972 Event 5156 `ProcessID` values matched the remote source process PID. In 2,528 cases, that PID disagreed with the receiving host’s local socket owner.

  A representative three-way contradiction is visible for `10.44.30.10:62142 → 10.44.20.20:445`:

  - `WEB-BO-01` eCAR at `2024-05-14T12:01:00.809Z`: outbound `/usr/sbin/rsyncd`, PID `303504`.
  - `FILE-BO-01` eCAR at `12:01:00.489Z`: inbound `System`, local PID `4`.
  - `FILE-BO-01` Security 5156 at `12:01:00.5406366Z`: `Application=System`, but `ProcessID=303504`.

  The receiver record combines the receiver image with the sender PID. The same defect occurs on the DC: for `10.44.10.25:50320 → 10.44.20.10:53`, source eCAR identifies PID `4952`/`svchost.exe`, receiver eCAR identifies PID `5656`/`dns.exe`, while the DC’s 5156 names `dns.exe` but records PID `4952`.

- **[distribution_texture] Linux PID allocation is tied almost exactly to elapsed time.**

  - `WEB-BO-01`: 151 eCAR PROCESS CREATE records; slope `1.999992` PIDs/second; \(R^2=0.9999999931\); maximum regression residual `4.73` PIDs.
  - `PROXY-BO-01`: 55 records; slope `1.999991` PIDs/second; \(R^2=0.9999999923\); maximum residual `5.60` PIDs.

  The sysstat CRON rows make the defect directly visible. On `PROXY-BO-01`, every 30-minute run from `12:01` through `17:31` advances the PID by exactly `3,600`, such as PID `1247787` at `12:01` and `1251387` at `12:31`. A real kernel PID counter advances according to actual forks/clones, whose rate varies with workload.

- **[contract_gap] Singleton Windows services accumulate impossible parallel instances.** Across the seven Windows systems, 74 `svchost.exe` starts appear in Security 4688, Sysmon 1, and eCAR, but none has a corresponding termination in Security 4689, Sysmon 5, or eCAR. This produces 56 still-live instances in 21 duplicate singleton-service command groups.

  On `DC-BO-01`, the capture contains:

  - Six concurrent `svchost.exe -k netsvcs -p -s wuauserv` instances.
  - Six concurrent `... -s LanmanServer` instances.
  - Four `CryptSvc`, three `Schedule`, three `BITS`, two `Winmgmt`, and two `AppXSvc` instances.

  The first captured `wuauserv` starts at `12:15:47` and remains unterminated while five more are started through `17:37:12`. Repeated, cross-source omission of every termination combined with duplicate singleton starts is more than selected Sysmon coverage alone.

- **[environment_or_collection_plausibility] Endpoint application concurrency resembles independent random spawning rather than stateful desktop use.** `WS-OREED-01` reaches five simultaneous `PanGPA.exe` processes at `14:34:47` and three simultaneous AnyConnect `vpnui.exe` processes at `14:22:21`, all under Owen Reed’s session. The same host also runs Zscaler client processes. Multiple installed VPN products are possible, but repeated overlapping launches of nominally singleton GUI clients are not credible normal endpoint state.

- **[distribution_texture] Service and updater lifetime texture is excessively repetitive.** `AdobeARMservice.exe` is repeatedly launched and terminated on multiple workstations—six times on `WS-NKAPOOR-01`, three on `WS-MPATEL-01`, three on `WS-OREED-01`, and four on `WS-VHALE-01`, often surviving only seconds or minutes. The behavior repeats as a generic activity motif rather than reflecting a stable service lifecycle.

- **[weak_signal] Human command texture is unusually curated.** The two bash histories contain 53 timestamped commands dominated by syntactically clean diagnostic checks and no visible corrections or malformed attempts. This is only a weak signal and was not used as a primary basis for the verdict.

## Evidence For Real

The following are meaningful realism strengths, though complete matching is not treated as proof of authenticity:

- Parsed scope includes 10,325 Security events, 3,609 Sysmon events, 17,028 eCAR records, 2,247 syslog rows, and 53 timestamped bash-history commands over roughly six hours.

- There are 713 Security 4688 ↔ Sysmon 1 matches within 141 milliseconds. All 713 agree on child PID/image, parent PID/image, command line, user, and LogonID.

- Sysmon contains 497 in-window process create/terminate pairs. Every pair preserves ProcessGuid, PID, image, and user, with no termination preceding creation and no duplicated termination GUID.

- Across 714 Sysmon process creates, the corpus contains 90 image/version groups and no group has inconsistent hashes. Every hash field has correctly formed SHA1, MD5, SHA256, and IMPHASH values.

- In eCAR, 1,807 dependent records resolve to captured source-process objects without PID, image, principal, or lifetime disagreement. A further 403 FLOW records with captured actors all occur inside the actor process lifetime.

- Linux SSH semantics are well ordered. All 44 successful SSH/PAM opens—34 on `WEB-BO-01`, ten on `PROXY-BO-01`—have matching inbound eCAR FLOW tuples preceding PAM session opening by approximately 1.0–3.36 seconds. Source IP, source port, sshd PID, PAM user, and logind session identifiers remain coherent through closure.

- All eight modeled Windows RDP logins have matching same-host eCAR FLOW evidence before the eCAR USER_SESSION login, by 12–1,776 milliseconds.

- Background coverage is varied: Defender scans and signature updates, UsoClient, TiWorker, GPO refresh, search processes, WMI, COM, scheduled tasks, Linux cron/anacron, unattended upgrades, logrotate, PAM, logind, and resolver activity all appear with plausible field formatting.

## Detailed Analysis

**Windows process and session lifecycles.** The basic process contract is strong. Security 4688 and Sysmon 1 agree almost perfectly, including hexadecimal/decimal PID translation. User processes reference visible logon sessions and do not execute before login or after logout. Cross-token process creation through services and brokers also retains consistent child user and LogonID metadata. The principal defect is higher-level state: service creation is represented accurately at each source, but the modeled service lifecycle does not prevent additional starts while earlier singleton instances remain alive.

**Windows network actor identity.** Outbound 5156 observations are mostly correct: their PIDs agree with local eCAR actor PIDs. The defect is direction-specific. On inbound events, tuple direction and receiver application are correct, but `ProcessID` usually comes from the source endpoint. This is a classic source/destination ownership inversion at the canonical event-to-renderer boundary, not random corruption.

Per receiving host, local PID mismatches included:

- `DC-BO-01`: 2,292 of 2,435 paired inbound events.
- `FILE-BO-01`: 223 of 560.
- Workstations: 14 additional mismatches across the small inbound samples.

Many apparent matches on `FILE-BO-01` occur only because both endpoints use PID `4` for `System`; cross-host comparison still shows the receiver field following the source PID in 559 of 560 paired flows.

**Modules, files, registry, and process access.** Sysmon 7/10/11/13 fields are structurally plausible. Captured module and dependent eCAR records stay within process lifetimes. Process access events retain source/target GUIDs, PIDs, images, and access masks without observable temporal inversion. Module-load startup sequences and stable image hashes add substantial training realism.

**Windows logon texture.** The dataset contains service, interactive, unlock, network, and remote-interactive logons. Network sessions use plausible Kerberos/NTLM distinctions: Kerberos often has `WorkstationName=-`, while NTLM commonly records a workstation. Type 3 sessions have varied durations, and RDP source tuples match eCAR transport. Special-privilege events follow SYSTEM, LOCAL SERVICE, NETWORK SERVICE, and privileged Nina Kapoor sessions coherently.

**Linux PID and process modeling.** Parent/child relationships are internally coherent: shell commands reference the correct bash object, pipeline children share the shell parent, sshd children inherit the proper listener identity, and create/terminate object IDs agree. However, the global PID counter is not state-driven. Its nearly exact two-PID-per-second relationship persists across quiet and busy intervals and on both independent servers. This is an overwhelming deterministic-generation signature.

**Linux SSH/PAM/logind behavior.** Individual session chains are convincing: connection, accepted key/password, PAM open, logind session creation, PAM close, and logind removal are ordered correctly. Stable per-host SSH key fingerprints and varied session durations are realistic. Boundary-censored logouts at the start and open sessions near the end are handled plausibly.

**User and environment texture.** Nina Kapoor has a substantially richer command and remote-administration footprint than other users, and bash-history timestamps correspond to actual eCAR process launches. The weakness is not narrative linearity; it is state management. Desktop applications, VPN clients, updater services, and Windows services are repeatedly instantiated without sufficient awareness of already-running instances.

No penalty was assigned for absent System logs, selected Sysmon event types, thin optional coverage, sanitized names, or cross-source completeness by itself.

## Synthetic Indicator Summary

| Indicator | Label | Quantified observation | Weight |
|---|---|---:|---|
| Receiver 5156 uses remote PID | hard_contradiction | 2,972/3,029 inbound records equal remote PID; 2,528 disagree with local PID | Decisive |
| Linux PID equals elapsed time ×2 | distribution_texture | Two hosts; 206 creates; \(R^2 > 0.99999999\) | Decisive |
| Duplicate singleton services | contract_gap | 56 concurrent instances across 21 duplicate service groups | High |
| Concurrent VPN-client GUIs | environment_or_collection_plausibility | Five PanGPA and three vpnui instances on one user host | Medium |
| Repetitive service/updater respawning | distribution_texture | Recurrent short Adobe/service processes across multiple hosts | Medium |
| Curated command history | weak_signal | 53 clean diagnostic commands with little correction texture | Low |

## Realism Score by Category

Scores use 10 for highly realistic and 1 for poor realism.

| Category | Score | Assessment |
|---|---:|---|
| Field format accuracy | 6/10 | XML, GUIDs, SIDs, hashes, and event schemas are mostly strong; inbound 5156 process ownership is materially wrong. |
| Temporal patterns | 5/10 | Session and transport ordering is good, but Linux PID/time coupling and repeated service lifecycles are unmistakably artificial. |
| Cross-source correlation | 8/10 | Process, session, GUID, LogonID, hash, and FLOW correlation is excellent aside from the inbound PID ownership inversion. |
| Behavioral realism | 4/10 | Individual actions are plausible; service and application concurrency is not. |
| Environmental consistency | 6/10 | Host/user/IP/domain relationships are stable, but endpoint software and singleton-service state are insufficiently constrained. |

## Recommendations

1. Fix inbound network ownership before rendering Event 5156. Resolve `ProcessID` and `Application` from the receiving endpoint’s socket owner; preserve the remote PID only in an explicit remote-actor field.

2. Add a cross-host invariant test: for every inbound Windows 5156 record, the PID must resolve locally and match the receiving eCAR FLOW actor, never the outbound peer’s actor.

3. Replace time-derived Linux PIDs with a stateful allocator advanced only by modeled and stochastic background forks/clones. Include variable unobserved process churn, PID reuse, and wrap behavior.

4. Add a statistical regression gate that rejects PID streams with implausibly deterministic PID/time relationships or exact fixed increments across scheduled jobs.

5. Model Windows service state explicitly. A singleton service cannot start again until its earlier instance stops or fails. Emit correlated Security 4689, Sysmon 5, and eCAR termination evidence before a restart.

6. Add process-family constraints for endpoint applications. Distinguish legitimate helper/renderer roles by command line and parentage, and prevent duplicate singleton instances of `PanGPA.exe`, `vpnui.exe`, updater services, and similar agents.

7. Preserve the existing strengths: exact 4688/Sysmon parentage, stable hashes, LogonID correlation, eCAR actor-object linkage, and transport-before-session ordering.
