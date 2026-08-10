# Blind Threat Hunter Review — Loop 58

## Verdict

- **Verdict:** Inconclusive
- **Verdict confidence:** 74/100
- **Synthetic confidence:** 58/100

The evidence is coherent and unusually huntable, with enough mundane activity and cross-host continuity to resemble a curated enterprise collection. I would not confidently call it real, however. Repeated command/activity templates and several conspicuously synchronized attack steps give the collection a designed-exercise texture.

## Category scores

| Category | Score | Assessment |
|---|---:|---|
| Background enterprise realism | 77/100 | Broad host roles, user activity, authentication, DNS, proxy, mail, and service traffic create credible investigative noise. |
| Attacker tradecraft realism | 84/100 | Discovery, credential access, lateral movement, persistence, exfiltration/staging, and cleanup use recognizable operator techniques. |
| Temporal and causal coherence | 88/100 | Most process, session, and network evidence can be ordered into defensible causal chains. |
| Cross-source correlation | 90/100 | Endpoint, Windows, Linux, Zeek, proxy, firewall, and IDS evidence provide useful independent pivots. |
| Huntability | 94/100 | The principal intrusion can be reconstructed with high confidence without privileged context. |
| Natural variation / resistance to templating | 61/100 | Repeated exact commands and unusually tidy attack choreography remain visible at corpus scale. |

## Concrete evidence

### Strong realism signals

1. **A coherent credential-access chain exists on WS-AJOHNSON-01.** At 15:45:20 UTC, `ms-index-service.exe` runs with `privilege::debug` and `sekurlsa::logonpasswords`; it subsequently opens `winlogon.exe` and `lsass.exe`, including `0x1FFFFF` access to LSASS, followed by a remote-thread event. The same host and user later initiate RDP sessions to FILE-SRV-01, DC-01, and MAIL-FIN-01. These are strong, causally connected hunting pivots rather than isolated indicators.

2. **The DC compromise has source-native depth.** At 16:15 UTC, `cmd.exe` under `WmiPrvSE.exe` launches `net.exe` to create `svc_mhsync` and add it to Domain Admins. At 16:20, the same execution lineage creates `DeviceSyncSvc`, with a corresponding service-create record. Later, encoded PowerShell connects through the proxy while `wevtutil cl Security` executes, and the account is deleted at 17:49. The sequence supports identity, process-tree, persistence, network, and anti-forensics hunts.

3. **SSH evidence generally supports multi-host pivots.** Around 14:14:22–14:14:52, WS-MCHEN-01 creates `ssh.exe`, connects from 10.10.1.31 to MAIL-CLIN-01:22, and the receiver exposes an `sshd` child plus a user-session login. Around 14:15, proxy-originated SSH to APP-INT-01 is visible to both endpoint and network/IDS sources. These chains are operationally useful.

4. **The background is not merely random filler.** Machine-account authentication, brief SMB sessions, DNS resolver traffic, proxy use, mail activity, browser/module startup, Defender access, service health checks, and Linux scheduler/package/service messages are distributed by host role and provide plausible competing explanations for many detections.

### Synthetic or curated-exercise signals

1. **Some attack actions are synchronized too neatly.** On DC-01, encoded PowerShell starts at 17:41:52.600 and a separate `cmd.exe /c wevtutil cl Security` starts at 17:41:52.602—two milliseconds later, from different long-lived parent processes. The encoded-PowerShell flow follows at 17:41:52.809. That almost simultaneous download/anti-forensics staging looks authored rather than like an operator interacting with a host.

2. **Exact command templates recur at conspicuous volume.** Examples include 47 identical `smbclient //FILE-SRV-01... -c 'ls'` commands, 43 corresponding DC commands, 55 identical Chrome OneNote launches, 51 identical Outlook `/recycle` launches, and repeated identical proxy `curl`/`wget` forms. The timing varies, but the command vocabulary is narrower and cleaner than a real multi-user estate normally produces.

3. **The principal storyline is exceptionally complete.** Reconnaissance, credential access, RDP/SSH movement, domain-account creation, Domain Admin membership, service persistence, encoded download, log clearing, and cleanup are all represented with high-fidelity evidence in a single six-hour window. This is excellent training data, but the density and completeness reduce the chance that the corpus is an ordinary production capture.

4. **Some remote-administration background is aggressive.** Numerous users initiate RDP or SMB sessions among workstations, servers, and the DC, while Linux hosts repeatedly enumerate Windows shares. Individual events are plausible, but the aggregate prevalence makes lateral movement less discriminating and feels intentionally designed to supply red herrings.

## Likely hunt reconstruction

The highest-confidence intrusion path begins with activity under `aisha.johnson`, progresses through suspicious discovery and credential access on WS-AJOHNSON-01, uses remote interactive/admin access to reach sensitive servers and DC-01, creates `svc_mhsync`, grants Domain Admin membership, installs `DeviceSyncSvc`, performs encoded outbound retrieval through the proxy, clears the Security log, and finally deletes the temporary account. SSH/SCP activity involving APP-INT-01 and DB-PROD-01 provides a second investigation branch around staged database material.

## Recommendations

1. Add per-actor command-shape variation: quoting styles, host notation, option ordering, shell wrappers, working directories, and alternate legitimate tools.
2. Avoid near-simultaneous independent attack steps unless a shared automation mechanism is also evidenced. Introduce human dwell time and occasional failed/retried commands.
3. Reduce or role-constrain routine RDP, SSH, and `smbclient` activity so malicious lateral movement remains challenging without requiring ubiquitous red herrings.
4. Preserve the strong cross-source pivots, but introduce realistic collection gaps and partial chains at the storyline level rather than making every major technique fully observable.
5. Expand benign user-specific behavior so each persona has a more distinctive application, file, and network footprint over the day.
