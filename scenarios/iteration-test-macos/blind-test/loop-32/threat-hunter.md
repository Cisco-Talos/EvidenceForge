# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 92
**Synthetic-Confidence Score:** 72

## Executive Summary

The collection supports useful, technically coherent hunting across Windows, Linux, macOS, network sensors and an explicit proxy. The strongest authenticity defect is a repeated timing fingerprint in native macOS Endpoint Security records: separate shell commands share exactly the same six fractional timestamp digits in many batches, while every observed inventory process lives exactly two seconds; a successfully authenticated interactive SSH session also has implausibly small client packet accounting.

## Evidence For Synthetic

- [distribution_texture] Native ES shell forks repeatedly preserve the exact fractional second across commands separated by tens of seconds. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 32, 35 and 38 fork PIDs 46145, 46192 and 46270 at `13:48:48.715405`, `13:49:18.715405` and `13:50:08.715405` UTC. Lines 49/52/55 repeat this pattern with `.314210`. Across both Macs, 35 of 55 `/bin/zsh`-parent fork notifications fall into 15 repeated-fraction groups. These are distinct processes, not duplicate exports of the same event. This is a strong scheduling fingerprint in event timestamps advertised at nanosecond precision.
- [distribution_texture] All six native ES inventory lifecycles have a fork-to-exit duration of exactly `2.000000` seconds, including the intervening xpcproxy and sw_vers execs. On MAC-MROSS-01, lines 28–31 are `13:30:38.076617` to `13:30:40.076617`; lines 62–65 and 123–126 do the same. On MAC-MROSS-02, lines 31–34, 96–99 and 131–134 repeat the exact duration. A scheduled inventory job is credible; six executions having exactly equal microsecond-level total lifetimes is not normal process timing texture.
- [contract_gap] `zeek-core/conn.json:6280`, UID `CUtuaJTtO20AlrI3YDD`, records a fully established, cleanly closed SSH connection from `10.10.1.42:59676` to `10.10.1.41:22`, lasting `970.324344` seconds, with only **5 originator packets**, `orig_bytes=2559`, `missed_bytes=0`, and history `ShADadfF`. This is the same tuple as MAC-MROSS-02's interactive `ssh -tt` client (`ecar.json:337`) and MAC-MROSS-01's inbound flow (`ecar.json:236`), followed by public-key acceptance and an actual remote shell/command. Five client packets do not credibly cover a fresh SSH transport, key exchange, user authentication, channel establishment, command use and clean close. This appears to be transport accounting disconnected from the application activity. I treat capture omissions as a possible alternative, so this is a contract gap rather than claiming an absolute packet-level impossibility from aggregate logs alone.
- [weak_signal] MAC-MROSS-01 native ES lines 100–102 show the remote `/usr/bin/id` PID 64517 forked at `16:03:37.361989`, execed at `16:03:37.375353`, and exiting at `16:05:02.362989`: an `85.001`-second lifetime for a simple identity query. Directory-service blocking could explain an individual slow command, so this receives little weight by itself.

## Evidence For Real

- `runas /netonly` is modeled with the correct identity distinction. `WS-AJOHNSON-01.meridianhcs.local/ecar.json:1096` runs `/netonly /user:marcus.chen`; its descendants remain local principal `aisha.johnson`. The workstation Security 4624 at `18:00:40.6779064Z` has Type 9, target local identity Aisha and `TargetOutboundUserName=marcus.chen`. FILE-SRV-01's Security 4624 at `18:01:05.9090327Z` authenticates Marcus from `10.10.1.35:54910`, with the following 5140/5145 records using the same server LogonID `0xf8858ba`. This avoids a common credential-ownership mistake.
- The Linux dump and transfer trail works across sources: DB-PROD-01 root history lines 1–6 contains the dump redirection, gzip and scp; eCAR lines 503–514 supplies matching processes/files/transport. APP-INT-01 syslog lines 217–222 supplies public-key acceptance, PAM session open/close and logind registration/removal for source port 51478. The network tuple is visible at `zeek-core/conn.json:10512` and `zeek-db/conn.json:342` with slightly different sensor timestamps and UIDs.
- The visible source mix is varied and role-sensitive. DCs are dominated by authentication and network activity; the web server and proxy have much larger network-oriented streams than ordinary endpoints. The collection includes failed authentications, background services, periodic health work, browser helper processes and scan-like traffic alongside suspicious actions.
- macOS records distinguish ES fork, exec and exit, preserve same-PID exec transitions, and expose xpcproxy/Terminal/login/zsh and sshd helper relationships. The policy message about MeetingAssist is not followed by a matching successful execution in the inspected native ES data; I did not infer execution from the policy message.
- I checked all 23 eCAR streams for referenced process activity later than that same process identity's visible termination and found no such violations. This does not prove every lifecycle is complete, but it is positive evidence of internal operational coherence.

## Detailed Analysis

### Orientation and collection scope

The endpoint data covers 23 hosts: ten Windows hosts, eleven Linux hosts and two Macs, with workstation, domain-controller, file-server, mail, proxy, web, application and database roles. The endpoint time range is `2026-11-02 13:00:01.077` through `18:59:52.211` UTC. Visible addresses separate client (`10.10.1.*`), server (`10.10.2.*`), DMZ/proxy (`10.10.3.*`) and database (`10.10.4.*`) activity.

Sources include 23 normalized eCAR streams, Windows Security/Sysmon XML, Linux syslog and histories, two native ES streams and selected Unified Log records, three Zeek sensors, perimeter ASA, two Snort sensors, proxy and web access logs. There are 18,945 Windows Security events and 11,789 Sysmon events. The three Zeek conn files contain 11,927 core, 9,167 DMZ and 379 database rows; the proxy has 3,387 access rows and ASA 21,990 lines. These are sufficient background volumes to require pivots rather than treating every record as attack evidence. I do not penalize sources simply for being thin or absent.

### Hunt pivots and operational coherence

The web pivot begins with `WEB-EXT-01.meridianhcs.local/web_access.log:501`: external `185.70.41.45` posts to `/ehr/admin/upload.php` at `14:19:57` UTC. The adjacent host evidence is `ecar.json:923`, a www-data bash command decoding an encoded shell command. `zeek-dmz/conn.json:1498` then records `10.10.3.10:37640 -> 45.33.32.30:8443` at epoch `1793629201.694975`. This is technically plausible timing for web execution followed by outbound shell transport. I do not score the ease of narrating that trail as an authenticity defect.

On DC-01, eCAR lines 3711/3718 execute `net user svc_dirsync ... /add /domain`, followed by lines 3734/3741 executing the Domain Admins addition. Native Security 4720 at `17:14:49.3063276Z` and 4728 at `17:14:53.8569773Z` contain consistent account SID `...-5272` and group SID `...-512`. Service creation and task registration have corresponding native 4697/4698 records. The task's embedded XML parses; I found no basis to call that content malformed.

For collection and exfiltration, workstation eCAR lines 1117–1192 show folder creation, named-share enumeration/copying, and archive creation. The outbound identity is Marcus despite locally running as Aisha, as noted above. Workstation eCAR lines 1330–1339 then show curl reading the archive and connecting through `10.10.3.20:8080`. `PROXY-01.meridianhcs.local/proxy_access.log:2908` reports the corresponding POST at `18:24:40`, including `cs_bytes=18783022`, `proxy_action=ssl-inspect`, and a tunnel identity. `zeek-dmz/conn.json:8309` shows the proxy's approximately 18.8 MB external transfer. The direction and scale are sensible, and the extra wire bytes are not themselves contradictory.

The DB dump does not have a missing-redirection problem: the process command line excludes shell syntax, while root bash history line 2 explicitly includes `> /tmp/rpt_0318.sql`. Likewise, an observed file creation is not enough by itself to establish all its contents; I follow the visible read/copy/transport evidence without inventing unseen effects.

### Native macOS timing and SSH accounting

The repeated-fraction result was calculated only from records whose event is `fork` and whose parent executable is `/bin/zsh`, separately within each native ES file. MAC-MROSS-01 has 26 such forks, with 16 in seven repeated-fraction groups. MAC-MROSS-02 has 29, with 19 in eight groups. For example, MAC-MROSS-02 lines 120/123/126 fork distinct commands at `17:32:54.495937`, `17:33:42.495937` and `17:34:30.495937`. This happens across local and remote command contexts, while individual exec/exit records carry other subsecond values. It is not simply a whole-stream timestamp-resolution limitation.

The six inventory samples provide a second, related timing fingerprint: native fork-to-exit time is always exactly two seconds despite varying start fractions and intervening exec transitions. Automation can create regular cadence, but the kernel-observation lifetimes and independent shell starts would normally contain scheduling and execution jitter.

The low-packet SSH case can be followed into native data. MAC-MROSS-01 Unified Log line 3 reports public-key acceptance from `10.10.1.42:59676` at `16:01:54.585527`. Its ES lines 83–97 show the receiving sshd lineage and eventual remote zsh; lines 100–102 show the remote id command. MAC-MROSS-02 ES lines 103–104 show the `ssh -tt` client and line 108 its exit. This establishes that the Zeek row is not merely a completed TCP probe labeled as SSH. Capture loss or aggregation might explain one accounting anomaly, but that explanation is not positively present in the row.

### Limits and counterevidence

I found no demonstrated same-identity post-exit activity in eCAR and no necessity to invent missing audit sources, pre-window processes or post-window closure. I did not use domains' external resolvability, filesystem timestamps, narrative linearity, clean attacker execution or complete cross-source alignment to score authenticity. The verdict is driven primarily by native timing texture, supported by transport/application accounting and only lightly by the slow id process. It is not a claim that every source is poor or that the intrusion trail is technically unusable.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| distribution_texture | Native macOS ES | 35/55 zsh-parent fork notifications, 15 groups across two hosts | Distinct command starts repeatedly preserve six identical fractional digits across integer-second separations. Strongest indicator. |
| distribution_texture | Native macOS ES | All six inventory runs on both hosts | Exact two-second total lifetime through multiple exec transitions is an independent timing fingerprint. |
| contract_gap | Zeek + native macOS ES/Unified Log + eCAR | One established interactive SSH session, tuple `10.10.1.42:59676 -> 10.10.1.41:22` | Only five client packets for visible SSH auth, shell activity and clean close; application complexity and network accounting disagree. |
| weak_signal | Native macOS ES | One remote id process | 85-second lifetime is unusual but potentially explained by directory-service delays; minimal score impact. |

## Realism Score by Category

- **Field format accuracy:** 9 — Structured records parse, source identities and native process structures are largely credible; no demonstrated widespread format defect.
- **Temporal patterns:** 4 — Repeated exact fractional starts and six exact inventory lifetimes expose strong timing texture despite otherwise varied activity.
- **Cross-source correlation:** 8 — Credential identity, SMB, DB transfer and proxy pivots work well; SSH packet accounting weakens one important lifecycle.
- **Behavioral realism:** 8 — Commands, credential boundaries and host roles mostly support technically plausible hunting.
- **Environmental consistency:** 8 — Role-sensitive source volumes and mixed-fleet background activity are credible within the bounded six-hour collection.

## Recommendations

- If this were synthetic, independently vary native command-start timing within a burst rather than carrying one fractional timestamp across all commands separated by integer seconds.
- If this were synthetic, vary the actual fork/exec/run/exit durations of inventory work; regular scheduling need not produce identical total process lifetimes to microsecond precision.
- If this were synthetic, derive SSH transport packet accounting from the modeled handshake, authentication, channel and command phases, preserving a plausible lower bound for successful interactive sessions. If capture loss is intended, make that collection condition explicit and internally consistent.
- If this were synthetic, avoid assigning a long arbitrary session-sized duration to a short identity command unless supporting evidence shows a real blocking condition; retain realistic variation for genuinely long-running commands.
