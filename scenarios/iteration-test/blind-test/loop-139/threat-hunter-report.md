# Threat Hunter - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

The dataset is highly coherent and operationally useful, with strong multi-source pivots and realistic attack progression. I judge it synthetic because several source-native details look generated rather than organic, especially recurring proxy user-agent/domain mismatches in OEM update traffic and patterned "human typo" artifacts in shell histories.

## Evidence For Synthetic

- `PROXY-01/proxy_access.log` repeatedly pairs OEM updater domains with the wrong updater user-agent, which looks like independent random selection from pools: Dell hosts with `HP+Image+Assistant` or `Lenovo+System+Update`, Lenovo hosts with `Dell+Command+Update/5.1`, and HP CAB URLs with Dell updater UA.
- Specific examples: `2024-03-18T12:11:31Z` `dellupdater.dell.com` with `HP+Image+Assistant`; `12:22:31Z` `download.lenovo.com` with `Dell+Command+Update/5.1`; `13:07:44Z` `hpia.hpcloud.hp.com/...platformList.cab` with `Dell+Command+Update/5.1`; `17:37:40Z` `dellupdater.dell.com/CatalogPC.cab` with `Lenovo+System+Update`.
- Bash histories contain many isolated nonsense commands that resemble synthetic typo injection rather than normal operator history: `systemclt`, `ccat`, `lodale`, `ipp`, `jd`, `cind`, `lw`, `fre`, `grouos`.
- Linux `syslog.log` session activity has a patterned feel: many `systemd-logind` "New session" records for `root`, `admin`, and `ubuntu`, with fewer visible removals and limited accompanying authentication context. The slice-of-time caveat weakens this as evidence, but the repetition across hosts feels manufactured.
- The intrusion storyline is very clean and training-like: recon, credential dumping, PsExec, domain admin creation, service persistence, scheduled task, C2, archive staging, and exfiltration all appear in a compact six-hour window with few dead ends.

## Evidence For Real

- The attack chain is technically coherent across sources. `WS-AJOHNSON-01` shows domain recon and `ms-index-service.exe` accessing `lsass.exe`; `DC-01` then shows PsExec-style service creation, `svc_mhsync` creation, Domain Admins membership, persistence, and cleanup.
- File exfiltration pivots line up well: `FILE-SRV-01` creates `C:\ProgramData\Microsoft\cache_7f3a.zip`, Zeek sees SMB transfer of that archive to `10.10.1.35`, and `PROXY-01/proxy_access.log` records a large POST to `https://api.westbridge-services.net/upload/telemetry/7f3a2b19`.
- The DB path is plausible: `DB-PROD-01` bash/eCAR show `mysqldump`, `gzip`, and `scp`; `APP-INT-01` syslog shows SSH from `10.10.4.10`; Zeek records the SSH transfer with matching direction and byte scale.
- Background noise is varied: DHCP renewals, proxy auth failures, web scans, UFW blocks, Snort alerts, HTTP 404/403/429/500 responses, package-manager/systemd activity, and normal user browsing.
- I did not find a hard impossible visible ordering inside the observed window.

## Detailed Analysis

**Orientation and Scope**

The data covers roughly `2024-03-18T12:00:00Z` through early evening, with host logs extending slightly past the main network capture window. Sources include Windows Security XML, Sysmon XML, eCAR JSON, Linux syslog, bash history, proxy logs, web access logs, Cisco ASA, Snort, and Zeek `conn`, `dns`, `http`, `ssl`, `files`, `x509`, `dhcp`, and `ocsp`.

The environment appears to include Windows workstations, a domain controller, file server, Linux app/db/web/proxy systems, a DMZ, and perimeter sensors. IP/host identity is internally consistent, for example `WS-AJOHNSON-01` as `10.10.1.35`, `DC-01` as `10.10.2.10`, `FILE-SRV-01` as `10.10.2.20`, `WEB-EXT-01` as `10.10.3.10`, `PROXY-01` as `10.10.3.20`, and `DB-PROD-01` as `10.10.4.10`.

**Attack Storyline Coherence**

The core intrusion is credible. On `WS-AJOHNSON-01`, Windows logs show discovery commands around `15:19Z-15:20Z`: `whoami /all`, `net user /domain`, `net group "Domain Admins" /domain`, and `net view /domain`. Around `15:44Z`, `ms-index-service.exe` runs with Mimikatz-like arguments and Sysmon records access to `lsass.exe` with `GrantedAccess=0x1FFFFF`.

On `DC-01`, PsExec-style execution follows: `C:\Windows\PSEXESVC.exe` is created at about `16:00:16Z`, service execution follows, and a test command `cmd.exe /c whoami && hostname` runs under that service context. At `16:15Z`, `svc_mhsync` is created and added to Domain Admins. At `16:20Z`, `DeviceSyncSvc` service and a scheduled task are created. Later, PowerShell downloads from `api.westbridge-services.net`, and `wevtutil cl Security` appears shortly after.

**Exfiltration and Pivot Feasibility**

The file theft path is one of the strongest realism points. `FILE-SRV-01` shows `Compress-Archive` targeting finance and patient export paths into `C:\ProgramData\Microsoft\cache_7f3a.zip`. Zeek `files.json` records SMB movement of that same archive from `10.10.2.20` to `10.10.1.35`, with size around 313 MB. `PROXY-01` then records a large POST to `api.westbridge-services.net`, with client bytes around 314 MB and a duration of about 6.4 seconds.

The database staging path also works: `DB-PROD-01` history/eCAR shows `mysqldump`, compression, and `scp` to `10.10.2.30`; `APP-INT-01` shows SSH acceptance and a file create under `/tmp/.cache/`; Zeek shows SSH from `10.10.4.10` to `10.10.2.30`. That is the kind of cross-source trail a hunter could actually pivot through.

**Authenticity Concerns**

The biggest authenticity break is the proxy updater traffic. Real enterprises absolutely have mixed OEM tooling, stale agents, and vendor drift, but individual HTTP requests should generally align: Lenovo System Update should not repeatedly fetch Dell catalogs, and Dell Command Update should not repeatedly request Lenovo or HP update metadata. The repeated mismatches suggest the generator selected a domain and user-agent from separate pools without binding them to a source-native software inventory.

The second concern is shell history texture. Real histories contain typos, but they usually have context: immediate correction, repeated muscle-memory mistakes, aliases, partial workflows, pasted commands, or operator-specific habits. Here, the invalid commands are short, isolated, and spread across unrelated users and hosts in a way that looks intentionally sprinkled.

## Realism Score by Category

- **Field format accuracy:** 7 - Most fields are well formed, but proxy OEM user-agent/domain mismatches are source-native realism failures.
- **Temporal patterns:** 7 - Event timing is varied and mostly plausible, though some attack stages are unusually clean and compressed.
- **Cross-source correlation:** 9 - Strong pivots across host, Zeek, proxy, firewall, and syslog with no impossible ordering found.
- **Behavioral realism:** 7 - The intrusion tradecraft is credible, but the storyline is very textbook and the shell-history noise feels artificial.
- **Environmental consistency:** 6 - Host/IP/service mapping is consistent, but updater traffic and Linux session patterns weaken the environment's organic feel.

## Recommendations

- **P1:** Bind software updater domains, paths, and user-agents to a per-host OEM/software inventory so Dell, Lenovo, and HP update traffic remains source-native.
- **P2:** Replace isolated bash typo injection with realistic command-history sequences: failed command, correction, repeated habits, aliases, pasted workflows, and user-specific style.
- **P2:** Improve Linux session accounting by tying `systemd-logind`, PAM, SSHD, sudo, cron, and service sessions to clearer causal sources.
- **P3:** Add more investigative messiness to the attack path: failed attempts, operator delays, alternate commands, access denials, and incomplete cleanup.
- **P3:** Revisit large exfiltration timing and throughput distribution so big uploads include more varied proxy/network behavior.
