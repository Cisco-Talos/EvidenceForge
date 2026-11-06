# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 53

## Executive Summary

The six-hour window (2026-11-02 13:00–18:59 UTC) contains a coherent, cross-source intrusion-like trail, including internal discovery, root SSH access, persistence on two Macs, and an EHR database export staged through APP-INT-01 to a file share. Those actions are suspicious, but their completeness and narrative clarity are not authenticity evidence by themselves. I found one moderate synthetic tell: both Macs receive the same root LaunchDaemon label and run the same minimal `sw_vers` job on a roughly two-hour cadence; that could also be a real fleet-management deployment, so I cannot confidently distinguish real from synthetic from these logs alone.

## Evidence For Synthetic

- [distribution_texture] The same root-created `/Library/LaunchDaemons/com.meridianhcs.endpoint-inventory.plist` appears on both `MAC-MROSS-01` and `MAC-MROSS-02` within about a minute (eCAR on MAC-MROSS-01 line 37 at 13:21:37; MAC-MROSS-02 line 33 at 13:22:34). On each endpoint the job launches only `/usr/bin/sw_vers` from a root `xpcproxy` instance, then repeats around two-hour intervals (MAC-MROSS-01 lines 48, 208, 439; MAC-MROSS-02 lines 66, 235, 405). This unusually neat, repeated persistence artifact is a possible templated fixture. The name and common deployment could also be legitimate endpoint inventory software, so it is not decisive.
- [weak_signal] On both Macs the visible installer process is only `/bin/sh`, and the available ES rows around installation show fork/exec activity rather than an explicit file-write or launch-registration notification. The evidence is split across eCAR and ES; the limited Unified Log excerpts (three rows on MAC-MROSS-01 and two on MAC-MROSS-02) do not independently explain the job's registration. This may reflect collection selection, but it makes the persistence lifecycle less independently verifiable.

## Evidence For Real

- The high-impact data movement pivots agree across endpoint, authentication, and network records. `DB-PROD-01` eCAR lines 670–678 show `mysqldump --single-transaction ehr patients insurance_claims`, gzip, then `scp` of `/tmp/rpt_0318.sql.gz` from `10.10.4.10:54865` to `10.10.2.30:22`. Zeek DB line 441 records that same tuple as an established SSH flow with 126,136 originator bytes. `APP-INT-01/syslog.log` lines 223–226 records public-key root authentication from `10.10.4.10:54865`, session open and close; APP-INT eCAR lines 740 and 745 record creation and later read of `/tmp/.cache/rpt_0318.sql.gz`. At 18:19, Zeek core `smb_files.json` lines 189–190 records that named archive written to `\\FILE-LNX-01\ClinicalResearch\Integration\DB-Staging`, and `FILE-LNX-01` eCAR line 1306 records the matching destination file write by `svc_mhsync`.
- WEB-EXT discovery and remote access also line up. `WEB-EXT-01` eCAR lines 989 and 1426 record `nmap -sn 10.10.2.0/24` and `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24`; line 1506 shows the failed TCP/22 probe to APP-INT (`10.10.2.30`). A later flow from `10.10.3.10:47058` to `10.10.2.30:22` is recorded at WEB-EXT eCAR line 2651 and by `APP-INT-01/syslog.log` lines 127–129 as a root password login and opened session. Zeek core line 4995 and Snort core/perimeter line 17/26 also see this tuple; the long Zeek connection ends within the visible window. The source and destination roles are consistent with internal discovery followed by lateral access.
- A later root session from `WS-EBROOKS-01` (`10.10.1.33`) to WEB-EXT is visible in WEB-EXT eCAR lines 3992–3997 and `WEB-EXT-01/syslog.log` lines 1224–1226. The session launches `shred -u /root/.bash_history`; its close appears at syslog line 1292. This is concrete cleanup activity and follows the logged root SSH lifecycle.
- Baseline evidence is not limited to attack events: Linux system processes and service traffic, Windows Security/Sysmon records, user shell histories, SMB activity, DNS, proxy, TLS and external scan noise appear across the window. For example, the proxy, firewall and Zeek data include routine web activity alongside failed inbound probes, so the suspicious events are not the only records in the environment.
- On macOS, the observed source formats are distinguishable and generally agree on process transitions. The ES records include version 11 fork/exec events and audit-token identities; eCAR shows Terminal/zsh child commands matching Maya Ross's timestamped zsh history. The sparse Unified Log entries are not enough to infer missing platform artifacts.

## Detailed Analysis

### Scope and collection

The supplied data covers a mixed fleet: Windows workstations and domain controllers with Security, Sysmon and eCAR; Linux servers and workstations with syslog, shell histories and eCAR; two macOS endpoints with Endpoint Security, Unified Log, zsh history and eCAR; and Zeek, proxy, firewall and Snort sources. The useful activity window is roughly six hours on November 2, 2026. Host and source coverage varies, so I do not treat a source's absence as evidence unless a visible action requires its companion.

### Internal discovery and SSH access

At 14:40, WEB-EXT-01 runs two Nmap scans against `10.10.2.0/24` (WEB-EXT eCAR lines 989 and 1426). The second scan tests ports 22, 80, 443, 445 and 3306; the APP-INT SSH probe at line 1506 fails. At 15:15, WEB-EXT opens TCP `10.10.3.10:47058 → 10.10.2.30:22`. APP-INT's syslog records the connection at 15:15:06, accepts a root password at 15:15:13, and opens the session (lines 127–129). Zeek core line 4995 describes an established SSH session with a 13,316-second duration. This is a successful root foothold with long-lived access, not merely an IDS signature.

The session's activity is followed by a distinct root SSH login from `WS-EBROOKS-01` to WEB-EXT at 18:40 (WEB-EXT eCAR lines 3992–3997; syslog lines 1224–1226). The `shred -u /root/.bash_history` command is visible immediately after login. The log evidence supports root access and history removal; it does not establish how the WS-EBROOKS account obtained those credentials.

### macOS persistence

On both Macs, root `/bin/sh` creates the same LaunchDaemon path, `com.meridianhcs.endpoint-inventory.plist`. eCAR reports the first creation on MAC-MROSS-01 at 13:21:37 (line 37) and on MAC-MROSS-02 at 13:22:34 (line 33). Subsequent process transitions under the matching label show `xpcproxy` followed by `/usr/bin/sw_vers`, repeated several times per host (MAC-MROSS-01 lines 46–49, 206–208, 437–439; MAC-MROSS-02 lines 64–66, 233–235, 403–405). Both eCARs later record deletion of that plist (MAC-MROSS-01 line 529; MAC-MROSS-02 line 471). This is consistent with root persistence followed by removal, but an enterprise inventory agent is also plausible. The visible records do not show the plist contents or establish that deletion unloaded the job.

### Database collection and staging

At 18:15, root on DB-PROD-01 dumps `ehr`, `patients` and `insurance_claims` to `/tmp/rpt_0318.sql`, compresses it, and copies it by SSH to APP-INT-01 as `/tmp/.cache/rpt_0318.sql.gz` (DB-PROD eCAR lines 670–678; root bash history lines 1–6). The matching Zeek DB flow and APP-INT SSH authentication provide independent network and server-side confirmation. About three minutes later APP-INT reads the staged file and SMB writes it to the `ClinicalResearch/Integration/DB-Staging` share on FILE-LNX-01 (APP-INT eCAR line 745; Zeek core `smb_files.json` lines 189–190; FILE-LNX eCAR line 1306). The transfer path is technically coherent. The names, root access and sensitive table names make it high-priority suspicious activity, though the data does not by itself prove the export was unauthorized.

### Authenticity judgment

The strongest authenticity concern is the repeated, nearly identical Mac LaunchDaemon deployment and periodic command. That is a concrete repeated pattern, but it is also compatible with a real fleet agent and is not an impossible field or ordering. The scan, root access, cleanup, and data staging are all supported by source-specific fields and matching times; I do not score their clarity or completeness as synthetic evidence. I found no demonstrated contradiction in the central cross-source pivots. This leaves a realistic but not conclusive authenticity assessment.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | macOS eCAR, Endpoint Security | Both MAC-MROSS hosts | The same root LaunchDaemon label and minimal `sw_vers` action recur at similar intervals on both endpoints. Fleet software is a plausible explanation, keeping this indicator moderate. |
| `weak_signal` | macOS eCAR / ES / Unified Log | Persistence installation | The records show creation and execution but do not independently document the plist contents or registration transition in the available sources. Collection selection could explain this gap. |

## Realism Score by Category

- **Field format accuracy:** 8 — eCAR, Linux syslog, Zeek JSON, Windows XML, ES and Unified Log structures are generally source-appropriate in the reviewed pivots.
- **Temporal patterns:** 7 — Authentication, flow and file events align across sources; repeated Mac job executions are unusually tidy but not impossible.
- **Cross-source correlation:** 9 — The two SSH pivots and the archive's transfer to the SMB staging share have matching endpoints, ports, filenames and sequence.
- **Behavioral realism:** 7 — The activity is technically plausible and sits among routine host and network events; authorization and credential provenance remain unknown.
- **Environmental consistency:** 7 — The mixed estate and shared internal naming are coherent; the repeated Mac inventory daemon may be legitimate fleet management or a templated artifact.

## Recommendations

- If this were synthetic, vary the rollout and polling times of the same Mac LaunchDaemon across hosts, or include more source-native deployment evidence (such as the plist contents and the corresponding registration/activation observations). The current records show repeated root installation and execution, but not what the job actually contains.
- If this were synthetic, retain the strong transfer pivots and add source-visible authorization context for the database export (for example, whether root's session was an approved maintenance account). The current records establish the export and staging path but cannot distinguish approved backup/integration activity from theft.
