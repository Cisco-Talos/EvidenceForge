# Host/EDR Forensics Analyst — Authenticity Assessment
## Verdict
**Assessment:** Synthetic
**Confidence:** 76

## Executive Summary
The Windows endpoint evidence is unusually strong and often source-native coherent, especially around Security/Sysmon/eCAR lifecycle and the DC log-clear sequence. I still assess the dataset as synthetic because several Linux/eCAR artifacts look generated: repeated LDAP recon commands use the wrong directory base for the environment, some short LDAP queries remain alive for hours, and the Linux command/PID patterns show command-pool fingerprints.

## Evidence For Synthetic
- `APP-INT-01.meridianhcs.local/ecar.json` lines 216, 238, 320, and 836 record `ldapsearch` against `DC-01`/`DC-01.meridianhcs.local` using `-b "dc=corp,dc=local"` at 2024-03-18 14:08:38, 14:20:20, 14:49:10, and 17:24:21 UTC. The visible environment is consistently `meridianhcs.local`; DC Security 4728 at 2024-03-18T16:14:40.5704109Z uses `DC=meridianhcs,DC=local`.
- Those same LDAP searches have implausible lifetimes for simple `(objectClass=user|computer)` queries: pid `840831` runs 14:08:38 to 17:32:11, pid `840554` runs 14:20:20 to 16:23:24, and pid `841685` runs 14:49:10 to 17:43:05 in `APP-INT-01.meridianhcs.local/ecar.json`.
- Linux bash histories show generic command-pool leakage. `APP-INT-01.../marcus.chen.bash_history` contains both `apt list --upgradable` and repeated `yum check-update`; `WEB-EXT-01.../marcus.chen.bash_history` does the same while other WEB-EXT commands are Debian/Apache2-style.
- Linux eCAR process PIDs are clustered in host-specific high bands: APP-INT creates all observed processes in `837856-850850`, DB-PROD in `693260-700481`, PROXY in `654729-663374`. Not impossible, but statistically tidy.

## Evidence For Real
- `DC-01.meridianhcs.local/windows_event_security.xml` has a coherent log-clear sequence: `powershell.exe -EncodedCommand` at 17:42:20, `wevtutil cl Security` at 17:42:22, Event ID 1102 at 17:42:24, then EventRecordID reset to `4/5/6...`. That is a very Windows-native artifact.
- No impossible visible ordering found in Sysmon process GUID lifecycles, Security logon IDs, or eCAR process/session lifecycles. Missing pre-window starts were present but not treated as suspicious.
- Security/Sysmon/eCAR process correlation has realistic jitter rather than exact timestamp copies. Security 4688 to Sysmon 1 deltas usually cluster around ~0.1s with varied positive and negative offsets.
- Windows host noise is credible: Zscaler, GlobalProtect, Cisco AnyConnect, Dropbox, OneDrive, WMI, Defender, TiWorker, SearchIndexer/SearchFilterHost, logon types 2/3/5/7/10/11, and plausible SIDs/domains.

## Detailed Analysis
Windows endpoint logs are the strongest part of the dataset. Process creation, network filtering, Sysmon process/network/DNS events, and eCAR objects generally agree without visible causality errors. The attack sequence on the DC is also source-native: PSEXESVC service install, `cmd.exe /c whoami && hostname`, `net user svc_mhsync ... /add /domain`, Event ID 4720 user creation, Event ID 4728 Domain Admins membership, service and scheduled task creation, encoded PowerShell, Security log clearing, and later account deletion.

The strongest synthetic indicators are in Linux/eCAR behavior. The LDAP recon commands are both environmentally wrong and temporally wrong: using `dc=corp,dc=local` inside a `meridianhcs.local` estate could be a one-off operator mistake, but it repeats several times and the processes remain alive for hours. That combination feels like generated command text joined to a generic process lifecycle model.

Bash history has some nice messiness: typos, `tail -f ... &`, service restarts, `journalctl`, `ss`, `grep`, and ordinary admin checks. But the repeated cross-distro package-manager commands on the same hosts and typo distribution feel more like a diversified command pool than lived-in muscle memory.

I did not count complete cross-source coverage as synthetic by itself. In fact, the cross-source integrity is mostly a realism point here because I found no concrete contradiction in visible event ordering.

## Realism Score by Category
- **Field format accuracy:** 8/10 — Windows XML and eCAR fields are mostly convincing; LDAP base DN mismatch hurts.
- **Temporal patterns:** 6/10 — Windows jitter is good, but multi-hour `ldapsearch` and tidy PID bands are suspicious.
- **Cross-source correlation:** 8/10 — Strong correlation without visible impossible ordering.
- **Behavioral realism:** 6/10 — Good admin and attacker story, with some command-pool artifacts.
- **Environmental consistency:** 6/10 — Mostly coherent MERIDIANHCS estate, but `dc=corp,dc=local` is a clear leak.

## Recommendations
Fix LDAP commands to use `dc=meridianhcs,dc=local` or explicitly model them as failed/typo attempts with short lifetimes. Tune Linux process duration and PID allocation so quick CLI tools terminate quickly and PID ranges feel less host-banded. Make package-manager commands OS-aware per host, and reduce repeated generic typo injection in bash histories while preserving the strong Windows event realism.

