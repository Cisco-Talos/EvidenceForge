# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 72/100  
**Synthetic-Confidence Score:** 57/100 (lower is more production-like)

## Executive Summary

The visible activity contains a credible compromise chain: an administrative upload is followed by an Apache-owned reverse shell, a successful outbound session, and a later attributable network scan. The cross-source joins are strong and operationally useful. The strongest synthetic cue is a prolonged, highly regular stream of random-looking `.top` DNS names from the compromised web host; the macOS shell histories also show a small repeated inventory-command vocabulary, but their timing and cross-host variation keep that signal weak. On this slice alone, I cannot reliably distinguish a deliberately authored exercise from production telemetry with an active intrusion.

## Evidence For Synthetic

- **[distribution_texture]** `zeek-dmz/dns.json:247,792,920` shows random-looking `.top` queries from `10.10.3.10` at 15:04:45, 18:23:00, and 18:45:19 UTC, mostly NXDOMAIN or sinkholed to `0.0.0.0`. The observed stream spans about 3 hours 40 minutes and uses a narrow naming pattern. This is plausible compromised-host behavior, but the sustained, nearly single-purpose sample has a deliberately constructed feel.
- **[weak_signal]** `MAC-MROSS-02.meridianhcs.local/zsh_history/maya.ross.zsh_history:18-20` records `find`, `ps`, and `pwd` at the identical second. Shell history often records second-resolution timestamps, so this is not a contradiction; it does slightly reduce confidence in the human timing texture.
- **[weak_signal]** The two Mac histories reuse a compact set of inventory commands (`id`, `sw_vers`, `uname`, `pwd`, `ls`, `du`, `df`, `ps`, `find`, `dscl`) while varying their order, spacing, and SSH targets. See `MAC-MROSS-01.../zsh_history/maya.ross.zsh_history:1-22` and `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history:1-20`. This can fit routine administration, but the repeated command pool is a mild generator-like cue.
- **[environment_or_collection_plausibility]** On both Mac endpoints, root creates `/Library/LaunchDaemons/com.meridianhcs.endpoint-inventory.plist` (`MAC-MROSS-01.../ecar.json:37`; `MAC-MROSS-02.../ecar.json` contains the corresponding file activity) and endpoint telemetry later shows `launchd` starting `xpcproxy com.meridianhcs.endpoint-inventory` (`MAC-MROSS-01.../ecar.json:46-48`). This is coherent service execution, though the identical named inventory agent and basic command sequence on both hosts suggest a curated exercise environment. File creation alone does not prove registration or activation; the subsequent process evidence does show execution.

## Evidence For Real

- The public HTTP upload and resulting shell activity have a concrete, plausible causal chain. `WEB-EXT-01.meridianhcs.local/web_access.log:460` records an HTTP 200 POST to `/ehr/admin/upload.php` from `185.70.41.45` at 14:19:57 UTC. `WEB-EXT-01.meridianhcs.local/ecar.json:833` records `www-data` bash spawned by `/usr/sbin/apache2` with a base64-decoding reverse-shell command; `WEB-EXT-01.meridianhcs.local/ecar.json:835` shows the matching outbound flow from `10.10.3.10:53317` to `45.33.32.30:8443`. `zeek-dmz/conn.json:1493` independently records that tuple as an established `SF` connection lasting 12.88 seconds with bidirectional bytes.
- The scan is attributed to a visible process and has plausible network outcomes. `WEB-EXT-01.meridianhcs.local/ecar.json:1216` records root running `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24`. `zeek-core/conn.json` then shows the scan's three targeted ports across the address range, with mostly `S0` responses, plus a small number of refused/reset and successful sessions. The expected mix is consistent with a real TCP connect sweep; it should not be treated as suspicious merely because the fan-out is easy to narrate.
- The Windows persistence activity has operationally consistent principal and process ancestry. `DC-01.meridianhcs.local/ecar.json:3806,3810` shows a WMI provider under Network Service launching `cmd.exe` and `sc.exe` to create `DeviceSyncSvc` as LocalSystem. Lines 3820 and 3826 show the same WMI-originated chain creating a SYSTEM scheduled task. Later service execution and Windows event records provide corroboration. This is concrete evidence of privileged actions, not an inference from a filename alone.
- Mac remote access is represented with a source and native authentication evidence. `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:3` records `sshd-session` accepting Maya Ross's ED25519 public key from `10.10.1.42:62470` at 16:02:17.562 UTC. The zsh history on both machines records SSH to the other Mac and several internal hosts, giving an analyst usable pivots across systems.
- The data supports incident triage without requiring a single artifact type: HTTP path/source, Unix process ancestry, network tuple, DNS, Zeek connection state, Windows service/task names, user identities, and Mac SSH principal are available for follow-up. The exact cross-source tuple match is neutral by itself; the process and transport facts around it make the chain useful.

## Detailed Analysis

### Web host ingress and shell lifecycle

The web access log records a successful `POST /ehr/admin/upload.php` from external address `185.70.41.45` at 14:19:57 UTC (`WEB-EXT-01.meridianhcs.local/web_access.log:460`). The Apache-owned `www-data` bash process is timestamped 14:19:56.221 UTC and carries a command that decodes and invokes an interactive Bash reverse shell (`WEB-EXT-01.meridianhcs.local/ecar.json:833`); the access log can be emitted after request handling, so this subsecond ordering is not by itself a contradiction. At 14:20:00.120 UTC, the same process identity owns a flow from `10.10.3.10:53317` to `45.33.32.30:8443` (`.../ecar.json:835`). Zeek records the same tuple at `zeek-dmz/conn.json:1493`, with `SF`, 620 origin bytes, and 1,840 responder bytes. These are mutually reinforcing details, not merely a suspicious URL followed by unrelated network noise.

### Host discovery and network visibility

At approximately 14:40:42 UTC, the web server's root process executes an explicit TCP connect scan of five ports over `10.10.2.0/24` (`WEB-EXT-01.meridianhcs.local/ecar.json:1216`). Zeek core records a short burst of connections from `10.10.3.10` to the selected ports on the subnet, chiefly `S0`, with a few `REJ`/reset outcomes and a handful of established connections. This result mix makes sense for a live sweep through a subnet with mixed host availability and service exposure. The scan itself is strong threat evidence, while its count and timing are not strong synthetic evidence because they are consistent with the command that is actually logged.

### DNS behavior

The DMZ sensor records random-looking A queries under `.top` from the same web host over an extended period. The sample at `zeek-dmz/dns.json:247` resolves to `0.0.0.0` at 15:04:45 UTC; `:792` and `:920` are NXDOMAIN at 18:23:00 and 18:45:19 UTC. That could represent a DGA or a sinkholed callback family. The concern is distributional: the slice exposes many similar names and few ordinary hostname queries for that host during the period, making the behavior feel concentrated. It is not a hard contradiction: compromised hosts can exhibit exactly this pattern, and the bounded view cannot establish what happened outside it.

### Windows persistence and privilege boundary

The DC-01 records show explicit privilege context. At `ecar.json:3806`, the WMI provider process (`WmiPrvSE.exe`, parent actor principal `NETWORK SERVICE`) starts a command that requests a LocalSystem automatic service. `:3810` records `sc.exe` as its child under SYSTEM. The next WMI-originated command creates an hourly SYSTEM scheduled task (`:3820,3826`), and `:3834` records a service object for `DeviceSyncSvc` with a LocalSystem account. These are successful-looking endpoint actions and establish a high-impact privilege boundary crossing. A process command plus a service object establishes service creation in this stream; claims about later payload behavior should rely on the observed service executions rather than the service name or scheduled task target alone.

### macOS endpoint behavior and collection limits

The Mac histories show routine discovery commands mixed with SSH to internal hosts. MAC-MROSS-01 records SSH to `MAC-MROSS-02`, `WEB-EXT-01`, `DB-PROD-01`, and `APP-INT-01` (`zsh_history/maya.ross.zsh_history:7,14-15,18`); MAC-MROSS-02 records SSH to the database, the first Mac, and the app host (`...:6,11,17`). The commands are plausible and the paths/user are internally consistent. Three commands at one second on MAC-MROSS-02 (`:18-20`) are a weak timing cue, not evidence of impossible execution. The Mac files also show root creating the LaunchDaemon path and later launchd/xpcproxy service activity; distinguish that observed execution from the earlier file write rather than assuming placement alone proves persistence activation. Sparse unified-log row counts are neutral in this bounded sample and are not scored as missing telemetry without a demonstrated collection expectation.

### Cross-source timing and identity

The major web-host process, flow, and Zeek connection facts align, as do the Mac SSH username/source details. This improves pivot feasibility. A DC-02 SMB login and its matching FLOW are both rendered at the same millisecond with LOGIN before FLOW (`DC-02.meridianhcs.local/ecar.json:1035-1036`); this is a precision/ordering ambiguity at the displayed granularity, not a demonstrated impossible ordering. I treat it as a weak signal only.

## Synthetic Indicator Summary

| Category | Evidence | Scope | Impact |
|---|---|---|---|
| distribution_texture | Sustained random-label `.top` DNS stream with NXDOMAIN/sinkhole responses (`zeek-dmz/dns.json:247,792,920`) | One compromised web host across several hours | Moderate synthetic cue; also plausible DGA behavior |
| weak_signal | Three distinct shell-history commands share one Unix-second timestamp (`MAC-MROSS-02.../zsh_history/maya.ross.zsh_history:18-20`) | One Mac, one second | Low; timestamp granularity limits inference |
| weak_signal | Similar compact inventory command vocabulary appears on both Macs | Two endpoints | Low; common administration can explain it |
| environment_or_collection_plausibility | Same named root LaunchDaemon inventory agent appears on both Macs with subsequent xpcproxy execution | Two endpoints | Low to moderate; fits managed fleet tooling and curated exercise setup |
| weak_signal | SMB login and corresponding flow have identical displayed millisecond and LOGIN precedes FLOW (`DC-02.../ecar.json:1035-1036`) | One connection | Low; no hard temporal contradiction established |

## Realism Score by Category

| Category | Score (1–10) | Rationale |
|---|---:|---|
| Operational lifecycle coherence | 8 | Apache shell, outbound session, scan, and Windows service/task records have visible process and lifecycle context. |
| Cross-source correlation and pivotability | 9 | Host, user, process, tuple, HTTP, DNS, and Zeek evidence provide concrete pivots. |
| Tradecraft and privilege-boundary plausibility | 8 | Web-shell follow-on and SYSTEM persistence are credible attacker actions with explicit principal transitions. |
| Environment and collection plausibility | 6 | Managed Mac tooling and broad security telemetry are plausible, though the shared agent pattern looks curated. |
| Distribution and background texture | 6 | Scan outcomes look realistic; the DNS concentration and repeated Mac inventory vocabulary are the main texture concerns. |

## Recommendations

- If this is synthetic, retain the HTTP-to-process-to-flow chain and the varied scan response states; they make the activity easy to investigate while remaining operationally coherent.
- Vary the `.top` DNS family with a more mixed resolution/outcome pattern and interleave ordinary host lookups or longer quiet intervals on the compromised host. Keep any DGA inference anchored to the observable query stream.
- Add modest variation to benign Mac administration command selection and spacing across users/endpoints; preserve the observed internal SSH pivots and avoid treating the same-second history entries as impossible.
- Keep the LaunchDaemon evidence explicit as separate file placement and launch/exec observations, as in this slice; this supports correct distinction between dropped artifact and demonstrated activation.
- If refining event timing, avoid identical displayed timestamps for dependent authentication and transport rows where source-native clocks can provide a small credible offset. The current SMB tie is weak evidence, not a confirmed defect.
