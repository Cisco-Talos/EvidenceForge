# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 45

## Executive Summary

The records support workable hunting pivots across Windows, Linux, macOS, network sensors, and the explicit proxy, and I did not establish a hard lifecycle or source-native contradiction. A remarkably tight cluster of repeated RDP connection durations and repetitive Linux background-message texture raise modest concerns, but policy timeouts and collection configuration remain credible explanations. The evidence does not justify confidently distinguishing sophisticated synthetic data from a curated production collection.

## Evidence For Synthetic

- [distribution_texture] Three distinct RDP connections from `10.10.1.99` to `10.10.1.35:3389` have durations within **1.044 milliseconds** of one another: `887.865532`, `887.866576`, and `887.866366` seconds. They start at `16:01:18.641065`, `16:21:50.083524`, and `16:44:58.759068` UTC in `zeek-core/conn.json`, lines 6602, 7149, and 7883, respectively, with different origin ports `57338`, `38655`, and `39368` and substantially different payload volumes. This precision around an unusual non-round duration looks like reuse of an underlying interval. It is a limited indicator: automated session behavior or a fixed disconnect timer could explain it, and the endpoint records support reconnection to an existing session.
- [distribution_texture] A small set of irqbalance messages forms a large fraction of several Linux syslog streams. `LOG-MON-01.../syslog.log` has 97 irqbalance records out of 297 total; the four recurring messages have counts 31, 23, 22, and 21. `DB-PROD-01.../syslog.log` has 62 such records out of 195, and `APP-INT-01.../syslog.log` has 59 out of 254. Examples include `IRQ 137 classified for CPU 3 balancing on ens192` at `13:12:50.492829` on LOG-MON-01, and `IRQ 16 affinity hint keeps vector on CPU 0 (ahci)` at `13:00:04.070199` on APP-INT-01. The repetition and source-family proportions resemble a limited background-message catalog, although verbose daemon configuration and centralized filtering could produce the observed proportions. This is a texture concern, not proof that irqbalance cannot emit these messages.

## Evidence For Real

- Process lifecycle checks were reassuring. Across the 23 normalized endpoint streams, checks of visible process object identities and their actor references found no dependent records before the corresponding visible process creation or after its visible termination. Separate checks of Windows Sysmon process GUIDs and macOS Endpoint Security PID/pidversion identities likewise found no impossible visible use-before-creation or use-after-exit relationships in the checked relationships.
- Remote SSH activity has technically useful transport, authentication, session, process, and close pivots. For example, `10.10.4.10:49550 -> 10.10.2.30:22` starts at `18:15:44.306524` in the core network view; APP-INT-01 then records the connection, accepted public key, PAM session opening, session 363, and session closing in the expected order.
- Windows account manipulation is represented through source-appropriate records. DC-01 shows `net user svc_dirsync ... /add /domain`, then Security 4720, followed by group-add execution and Security 4728. The same account SID ending `-2188` appears in the later deletion record. This provides a viable account-centric pivot rather than merely suggestive command text.
- Network accounting was internally credible in the checks performed. No checked connection had IP byte totals below its associated application payload bytes; no single-connection Zeek file observation exceeded the matching direction's connection payload; and no checked HTTP request or response body length exceeded that connection's corresponding payload total.
- The environment contains operational clutter with recognizable roles: mail-specific Postfix/Dovecot records, SMB server audit activity, workstation DHCP and desktop messages, database traffic, Windows service and authentication activity, scanner-like requests, and failed logons. These are concrete sources of hunting ambiguity. Their presence is more persuasive than the mere number of source types.
- The macOS evidence distinguishes fork from exec and preserves PID/pidversion changes, launchd/xpcproxy launch chains, GUI terminal setup, shell execution, and SSH-related process transitions. Its native records are sufficiently different from normalized eCAR records to permit an independent lifecycle check.

## Detailed Analysis

### Scope, sources, and collection interpretation

The visible endpoint population comprises 23 hosts: ten with Windows Security/Sysmon exports, eleven with Linux-style syslog, and two Macs with Endpoint Security exports, limited Unified Log records, and zsh histories. All have normalized eCAR records. Hostnames and communications suggest the `meridianhcs.local` directory environment, two domain controllers, Windows and Linux file servers, application and database systems, mail systems, a proxy, an external web server, monitoring, and user workstations. The major address groups are `10.10.1.0/24`, `10.10.2.0/24`, `10.10.3.0/24`, and `10.10.4.0/24`.

The endpoint records cover approximately `2026-11-02 13:00–19:00 UTC`. There are 37,414 eCAR rows, 17,780 Windows Security events, 11,606 Sysmon events, and 4,088 Linux syslog lines. Network views contain 12,230 core connections, 10,481 DMZ connections, and 430 database connections; these are sensor observations and should not simply be summed as distinct activities. The available sources also include 4,379 proxy access lines, 899 web access lines, perimeter firewall records, IDS alerts, and several Zeek protocol/file families.

These volumes are compatible with a selected six-hour collection. I did not use absent Sysmon types, small Unified Log exports, absent pre-window creations, or absent post-window terminations as evidence of synthesis. I also did not interpret complete correlation as suspicious by itself.

### Hunting pivot: web execution and outbound transport

`WEB-EXT-01.../web_access.log`, line 509, records a successful-status POST to `/ehr/admin/upload.php` at `14:20:17`. Endpoint line 960 then records `/bin/bash` under `/usr/sbin/apache2`, principal `www-data`, PID `3044224`, at `14:20:27.968`. Its command decodes a Base64 payload and pipes it into bash; separate child records show `base64 -d` and `bash`.

The decoded command is consistent with a bash reverse connection to `45.33.32.30:8443`. `zeek-dmz/conn.json`, line 2170, records `10.10.3.10:48003 -> 45.33.32.30:8443` at `14:20:31.482414`, duration `22.413812`, state `SF`, with 620 origin and 1,840 response payload bytes. This is a useful process-to-network pivot. It does not by itself establish everything that happened inside the encrypted or raw stream, and I do not infer additional execution merely from the HTTP 200 response.

### Hunting pivot: database extraction, SCP, and staging

On DB-PROD-01, an SSH root login from `10.10.2.30:39333` follows an observed TCP connection at `18:14:57.176913` in `zeek-db/conn.json`. Native syslog records the connection at `18:15:00.571078`, password acceptance at `18:15:07.783407`, PAM opening at `18:15:07.936251`, and logind session 390 at `18:15:08.415060`. Endpoint records then show the root bash shell, `mysqldump --single-transaction ehr patients insurance_claims`, creation of `/tmp/rpt_0318.sql`, gzip execution, and the `.gz` artifact. The shell history supplies the output redirection absent from the executable's own command line; that distinction is expected.

The subsequent SCP command sends `/tmp/rpt_0318.sql.gz` to APP-INT-01. The network tuple is `10.10.4.10:49550 -> 10.10.2.30:22`; native receiver syslog, lines 220–225, shows connection at `18:15:49.697537`, key acceptance at `18:15:50.937493`, session opening at `18:15:51.114422`, and session closing at `18:16:08.532972`. Receiver eCAR line 796 shows `/tmp/.cache/rpt_0318.sql.gz` created at `18:16:08.581`. Small differences among native and normalized observations do not establish impossible canonical ordering.

`zeek-core/files.json`, line 605, later records a 17,238-byte SMB staging file named `Integration\DB-Staging\rpt_0318.sql.gz`, sent from `10.10.2.30` to `10.10.2.21`. The SCP transport's 27,702 origin bytes can accommodate that file plus SSH overhead. The considerably larger subsequent outbound upload is not, by itself, a contradiction: the visible 18 MB upload is not established to contain only this one compressed SQL file.

### Hunting pivot: account changes and explicit proxy upload

DC-01 eCAR shows `cmd.exe` and child `net.exe` creating `svc_dirsync` at `17:15:01.957` and `17:15:02.156`. Security 4720 follows at `17:15:05.8149075`, SID `S-1-5-21-1524654518-2022274387-1755902678-2188`. The group-add command follows at `17:15:06`, and Security 4728 records Domain Admins membership at `17:15:13.8607171`. Security 4726 later records deletion at `18:50:30.3730345` with the same SID. Security 4698 at `17:19:47.7438924` contains a parsable task XML definition for `\Microsoft\Windows\Maintenance\DeviceSync`; I did not find malformed embedded task XML in that record.

The explicit proxy provides another useful pivot. Proxy lines 4044–4045 identify `10.10.1.35`, `MERIDIANHCS\aisha.johnson`, `curl/8.4.0`, tunnel `PT-e1698317f3ded0de`, and a POST to `https://api.westbridge-services.net/upload/telemetry/7f3a2b19` at `18:25:21`. The log separates CONNECT control bytes from tunnel totals and inspected request bytes. The DMZ connection from the proxy (`10.10.3.20:42625`) carries 18,813,253 origin payload bytes, consistent in scale with the proxy's 18,783,258-byte inspected request. This avoids confusing the proxy's external source address with the original endpoint.

### macOS observations and limits

I treated Endpoint Security, Unified Log, normalized eCAR, and shell histories as distinct representations. For example, MAC-MROSS-01 Endpoint Security records PID 44182 progressing from launchd through xpcproxy and sshd-keygen-wrapper to sshd/sshd-session around `16:02:07`. Unified Log records public-key acceptance for `maya.ross` from `10.10.1.42:54545` at `16:02:08.243284`; the core transport starts at `16:02:02.087110`. Native shell-related fork/exec records follow acceptance. These relationships are operationally credible.

The `15:42:09.009673` Unified Log message about policy that “would not allow” MeetingAssist is a policy diagnostic. I did not treat it as proof of successful execution, definitive authorization denial, child execution, or downstream effects. Nor did I require native Mac endpoint semantics from network rows merely because they concern a Mac.

### Weight of the remaining texture concerns

The three RDP durations are the strongest residual concern because they reproduce an interval to approximately a millisecond despite separate starts and different payload volumes. However, they concern one endpoint pair and a reconnecting session, making a common timeout explanation substantially more plausible than it would be across unrelated users and protocols. The IRQ-message proportions add a weaker concern about repeated background texture, but a common fleet logging policy could explain those too.

I therefore kept the score near the uncertain middle and below the “likely synthetic” band. The absence of demonstrated contradictions constrains the verdict; it does not prove the data are real.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| distribution_texture | Zeek RDP connection timing | Three connections, one source/target pair, `16:01–16:44` | Nearly identical unusual durations suggest interval reuse; fixed policy or automation remains a viable alternative. Moderate, localized influence. |
| distribution_texture | Linux syslog / irqbalance | LOG-MON-01, DB-PROD-01, APP-INT-01 | A few recurring messages occupy roughly 23–33% of these streams, suggesting limited baseline texture; verbose collection could explain it. Small influence. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed Windows XML and embedded task XML, ordinary protocol fields, and distinct native Mac process representations held up in the checks performed.
- **Temporal patterns:** 8 — Credible ordering and variable activity; the three tightly clustered RDP durations remain an unresolved localized concern.
- **Cross-source correlation:** 9 — SSH, process/network, file-staging, account, and proxy pivots work without an established impossible relationship.
- **Behavioral realism:** 8 — Commands and observed effects generally fit their hosts and account contexts; common administrative and suspicious behaviors coexist.
- **Environmental consistency:** 8 — Role-specific mail, database, SMB, endpoint, and network activity is plausible; repetitive daemon-message proportions modestly weaken the background texture.

## Recommendations

- If this were synthetic, review the source of the three approximately `887.866`-second RDP intervals. Preserve an actual policy-driven timer if that is the intended cause; otherwise derive independent session durations from the modeled activity and reconnect/disconnect behavior. Do not add jitter solely to hide a valid timer.
- If this were synthetic, review the irqbalance collection level and its contribution to host syslog volumes. Match the observed fleet's daemon configuration and recurring conditions, and broaden that daemon's message mix only when additional real conditions warrant it. The goal should be credible source proportions, not an arbitrary larger log count.
- Retain the existing identity, lifecycle, transport, and proxy-control/data distinctions. I found no evidence-based need to add arbitrary source families or out-of-window lifecycle rows.
