# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 64

## Executive Summary

The collection spans a mixed Windows, Linux, and macOS environment over roughly six hours and contains a coherent huntable trail: privileged directory-account creation, suspicious data collection and staging, database dumping, outbound transfers, and high-volume TXT DNS activity. Source mix and much of the cross-source timing are plausible, but repeated near-identical operator command sequences across two Macs and the unusually coordinated, compact identifiers and handoffs across otherwise separate host activity make a synthetic origin more likely. The score is moderate rather than extreme because these are distribution and environmental signals; the core suspicious actions are technically possible and their multi-source corroboration is not itself evidence of synthesis.

## Evidence For Synthetic

- [distribution_texture] The two Maya Ross Mac histories repeat nearly the same ordered host-survey sequence (`sw_vers`, `uname -a`, `pwd`, `ls -la ~/Documents`, `du`, `df`, `ps`, `find ... '*.pdf'`, `ifconfig`) on both `MAC-MROSS-01` and `MAC-MROSS-02`, interspersed with SSH hops. On `MAC-MROSS-02`, the same survey commands recur again later in the six-hour window. This looks like a small reusable command set being replayed across hosts rather than varied user work; it is a moderate tell, not proof.
- [environment_or_collection_plausibility] The visible `WS-AJOHNSON-01` staging sequence copies `cache_7f3a.zip` from `\\WS-AJOHNSON-01\C$\ProgramData\Microsoft\cache_7f3a.zip` back onto the same workstation under Aisha's Temp directory, then later uploads the original ProgramData path. A same-host administrative-share copy is possible, but is an unusually contrived transfer step for this apparent workstation activity.
- [distribution_texture] Identifiers and filenames are tightly reused across events and operators (`MHS-48217`, `mhs-support-48217.tar.gz`, `rpt_0318.sql.gz`, `cache_7f3a.zip`, and upload path token `7f3a2b19`). The linked naming helps investigation, but the same short, task-like labels across Linux diagnostic upload and Windows collection/exfiltration have a staged-data feel.
- [weak_signal] `MAC-MROSS-01` records three failed local logins for `maya.ross` within 14 seconds (14:08:37, :42, :51 UTC), and `MAC-MROSS-02` records repeated failed-login bursts at 15:41 and 17:16. Those are possible user mistakes, but the repeated patterned bursts across both machines add to the synthetic texture.

## Evidence For Real

- The host and source mix is broad: two domain controllers, Windows workstations and file/mail servers, Linux application/database/file/monitoring hosts, two macOS systems, proxy and perimeter firewall, three Zeek vantage points, and Snort. Record counts vary substantially by host and source family; this is not a flat one-record-per-source fixture.
- There is useful background noise around the suspicious activity: ordinary shell/system administration, service logs, Windows security and Sysmon activity, DNS/Kerberos, SMB, proxy access, DHCP, and network alerts. Activity extends from approximately 13:00 to 19:00 UTC on 2026-11-02, with irregular event timing and intervening routine events.
- Suspicious operations have plausible visible prerequisites and effects. `WS-AJOHNSON-01` has a Sysmon PowerShell `Compress-Archive` command creating `C:\ProgramData\Microsoft\cache_7f3a.zip`, then a PowerShell copy, `curl.exe` file read, and a proxied HTTPS flow at 18:24:33–18:24:37. `FILE-SRV-01` Security/Sysmon and endpoint records provide a separate SMB/service context.
- On `DC-01`, 17:15:10 UTC process records show `WmiPrvSE.exe` launching `cmd.exe` and `net.exe` to add `svc_dirsync`; at 17:15:14, a second `net group "Domain Admins" svc_dirsync /add /domain` follows. A 18:49:50 deletion command is also visible. This is operationally plausible privileged persistence and cleanup, and it has surrounding domain-controller auth and network activity.
- `DB-PROD-01` shows Lina Nguyen's 18:14:44 `mysqldump --single-transaction ehr patients insurance_claims`, creation of `rpt_0318.sql`, gzip at 18:15:11, and an SCP flow/read at 18:15:39–18:15:49 to `10.10.2.30`. Her shell history independently contains the dump, compression, and SCP commands. Separately, her workstation history and EDR records show a diagnostics archive and HTTP multipart upload at 16:31:35–16:32:32.
- Network pivots work in several cases: eCAR captures the client-side proxy destination and process/file activity; Zeek and firewall records show perimeter connections from the proxy host to `45.33.32.30:443` with TLS SNI `api.westbridge-services.net`, including repeat sessions. Domain names and addresses are treated as potentially sanitized.

## Detailed Analysis

### Scope, coverage, and noise

The Windows XML exports cover approximately 13:00–19:00 UTC. `DC-01` has 6,686 Security and 4,463 Sysmon events; `DC-02` has 5,875 Security and 3,686 Sysmon events. Workstations generally have hundreds of Security/Sysmon events apiece, while Linux and macOS hosts provide eCAR plus native Syslog/Endpoint Security and shell-history views. Network coverage includes `zeek-core`, `zeek-dmz`, `zeek-db`, Snort, proxy access, and ASA firewall records. This creates enough benign activity to hunt through, although the window is only one workday slice and cannot establish longer-term baselines.

The security process is not merely a compact intrusion narrative. Windows hosts have ordinary logon, process, and allowed-connection activity; Linux hosts show package/service/journald, sudo, SSH, and cron noise; Mac records include normal app/system activity. I do not treat selected source-family absence or complete cross-source alignment as synthetic evidence.

### Lateral movement and privilege change

The strongest domain pivot is on `DC-01`: at 17:15:10 UTC, `cmd.exe /c net user svc_dirsync MhsSvc!2024 /add /domain` is launched by `WmiPrvSE.exe` under SYSTEM, followed by the `net.exe` child. Four seconds later, `net group "Domain Admins" svc_dirsync /add /domain` is recorded. The account is removed at 18:49:50. This is high-impact, technically credible activity, although the visible command line exposes the new password in plaintext. That exposure is a threat-hunting signal, not by itself an authenticity defect. The earlier and surrounding normal Kerberos, LDAP, SMB, DNS, and process-open events make this a plausible directory-server collection.

### Collection and egress

On `DB-PROD-01`, a root-owned dump command reads tables named `patients` and `insurance_claims`, writes `/tmp/rpt_0318.sql`, compresses it, and sends it to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. The originating Linux history on `WS-LNGUYEN-01` also shows Lina running the same SQL dump, gzip, and SCP sequence. At 16:31, that workstation separately archives EHR connector logs and submits them with multipart `curl` to a support endpoint through the proxy. A real support workflow could explain the latter, but its archive, ticket ID, and external upload make it a valuable corroborating pivot.

At 18:18–18:24 on `WS-AJOHNSON-01`, the logs show copying and uploading a ZIP with `curl.exe` to a remote HTTPS upload path via `10.10.3.20:8080`. Endpoint records include process create, module loads, file read, and flow connect. The proxy/perimeter evidence confirms TLS sessions from `10.10.3.20` to `45.33.32.30:443` with the same SNI in the later window. I could not establish a one-to-one perimeter session for the exact 18:24 client request from the inspected log rows, so I treat the high-level pivot as supported while leaving byte-level transfer confirmation unresolved.

### DNS and beaconing

`zeek-core/dns.json` contains 268 queries matching `westbridge` during the window, 266 from `10.10.2.30`. Most are TXT queries to `ns1.westbridge-services.cloud` with changing high-entropy-looking left labels and short variable answers; examples begin at 17:44:50 UTC and recur over about an hour. There are also ordinary DNS A queries for `api.westbridge-services.net`. This pattern is consistent with command-and-control or DNS-based transfer and gives a useful pivot from the database recipient address. It is suspicious but possible behavior, not an impossible source-native condition.

### Concrete texture concerns

The strongest authenticity concern is not that suspicious steps are easy to follow, but that user-level artifacts reuse a narrow, repeated shell-survey recipe on two separate Mac hosts, while several transfer labels and tokens recur consistently across unrelated collection activities. This can arise from a deliberately scripted investigation or shared operational playbook, so I keep the synthetic score below the high-confidence range. The self-share copy on Aisha's workstation is another odd but possible action, not a hard contradiction. I did not find a proven impossible ordering or impossible field value in the reviewed high-impact trails.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | macOS shell histories | Two Mac hosts, multiple hours | Repeated ordered system-survey commands on both hosts resemble a small replayed command pool. |
| `environment_or_collection_plausibility` | Windows eCAR/Sysmon | `WS-AJOHNSON-01`, 18:18–18:24 UTC | Archive is copied from the workstation's own `C$` share back to itself before upload; possible but contrived. |
| `distribution_texture` | Linux/Windows command and file fields | Multiple hosts, 16:31–18:24 UTC | Short ticket, archive, dump, and upload identifiers are unusually coordinated across separate operations. |
| `weak_signal` | macOS eCAR login events | Two Mac hosts | Recurrent tight clusters of failed local logins are suspiciously patterned but can reflect real user retries. |

## Realism Score by Category

- **Field format accuracy:** 8 — Source-specific formats and useful host/user/process fields are present in the inspected records.
- **Temporal patterns:** 7 — Main activity ordering is plausible and irregular, though repeated Mac survey sequences add texture concerns.
- **Cross-source correlation:** 8 — Process, file, proxy, DNS, TLS, and perimeter pivots often align; exact session-level egress confirmation is incomplete for one upload.
- **Behavioral realism:** 6 — Privilege change, database collection, support upload, and DNS TXT behavior are plausible, while the self-share copy and repeated Mac survey routine feel staged.
- **Environmental consistency:** 7 — The mixed clinical/enterprise fleet and source volumes are credible overall, with several compact cross-host labels that look authored.

## Recommendations

If this were synthetic, vary the Mac shell activity with host-specific and task-specific command sequences rather than repeating the same ordered survey on both hosts. Replace the same-host `C$` copy with a transfer path that explains why a remote share is involved, or omit the redundant copy if it has no operational purpose. Give the separate database, support-diagnostics, and Windows archive operations independent naming conventions unless a visible log event establishes that they are part of one response or campaign. Keep the existing proxy/DNS/TLS and process/file pivots, and add a direct perimeter or proxy record for the exact 18:24 upload if the intended collection assumption is that every egress request is retained.
