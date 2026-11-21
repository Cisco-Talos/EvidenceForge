# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 74
**Synthetic-Confidence Score:** 61

## Executive Summary

The strongest reason to favor synthetic origin is a repeated, microsecond-exact scheduling pattern in macOS shell fork observations on both Macs, including matching whole-second steps in their monotonic clocks. Otherwise, the environment supports credible investigations across endpoint, authentication, shell, network, proxy, and file evidence; I found substantially more operational coherence than broken causality, so this is a qualified verdict rather than a finding of pervasive contradictions.

## Evidence For Synthetic

- [distribution_texture] `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 35, 38, 41, and 44, records four forks from zsh PID 25529 at `13:48:41.198588000Z`, `13:49:08.198588000Z`, `13:49:43.198588000Z`, and `13:50:02.198588000Z` on November 2. These are separate commands—curl, bash, ls, and id—with gaps of exactly 27, 35, and 19 seconds, retaining the identical fractional second to six significant decimal places. Their `mach_time` values also advance by exact multiples of 24,000,000 ticks per second, making this more than an isolated wall-clock string artifact.
- [distribution_texture] The same pattern recurs in a second command group on that host: lines 55, 58, and 61 have fork times `14:37:50.487145000Z`, `14:38:28.487145000Z`, and `14:38:57.487145000Z`. On `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, lines 86, 89, and 92 have `15:30:55.965208000Z`, `15:31:17.965208000Z`, and `15:31:58.965208000Z`, all from zsh PID 88255. Three distinct clusters across two endpoints suggest command offsets added to a common precise anchor. Automation could explain approximate whole-second spacing, but exact repeated microseconds in native fork observations through multiple separate OS operations are substantially less plausible. I treat these as instances of one timing defect, not three independent classes of defect.

## Evidence For Real

- SSH supports useful transport-to-authentication pivots. For example, core Zeek observes `10.10.1.41:62772 -> 10.10.1.42:22` before the receiving Mac's `14:24:35.206464+0000` accepted keyboard-interactive/PAM message, followed by a native SSH process tree, remote shell commands, and session termination.
- The database transfer has visible prerequisites and effects: root authentication on DB-PROD-01, mysqldump, creation of the SQL file, gzip, reading the compressed file, SSH transport back to APP-INT-01, and creation of the receiving file. The compressed file is not visibly read before its visible creation.
- Network data has realistic operational variation. Core DNS contains 206 NXDOMAIN, 12 SERVFAIL, and five REFUSED responses alongside 2,965 NOERROR responses. HTTP includes authentication challenges, denials, redirects, cache responses, partial content, and gateway/service failures. Connections include reset, rejected, unanswered, partial, and successful states.
- The sources distinguish a downloaded Mac shell script from its subsequent bash execution. Likewise, the MeetingAssist policy message is present without a matching visible execution or effect that would require treating that message as successful execution.
- Windows records provide meaningful account and privilege pivots: DC-01 records creation of `svc_dirsync`, the same account SID receiving Domain Admins membership, a scheduled task, and later deletion. These are traceable source fields, rather than an analyst having to infer privileged persistence from command names alone.

## Detailed Analysis

### Scope and orientation

I examined only the supplied data directory. It contains 115 files, 23 endpoint directories with eCAR records, and 37,414 eCAR records in total. I counted 39 distinct nonempty principal strings; that includes system and service identities and should not be interpreted as 39 human users. The apparent collection window is approximately November 2, 2026, 13:00–19:00 UTC.

The environment spans Windows domain controllers, workstations, a Windows file server and mail host; Linux workstations and application, database, web, file, mail, proxy, and monitoring systems; and two Macs. Observed address spaces include 10.10.1.x, 10.10.2.x, 10.10.3.x, and 10.10.4.x. Three Zeek sensors contain 23,141 connection records altogether. Additional evidence includes Windows Security and Sysmon XML, Linux syslog and bash histories, Mac Endpoint Security and Unified Log records and zsh histories, web/proxy logs, ASA firewall logs, and IDS alerts.

The volume differences have recognizable roles: DC-01 and DC-02 carry heavy authentication and network activity, PROXY-01 has 6,225 endpoint FLOW observations, and WEB-EXT-01 has 3,813. I did not score a coverage deficiency merely because a source had fewer records or because a different product could have provided more evidence.

### Intrusion pivots and technical feasibility

On WEB-EXT-01, eCAR line 960 records PID 3044224, owned by `www-data` and parented by PID 23966, executing a base64-decoding bash command at `14:20:27.968Z`. The decoded payload invokes an interactive bash connection to `45.33.32.30:8443`. The visible base64 and bash children occur next; endpoint FLOW line 963 shows child PID 3044226 connecting from `10.10.3.10:48003` at `14:20:31.414Z`. DMZ Zeek line 2170 independently observes that tuple at epoch `1793629231.482414`, with 22.413812 seconds of successful transport and bytes in both directions. This is a workable process/network pivot.

A separate root SSH session arrives on WEB-EXT-01 from `10.10.1.31:60616`: syslog records connection at `14:39:30.803878Z`, successful public-key authentication at `14:39:36.245632Z`, and PAM session opening thereafter. Endpoint root shell PID 3050069 appears at `14:39:36.995Z`. Commands include internal discovery and reading configuration and key material. I do not assume that the earlier reverse shell itself explains the Windows-origin SSH credentials; the records establish separate observable actions, and the visible evidence does not require them to be a single process lineage.

APP-INT-01 accepts root SSH from WEB-EXT-01 at `15:15:07.108767Z`. Later, its root shell starts `ssh root@DB-PROD-01` at `18:14:42.160Z`. DB-PROD-01 records the incoming connection at `18:15:00.571078Z`, accepted root authentication at `18:15:07.783407Z`, and the root shell at `18:15:10.415Z`. The delay between starting a client and opening transport is not an impossible ordering.

DB-PROD-01 runs mysqldump at `18:15:14.113Z`, creates `/tmp/rpt_0318.sql` at `18:15:15.413Z`, runs gzip at `18:15:29.703Z`, and creates the compressed artifact at `18:15:33.651Z`. Scp begins at `18:15:41.710Z`; the endpoint FLOW at `18:15:45.039Z` uses `10.10.4.10:49550 -> 10.10.2.30:22`. Core Zeek line 10909 observes that transport at `1793643344.306524`; DB Zeek line 372 provides a second sensor view. APP-INT-01 accepts the matching source tuple at `18:15:50.937493Z` and records `/tmp/.cache/rpt_0318.sql.gz` creation at `18:16:08.581Z`. This supports staging and transfer, though the logs do not expose the SQL file contents.

DC-01's Windows Security records establish another high-value pivot: `svc_dirsync`, SID ending `-2188`, is created at `17:15:05.8149075Z`, receives a password reset, and is added to Domain Admins at `17:15:13.8607171Z`. Event 4698 at `17:19:47.7438924Z` registers `\Microsoft\Windows\Maintenance\DeviceSync` to run `C:\Windows\System32\DeviceSyncSvc.exe` as SYSTEM. I parsed the embedded TaskContent successfully as XML. Account deletion at `18:50:30.3730345Z` retains the same SID. These records are useful hunting evidence; their narrative completeness is not an authenticity indicator.

### Lifecycle and correlation checks

I checked eCAR process creation/termination and parent references across all 23 endpoints. For the relationships with visible initiating or terminating records, I found no child created before its visible parent, no child created after its visible parent's termination, no negative process lifetime, and no non-process actor-dependent record preceding its visible process creation or following its visible termination. This is a bounded statement about identifiers represented in these files, not proof that every possible dependency is present.

I also checked available Sysmon process GUID lifecycle relationships across the Windows hosts without finding the corresponding ordering defects. Within each Zeek sensor, HTTP, SSL, DNS, SMTP, and SMB-file rows checked against their connection references had matching represented tuple fields and timestamps inside connection intervals, allowing 300 ms tolerance. TCP five-tuples did not overlap within a sensor. Basic packet bounds did not reveal payload bytes exceeding recorded IP bytes or positive payload assigned to zero packets.

These successful checks support production plausibility. I do not penalize their completeness.

### Why the remaining timing concern matters

The Mac finding concerns native fork observations, not second-resolution shell history. Across 54 shell-originated fork records on the two Macs, ten records occupy three groups with exactly repeated fractional seconds; the other forks show much greater fractional variation. The groups include routine identity, filesystem, and directory-service commands as well as the connector script activity, so this is not simply one periodic system service.

On MAC-MROSS-01 the first group's `mach_time` values are `24953308766112`, `24953956766112`, `24954796766112`, and `24955252766112`. The second group's are `25024091691480`, `25025003691480`, and `25025699691480`. On MAC-MROSS-02 they are `56204543164992`, `56205071164992`, and `56206055164992`. The exact wall-clock intervals are preserved in these monotonic values. This looks like anchor-and-offset timing carried into source-native records, with more varied exec observation times added afterward.

A deliberately paced command runner remains a possible real explanation, so this does not demonstrate an impossible event. Its repetition across hosts is enough to lean synthetic, while the otherwise strong technical coherence keeps the synthetic-confidence score near the lower end of “likely synthetic.” I found no defensible hard contradiction that would justify the highest score band.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security fork observations | Ten shell forks in three clusters across two Macs | Exact repeated fractional seconds and matching whole-second monotonic-clock steps suggest common-anchor scheduling; primary reason for the synthetic verdict. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled native records parse and carry useful identifiers; embedded scheduled-task XML is valid. No demonstrated native-schema contradiction was found.
- **Temporal patterns:** 6 — Operational ordering is strong, but repeated microsecond-exact Mac command clusters are a specific scheduling artifact.
- **Cross-source correlation:** 9 — Process, SSH, transfer, and network pivots are feasible; the broad identifier and interval checks passed within their stated scope.
- **Behavioral realism:** 9 — Shell execution, privilege changes, staging, and transfer have technically credible visible relationships amid routine activity.
- **Environmental consistency:** 9 — Source volumes and roles vary plausibly across the mixed fleet; account namespaces and collection-window boundaries do not force a contradiction.

## Recommendations

- If this were synthetic, derive separate command launch times from the modeled execution of each interactive action, including scheduler and observation variation. Preserve true causal ordering while avoiding repeated six-digit fractional seconds across unrelated command launches.
- If the exact command spacing is intended to represent automation, make its execution mechanism observable where the existing process collection would capture it. Native fork wall-clock and monotonic timestamps should reflect actual scheduled execution, rather than repeated idealized offsets. This recommendation addresses the specific three clusters above, not a demand for additional log products or broader collection.
