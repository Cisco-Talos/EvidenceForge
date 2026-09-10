# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 74  
**Synthetic-Confidence Score:** 44

## Executive Summary

The dataset is highly production-like: source-native fields are well formed, malicious operations are technically coherent, and independent sensors exhibit realistic clock and packet-accounting differences. The strongest synthetic indicators are repeated administrative-command vocabulary and selective initiator-side process gaps, but neither is decisive enough to overcome the dataset’s substantial environmental entropy and lifecycle consistency.

## Evidence For Synthetic

- `[distribution_texture]` Identical administrative commands recur across unrelated Linux systems and users, including `/usr/bin/systemctl list-units --state=failed --no-pager`, `/usr/bin/lsof -i -P -n`, and `/usr/bin/find /etc/systemd/system -maxdepth 2 -type l`. The repetition across APP, DB, file, monitoring, mail, and web roles resembles a shared command pool more than independently accumulated operator behavior.
- `[contract_gap]` Several high-value remote-administration operations have network and target-side evidence but no corresponding client process on an endpoint that otherwise records process activity:
  - WEB-EXT opens SSH to APP-INT at approximately `14:15:04`, followed by target `sshd`, login, and shell events, but the source SSH client is not visible.
  - LT-MRIVERA initiates the RDP connection associated with the `15:19:50` Type 10 logon on WS-AJOHNSON, but no visible RDP client process accompanies the source flow.
  - WS-AJOHNSON opens SMB/RPC connections to DC-01 around `15:59`, followed by `PSEXESVC` installation and execution on the DC, but the source PsExec process is absent.
  These could result from filtering, although their concentration around consequential remote actions is mildly artificial.
- `[distribution_texture]` Linux `sysstat` activity follows a common approximately 30-minute pattern on numerous hosts. Per-host phase offsets, occasional skips, and jitter make this plausible timer behavior, but its broad uniformity is still a modest synthetic tell.
- `[distribution_texture]` SMB activity repeatedly uses generic enterprise-document vocabulary such as `meeting-notes`, `action-items`, and `project-plan`, often with `draft`, `review`, or `final` suffixes. The files are operationally plausible but have a curated, template-like long-tail distribution.
- `[weak_signal]` The same small administrative population appears in numerous interactive and remote sessions during the six-hour window. Two Aisha Johnson RDP session objects also coexist on WS-AJOHNSON after the first session is disconnected at `15:08:14` and a second starts at `15:19:50`. Disconnected-session retention explains this, so it does not constitute a contradiction.

## Evidence For Real

- Approximately 122,679 records cover 21 endpoints, three Zeek observation points, a perimeter firewall, two IDS feeds, proxy and web access logs, Linux syslog, Windows Security/Sysmon, and endpoint eCAR telemetry. The source volume and mix are credible for the visible six-hour, multi-segment environment.
- Independent Zeek sensors do not produce bit-identical copies. For 4,184 matched core/DMZ connections, the median clock difference is approximately `-114 ms`, with thousands of distinct millisecond offsets and occasional duration or packet-accounting differences. DB-sensor comparisons show different offsets. This resembles independent capture points and clocks.
- DHCP behavior is lifecycle-consistent. Forty-seven records show stable MAC/IP/hostname associations and lease renewals near half-life for 3,600-, 7,200-, and 14,400-second leases, with host-specific phase and jitter.
- TLS behavior is realistic: services generally retain stable leaf-certificate identities across handshakes, while resumed sessions often omit certificate chains. MAIL-CLIN shows two certificate identities, which is plausible for load balancing or rotation.
- Sysmon process hashes remain stable per executable and host throughout the window. Different Windows build clusters produce distinct, internally consistent version/hash groupings.
- The DC-01 Security log clear is represented coherently. Commands invoking `wevtutil cl Security` appear at `17:42:28–17:42:29`; Event ID 1102 follows at `17:42:33`, and `EventRecordID` restarts at 1 rather than continuing the prior sequence.
- Linux shell behavior contains natural imperfections. A mistyped `grroups` command lacks a successful process event, aliases such as `ll` resolve to `ls`, and a backgrounded `tail -f ... &` is represented as the executed process rather than copied literally.
- External scanning shows heterogeneous port preferences and irregular arrivals. Major scanning sources have high interarrival variation rather than fixed schedules.
- No malformed XML/JSON, impossible PID reuse, duplicate visible process creation, future object reference, or systematic dependent-before-create ordering was identified.

## Detailed Analysis

### Scope and collection profile

The data covers approximately `2024-03-18 12:00–18:00 UTC`. Twenty-one endpoint directories represent domain controllers, workstations, application and database servers, file servers, mail systems, a proxy, a monitoring server, and an Internet-facing web server.

The reviewed volume consisted of approximately:

- 32,991 eCAR endpoint records
- 29,774 Windows Security and Sysmon events
- 33,250 Zeek records across core, DMZ, and DB sensors
- 26,664 firewall, IDS, proxy, web, and syslog records

Windows Security volume is appropriately dominated by filtering-platform Event ID 5156 and Kerberos events on domain controllers. Endpoint process creation and termination are broadly balanced. Zeek contains substantial connection, DNS, HTTP, TLS, file, and SMB traffic rather than only attack-related records.

### Attack lifecycle and pivot feasibility

At `13:20:22`, DMZ Zeek observes inbound TLS from `185.70.41.45:60210` to WEB-EXT `10.10.3.10:443`, UID `C1jtztilsAHGi25w4A`, with SNI `ehr-portal.meridianhcs.com`. At `13:20:25.035`, WEB-EXT eCAR records `/bin/bash`, parented by Apache and running as `www-data`, decoding and executing a reverse shell to `45.33.32.30:8443`. Zeek records that outbound tuple at `13:20:28.694`, and endpoint telemetry attributes the corresponding flow to Bash. The process and connection lifetimes are compatible.

Later WEB-EXT root SSH sessions contain reconnaissance commands, including network configuration review, credential-file searches, and scans of `10.10.2.0/24`. At `14:15:04`, WEB-EXT connects to APP-INT over TCP/22. APP-INT then records `sshd`, inbound flow, root authentication, and shell creation between `14:15:05` and `14:15:25`.

RDP activity from LT-MRIVERA `10.10.1.99` to WS-AJOHNSON includes failed network logons followed by successful Type 3 and Type 10 authentication. The `15:19:50` Type 10 session matches an outbound RDP flow opened at `15:19:45.393`. Commands including `whoami /all`, domain-user enumeration, Domain Admins enumeration, and `net view /domain` follow.

At `15:44:39`, WS-AJOHNSON launches `ms-index-service.exe` with Mimikatz-style `privilege::debug` and `sekurlsa::logonpasswords` arguments. Sysmon/eCAR subsequently show access to `winlogon.exe`, full-access opening of LSASS, and a remote thread in LSASS at approximately `15:44:42`. The process exits shortly afterward. The access sequence and permissions are technically consistent with credential dumping.

At `15:59`, WS-AJOHNSON opens SMB and RPC connections to DC-01. DC-01 records an Aisha Johnson network logon, Event ID 4697 installing `PSEXESVC`, execution of the service binary, and a child `cmd.exe` running `whoami && hostname`. The target-side PsExec lifecycle is coherent.

DC-01 later records creation of `svc_dirsync`, addition to Domain Admins, service and scheduled-task persistence, an encoded PowerShell retrieval, Security-log clearing, and account deletion. The Security record-number reset correctly reflects the clear operation.

Data collection is also operationally coherent. DB-PROD executes `mysqldump` at `17:15:19`, creates and compresses `/tmp/rpt_0318.sql`, transfers it over SSH/SCP to APP-INT, and then stages it through SMB. Zeek SMB events report the expected filename and a consistent file size. WS-AJOHNSON separately creates an archive and uploads it through PROXY-01 at `17:25:17`.

The suspicious activity is therefore pivotable across endpoint, authentication, process, network, SMB, proxy, and server logs. I did not treat that completeness as synthetic evidence.

### Temporal and lifecycle integrity

XML events remain timestamp-ordered. Event-record gaps are compatible with filtered exports, and the one major sequence reset is explained by the visible Security-log clear.

Endpoint object-reference checks found no systematic case where dependent activity preceded a visible creation of the referenced process, session, or flow. Process identifiers were not visibly reused while prior instances remained active. A small number of terminations and logoffs lacked starts, but those are expected when active objects predate the six-hour collection boundary.

Remote-interactive ordering is generally believable: transport occurs before or around target authentication, and target shells occur after acceptance. Sensor-specific delays are small and nonuniform rather than globally fixed.

### Baseline and distribution realism

The baseline contains DHCP renewal cycles, authentication traffic, directory access, routine SMB use, web browsing, TLS, mail relay activity, scheduled services, package-management commands, and Internet scanning. Connection durations and byte counts have substantial variation. Scanner behavior differs by source and targeted service family.

The weakest distribution is human/admin vocabulary. Several diagnostic sessions appear assembled from the same compact list of commands, and generic office filenames recur more often than expected from unrelated users. These patterns are visible but not sufficiently extreme to establish generation.

### Source-native and environmental consistency

Windows logon types, LogonIDs, service-install events, account-management events, Sysmon access masks, and process ancestry are largely source-appropriate. Zeek connection states, UIDs, TLS fields, DNS transactions, SMTP relay identifiers, and SMB operation pairs are structurally coherent.

Cross-sensor observations preserve common tuples and identities while retaining realistic timestamp and packet-accounting differences. No impossible address-role assignment or source-native field value was identified.

The main collection concern is the selective absence of initiating remote-administration processes. Because the same endpoints contain substantial process telemetry, explicit observation loss or filtering would make that profile more convincing. Nevertheless, process absence within a bounded capture is not enough to classify the data as synthetic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Linux eCAR/syslog | Repeated exact diagnostic commands across unrelated hosts and users | Highest-impact synthetic tell; suggests a shared finite command pool |
| `contract_gap` | eCAR, Windows, Zeek | Missing source client processes for several SSH, RDP, and PsExec pivots despite rich target evidence | Moderate impact; possibly explained by endpoint filtering |
| `distribution_texture` | Linux process telemetry | Common 30-minute `sysstat` cadence across many hosts | Low impact because host-specific phase, jitter, and skips are present |
| `distribution_texture` | Zeek SMB/file activity | Repeated generic document stems and workflow suffixes | Low-to-moderate impact; plausible but curated-looking vocabulary |
| `weak_signal` | Windows logon/session telemetry | Reused administrator population and retained/disconnected RDP sessions | Low impact; operationally possible and not contradictory |

No `hard_contradiction` or material `schema_or_format` defect was found.

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Sysmon, Zeek, firewall, proxy, syslog, and eCAR records are source-appropriate and consistently parseable.
- **Temporal patterns:** 8 — Lifecycles and cross-source ordering are coherent, with realistic sensor skew; some scheduled/background patterns are conspicuously regular.
- **Cross-source correlation:** 8 — Pivots are technically traceable with realistic sensor differences, although several source-side client processes are absent.
- **Behavioral realism:** 7 — Attack and administrative actions work technically, but repeated command and filename vocabulary weakens the human texture.
- **Environmental consistency:** 8 — Host roles, network paths, service placement, source volume, and baseline traffic are broadly credible.

## Recommendations

- If this were synthetic, expand administrative command generation into role-, operator-, and host-history-specific behavior. Avoid repeating exact multi-command diagnostic sets across unrelated systems.
- Model a broader long tail of SMB filenames, extensions, directory depths, abandoned drafts, application lock files, and user-specific naming habits.
- Make endpoint observation policy explicit and consistent for remote-administration initiators. Either retain SSH/RDP/PsExec client-process evidence when the associated network flow is visible or introduce broader, source-coherent process-observation gaps.
- Preserve the existing sensor-specific clock skew, TLS session behavior, DHCP renewal state, Windows record-reset semantics, and lifecycle checks; these are among the strongest production-like characteristics.
- Continue varying scheduled activity by host configuration and operational history, including missed runs, delayed execution, package differences, and maintenance-driven schedule changes.
