# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 84

## Executive Summary

The endpoint telemetry preserves process identifiers, session lifecycles, hashes, and cross-source relationships unusually well, but several dataset-wide artifacts indicate generation rather than production collection. The strongest signals are an unrealistic Windows process-volume/profile, missing browser and Electron subprocess trees, uniformly bounded Security-log thread identifiers, highly homogenized PE version metadata, and repeated Linux background-event quotas.

## Evidence For Synthetic

- `[contract_gap]` The Windows process population is implausibly sparse given the visible applications. Ten Windows hosts contain only 992 Sysmon Event 1 records over approximately six hours—16.5 creations per host-hour; the six workstations average only 13.4 per hour. Thirty-nine launches of Chrome, Edge, Firefox, Teams, Slack, Webex, Postman, Dropbox, or Google Drive produce no normal renderer, GPU, crash-handler, updater, or utility subprocess population.
- `[contract_gap]` Fresh interactive sessions demonstrate the missing-process problem directly. On `WS-SMARTINEZ-01`, a new `userinit.exe → explorer.exe` session at `12:08:26Z` launches Chrome at `12:11:29Z`, Webex at `12:36:12Z`, and Slack at `12:39:26Z`, but no normal children of those applications appear in Security 4688, Sysmon Event 1, or eCAR PROCESS/CREATE. Similar behavior follows the `13:43:00Z` login on `WS-PPATEL-01`.
- `[distribution_texture]` Security-event `Execution ThreadID` values show a repeated bounded-random texture. For events attributed to PID 4, each host uses hundreds of distinct thread IDs—382 to 807 unique values—spread across nearly the same 0-to-4,000,000 range; host maxima cluster between 3,955,384 and 3,999,720. This is unlike a stable set of kernel/LSASS audit workers and resembles independent draws from a fixed generator range.
- `[schema_or_format]` PE version metadata is nearly host-wide rather than file-specific. Of 850 Sysmon process creations under `C:\Windows`, 787 report one base-build `.1` version: `10.0.17763.1`, `10.0.19041.1`, `10.0.20348.1`, or `10.0.22621.1`. Real patched systems normally retain more file-level revision diversity.
- `[schema_or_format]` Known Windows binaries have selective catalog-like metadata gaps. All three observed `C:\Windows\System32\runas.exe` executions and all three `C:\Windows\System32\curl.exe` executions have `FileVersion`, `Company`, `OriginalFileName`, and `Hashes` set to `-`, even though Sysmon successfully hashes neighboring system binaries.
- `[distribution_texture]` Ten of the eleven syslog-producing hosts have exactly two `systemd-resolved` “Using degraded feature set” messages and exactly two “Grace period over” messages; `DB-PROD-01` has zero of each. The identical per-host quota across workstations, mail servers, proxy, web, file, application, and monitoring roles is stronger than a shared-network explanation.
- `[distribution_texture]` For 984 process creations matched across all three Windows sources, Sysmon precedes Security 4688 every time, with a tightly bounded 35–1,226 ms delay. Consistent source precedence is possible, but its dataset-wide bounded shape adds to the generator-like timing texture.
- `[environment_or_collection_plausibility]` An isolated process relationship is difficult to reconcile with ordinary user execution: at `2024-03-18T14:06:27.7336990Z`, `WS-MCHEN-01` records Firefox PID 7712 spawning `runas.exe /netonly /user:marcus.chen-admin "cmd.exe /c dir \\WEB-EXT-01\ADMIN$"`. Security 4688 and eCAR repeat that parent relationship, suggesting a common modeled parent rather than a source parser error.
- `[weak_signal]` Windows user activity draws from a conspicuous catalog of single-instance top-level applications and administrative commands. The role differentiation is good, but the absence of the normal process noise belonging to those applications makes the catalog visible.

## Evidence For Real

- The core Windows process correlations are strong. All 992 Sysmon Event 1 records have unique ProcessGUIDs, and no child references a known parent created later or a parent already terminated.
- Security 4688 and Sysmon Event 1 agree on PID, image, command line, and parent image for every matched process. Of 992 Sysmon process creations, 991 have a matching 4688 within five seconds; the unmatched cases are sparse and source-loss-like rather than systematic.
- eCAR identity relationships are internally sound. No examined `actorID` points to a later visible process creation, no process termination precedes the matching creation, and event IDs are unique.
- The `DC-01` Security-log clear is modeled convincingly: Sysmon records `cmd.exe → wevtutil.exe` at `17:42:03Z`; Security 4688 records both processes; Event 1102 follows at `17:42:07.0971028Z` with `EventRecordID=1`; subsequent records continue from 2.
- Hashes are consistent for the same visible binary and version. The only cross-host multi-hash case is `MpCmdRun.exe` with an unavailable version, which is explainable by different Defender platform builds.
- Lock and unlock lifecycles are credible. On `WS-PPATEL-01`, logon ID `0xd980fcc` is locked at `14:32:24Z`, receives a type-7 logon at `14:52:48Z`, and is unlocked at `14:52:49Z`; equivalent sequences occur on `WS-MCHEN-01`, `WS-SMARTINEZ-01`, and `WS-AJOHNSON-01`.
- RDP sessions have plausible durations and disconnection/logoff behavior. For example, `MAIL-FIN-01` records Marcus Chen type-10 sessions lasting roughly 29–43 minutes, with intervening 4779 disconnect events.
- Linux SSH sessions contain realistic connection, authentication, PAM, `systemd-logind`, and closure sequences. User key fingerprints remain stable across hosts: Aisha Johnson uses the same RSA key, Marcus Chen the same ECDSA key, and Priya Patel the same RSA key.
- Linux background PIDs persist correctly while transient PIDs advance, and cron activity such as the `sysstat` jobs at minutes 1 and 31 is source-native and believable.
- User roles are meaningfully differentiated: Aisha Johnson uses MMC, RDP, SSH, and PowerShell administration; Marcus Chen uses VS Code, Postman, PostgreSQL tools, and remote administration; Diego Ramirez uses Power BI, Excel, and collaboration tools.

## Detailed Analysis

### Process Trees and Volume

The dominant Windows trees are individually plausible: `services.exe → svchost.exe`, `svchost.exe → WmiPrvSE.exe`, `smss.exe → winlogon.exe → userinit.exe → explorer.exe`, and `csrss.exe → conhost.exe`. Known parent ProcessGUIDs resolve correctly, and there are no visible children created after the corresponding parent termination.

The defect is population-level. The six Windows workstations produce only 484 process creations across 36 host-hours. Modern browsers and Electron applications are explicitly launched but their mandatory multi-process populations are absent. Across 39 relevant top-level launches, only two later processes have one of those applications as parent; neither is a normal browser renderer/helper relationship. This is more than generic thin coverage because the included top-level launch requires companion processes under the same enabled process-creation event families.

`WS-MCHEN-01` also contains the anomalous Firefox-to-`runas.exe` relationship at `14:06:27Z`. The parent GUID is internally consistent, so this is not a dangling reference; it is a behavior-model problem.

### Logon and Session Lifecycles

Security 4624/4634 lifecycles are generally coherent. Network logons commonly last seconds, while interactive and RDP sessions last tens of minutes to hours. Orphan logoffs close sessions that can reasonably predate the window and were not treated as defects.

Lock/unlock activity is particularly convincing because 4800, type-7 4624, and 4801 events preserve the same user, logon ID, and terminal session. Linux SSH evidence likewise maintains the expected order from connection through PAM and `systemd-logind` removal.

One caveat is that interactive Sysmon Event 1 records frequently carry an all-zero `LogonGuid`, including processes created under visible successful sessions. This can occur on Windows and was therefore not scored independently, but the prevalence reduces the usefulness of that correlation field.

### Security, Sysmon, and eCAR Correlation

Process creation correlation is a strength. PID, image, command line, and parent image match across the major sources, while sparse one-source omissions prevent the data from looking mechanically identical.

The `DC-01` audit-log clear demonstrates correct visible causality and record-ID reset behavior. eCAR object lifecycles likewise contain no actor-after-activity or termination-before-create contradictions.

The cross-source latency distribution is less organic. Security 4688 follows Sysmon Event 1 for all 984 triple-matched creations, with a minimum delay near 35 ms and most delays below 650 ms. This is not impossible, but in combination with the other bounded distributions it resembles source-specific synthetic jitter.

### Windows Field and Collector Realism

Event IDs, versions, tasks, keywords, and most native payload fields are accurate. Sysmon’s own `Execution ProcessID` remains constant per host and uses only a few thread IDs, as expected for a service process.

Security XML behaves differently: PID 4 alone is associated with hundreds of distinct, mostly non-repeating thread IDs on every host, drawn across a nearly identical four-million-value range. For example, `WS-AJOHNSON-01` has 711 PID-4 events using 484 distinct thread IDs, while `DC-02` has 3,974 such events using 807. The repeated ceiling across unrelated hosts is a strong synthetic distribution fingerprint.

The PE metadata is also overly normalized. Nearly every Windows component on a given host reports the OS base-build `.1` version. Additionally, core binaries such as `runas.exe` and `curl.exe` lose all metadata and hashes while surrounding events retain them, which looks like missing entries in an executable catalog.

### Linux and Bash Evidence

SSH and sudo records are well structured, with plausible authentication delays, stable user IDs, changing session PIDs, and correct open/close ordering. Bash histories vary substantially in length and contain role-specific work: Lina Nguyen uses Git and Docker, Marcus Chen performs operational diagnostics, and Omar Haddad uses Python and pandas.

The main Linux defect is repeated background-event allocation. Exactly two degradation and two recovery messages occur on ten distinct hosts, despite role and volume differences. Examples include `FILE-LNX-01` at `12:02:58Z`, `12:06:27Z`, `12:10:18Z`, and `12:11:15Z`, and `MAIL-EDGE-01` at `12:00:34Z`, `12:03:53Z`, `12:08:03Z`, and `12:09:40Z`. Individual sequences are possible; the identical quota across the fleet is not production-like.

### Overall Weighting

There are no decisive impossible timestamps or broken identifier lifecycles. Nevertheless, the browser-process contract gap, uniformly sparse Windows process population, repeated Security-thread-ID ceiling, homogeneous PE metadata, and fixed Linux background-event quotas affect multiple hosts and source families. Their combined scope outweighs the otherwise excellent source formatting and correlation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `contract_gap` | Security 4688, Sysmon 1, eCAR PROCESS/CREATE | All Windows workstations | Visible fresh browser/Electron launches lack required helper and renderer process populations across all three endpoint sources. |
| `distribution_texture` | Windows Security XML | All 10 Windows hosts | PID-4 thread IDs use hundreds of near-unique values with the same approximately 4,000,000 ceiling on every host. |
| `schema_or_format` | Sysmon Event 1 | All Windows hosts | PE versions collapse to base-build `.1`; selected core binaries consistently lack metadata and hashes. |
| `distribution_texture` | Linux syslog | 10 of 11 syslog hosts | Every affected host receives exactly two resolver degradation and two recovery records. |
| `environment_or_collection_plausibility` | Sysmon, Security, eCAR | `WS-MCHEN-01` | Firefox is recorded as the parent of an interactive administrative `runas.exe` command. |
| `distribution_texture` | Security/Sysmon/eCAR timing | Dataset-wide | All matched Security process events follow Sysmon within a narrow positive-delay envelope. |

## Realism Score by Category

- **Field format accuracy:** 6 — Native XML and JSON shapes are strong, but thread-ID texture and PE metadata gaps are conspicuous.
- **Temporal patterns:** 7 — Session and process causality is good, while fixed source ordering and repeated Linux event quotas reduce realism.
- **Cross-source correlation:** 9 — Process, session, parent, and eCAR identities correlate extremely well without visible impossible ordering.
- **Behavioral realism:** 5 — Roles and administrative workflows are differentiated, but multi-process application behavior is substantially absent.
- **Environmental consistency:** 5 — Host roles are recognizable, but endpoint process volume and fleet-wide background distributions are not production-like.

## Recommendations

- If this were synthetic, generate complete process families for visible browser and Electron launches, including renderer, GPU, utility, crash-handler, updater, and application-specific helper processes. Ensure Security 4688, Sysmon Event 1, and eCAR observe those children according to a documented collection profile.
- Model Windows process volume from real per-role distributions. The current 13.4 workstation process creations per host-hour should be replaced with higher-volume activity containing bursts, short-lived helpers, and a meaningful long tail.
- Replace bounded-random Security `Execution ThreadID` generation with per-host thread allocation and reuse tied to the emitting process. Avoid a common fleet-wide ceiling.
- Populate PE metadata from file- and build-specific profiles rather than one host-wide OS version. Core binaries such as `runas.exe` and `curl.exe` should retain realistic version, company, original filename, and hash fields.
- Drive Linux resolver degradation from shared network state or host-specific resolver behavior rather than allocating an identical number of messages to each host.
- Constrain parent selection by executable behavior. Interactive commands such as `runas.exe` should originate from `cmd.exe`, PowerShell, Explorer, or another source justified by a visible shell/protocol-launch relationship.
- Add collection-profile validation that compares visible top-level applications with required companion processes and checks that source-specific filtering does not self-contradict the observed event population.