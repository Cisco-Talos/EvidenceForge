# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 91
**Synthetic-Confidence Score:** 74

## Executive Summary

The dataset is unusually strong in process identity, lifecycle ordering, hashes, logon correlation, and Linux session detail. However, repeated source-native contradictions in Sysmon RDP process trees—combined with an RDP-specific `userinit.exe` lifecycle pattern and smaller periodic-background fingerprints—make synthetic generation substantially more likely than sanitized production telemetry.

## Evidence For Synthetic

- `[hard_contradiction]` Four RDP `userinit.exe` events report the interactive user as `ParentUser`, although their exact `ParentProcessGuid` resolves to a visible `winlogon.exe` event whose `User` is `NT AUTHORITY\SYSTEM`. Examples:
  - `WS-AJOHNSON-01.../windows_event_sysmon.xml`, 2024-03-18 15:01:35.719: PID 5956 names parent GUID `{fd907e59-574e-65f8-c700-0000d3331ea9}` and `ParentUser=MERIDIANHCS\aisha.johnson`; the parent event at 15:01:34.369 identifies that GUID as PID 5916 `winlogon.exe`, `User=NT AUTHORITY\SYSTEM`.
  - The same contradiction occurs on `WS-AJOHNSON-01` at 15:20:11.972, `MAIL-FIN-01` at 17:06:19.357, and `DC-01` at 17:09:37.716.
- `[contract_gap]` The corresponding eCAR records correctly call the RDP `winlogon.exe` parent `source_principal=SYSTEM`, directly disagreeing with Sysmon's `ParentUser`. Examples are PID 5956 on `WS-AJOHNSON-01` and PID 5348 on `MAIL-FIN-01`.
- `[contract_gap]` All four visible RDP-launched `userinit.exe` processes remain alive for implausibly long periods: approximately 1,840, 2,904, 8,766, and 9,885 seconds. By contrast, the nine paired non-RDP `userinit.exe` instances exit in approximately 3.0–5.2 seconds. The sharp source-path split suggests RDP session lifetime was incorrectly assigned to `userinit.exe`.
- `[distribution_texture]` Sysmon-to-Security process timing follows an unusually uniform collection contract: all 947 matched Sysmon Event 1 records precede their Security 4688 counterparts, always by 35–648 ms. This is possible operationally, but the invariant direction and bounded envelope across ten hosts resemble a modeled source-latency policy.
- `[distribution_texture]` Linux `CRON` records for `debian-sa1` use host-specific half-hour schedules but contain isolated 60-minute holes while other syslog activity remains continuous. Examples include `MAIL-EDGE-01` missing 13:36 and 17:06 occurrences and `WS-LNGUYEN-01` missing 14:33. Random omission of individual deterministic cron executions across several hosts is difficult to reconcile with an otherwise continuous collection profile.
- `[distribution_texture]` Windows Search child command lines have a narrow cross-host vocabulary: 25 `SearchFilterHost.exe` starts use only four argument strings—`0 804 0 0 0`, `0 812 0 0 0`, `0 820 0 0 0`, and `0 828 0 0 0`—repeated across six independent workstations. This is a weaker signal because similar handle allocation can occur naturally.

## Evidence For Real

- All 947 Sysmon Event 1 process creations matched a Security 4688 record by host, PID, image, command line, and logon ID. The four additional 4688 records without Sysmon Event 1 counterparts were isolated rather than systemic.
- No visible Sysmon process reference, parent relationship, network event, or termination used a matching ProcessGUID before its creation or after its termination.
- Security 4689 and Sysmon Event 5 records showed no image disagreements for matched PIDs.
- Hash behavior was coherent: 947 process events contained valid SHA-1, MD5, SHA-256, and import-hash sets; no image/version combination changed hashes, and no hash set was reused for a different image.
- Process trees generally followed credible Windows semantics, including `services.exe → svchost.exe`, `svchost.exe → taskhostw.exe/WmiPrvSE.exe/dllhost.exe`, `csrss.exe → conhost.exe`, and `winlogon.exe → userinit.exe → explorer.exe`.
- Workstation behavior was differentiated. Developer/admin activity included SSH, PowerShell, MMC, DBeaver, Postman, Git, compilers, and container tools, while other users showed Office, browser, collaboration, VPN, Power BI, and Citrix activity.
- Logon lifecycle evidence included service, interactive, network, unlock, new-credentials, and RDP sessions. I found no visible matching logoff before its logon. Lock/unlock pairs retained the same logon ID.
- The DC-01 Security record-number reset is naturally explained by Event 1102 at 2024-03-18 17:42:10.9908924Z: EventRecordID changes from 28261032 to 1 immediately after the audit log is cleared.
- Linux SSH evidence contains credible multi-stage sequences. On `APP-INT-01`, PID 1894405 records connection at 12:21:49.142623, public-key acceptance at 12:21:54.858457, PAM opening at 12:21:54.966436, and session closure at 13:01:25.988631.
- Bash history and eCAR process telemetry correlate sensibly. For example, Lina Nguyen's `make clean && make all` history produces separate `/usr/bin/make` processes with ordered creation and termination, as a real shell would.
- Linux syslog includes a meaningful long tail: DHCP renewal, NetworkManager changes, anacron lifecycles, sudo PAM pairs, mail queues, Dovecot sessions, package activity, log rotation, journald, desktop services, Samba auditing, and external scan noise.

## Detailed Analysis

### Process Trees and Identity

The core process graph is substantially more realistic than a simple event generator. Visible parent ProcessGUID links agree on PID, path, and command line, and no child precedes its visible parent. Background Windows families also have credible parents and security contexts.

The decisive exception is RDP `userinit.exe`. On `WS-AJOHNSON-01`, the parent GUID for PID 5956 resolves unambiguously to PID 5916 `winlogon.exe` running as SYSTEM. Nevertheless, the child event says `ParentUser=MERIDIANHCS\aisha.johnson`. The same defect appears in every visible RDP bootstrap where the parent is available, across three hosts and two users. Local interactive `userinit.exe` records do not exhibit it.

eCAR preserves the correct parent truth for these same events. Its 15:01:35.907 record for PID 5956 says `source_pid=5916`, `source_image_path=...\winlogon.exe`, and `source_principal=SYSTEM`. This makes the Sysmon value a concrete source contradiction rather than an ambiguous interpretation.

### Process Lifecycles

Most short-lived tools and infrastructure processes have plausible durations. Examples include `net.exe` around three to four seconds, ordinary `userinit.exe` around three to five seconds, and widely variable `taskhostw.exe`, `WmiPrvSE.exe`, and `dllhost.exe` lifetimes.

RDP `userinit.exe` behaves differently:

- `MAIL-FIN-01`, PID 5348: 17:06:19.358–17:36:59.720, about 30.7 minutes.
- `DC-01`, PID 5660: 17:09:37.717–17:58:01.719, about 48.4 minutes.
- `WS-AJOHNSON-01`, PID 5984: 15:20:11.973–17:46:17.668, about 146.1 minutes.
- `WS-AJOHNSON-01`, PID 5956: 15:01:35.720–17:46:20.543, about 164.7 minutes.

`userinit.exe` normally initializes the user environment, starts the shell and logon scripts, and exits. A single long instance could reflect a hung logon script, but four out of four RDP instances following this pattern—while every ordinary instance exits promptly—indicates an incorrect lifecycle contract.

### Security and Sysmon Correlation

Across ten Windows hosts, 947 Sysmon Event 1 records matched Security 4688 on PID, image, command line, and logon ID. Sysmon Event 5 and Security 4689 also showed no matched image conflicts. Hashes remained stable for each image/version pair while differing appropriately among OS versions and binaries.

ProcessGUID ordering was sound. I found no visible process-dependent Sysmon event before creation and no event after termination for the same GUID. The exact parent GUID links were similarly ordered.

The timing texture is less convincing. Every matched Sysmon process creation precedes 4688, with a bounded 35–648 ms delay. Source callbacks can create a consistent order, so this is not independently dispositive, but its dataset-wide regularity contributes modestly to the synthetic score.

### Logon and Session Evidence

Security logs contain realistic mixtures of types 2, 3, 5, 7, 9, and 10. Type 7 unlocks reuse the active logon ID, and corresponding 4800/4801 events are correctly sequenced. Network sessions generally terminate within seconds, while interactive and RDP sessions persist longer.

No impossible same-identifier logoff-before-logon relationship was found. Pre-window sessions were not penalized. RDP transport and target logons use credible remote addresses and ports, but the RDP-specific child-process attribution and `userinit.exe` lifetime defects undermine this otherwise strong lifecycle modeling.

`WS-SMARTINEZ-01` also shows two Type 2 logons for Sophia Martinez only 53 seconds apart, each producing `winlogon/userinit/explorer` activity without an intervening logoff. Concurrent local sessions can exist through session switching, so I treat this as suspicious environmental behavior rather than a hard contradiction.

### Linux and Shell Evidence

SSH authentication sequences preserve PID, source tuple, user, authentication method, PAM opening, and closure. Failed attempts include connection, invalid-user recognition, authentication failure, and pre-auth closure in credible order.

Shell history timestamps are monotonic. Compound commands are decomposed plausibly in endpoint telemetry: `make clean && make all` produces two processes, while editors, Git, Docker, Python, and administrative commands retain credible executable paths and shell parents.

The principal weakness is scheduled-background texture. The `debian-sa1` cron family is locked to one host-specific minute and a 30-minute grid, yet individual executions disappear without a visible reboot or collection interruption. The omission pattern across numerous hosts resembles probabilistic thinning of a scheduled generator.

### Endpoint Behavior and Environment

The collection contains credible OS-specific software placement: Exchange components on `MAIL-FIN-01`, administrative tools on DCs and admin workstations, Windows 10/11-era versions on endpoints, Server 2019/2022-era versions on servers, Linux mail components on mail hosts, and desktop services on Linux workstations.

User activity is not cloned wholesale. Exact bash commands rarely recur across five or more histories, timestamps vary naturally, and users exhibit differentiated tool sets. The narrow Windows Search argument vocabulary is still less entropic than expected, but it is secondary to the RDP defects.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Sysmon Event 1 | Four RDP bootstraps across three hosts | Child `ParentUser` conflicts with the visible parent ProcessGUID’s actual SYSTEM identity. |
| `contract_gap` | Sysmon and eCAR | Same four RDP bootstraps | eCAR correctly reports the parent as SYSTEM while Sysmon reports the interactive user. |
| `contract_gap` | Sysmon process lifecycle | Every visible RDP `userinit.exe` | RDP instances live 31–165 minutes; all ordinary instances exit in 3–5 seconds. |
| `distribution_texture` | Linux syslog/CRON | Multiple Linux hosts | Half-hour schedules contain isolated hour-long gaps despite continuous surrounding telemetry. |
| `distribution_texture` | Sysmon/Security timing | Dataset-wide, 947 matched creations | Sysmon always precedes 4688 inside a fixed 35–648 ms envelope. |
| `distribution_texture` | Sysmon Windows Search | Six workstations | Only four nearly identical `SearchFilterHost.exe` argument patterns cover 25 launches. |

## Realism Score by Category

- **Field format accuracy:** 8 — XML, JSON, Windows fields, hashes, and Linux messages are generally source-native, but the repeated Sysmon `ParentUser` contradiction is significant.
- **Temporal patterns:** 7 — Most ordering and durations are credible; RDP `userinit.exe` lifetimes and cron holes expose modeled timing.
- **Cross-source correlation:** 8 — Correlation is technically strong, though eCAR versus Sysmon parent-principal disagreement is concrete.
- **Behavioral realism:** 8 — User, server, shell, mail, and administrative activity is varied and operationally plausible.
- **Environmental consistency:** 8 — Host roles and software placement generally cohere; only a few session and scheduled-collection patterns stand out.

## Recommendations

If this were synthetic, here is what would improve it:

- Derive Sysmon `ParentUser` directly from the canonical parent process identity. For RDP `winlogon.exe → userinit.exe`, the child’s `ParentUser` must remain `NT AUTHORITY\SYSTEM`, matching both the parent ProcessGUID and eCAR `source_principal`.
- Give `userinit.exe` its own short initialization lifecycle rather than tying it to the RDP session or shell lifetime. Preserve long session ownership in `winlogon.exe`, `explorer.exe`, and the session record.
- Make scheduled syslog collection internally coherent. Either retain every cron execution during uninterrupted collection or model an explicit host/source outage that also affects neighboring records.
- Broaden or derive Windows Search host-process arguments from per-process state so independent hosts do not repeatedly cycle through the same four argument tuples.
- Revisit the cross-source creation-latency model. Preserve plausible provider ordering, but avoid imposing one bounded timing distribution identically across every host and process family.
