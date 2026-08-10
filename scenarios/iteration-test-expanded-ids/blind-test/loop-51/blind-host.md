# Assessment

Synthetic

# Verdict Confidence

94%

# Synthetic-Confidence Score

78/100 — likely synthetic

# Executive Summary

The host/EDR evidence is technically sophisticated and often strongly correlated, but several
repeated causal and lifecycle artifacts are difficult to reconcile with native endpoint behavior.
The decisive indicators are not neat storytelling, selected coverage, or missing pre-window
initiators. They are actor-native registry contradictions across multiple Windows hosts,
implausibly long lifetimes for one-shot commands, repeated templated maintenance behavior, and
highly curated endpoint side effects.

# Evidence For Synthetic

- Actor/registry ownership is repeatedly implausible:

  - `OUTLOOK.EXE` modifies `...\Search\SearchboxTaskbarMode` on WS-AJOHNSON-01 at
    `14:53:38.568Z`, then emits two identical writes at exactly `15:00:29.834Z` to Word's
    `Reading Locations\Document 1\Datetime`.
  - PowerShell modifies `ContentDeliveryManager\SubscribedContent-338389Enabled` and
    `InputPersonalization\...\HarvestContacts` on WS-MCHEN-01.
  - `dllhost.exe` changes `EnableLUA` on WS-AJOHNSON-01 and `ClearPageFileAtShutdown` on
    WS-EBROOKS-01.
  - Defender processes repeatedly add numbered `C:\ProgramData\Vendor\Cache\NN` exclusions
    across DC-01, FILE-SRV-01, MAIL-FIN-01, and several workstations. DC-01 alone has nine such
    writes over six hours. This resembles random effect attachment rather than stable product
    behavior.

- One-shot process lifetimes are often implausible:

  - `docker ps` on WS-LNGUYEN-01 survives 6,593 seconds.
  - `dotnet-sdk-installer.exe /install /quiet` survives 6,785 seconds.
  - `backup-check.ps1` on WS-AJOHNSON-01 survives 8,392 seconds.
  - Several `GoogleUpdater.exe -Embedding` instances persist for 4,000–9,500 seconds.
  - These are matched create/terminate pairs, so the issue is not a missing pre-window initiator
    or post-window termination.

- Scheduled/service process semantics appear selected from generic templates. Recurring
  `backup-check.ps1` and `service-health.ps1` executions are parented directly by `services.exe`
  across workstations and persist for hours, without evidence that these scripts are installed as
  long-running services.

- Windows module evidence is curated into compact reusable palettes. For example, WS-MCHEN-01
  repeatedly loads `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `ucrtbase.dll`, `rpcrt4.dll`,
  `advapi32.dll`, and `bcryptprimitives.dll` in near-startup clusters. The DLL choices are
  plausible individually, but the repeated small catalog across many unrelated processes and
  hosts is generator-like.

- Linux syslog has broad host-specific texture, yet repeatedly draws from the same conspicuous
  messages: resolver "changed features" cache flushes, rsyslog queue-health prose,
  unattended-upgrade status, and sysstat CRON pairs. The recurrence and wording across diverse
  servers is more regular and curated than ordinary collected syslog.

# Evidence For Real

- Windows XML is structurally convincing: provider metadata, versions, tasks, keywords, SIDs,
  hexadecimal PIDs/logon IDs, Sysmon UtcTime truncation, and ROT13 UserAssist paths are
  represented credibly.

- EventRecordIDs are host-specific and include nonuniform gaps. Sysmon median increments range
  from 1 to 3, and the DC Security log plausibly resets around an Event 1102 clear rather than
  remaining globally sequential.

- Cross-provider timing is not mechanically fixed. Matched Sysmon Event 1 and Security 4688
  observations vary by roughly ±20 ms on most hosts, with both provider orderings represented.

- Process and session identity is generally coherent. Parent PIDs, actor UUIDs, principals, logon
  IDs, and process object IDs usually remain stable through child activity and termination.

- SSH/SCP endpoint construction is strong. The DB-PROD-01 transfer uses the same source tuple at
  APP-INT-01, orders transport before login, assigns receiver-side `sshd` ownership, creates the
  destination file, and closes the session afterward.

- eCAR FLOW attribution is internally disciplined: rows generally have either PID, principal,
  and actor ID together or omit all three, avoiding partial actor records.

- Linux bash histories are monotonic and use plausible shell syntax, host roles, users, and
  operational commands.

# Detailed Analysis

Windows/Sysmon realism is above average. Security 4688/4689 and Sysmon 1/5 lifecycles correlate
well, and process-provider timing includes believable jitter. Security 5156 volume reflects host
role: DC-01 has 4,376 rows, while workstations have roughly 360–477. Authentication also varies
appropriately between DC/server and workstation roles.

The primary Windows failure is causal ownership. Registry events appear to be chosen from
plausible Windows keys and then attached to an arbitrary live process. That produces individually
credible Sysmon Event 13 records whose process/key relationships are not credible. The repeated
Defender exclusion mutations are particularly diagnostic because the same numbered-cache
construction recurs across unrelated hosts and Defender versions.

Process lifecycle realism is mixed. Many short Linux utilities terminate in 2–10 seconds, SSH
shells and services have reasonable longer spans, and open-at-boundary processes are not treated
as faults. However, several explicitly bounded commands remain alive for one to three hours.
These matched lifecycle pairs indicate a duration model that does not adequately distinguish
one-shot utilities, installers, scheduled scripts, and daemon-like processes.

Linux host evidence has realistic PID growth, process ownership, SSH/PAM ordering, shell
histories, and per-host CRON minute offsets. Its weakness is repeated message-family texture.
Resolver and log-forwarder status messages recur on many systems with broadly interchangeable
parameters, suggesting a shared enumerable pool rather than native daemon state.

Session/authentication evidence is one of the strongest areas. SSH login/logout counts are
generally compatible once boundary sessions are allowed, source tuples remain stable where known,
and remote command ownership is usually attached to appropriate shells or SSH processes.

# Synthetic Indicator Summary

| Indicator | Category | Strength |
|---|---|---:|
| Arbitrary process-to-registry ownership | Windows causality | Very high |
| Repeated numbered Defender cache exclusions | Windows behavior | Very high |
| Multi-hour one-shot command lifetimes | Process lifecycle | High |
| Generic services.exe script parenting | Parentage | Medium-high |
| Curated reusable DLL startup palettes | Sysmon distribution | Medium |
| Recurrent resolver/rsyslog prose across Linux hosts | Linux distribution | Medium |
| Exact duplicate Outlook registry writes | Event construction | Medium-high |

# Realism Categories

| Category | Realism |
|---|---:|
| Windows/Sysmon source-native fidelity | 7/10 |
| Process lifecycle and duration | 4/10 |
| Actor/parent/effect ownership | 3/10 |
| Session and authentication correlation | 8/10 |
| Linux/eCAR host behavior | 6/10 |

# Recommendations

1. Generate file and registry effects from executable-specific behavior contracts; never attach
   them to an arbitrary live actor.
2. Remove generic Defender exclusion churn. When exclusions change, model an explicit
   administrative or malicious initiator and preserve that process identity.
3. Use executable-aware lifetime distributions so one-shot tools terminate promptly unless a
   modeled stall or long-running operation explains otherwise.
4. Distinguish Task Scheduler, Windows service, WMI, and interactive launch parentage instead of
   broadly using `services.exe`.
5. Expand Windows module observation by process family and collection policy, with incomplete and
   host-specific coverage rather than compact repeated catalogs.
6. Drive resolver, rsyslog, journald, and update messages from host state transitions and suppress
   repetitive cross-host template reuse.
