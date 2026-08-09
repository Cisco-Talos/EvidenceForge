# Host/EDR — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 92
**Synthetic-Confidence Score:** 85

## Executive Summary

The corpus is source-aware and internally coordinated, but several log-visible artifacts are
difficult to reconcile with authentic endpoint collection.

The strongest defect is a fully visible local-login process tree on `PROXY-BO-01` that has no
corresponding session-open record in either eCAR or syslog: `/bin/login` PID `527891` creates Bash
PID `527892` at 14:04 UTC, the shell executes commands for almost three hours, and eCAR records a
session logout at 16:59:15.866, yet no `USER_SESSION/LOGIN`, PAM login-open, or logind new-session
event exists for Logon ID `0x549343f` / session `80370`. This cannot be explained by a pre-window
initiator because the login process itself begins inside the window.

Additional high-weight indicators include simultaneous same-user Windows Type 2 sessions
attributed to one `winlogon.exe` PID despite distinct terminal session IDs; repeated millisecond-
perfect eCAR module-load templates across unrelated applications; Windows SYSTEM LUID `0x3e7`
applied broadly to Linux processes; improbable workstation software inventories; and extremely
repetitive Linux background-message distributions.

The data nevertheless demonstrates substantial realism: Windows XML schemas are generally
accurate, GUID/PID lifecycles are coherent, process ancestry is consistent, eCAR object identities
survive termination correctly, successful SSH endpoint flows precede authentication, and source
volumes differ credibly by host role.

## Evidence For Synthetic

- **contract_gap — visible local session has only a logout.** PROXY eCAR records `/bin/login` PID
  `527891` at `2024-05-14T14:04:43.166Z`, Bash PID `527892` at `.551Z`, many commands in Logon ID
  `0x549343f` / session `80370`, both process terminations at 16:59:15, and `USER_SESSION/LOGOUT` at
  `.866Z`. Neither eCAR nor syslog contains its opening. A later local login does contain explicit
  opening evidence, making the asymmetry conspicuous.

- **hard_contradiction — one winlogon PID owns concurrent distinct console sessions.** On
  `WS-NKAPOOR-01`, Type 2 sessions `0x847177c` and `0x8485238` use terminal session IDs 4 and 3 and
  overlap, but both 4624 rows use winlogon PID `0x1730`. On `WS-OREED-01`, overlapping terminal
  sessions 5 and 2 both use PID `0x9ac`. Winlogon is session-specific.

- **distribution_texture — fixed millisecond module templates.** On `WS-NKAPOOR-01`, unrelated
  SSH and OneDrive processes load the same ordered nine core modules at almost perfectly
  alternating 2–3 ms increments. The exact tuple occurs 44 times on that endpoint; 55 process
  groups have at least five module events within 30 ms. Similar templates recur across unrelated
  products and hosts.

- **schema_or_format — Windows LUID leaked into Linux semantics.** Linux eCAR repeatedly uses
  `logon_id="0x3e7"`, Windows' well-known Local System LUID, for sysstat, shell, Java, and other
  Linux processes. WEB has 150 such records and PROXY has 77.

- **environment_or_collection_plausibility — implausible endpoint software mixtures.** Workstations
  combine multiple competing VPN/security and file-sync stacks, while several ordinary user
  workstations run the server-oriented Veeam Backup & Replication service.

- **distribution_texture — implausibly chatty canned Linux subsystems.** WEB produces roughly 120
  messages each from irqbalance, rsyslogd, and systemd-resolved plus 107 snapd records in six hours.
  One stable rsyslog PID repeatedly reports reload completion and journal-socket acquisition.

- **distribution_texture — synthetic scan personalities.** WEB contains 864 UFW blocks dominated
  by eight recurring sources, each with invariant packet length and TTL and a narrow service family.

- **contract_gap — one successful external SSH lacks endpoint FLOW.** A successful WEB SSH session
  from `185.199.110.42:50542` has connection, auth, PAM, logind, process, and session evidence but no
  eCAR FLOW for the exact tuple. All 31 peer tuples have FLOW, so this is supporting rather than
  decisive evidence because a single drop remains possible.

## Evidence For Real

- Windows Security and Sysmon XML structures are generally source-native.
- No Sysmon dependent references a known process before creation or after termination; eCAR actor
  lifetimes and object IDs are likewise coherent.
- Parent-child ancestry is consistent, including Linux pipelines.
- All matching successful SSH endpoint flows precede authentication on WEB and PROXY.
- Windows source timing has bounded, non-identical cross-provider skew.
- Source volumes differ credibly by host role.
- Bash histories correlate with endpoint processes and include credible mistakes.

## Detailed Analysis

Windows lifecycle handling is the strongest component. Security 4688, Sysmon Event 1, and eCAR
PROCESS/CREATE agree on PIDs, images, users, parents, and broadly contemporaneous timestamps.
Sysmon ProcessGuids retain host-specific identity across dependent event types, and terminations do
not precede dependents.

The weakness lies above individual events. Interactive-session allocation uses distinct terminal
session IDs but projects one fixed host-level winlogon PID. Newly visible Type 2 logons also lack a
fully visible userinit/explorer startup chain, a lower-confidence supporting gap. Linux SSH bundles
are generally strong, but the local-session path materializes an in-window login process for a
session whose opening is absent.

eCAR object ownership is internally excellent, but its module behavior is conspicuously generated.
Common modules are emitted as reusable ordered lists with fixed short spacing and application-
specific suffixes. The Windows software inventory is individually plausible yet collectively
incoherent. Linux syslog text is syntactically credible but statistically resembles weighted
message-pool sampling; scan traffic shows similarly fixed personas.

## Synthetic Indicator Summary

- **High — contract_gap:** in-window PROXY local-login lifecycle lacks its opening.
- **High — hard_contradiction:** one winlogon PID owns concurrent terminal sessions.
- **High — distribution_texture:** repeated fixed eCAR DLL sequences at 2–3 ms cadence.
- **Medium-high — schema_or_format:** Linux processes reuse Windows SYSTEM LUID `0x3e7`.
- **Medium-high — environment_or_collection_plausibility:** competing endpoint stacks and server
  backup services on workstations.
- **Medium — distribution_texture:** repetitive daemon and scanner populations.
- **Low-medium — contract_gap:** one successful external SSH session lacks endpoint FLOW.
- **Weak:** smooth bounded cross-source delays may be sampled jitter.

## Realism Score by Category

- **Field format accuracy:** 7/10
- **Temporal patterns:** 5/10
- **Cross-source correlation:** 7/10
- **Behavioral realism:** 4/10
- **Environmental consistency:** 4/10

## Recommendations

- Keep pre-window local-session parents before the collection boundary, or emit a matching opening
  whenever an actual in-window local login is created.
- Use one session-owned winlogon identity per concurrent terminal session.
- Replace fixed DLL lists and millisecond sequences with process/profile-specific observations and
  more natural timing and filtering.
- Use Linux-native session identifiers for Linux system activity.
- Model coherent managed software profiles, state-derived daemon messages, and broader scanner
  populations.
- Validate successful SSH transport evidence against the configured observation contract.
