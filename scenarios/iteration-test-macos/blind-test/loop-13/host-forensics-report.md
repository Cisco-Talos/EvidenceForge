# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 62

## Executive Summary

The macOS endpoint evidence has convincing native process ancestry, user/session ownership, and useful alignment among shell history, eCAR, Endpoint Security, and Unified Log records. Two repeated timing patterns across the paired Macs—the nearly identical SSH command-to-authentication delays and the near-parallel root inventory-plist create/remove lifecycle—are concrete distribution cues that make the records look generated, but they are not hard contradictions.

## Evidence For Synthetic

- [distribution_texture] Reciprocal SSH sessions have nearly the same long client-start-to-server-authentication delay. On MAC-MROSS-01, eCAR records `ssh maya.ross@MAC-MROSS-02.meridianhcs.local` at 2026-11-02 14:24:23.188Z; MAC-MROSS-02 Unified Log records accepted keyboard-interactive auth at 14:24:42.089Z and eCAR records its SSH login at 14:24:42.956Z. In the reverse direction, MAC-MROSS-02 eCAR records `ssh -tt maya.ross@MAC-MROSS-01.meridianhcs.local` at 16:02:03.767Z; MAC-MROSS-01 Unified Log records accepted public-key auth at 16:02:22.832Z and eCAR records login at 16:02:23.413Z. Both source-to-auth gaps are about 19 seconds. This is possible, but the close match in both directions is an unusually regular pattern for separate LAN sessions.
- [distribution_texture] Both Macs have a root `/bin/sh` process create and later delete the same `/Library/LaunchDaemons/com.meridianhcs.endpoint-inventory.plist`. On MAC-MROSS-01, PID 43379 appears at 13:19:31.118Z, creates the file at 13:21:50.342Z, and deletes it at 18:41:16.391Z. On MAC-MROSS-02, PID 19699 appears at 13:19:34.582Z, creates it at 13:22:52.904Z, and deletes it at 18:41:42.829Z. The mirrored schedule and multi-hour interval are conspicuous. The records establish file creation and deletion only; they do not establish launchd registration, activation, or unload.

## Evidence For Real

- The local session evidence is internally plausible. MAC-MROSS-01 eCAR records a successful `maya.ross` local login at 13:02:57.540Z, matching its loginwindow workspace message at 13:02:57.640Z. MAC-MROSS-02 has the same pairing at 13:03:45.839Z and 13:03:45.961Z.
- The interactive process trees use plausible macOS paths and ownership. MAC-MROSS-01 shows launchd/xpcproxy launching Terminal, followed by `/usr/bin/login` and `/bin/zsh`; MAC-MROSS-02 shows iTerm2/iTermServer, `/usr/bin/login`, ShellLauncher, and `/bin/zsh`. The per-user shells own expected utilities such as `id`, `sw_vers`, `ls`, `find`, and `cat`.
- The two SSH sessions have strong host-side correlation. MAC-MROSS-01’s incoming SSH session from `10.10.1.42:53121` has eCAR login ID `0x894805e`, an SSH process/session tree, and logout at 16:18:12.888Z. The source MAC-MROSS-02 has the corresponding SSH command at 16:02:03.767Z. In the other direction, MAC-MROSS-02 records an incoming session from `10.10.1.41:53075`, with matching Unified Log authentication and logout at 14:35:08.047Z; MAC-MROSS-01 has the corresponding client command at 14:24:23.188Z.
- The host’s shell history corroborates concrete process activity rather than merely resembling it. MAC-MROSS-02’s `maya.ross.zsh_history` records `sw_vers -productVersion` at epoch 1793625108, aligning with eCAR’s `sw_vers` process at 13:11:48.991Z. Endpoint Security also records the shell child/exec sequence for this activity.
- Session and process lifecycles are visible and plausible: the SSH sessions have user shells and later logouts, and the local sessions have later logouts. Short-lived command processes have termination records. The different eCAR logon IDs for local and SSH sessions distinguish their ownership.

## Detailed Analysis

### Scope and source interpretation

The reviewed host data contains two macOS hosts, MAC-MROSS-01 and MAC-MROSS-02, each with normalized eCAR, macOS Endpoint Security NDJSON, and macOS Unified Log NDJSON; MAC-MROSS-02 also has a `maya.ross` zsh history. The records cover 2026-11-02, approximately 13:00–18:57Z. I treat eCAR as normalized endpoint telemetry, Endpoint Security as event notifications with audit-token/process identity, Unified Log as a separate native log stream, and shell history as command history. These sources have distinct semantics.

### Process ownership and lifecycle

The local interactive sequences are credible. On MAC-MROSS-01, PID 42233 transitions from launchd/xpcproxy to Terminal at 13:08:27Z; PID 42234 runs `/usr/bin/login`; PID 42235 becomes `/bin/zsh` as `maya.ross`. On MAC-MROSS-02, PID 18959 launches iTerm2 and its server; PID 18961 runs `/usr/bin/login`; PID 18962 becomes the user's zsh. Commands are forked from the respective shells and generally terminate shortly after execution. The process start-to-command and command-to-exit intervals vary, rather than being uniformly identical.

Endpoint Security records on MAC-MROSS-02 include 164 events: 64 exec, 53 fork, and 47 exit notifications. For example, the SSH client shell child (PID 45528) is visible in the ES stream around 16:02:03Z and in eCAR at 16:02:03.767Z. This supports identity and timing continuity. Exact cross-source matching is positive evidence of usable correlation, not a synthetic clue by itself.

### SSH session correlation and timing

Both reciprocal SSH paths have coherent IP/user/session ownership and shell activity. MAC-MROSS-02 accepts a session from MAC-MROSS-01 (`10.10.1.41:53075`) at 14:24:42Z; its Unified Log says keyboard-interactive/PAM and its eCAR session is `maya.ross`, type `ssh`, ID `0x138a1df9`. The spawned `/bin/zsh` runs under that ID, and the session logs out at 14:35:08Z. MAC-MROSS-01 accepts a session from `10.10.1.42:53121` at 16:02:23Z; the Unified Log says public key, the eCAR login is type `ssh` with ID `0x894805e`, and the session logs out at 16:18:12Z.

The suspicious point is timing texture, not correlation completeness: in both directions, the client command precedes accepted authentication by about 19 seconds. The similar delay is a weak-to-moderate synthetic signal because it is repeatable across two separate sessions, although SSH negotiation, authentication policy, or collection timing can produce delays.

### File and launch-item observations

The eCAR records show the same root shell PID creating and deleting the endpoint-inventory plist on both Macs. The two create events occur around 13:22Z and both removals occur around 18:41Z. A several-hour shell lifetime and near-mirrored actions merit scrutiny as distribution texture. The visible evidence does not show plist contents, a launchd bootstrap/registration, activation, or unload, so I do not infer any of those steps or treat their absence as a lifecycle contradiction. The shell process's parent PID is not otherwise visible in the reviewed records; a missing initiator outside the visible collection window is not itself a defect. No visible dependent file action precedes its corresponding shell process.

### Collection limits and scoring rules

Unified Log exports are sparse relative to eCAR and Endpoint Security, but the visible SSH authentications have matching native log entries, and the local workspace messages align with successful logins. Thin Unified Log coverage alone is not scored: the reviewed records do not establish an unrealistic source-volume distribution, a missing companion required by visible activity, or a contradictory collection profile. An initiator absent because it predates the visible window is not a defect; a visible initiator ordered after its dependent event would be a valid finding. I found no such visible inversion. I also do not use narrative linearity or lifecycle completeness as a score driver.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | eCAR + macOS Unified Log | Two reciprocal SSH sessions across both Macs | Each client command precedes server authentication by about 19 seconds, with closely matching delays in both directions. Possible, but unusually regular. |
| `distribution_texture` | eCAR process and file events | Same root inventory-plist activity on both Macs | Similar root `/bin/sh` lifecycles create the same plist near 13:22Z and remove it near 18:41Z. This is suspiciously mirrored, but not an impossible sequence. |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Observed macOS paths, eCAR session fields, Endpoint Security audit tokens, and Unified Log timestamps are structurally plausible.
- **Temporal patterns:** 7/10 — Most process/session sequences are coherent; the mirrored approximately 19-second SSH authentication delays and paired plist schedule reduce realism.
- **Cross-source correlation:** 9/10 — Client commands, remote auth, source IPs, session IDs, process trees, and shell history align. Matching alone is not counted against authenticity.
- **Behavioral realism:** 7/10 — Interactive utilities, user-owned shells, and reciprocal SSH are plausible; the repeated inventory-plist routine is conspicuous.
- **Environmental consistency:** 8/10 — The two Macs have credible macOS user sessions and application/process ancestry. The inventory activity is possible but its mirrored timing is unusual.

## Recommendations

If this were synthetic, vary SSH client-to-auth timing across separate sessions so both directions do not produce nearly the same ~19-second interval. Vary or further substantiate the paired inventory-plist activity across the two hosts; the current evidence shows only similar root-shell file creation and removal, so any added records should represent actual observed transitions rather than imply registration or activation from file writes alone.
