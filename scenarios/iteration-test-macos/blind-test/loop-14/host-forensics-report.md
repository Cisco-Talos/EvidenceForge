# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 87  
**Synthetic-Confidence Score:** 66

## Executive Summary

The endpoint evidence is structurally coherent across the two Macs: fork/exec transitions, user identities, shell sessions, and several SSH connections line up across eCAR, Endpoint Security, Unified Log, and shell history. The strongest synthetic signals are repeated, near-identical LaunchDaemon workflows on both Macs and unusually repetitive shell histories, including `cat` against Office/PDF files. These are concrete distribution and environmental-pattern concerns, while the observed process ordering and cross-source matches themselves are not suspicious.

## Evidence For Synthetic

- [distribution_texture] Both Macs show the same unusual `com.meridianhcs.endpoint-inventory` LaunchDaemon lifecycle. On `MAC-MROSS-01`, eCAR records `/bin/sh` PID 43379 creating `/Library/LaunchDaemons/com.meridianhcs.endpoint-inventory.plist` at 13:21:50 UTC, `xpcproxy com.meridianhcs.endpoint-inventory` running `/usr/bin/sw_vers` at 13:31:02, 15:15:46, and 17:38:37, and PID 43379 deleting the plist at 18:41:16. On `MAC-MROSS-02`, `/bin/sh` PID 19699 creates the same path at 13:22:52, corresponding xpcproxy jobs run `sw_vers` at 13:43:30, 15:46:46, and 17:51:41, and the same shell PID deletes the plist at 18:41:42. The repeated same-day install, periodic execution, and removal sequence on both hosts is a notable repeated texture. The name and `sw_vers` action could fit an internal inventory task, so this is not proof of an impossible launchd workflow.
- [distribution_texture] The two `zsh_history/maya.ross.zsh_history` files reuse a narrow set of nearly identical host-inspection commands (`id`, `sw_vers`, `uname`, `ps`, `df`, `find`, `dscl`, `pwd`, and repeated listings/size checks of Documents) throughout the roughly six-hour period. Both histories also show `/bin/cat` used on `.pdf` and `.xlsx` files, for example Mac 01 at 14:43:41 (`/Volumes/Users/Documents/contacts.xlsx`) and Mac 02 at 16:54:06 (`/Volumes/ClinicalResearch/Archive/status-update-review.pdf`). These commands are possible, but the repeated command pool and repeated raw `cat` treatment of binary office documents look templated rather than like varied everyday workstation activity.
- [environment_or_collection_plausibility] The identical LaunchDaemon sequence has a weakly explained actor: in both eCAR streams a root `/bin/sh` process creates and later removes the plist, while the recorded command line is only `/bin/sh`. The event data shows executions of `sw_vers`, but does not show the script/configuration contents that would establish why the same temporary inventory daemon is installed and removed on both Macs. This could be a real management workflow, but it is an unusually specific repeated lifecycle in the visible endpoint evidence.

## Evidence For Real

- On `MAC-MROSS-01`, Endpoint Security records a plausible Terminal startup at 13:08:26 UTC: launchd forks PID 42233; exec transitions that PID through `xpcproxy` to Terminal; Terminal forks `/usr/bin/login`; login forks and execs `/bin/zsh` as Maya Ross. eCAR records the corresponding process lineage and user identity. This correctly treats the successive executable images as one PID's exec transitions.
- On `MAC-MROSS-02`, eCAR records an SSH session from `10.10.1.41:53075`; Unified Log records `Accepted keyboard-interactive/pam for maya.ross from 10.10.1.41 port 53075 ssh2` at 14:24:42.089 UTC, and eCAR records the successful session at 14:24:42.956. The client flow and port correspond to the visible connection. The session later has a matching logout at 14:35:08.
- A second SSH flow is represented as client activity on Mac 02 and server activity on Mac 01. Mac 02 records an `ssh` process and client flow toward `MAC-MROSS-01`; Mac 01 records an accepted SSH session from `10.10.1.42` and its server-side process chain. The relationship is technically plausible across the two endpoint records.
- Endpoint Security records on both Macs use nested `fork`, `exec`, and `exit` event payloads, audit tokens, PID versions, executable paths, and signing metadata. The sample process paths and parent relationships include expected macOS actors such as `launchd`, `xpcproxy`, Terminal/iTerm, `login`, `zsh`, Chrome helpers, and `sshd` components. I do not see an impossible process-parent relationship in the reviewed sequences.
- The visible eCAR local logons and logoffs are paired for the main Maya sessions (`0x87e130d` on Mac 01 and `0x137ffa99` on Mac 02). Mac 02 also shows a separate Lina Nguyen local session, which has its own logon ID and later logout. The separate identity/session values are plausible for a shared or switched workstation.
- The eCAR exports contain network activity beyond the suspicious workflows: both Macs show substantial proxy traffic to `10.10.3.20:8080`, internal DNS, directory, Kerberos, SMB, and syslog traffic. App launches include Chrome, Zoom, Slack, and Microsoft Office. Their presence provides ordinary endpoint context and is consistent with an enterprise environment.

## Detailed Analysis

### Scope and endpoint sources

The data includes two macOS endpoints, `MAC-MROSS-01` (`10.10.1.41`) and `MAC-MROSS-02` (`10.10.1.42`), each with an eCAR stream, Endpoint Security NDJSON, Unified Log NDJSON, and Maya Ross shell history. The Endpoint Security files contain 140 and 164 rows respectively, with visible fork, exec, and exit event payloads. Unified Log is sparse (3 rows on Mac 01, 2 on Mac 02), so its silence outside those records is not treated as a missing-event defect. The eCAR streams contain 574 and 598 rows, mostly FLOW and PROCESS records.

### Process and user-session lifecycle

The Mac 01 local login is recorded in eCAR at 13:02:57.540 UTC with `logon_id=0x87e130d`. The visible Terminal process chain begins at 13:08:26, several minutes later, which is consistent with opening Terminal after an already-established desktop session. The shell history begins with `id`, `sw_vers`, and `uname`; the EDR stream includes those commands under the `zsh` parent. The gap before the Terminal chain is not a dependent-after-initiator contradiction.

The Mac 02 local and SSH activity similarly has plausible ownership. At 14:24:42, the accepted SSH session from Mac 01 is followed by `sshd-session`, an auth/session child, and a Maya-owned `zsh`. eCAR records commands under that shell and a logout at 14:35:08. The local Maya and Lina sessions have distinct logon IDs; their later logout records match their respective local sessions. I did not treat complete PID, port, or session matching as synthetic evidence.

### Repeated LaunchDaemon workflow

The strongest environmental pattern is the repeated `com.meridianhcs.endpoint-inventory` workflow. On Mac 01, eCAR records the plist write at 13:21:50.342 and the first visible xpcproxy invocation at 13:31:02.616, followed by more invocations later in the collection period; the same shell PID deletes the plist at 18:41:16.391. On Mac 02, the same plist is created at 13:22:52.904, the xpcproxy job is seen at 13:43:30.521, 15:46:46.441, and 17:51:41.981, and the same shell PID deletes it at 18:41:42.829.

The recorded job executes `/usr/bin/sw_vers`, which is a reasonable inventory action, and the interval is not perfectly uniform. A managed inventory job is therefore plausible. Still, the paired temporary installation and removal, identical job label, same command, and root shell actor on both Macs are unusually repeated. That repeated workflow affects the score as a distribution/environment signal; the file write, later job execution, and removal are separate lifecycle facts, not an assumed atomic action.

### User behavior and file actions

The shell histories and eCAR process records agree on many simple commands, which supports source consistency. However, both histories repeatedly sample a similar host-inspection vocabulary over the visible workday. Their `cat` commands target PDFs and spreadsheets as well as text files. Reading those bytes through `cat` is technically possible, but the same narrow pattern on both systems makes the user activity less organic than the otherwise credible app/process context. This is a moderate distribution concern, not a hard contradiction.

### Ordering and collection interpretation

Some eCAR flows occur before the visible Terminal process chains. Those rows do not name a process, and background or already-running processes could account for them; I did not infer a missing initiator as synthetic evidence. The observed user-shell commands follow their visible shell execs, and SSH acceptance/session records follow the corresponding connection attempts. No reviewed child execution or file effect appears before its visible initiating process. I also did not treat compactness, narrative completeness, or source alignment as score drivers, and did not penalize sparse Unified Log coverage by itself.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | eCAR PROCESS/FILE and macOS Endpoint Security | Both Macs | Same temporary LaunchDaemon label/path, root-shell install/removal, and repeated `sw_vers` job pattern recur on both hosts. Plausible as management activity, but unusually mirrored. |
| `distribution_texture` | zsh history and eCAR PROCESS | Both Macs / Maya Ross | Repeated narrow command pool and repeated `cat` of PDF/XLSX files provide a concrete templated-behavior signal. |
| `environment_or_collection_plausibility` | eCAR PROCESS/FILE | Both Macs | Root `/bin/sh` owns the repeated plist write/removal, but the visible command line and logs do not explain the same temporary inventory job on both endpoints. This remains a weak-to-moderate signal because an internal management workflow could explain it. |

## Realism Score by Category

- **Field format accuracy:** 8 — The sampled Endpoint Security records have coherent nested payloads, audit tokens, PID versions, paths, and event-specific fork/exec/exit data; no demonstrated schema contradiction was found.
- **Temporal patterns:** 7 — Visible process and SSH sequences are ordered plausibly, with a recurring job interval that is not perfectly uniform; the install/run/remove pattern is repeated across hosts.
- **Cross-source correlation:** 8 — SSH source ports, host addresses, logon/session evidence, and process ownership line up in the reviewed examples. Alignment itself is not counted against authenticity.
- **Behavioral realism:** 5 — Everyday app launches and shell activity are plausible, but both Macs show a narrow recurring command pool and raw `cat` access to office documents.
- **Environmental consistency:** 6 — The inventory job could be an internal tool, but the duplicated temporary LaunchDaemon lifecycle and unexplained root shell make its endpoint context less convincing.

## Recommendations

- If this were synthetic, vary the two Macs' background management activity or provide distinct, log-visible management behavior; the same named plist, root-shell write/remove, and `sw_vers` execution recur on both hosts.
- If this were synthetic, diversify shell tasks and include realistic application-based access for the PDF/XLSX files. The histories repeat basic inspection commands and use `cat` against multiple binary office documents on both machines.
- If this were synthetic, make the inventory job's source and lifecycle clearer in endpoint evidence, such as a distinct established management process or additional ordinary inventory actions, rather than the same bare `/bin/sh` actor on both hosts.
