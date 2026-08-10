# Loop 59 Blind Host/EDR Forensics Review

## Verdict

- **Verdict:** Synthetic
- **Verdict confidence:** 76/100
- **Synthetic confidence:** 72/100

The endpoint corpus is unusually strong in its process, session, and attack-chain correlation. It
would support a credible investigation without privileged context. The deciding synthetic marker is
not the malicious storyline; it is repeated source-process ownership that crosses application
boundaries in ways ordinary endpoint telemetry should not. The same ownership pattern appears on
multiple hosts, making it look like a shared generation rule rather than isolated collection noise.

## Category scores

| Category | Score | Assessment |
|---|---:|---|
| Process and identity fidelity | 88/100 | PIDs, principals, parentage, process UUIDs, and command lines are generally detailed and internally useful. |
| Lifecycle and temporal coherence | 85/100 | Create/terminate and login/logout relationships are mostly coherent; boundary-visible or long-lived processes explain many apparent orphans. |
| File and registry semantics | 61/100 | Repeated process-to-file ownership errors are the strongest synthetic tell. |
| Cross-source investigative utility | 91/100 | eCAR, Windows audit/Sysmon, and Linux session evidence provide useful pivots and preserve major attack causality. |
| Background texture and diversity | 82/100 | Good host-role and OS variety, though some process/command families recur with pool-like regularity. |
| Overall host realism | 79/100 | Convincing at first pass, but distinguishable under application-semantic scrutiny. |

## Evidence

### Strong realism signals

- The DC attack sequence is operationally coherent: PSEXESVC service installation, domain account
  creation, Domain Admins membership modification, scheduled-task persistence, encoded PowerShell,
  Security-log clearing, and account cleanup have concrete process trees, users, paths, and close
  timestamps rather than existing as disconnected indicators.
- Explicit credential use is rendered as a plausible short-lived caller:
  `runas.exe /netonly /user:marcus.chen "cmd.exe /c dir \\DC-01\ADMIN$"`.
- SSH evidence preserves useful receiver-side identity. Sessions carry source IP/port, logon ID,
  session ID, responder `sshd` processes, shells, and logout records. The SCP activity also has a
  plausible sender command and receiver-side file path.
- Windows service, network, and interactive logons use differentiated principals and logon types;
  machine accounts, service identities, anonymous access, and human users are not collapsed into one
  generic pattern.
- Records are ordered within endpoint files, event IDs are unique in the reviewed corpus, and shared
  object IDs are reused to correlate related observations.

### Synthetic indicators

1. **Browsers repeatedly own Outlook-private artifacts.** There are 10 file events where Chrome or
   Edge is attributed as the source process for files under either
   `Microsoft\Outlook\RoamCache` or `Microsoft\Windows\INetCache\Content.Outlook`. This occurs on
   both WS-DRAMIREZ-01 and WS-EBROOKS-01. Examples include Chrome creating
   `...\Outlook\RoamCache\1000EMRX7O.dat` and Edge creating
   `...\Outlook\RoamCache\1001HSNNKH.dat`. Outlook owns RoamCache; repeating this on multiple hosts
   is a hard application-ownership contradiction.

2. **Other file activity shows the same cross-product assignment pattern.** RuntimeBroker writes
   `C:\Users\evelyn.brooks\Documents\presentation.pptx`, while Explorer writes the same document
   class for another user. RuntimeBroker is also credited with direct Chrome/Edge cache reads.
   Individual shell-mediated operations can be unusual, but this combination looks like file-path
   classes sampled independently from the actor process.

3. **Some background command families are visibly pool-like.** Across a six-hour view, the exact
   `debian-sa1 1 1` and wrapper pair each appears 88 times, while Windows hosts repeatedly emit a
   small set of identical `taskhostw`, `WmiPrvSE`, `dllhost`, updater, and `conhost` forms. These are
   individually legitimate and much weaker than the ownership contradiction, but their exact reuse
   contributes to a generated texture.

4. **Lifecycle completeness is good but not perfect.** The endpoint view contains 1,647 process
   creates and 1,425 terminations; 321 host/PID creates have no visible termination and 99
   terminations have no visible create. Much of this is compatible with window boundaries,
   long-running services, and source observation gaps, so it is supporting evidence rather than a
   verdict driver.

## Recommendations

1. Make file-path selection conditional on the owning application family. Outlook-only RoamCache
   and Content.Outlook artifacts should be emitted by Outlook (or by a clearly modeled child/helper),
   browser cache artifacts by the matching browser, and Office documents by the corresponding Office
   application unless a specific shell operation is modeled.
2. Add a family-level invariant covering the cross-product of process image and file path, including
   negative assertions for Chrome/Edge versus Outlook-private directories and RuntimeBroker versus
   user Office documents.
3. Diversify high-frequency scheduled/background process command lines and cadence per host while
   retaining role-appropriate repetition.
4. Continue preserving the strong action-level correlations already present in the explicit
   credential, SSH/SCP, service-installation, and account-manipulation chains.
