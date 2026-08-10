# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Inconclusive | 74 | 58 | Synthetic | 78 | 68 |
| Detection Engineer | Real | 84 | 25 | Inconclusive | 80 | 51 |
| Network Forensics | Synthetic | 78 | 69 | Synthetic | 82 | 73 |
| Host/EDR Forensics | Synthetic | 82 | 76 | Synthetic | 87 | 82 |

The initial mean synthetic-confidence score was **57.0**. After cross-examination,
the revised mean is **68.5**. The panel does not reach unanimous verdict consensus,
but three reviewers now assess the corpus as synthetic and the fourth regards it as
inconclusive rather than real.

## Round 1 — Initial Positions

### Threat Hunter

The hunter initially returned **Inconclusive (74 confidence, 58 synthetic)**. The
strongest realism evidence was a coherent credential-access and lateral-movement
chain, source-native depth around the domain-controller compromise, and useful
cross-source SSH pivots. The strongest synthetic evidence was exact command-template
reuse, near-simultaneous independent attack steps, and an unusually complete six-hour
storyline. The hunter's unique contribution was the behavioral view: the corpus is
highly huntable, but the intrusion choreography and benign remote-administration
volume feel curated.

### Detection Engineer

The detection engineer initially returned **Real (84 confidence, 25 synthetic)**.
Their strongest evidence was correct Windows provider/version/task metadata, clean
Security/Sysmon/eCAR process correlation, and a correctly shaped Security-log clear
with a causally explained record-ID reset. The principal concerns were invariant
4648 network/GUID fields, seven unmatched 4634 closes, and a broad process-create /
terminate asymmetry. They treated all three as legal or plausibly attributable to
window boundaries and collection loss.

### Network Forensics Analyst

The network analyst initially returned **Synthetic (78 confidence, 69 synthetic)**.
The decisive observation was that the apparent domain controller and infrastructure
server emitted 95 proxy requests with a workstation-like mixture of interactive
search, endpoint/VPN clients, Python traffic, and a large Citrix installer download.
Secondary concerns were a ten-value TLS-history vocabulary, total absence of NTP,
and DHCP companion timestamps quantized to four integer-millisecond offsets. Strong
counterevidence included coherent connection states, complete UID joins, rich DNS,
and source-native TLS/proxy behavior.

### Host/EDR Forensics Analyst

The host analyst initially returned **Synthetic (82 confidence, 76 synthetic)**.
They identified two family-wide lifecycle defects: 45 of 52 created Linux responder
`sshd` processes lacked termination, including explicit sessions with PAM close and
eCAR logout; and 83 of 84 `taskhostw.exe` creates lacked termination despite rich
termination telemetry for neighboring short-lived process families. They also found
a narrow, role-insensitive Windows maintenance palette. Their strongest realism
evidence was internally sound process-tree correlation and the absence of dependent
events outside visible actor lifetimes.

## Round 2 — Cross-Examination

### Is process asymmetry merely window censoring?

This was the principal conflict between the detection and host reviews. The detection
engineer reasonably noted that aggregate create/terminate imbalance can arise from
durable processes, right-censoring, and source loss. The host analyst's narrower
family analysis is stronger, however: named SSH responder PIDs have both an in-window
session close and eCAR logout, yet no process termination; `taskhostw.exe` launches
occur throughout the window while adjacent short-lived families terminate cleanly.
Those facts remove the two most plausible aggregate-level explanations. The panel
therefore classifies the SSH finding as a **hard contract gap** and the task-host
finding as a **strong family lifecycle gap**, not generic missingness.

### Does strong source formatting establish authenticity?

The panel agrees that the Windows, Sysmon, Zeek, eCAR, proxy, and RFC5424 records are
unusually well formed. It also agrees that UID, tuple, PID, and session correlations
survive detailed checks. These are meaningful realism signals, but they do not
explain away a source-visible logout whose per-session responder process remains
alive, nor repeated short-task hosts that almost never terminate. Field accuracy and
cross-source correlation therefore lower confidence in a crude generator diagnosis,
but do not overcome the lifecycle evidence.

### Is the domain-controller proxy workload a contradiction?

Some management-agent egress, downloads, and even scripted HTTP from a domain
controller are plausible. The concern becomes stronger in aggregate: multiple
overlapping endpoint/VPN-client identities, interactive-looking searches, generic
Python activity, and a large end-user software download all land on the same critical
infrastructure host. The panel retains this as an **environment/role plausibility
gap**, but ranks it below the SSH lifecycle contradiction because an unusual software
inventory or administrative action could still explain portions of it.

### Are command repetition and attack synchronization decisive?

The hunter's exact command counts and two-millisecond separation between independent
attack steps are conspicuous. A scripted operator, scheduled execution, standardized
fleet management, or a curated security exercise could explain each pattern. With no
visible common automation mechanism, these remain **distribution texture** and
**behavioral choreography** signals rather than hard contradictions. They reinforce
the synthetic assessment but do not lead it.

### Do sparse session and timing irregularities matter?

Seven unmatched Windows logoff events, invariant legal 4648 fields, ten TLS-history
forms, absent NTP, and four-value DHCP offsets are all worth improving. Individually,
each has an ordinary alternative explanation or limited impact. The panel classifies
them as **weak signals or distribution texture**, subordinate to explicit lifecycle
and host-role findings.

## Round 3 — Revised Positions

### Threat Hunter — revised to Synthetic (78 confidence, 68 synthetic)

The hunter moves from inconclusive to synthetic. The decisive new evidence is not the
corpus's completeness, but the host analyst's repeated examples where an SSH session
visibly closes while its per-session responder remains alive. The task-host family
imbalance and DC role mismatch reinforce the hunter's pre-existing template and
choreography concerns.

### Detection Engineer — revised to Inconclusive (80 confidence, 51 synthetic)

The detection engineer no longer sustains a real verdict. Correct schemas, audit-log
semantics, and process/UID correlation remain strong, so the score does not move to a
high synthetic value. However, executable-specific lifecycle ratios and explicit
PAM/eCAR close examples invalidate the broad right-censoring explanation that
supported the initial verdict.

### Network Forensics Analyst — remains Synthetic (82 confidence, 73 synthetic)

The network analyst retains the verdict and raises confidence modestly. The endpoint
lifecycle contradictions independently support the role-model diagnosis. The analyst
still treats the DC workload, rather than the small TLS vocabulary or missing NTP, as
their strongest network-native evidence.

### Host/EDR Forensics Analyst — remains Synthetic (87 confidence, 82 synthetic)

The host analyst retains the verdict and increases confidence. The detection
engineer's detailed validation confirms that the corpus is broadly instrumented and
that termination telemetry is plentiful, making the sharply family-specific gaps
harder—not easier—to attribute to generic loss. Strong correlation remains an
important mitigating realism signal.

## Key Agreements

- The source formats and most cross-source identifiers are high quality.
- The SSH responder lifecycle is the strongest hard contradiction: explicit session
  closure is repeatedly not followed by coherent per-session process retirement.
- Windows `taskhostw.exe` requires bounded lifecycle ownership rather than fleet-wide
  accumulation.
- Distribution texture exists in command forms, maintenance processes, TLS histories,
  and DHCP child timing, but it is weaker than lifecycle evidence.
- Host-role constraints should prevent endpoint-oriented activity pools from being
  applied wholesale to critical infrastructure.

## Key Disagreements

- The detection engineer remains less certain that the corpus is synthetic because
  source schemas, temporal rendering, and identifier correlation are exceptionally
  strong. The other reviewers give more weight to lifecycle and role-level defects.
- The network analyst treats the domain-controller proxy workload as nearly decisive;
  the rest of the panel regards it as strong but potentially explainable by an unusual
  management/software inventory.
- The hunter views attack completeness and timing as meaningful design texture, while
  the technical reviewers treat those observations as supporting rather than primary
  evidence.

## Most Convincing Evidence

1. **Hard contract gap — SSH lifecycle:** 45 of 52 created responder `sshd`
   processes lack termination, including named PIDs with explicit PAM close and eCAR
   logout in the same visible window.
2. **Strong contract gap — task-host lifecycle:** 83 of 84 `taskhostw.exe` creates
   lack termination while multiple adjacent short-lived families have balanced
   lifecycle telemetry.
3. **Environment/role plausibility:** the apparent domain controller produces a
   broad workstation-like proxy workload spanning interactive search, overlapping
   endpoint/VPN clients, scripted HTTP, and end-user software retrieval.
4. **Distribution texture:** exact command templates and Windows maintenance commands
   recur at high fleet-wide volume with limited actor/role variation.
5. **Behavioral choreography:** distinct attack steps occur within milliseconds and
   the full intrusion is unusually complete without an evidenced common automation
   mechanism.

## Ranked Family Improvements

1. **SSH receiver process lifecycle — selected top recommendation.** When a successful
   SSH session emits a source-visible PAM close or eCAR logout, retire the exact
   per-session responder `sshd` process and emit—or coherently omit as one observation
   group—its termination. Validate this contract across every in-window successful
   SSH close and preserve PID/session/tuple identity through teardown.
2. **Windows task-host lifecycle.** Give each `taskhostw.exe` launch a bounded,
   task-appropriate lifetime; pair its termination coherently with the same process
   object, and impose a fleet-level concurrency invariant that prevents dozens of
   completed task hosts from accumulating.
3. **Role-constrained outbound activity.** Restrict domain-controller proxy traffic to
   defensible infrastructure, update, monitoring, and explicit administrative use;
   exclude consumer searches, generic browsing pools, overlapping endpoint VPN
   identities, and end-user installer downloads unless specifically modeled.
4. **Actor- and role-specific behavioral variation.** Diversify commands, quoting,
   option order, wrappers, software cohorts, and schedules; add human dwell and
   occasional failures/retries between independent attack actions.
5. **Protocol/timing texture.** Derive a broader valid TLS-history tail from protocol
   state, add role-appropriate time synchronization, and replace integer-millisecond
   DHCP child offsets with ordered sub-millisecond variation.

## Selected Top Recommendation

**Fix the SSH receiver-process lifecycle contract first.** It is the narrowest,
highest-confidence contradiction, is demonstrated across multiple hosts with explicit
source-visible closes, and can be tested as an exact family invariant: every observed
successful SSH session close must have a lifecycle-compatible responder-process
termination, or the close and termination must share one coherent source-observation
decision.
