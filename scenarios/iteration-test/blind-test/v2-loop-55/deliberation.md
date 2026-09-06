# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 72 | 65 | Synthetic | 83 | 76 |
| Detection Engineer | Synthetic | 88 | 72 | Synthetic | 92 | 82 |
| Network Forensics | Real | 74 | 30 | Real | 55 | 44 |
| Host/EDR Forensics | Synthetic | 84 | 74 | Synthetic | 90 | 82 |

## Key Agreements

- All four experts considered the dataset technically sophisticated and substantially more realistic than typical synthetic telemetry. They agreed that Zeek UID and tuple integrity, certificate relationships, source-native Windows schemas, process correlation, attack sequencing, and signal-to-noise were strong.
- The panel agreed that the strongest authenticity defects are concentrated in specific generation contracts rather than broad narrative implausibility.
- The Detection Engineer’s RDP findings received the strongest cross-panel acceptance: all four Type 10 logons use a `ProcessId` inconsistent with the nearby `winlogon.exe`; three logons precede creation of that process; overlapping sessions reuse one PID; and the RDP `winlogon.exe` processes have implausible System parentage.
- The Host/EDR analyst’s long-lived `userinit.exe` finding reinforced the RDP diagnosis. Four instances survive for 30 minutes to 2.7 hours, including two overlapping instances that terminate nearly together. The panel considered this compatible with an incorrect session-finalization model rather than an isolated logging anomaly.
- The Windows SYSTEM LUID `0x3e7` appearing in 811 Linux eCAR records was accepted as a platform-semantic leak. No expert offered a credible source-native Linux interpretation for it.
- The panel agreed that collection loss can plausibly explain sparse omissions—such as seven unresolved Zeek FUID references or four unmatched Security/Sysmon process records—but not repeated type-specific identity and lifecycle contradictions.
- The Network Forensics analyst retained a Real verdict because the network evidence alone remains production-like. However, the endpoint findings lowered that expert’s verdict confidence and increased synthetic-confidence substantially.
- The Threat Hunter increased synthetic-confidence after the RDP, Linux identity, and `userinit.exe` findings showed that the previously identified remote-administration and subprocess gaps were part of a broader pattern of weak action-specific contracts.
- The Detection Engineer’s position strengthened after the Host/EDR analysis independently connected the malformed RDP process setup to incorrect downstream lifecycle termination.
- The Host/EDR analyst’s position strengthened after the Detection Engineer established identifier-level RDP contradictions and the Threat Hunter demonstrated analogous correlation gaps in privileged remote-administration paths.

## Key Disagreements

The primary disagreement remained whether excellent network telemetry should outweigh repeated endpoint contradictions.

The Network Forensics analyst argued that varied connection states, DNS failures, service-sensitive durations, proxy topology, sensor-local UIDs, TLS behavior, certificate chains, packet accounting, and multi-sensor visibility are consistent with a real capture. That expert regarded uniform missing `REJ` durations, stable sensor offsets, and redirect MIME typing as suspicious but individually explainable.

The other three experts found the endpoint evidence more discriminating because it contains repeated, action-specific impossibilities or semantic leaks:

- A real collection gap might omit a process, but it does not explain a 4624 identifying the wrong PID in every visible RDP session.
- Provider latency might reorder closely timed records, but it does not explain wrong per-session ownership, PID reuse across overlapping sessions, direct System parentage, and `userinit.exe` retention together.
- Normalization might introduce a generic Linux session identifier, but consistently importing Windows’ well-known SYSTEM LUID across eleven Linux hosts strongly suggests a shared cross-platform model.

The panel therefore reached a 3–1 Synthetic majority, not unanimity. The dissent is source-scoped: the Network Forensics analyst considers the network corpus independently believable while acknowledging that the combined multi-source dataset is materially more suspicious.

A secondary disagreement concerned behavioral repetition. The Host/EDR analyst considered the fresh-shell-to-SSH pattern and fleet-wide Snap package activity strong synthetic texture. The Threat Hunter found similar Linux command reuse but weighted it below identity and lifecycle failures. The panel agreed these repetitions matter cumulatively but should not outrank concrete contract defects.

The Threat Hunter’s remote-administration port mismatch was also debated. Collection filtering could theoretically hide an authentication connection, and SMB/RPC workflows can involve multiple transports. However, the exact-match rate for ordinary network logons—165 of 172 on `DC-01` and 135 of 141 on `DC-02`—combined with clustering around privileged actions makes random loss a weak explanation. The panel retained this as strong evidence, but below the RDP contradictions.

## Most Convincing Evidence

1. **Broken RDP process identity and ordering.** All four Type 10 logons identify a PID different from the associated `winlogon.exe`; three precede its creation; overlapping sessions reuse one PID; and all four processes are attributed directly to System. The repeated, type-specific, identifier-level nature makes logging delay or collection loss inadequate explanations.

2. **Windows authentication semantics leaking into Linux eCAR.** The Windows SYSTEM LUID `0x3e7` appears in 811 records across eleven Linux/syslog hosts, including ordinary Linux daemons and processes. This is a dataset-wide platform-model defect.

3. **Incorrect RDP session-process lifecycle.** Four `userinit.exe` processes persist for 30 minutes to 2.7 hours, with two overlapping instances terminating almost simultaneously near session cleanup. This independently corroborates an incorrect RDP lifecycle implementation.

4. **Privileged remote-administration logons using unobserved source ports.** Repeated DC Type 3 logons cite ports absent from Zeek while nearby PsExec SMB/RPC transports use different ports. Ordinary network logons correlate at very high rates, making the attack-path concentration especially revealing.

5. **Required subprocesses omitted from visible command chains.** Encoded Linux shell execution lacks `base64` and inner-shell children; cleanup lacks the required `cat` process; and `cmd.exe /c whoami && hostname` lacks both child executables despite otherwise detailed short-lived process collection.

## Most Debated Points

- **Can network realism preserve a Real verdict for the complete dataset?** The network corpus contains no broad structural breakdown and remained convincing to its specialist. The majority concluded that endpoint identity contradictions have greater authenticity leverage because they cannot be explained by realistic traffic diversity elsewhere.
- **Could RDP ordering be provider latency?** Small timestamp inversions alone might be defensible. The combination of wrong PIDs, reused ownership, incorrect parentage, and abnormal `userinit.exe` lifetimes made latency insufficient.
- **Could missing source ports represent collection gaps?** This remains possible for an individual event. Its repeated concentration around privileged actions, against a highly successful ordinary-logon correlation baseline, supports a separate modeled path with incomplete tuple inheritance.
- **How much weight should repeated SSH launcher behavior carry?** Twenty-two of 23 Windows SSH launches follow newly created shells within a narrow delay. The panel judged this generator-like, while acknowledging that administrator habits and instrumentation scope can create repetition.
- **Is fleet-wide Snap activity merely standardized deployment?** Shared packages are plausible in a managed Ubuntu fleet. Installing `microk8s`, `lxd`, and desktop integration across unrelated headless roles—and emitting 79–105 Snap messages per host in six hours—was harder to justify. It remained secondary because environmental policy was not independently available.
- **Do sparse missing artifacts indicate synthesis?** Seven unresolved FUIDs and four unmatched process records were judged weak. Real collection pipelines lose records, so these gaps carry little weight without systematic clustering or impossible references.
- **Are fixed sensor offsets artificial?** Stable 65–179 ms offsets could be programmed, but fixed NTP skew and capture-point latency are credible alternatives. No panel consensus treated this as decisive.
- **Does uniform omission of `REJ` duration expose generation?** All 49 rejected connections omit duration despite visible SYN/RST exchange. The panel accepted this as a concrete source-native defect, but ranked it below identity and lifecycle failures because Zeek versioning or normalization behavior might contribute.

## Improvement Recommendations (Consensus)

1. **Unify RDP lifecycle ownership.** Create a unique per-session `winlogon.exe` through the correct `smss.exe` session path before emitting 4624. Use that exact PID and process identity in the logon, retain distinct identities for overlapping sessions, and terminate each process according to its real lifecycle.

2. **Decouple `userinit.exe` from session teardown.** Terminate it a few seconds after it launches the user shell. Do not retain it until `explorer.exe`, `winlogon.exe`, or the remote session closes.

3. **Use OS-native authentication identities.** Replace Linux eCAR `0x3e7` values with modeled Linux audit session IDs, login UIDs, systemd session identifiers, or an explicit source-native system-session representation. Add validation that rejects Windows well-known LUIDs on Linux events.

4. **Carry canonical transport identity into authentication events.** For PsExec, WMI, RDP, and related remote-administration actions, preserve the actual source IP and allocated source port across network transport, endpoint FLOW, authentication, and session evidence. Ensure retained transport observations precede their dependent logons.

5. **Materialize command-required child processes.** Parse modeled shell and command chains into explicit process lifecycles where external executables must run. Cover `base64 | bash`, `cat`, `whoami.exe`, and `hostname.exe`, with correct parent PID, principal, timestamps, and termination events.

6. **Add multi-session regression tests.** Exercise simultaneous RDP sessions and privileged remote-administration actions on one host. Assert distinct Logon IDs, session IDs, PIDs, process GUIDs, parent chains, source ports, and lifecycle closure.

7. **Diversify SSH initiation behavior.** Reuse existing terminals regularly, allow direct terminal/profile launches, broaden command-entry delays, and avoid creating a fresh shell immediately before nearly every `ssh.exe` execution.

8. **Make Linux package telemetry role-aware and stateful.** Restrict `microk8s`, `lxd`, and desktop integration to hosts whose roles justify them. Generate coherent refresh transactions with realistic state transitions and substantially lower routine message volume.

9. **Correct source-native network edge cases.** Give `REJ` connections positive SYN-to-RST durations derived from modeled RTT, derive redirect MIME types from actual response entities rather than requested extensions, and model sensor clocks with gradual drift and bounded timestamp noise.

10. **Preserve correlation under observation loss.** If application-level FUIDs or process records are retained, keep their required referenced objects observable. When simulating collection loss, apply coherent source-local drop decisions that do not leave unexplained orphan references.
