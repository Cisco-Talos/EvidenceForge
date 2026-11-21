# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 82 | 45 | Synthetic | 79 | 68 |
| Detection Engineer | Synthetic | 84 | 72 | Synthetic | 87 | 76 |
| Network Forensics | Real | 70 | 20 | Inconclusive | 84 | 58 |
| Host/EDR Forensics | Inconclusive | 84 | 55 | Synthetic | 78 | 68 |

The arithmetic mean of the four actual final synthetic-confidence scores is **67.5/100**: `(68 + 76 + 58 + 68) / 4 = 67.5`. Three final verdicts are Synthetic and one is Inconclusive. This is a majority leaning toward synthetic origin, not a unanimous verdict. Verdict confidence and synthetic-confidence are distinct measures; the mean above uses only synthetic-confidence scores.

This summary reflects the four original reports and each expert's actual deliberation response. The responses re-examined other experts' original findings; they were not a live exchange among the revised positions. The facilitator performed no independent authenticity assessment.

The original positions and their strongest evidence were:

- **Threat Hunter:** Inconclusive, 82/45. The Windows netonly sequence preserved local `aisha.johnson` execution versus outbound `marcus.chen` credentials; the DB SSH/dump/compression/SCP sequence supplied coherent hunt pivots; independent sensors differed plausibly in UID and packet observation. Unique weaker concerns were the redirected dump's normalized file-creation attribution, repeated irqbalance vocabulary, and a secondary syslog destination.
- **Detection Engineer:** Synthetic, 84/72. The principal indicator was gapless native macOS `audit_token.pidversion` sequences beginning at 12 on both hosts. The identical low starts and older launchd snapshots reinforced that same finding. Broad XML/JSON parsing, Windows process-lifecycle checks, and protocol/byte-accounting checks supplied substantial counterweight.
- **Network Forensics:** Real, 70/20. Protocol/transport tuples and intervals, direction-specific accounting, DNS variation, separate proxy legs, and passive TLS visibility were credible. The unmatched SMB mapping reference remained compatible with an export/window boundary. This specialist found no substantive network indicator of construction.
- **Host/EDR Forensics:** Inconclusive, 84/55. Three native macOS fork groups preserved exact microsecond phases across distinct commands. Windows process fields and lifetimes, eCAR actor relationships, and Mac fork/exec distinctions remained coherent. The analyst also distinguished separate denied/successful sudo processes and policy observations from proof of execution.

## Key Agreements

- **All four accepted the macOS identity pattern after rechecks.** The new fork-child/exec-target identities run exactly 12–112 on Mac 01 (101 values) and 12–133 on Mac 02 (122 values), in retained-record order over more than five hours. These are audit-token identity values, not legitimate ES client sequence counters. Each expert treated the pattern as substantive distribution texture, while retaining identifier remapping during sanitization as an alternative explanation.
- **All four accepted the repeated native fork phases.** Ten of 103 forks participate in three groups with fractions `.198588`, `.487145`, and `.965208`. Later exec phases vary. The experts count this as one repeated timing mechanism, with scripted scheduling or timestamp transformation still possible. The Detection Engineer additionally checked that the first group's Mach-clock differences reproduce the exact integer-second spacing; this corroborates the same occurrence timing rather than adding a separate defect.
- **Endpoint metadata concerns and coherent operational behavior can coexist.** All retained substantial positive weight for the network and Windows evidence. Accurate local fork/exec transitions do not settle the broader distribution of process-generation values. Useful hunt pivots do not independently establish production origin.
- **No reviewed finding established a hard native lifecycle contradiction.** The findings that drove revisions were distribution artifacts concentrated in the native macOS source family. The experts did not generalize them into demonstrated defects in every source.
- **Secondary observations remained qualified.** The DB output attribution depends on normalized CREATE semantics. Repeated daemon diagnostics can legitimately have a small vocabulary. Receiving and forwarding syslog are compatible roles, and the unmatched SMB connection reference remains compatible with collection boundaries. No expert used missing optional sources or complete correlations as an origin fingerprint.

## Key Disagreements

The remaining disagreement concerns evidential weight and the threshold for an origin verdict, rather than the observed macOS counts or timestamps.

- **Three experts crossed or retained the Synthetic threshold.** The Threat Hunter moved from 45 to 68 after confirming both macOS patterns; the Host/EDR analyst moved from 55 to 68 after reproducing the identity pattern alongside the timing concern already identified. The Detection Engineer retained Synthetic and increased 72 to 76 after confirming the timing pattern. Their final verdict confidences were 79, 78, and 87, respectively. All retained transformation alternatives and strong cross-source coherence as reasons to avoid the highest synthetic-confidence band.
- **Network Forensics stopped at Inconclusive.** This expert moved from Real/20 to Inconclusive/58, with verdict confidence rising from 70 to 84. Both endpoint patterns warranted abandoning the original dataset-level Real verdict, but permitted identifier/timestamp transformations and the absence of a demonstrated source-native impossibility preserved meaningful uncertainty. The network-specific findings remained unchanged.
- **Small concerns received different minor weights.** Host/EDR assigned small contributions to normalized dump attribution and irqbalance texture; the Detection Engineer treated dump attribution as nondecisive and daemon repetition as slight corroboration. The Threat Hunter explicitly said those original weaker concerns did not cause the verdict change. Network Forensics gave the file ambiguity minor influence and rejected daemon repetition as a major indicator. These differences did not drive the principal split.

## Most Convincing Evidence

The following ordering summarizes the emphasis in the actual responses; the panel did not conduct a separate ranking vote.

1. **Gapless retained macOS process-generation identities — strongest shared synthetic indicator.** Both hosts start new observed identities at 12 and consume every subsequent value for retained fork/exec transitions. All four reproduced and accepted the pattern. The Detection Engineer first identified it; it was the main new evidence changing the Host/EDR verdict and contributed to both other verdict changes. Old launchd start dates and PID progression corroborate this one finding. Identifier normalization remains a viable alternative, and PID jumps alone were not accepted as proof of a specific number of intervening allocations.
2. **Exact native fork timestamp phases — shared additional synthetic indicator.** Three command groups on two Macs preserve six-digit fractional phases across separate forks. All four accepted the Host/EDR finding; it caused the Detection Engineer's score increase and supported the Threat Hunter's and Network analyst's revisions. Scripted timing or transformation remains possible. The two clock representations and three groups are not counted as independent extra defects.
3. **Coherent source-native endpoint lifetimes and credential semantics — substantial counterweight.** The Host/EDR analyst matched 945 of 949 Windows Sysmon process creations to Security counterparts using a conservative method, with matched executable paths and command lines agreeing. Detection and host checks found no tested substantial process-lifecycle inversion. The Threat Hunter's netonly example retained distinct local and outbound identities. The revisions preserve these results while limiting what they establish about origin.
4. **Coherent transport, proxy and TLS observations — substantial counterweight.** Network and Detection checks supported tuples, intervals, byte accounting, separate client/proxy/external legs, and passive TLS certificate visibility. Other experts accepted these results as compatible with the endpoint concerns. No newly demonstrated network defect emerged during deliberation.

## Most Debated Points

- **Native identity distribution versus valid local identity relationships:** The Mac process trees can be locally correct while the retained `pidversion` values appear artificially enumerated. All accepted this distinction. The unresolved challenge is whether export-time identifier remapping sufficiently explains the global texture.
- **Repeated phases versus legitimate automation:** Exact fork phases are not an allegation that command narratives are too compact. They occur in native timestamps, with separately varying exec fractions; the Detection Engineer also checked Mach timing. Scripted scheduling and timestamp processing were not excluded, so none classified the pattern as impossible ordering.
- **What network realism establishes:** The original Real network verdict emphasized detailed protocol plausibility. After considering endpoints, that expert revised to Inconclusive. The final disagreement therefore persists after accepting endpoint evidence, rather than because the network expert denied it.
- **Shell redirection and normalized CREATE attribution:** DB-PROD-01 creates mysqldump at `18:15:14.955` and attributes `/tmp/rpt_0318.sql` FILE/CREATE to it at `18:15:15.680`; shell history contains the redirection. A literal opening syscall precedes utility exec, but a forked shell child can retain the same PID through exec, and normalized CREATE may describe first output or later writer attribution. Detection and Host/EDR explicitly cautioned against automatically assigning creation to the interactive parent shell. This remained a narrow semantic ambiguity.
- **Secondary syslog routing and daemon repetition:** Network Forensics corrected the transport description: FILE-LNX-01 receives 114 combined syslog-service connections, comprising 92 UDP/514 and 22 TCP/514, rather than 114 UDP-only connections. The receiving/forwarding topology does not establish a loop. The four-message irqbalance vocabulary reproduces but remains compatible with real shared daemon configurations; it carries at most mild weight.

## Improvement Recommendations (Consensus)

These recommendations are conditional on synthetic origin or an undocumented transformation. They summarize support present in all or most responses, rather than presupposing the records' provenance.

1. **Represent host-wide macOS process-generation history before filtering.** All four recommend deriving identity values from independent host histories that include unretained process/exec activity. Preserve valid same-PID exec transitions and independent starting states instead of advancing identity only when a retained notification is written.
2. **Represent actual command-start scheduling.** All four recommend avoiding accidental inheritance of a shared activity anchor's exact fractional phase across distinct shell actions. Retain exact scripted timing when the execution mechanism supports it, and keep wall/Mach clocks consistent with the same underlying occurrences.
3. **Document identifier and timestamp transformations.** All four identify this as the key alternative explanation. If sanitization rebases identities or transforms scheduling timestamps, state those semantics explicitly so transformed fields can be assessed appropriately.
4. **Clarify normalized FILE/CREATE semantics before changing attribution.** Detection, Host/EDR and Network explicitly recommend this. Distinguish pre-exec redirection opening from later utility writes or first-observed content. Account for a shell child retaining its PID through exec; do not prescribe a universal transfer of ownership to the interactive parent shell.

No majority-supported network protocol repair was established. The Network and Detection experts, with the other reviewers retaining their positive observations, supported preserving the existing coherent protocol/proxy/TLS behavior. Irqbalance calibration remained a lower-priority conditional suggestion from Threat Hunter and Host/EDR, rather than an agreed requirement to diversify naturally repetitive diagnostics.
