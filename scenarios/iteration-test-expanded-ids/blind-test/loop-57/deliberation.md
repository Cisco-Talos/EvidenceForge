# Deliberation Summary

## Round 1 — Independent Positions

- **Threat Hunter — Inconclusive (78% verdict confidence, 53% synthetic-confidence).**
  The attack chain, proxy/NAT pivots, and source-native cross-source differences were
  convincing. The strongest synthetic concern was a fleet-wide Linux probe grammar: 81
  root-owned health-check or proxy-aware `wget` executions rotated through 62 unrelated
  public targets. The hunter also identified 88 SSH launches by two Windows users across
  six Linux destinations.
- **Detection Engineer — Real (73%, 29%).** Windows XML, Sysmon, Zeek, and eCAR records
  were schema-correct and lifecycle-coherent, including source-native Security-log clear
  behavior, process identity, authentication values, and small collection gaps. The main
  doubts were redundant eCAR aliases, uniform WFP device-volume paths, and unusually tight
  Security/Sysmon process-create timing.
- **Network Forensics Analyst — Synthetic (72%, 68%).** Protocol fan-out, packet
  accounting, independent-sensor differences, routing, and proxy semantics were strong.
  The contrary evidence was dataset-wide: nearly fixed per-client DHCP renewal intervals,
  no UDP/123 traffic, about 46 SSH session-hours from three workstations in six wall-clock
  hours, dense RDP activity, and a small stylized scanner population.
- **Host/EDR Forensics Analyst — Real (68%, 34%).** Windows process/session lifecycles,
  ProcessGuid ownership, hashes, Security/Sysmon offsets, and SSH/PAM correlation survived
  detailed checks. The analyst nevertheless found more than 110 SSH client launches from
  three admin workstations and broad reuse of the same Linux sudo identities and diagnostic
  commands across unrelated host roles.

## Round 2 — Cross-Examination

### Technical fidelity versus behavioral distribution

The detection and host analysts established that individual artifacts are highly credible:
schemas are source-native, identities remain stable, and visible lifecycle ordering is
causal. That evidence directly limits claims that the collection is mechanically malformed.
It does not, however, answer the network analyst's aggregate measurements or the hunter's
cross-host behavioral observations. A generator can produce technically correct individual
records while drawing too often from a shared activity grammar. The panel therefore treats
the technical fidelity as strong evidence of realism and the population-level regularities
as a separate, simultaneously valid concern.

### Remote administration: legitimate operations or generated texture

Three specialties independently identified the same SSH issue. The hunter counted 88
launches by two users across six destinations; the host analyst counted more than 110 from
three workstations and noted frequent short reconnects; the network analyst measured about
46 SSH session-hours and peak concurrency of seven, seven, and five. Any one observation
could be explained by an operations team, but their agreement across process, session, and
network views makes the aggregate density a strong distributional indicator. It remains a
soft rather than hard contradiction because administrator roles, multiplexing, or active
maintenance could explain some concurrency.

### DHCP regularity and absent NTP

The DHCP finding is quantitatively strong within the network evidence: all 69 renewals use
the same two-message form and each client repeats a private cadence with roughly two seconds
or less of cycle variation. The other analysts did not independently test DHCP, so this is
not cross-specialty corroboration, but no report offers a competing explanation for that
degree of repetition. The absence of UDP/123 is weaker: an unseen time source, local clock
policy, capture filtering, or a collection boundary could explain it even in a broad feed.

### Stable probes, shared Linux command pools, and standardized imaging

The hunter's rotating health-check destinations and the host analyst's reused sudo
identities point in the same general direction: Linux behavior lacks enough role affinity.
They concern different action families, so they reinforce a broad cross-role texture finding
without proving one implementation defect. Conversely, uniform WFP volume paths, similar
updaters, and tight Security/Sysmon offsets all have straightforward managed-image or local
provider explanations and remain weak signals.

### Evidence classification

- **Hard contradictions:** None. No reviewer found impossible visible ordering, broken UID
  or tuple ownership, invalid source schema, negative lifecycle duration, or contradictory
  principal/process identity.
- **Strong synthetic indicators:** over-dense cross-role SSH/RDP administration; nearly
  fixed per-client DHCP renewal cadence; broad rotating destinations for repeated Linux
  health-check/proxy commands.
- **Moderate environment/collection indicators:** no visible UDP/123 in a broad mixed-estate
  capture; shared Linux sudo identities and diagnostic commands across unrelated roles;
  scanner activity concentrated in a small set of port-specialized sources.
- **Weak indicators:** eCAR aliases, uniform WFP volume ordinals, narrow Security/Sysmon
  offsets, curated updater cohorts, and two sessions closing beyond the apparent window.
- **Strong evidence for realism:** source-native Windows schemas and log-clear semantics;
  stable process/session identities; coherent protocol fan-out; independent Zeek sensor
  UIDs and observation times; physically credible packet/byte accounting; and a correlated
  web-compromise, staging, proxy, NAT, and exfiltration chain.

## Round 3 — Revised Positions

- **Threat Hunter — remains Inconclusive; confidence 82%, synthetic-confidence 57%.** The
  network and host measurements independently confirm that excessive remote administration
  is not merely a hunt-level impression. Strong causal and proxy evidence prevents a
  synthetic verdict.
- **Detection Engineer — revises to Inconclusive; confidence 69%, synthetic-confidence
  42%.** The source schemas and event contracts remain persuasive, but the independently
  measured SSH workload, DHCP cadence, and cross-role Linux behavior show that correct
  records can still have generator-like population texture.
- **Network Forensics Analyst — remains Synthetic; confidence 76%, synthetic-confidence
  69%.** Host-process counts and the hunter's destination breadth strengthen the remote-admin
  finding. Confidence rises only modestly because the other reviewers found no hard
  contradiction and demonstrated unusually strong source-native fidelity.
- **Host/EDR Forensics Analyst — revises to Inconclusive; confidence 72%, synthetic-confidence
  45%.** The network quantification raises the weight of the SSH concern, and the DHCP
  regularity adds an independent scheduling signature. Coherent Windows and SSH lifecycles
  still argue against a confident synthetic classification.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|-----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 78 | 53 | Inconclusive | 82 | 57 |
| Detection Engineer | Real | 73 | 29 | Inconclusive | 69 | 42 |
| Network Forensics | Synthetic | 72 | 68 | Synthetic | 76 | 69 |
| Host/EDR Forensics | Real | 68 | 34 | Inconclusive | 72 | 45 |

The final mean synthetic-confidence is **53.25**. The panel does not reach a unanimous
verdict: three experts settle on Inconclusive and the network analyst retains Synthetic.

## Key Agreements

- Individual event schemas, identifiers, tuple relationships, and visible lifecycle ordering
  are technically strong; the panel found no hard contradiction.
- Cross-source attack evidence is coherent while retaining plausible sensor-specific timing,
  UIDs, and byte scopes.
- Routine remote administration is too dense and too broadly distributed across users and
  host roles to dismiss as a single-reviewer impression.
- The highest-value improvements concern behavior distributions, not field formatting.

## Key Disagreements

- The detection engineer initially weighted source-native correctness and small collection
  gaps as sufficient for a Real verdict, while the network analyst weighted dataset-wide
  scheduling and protocol distributions more heavily. Deliberation narrowed but did not
  eliminate that disagreement.
- The panel cannot determine from the blind evidence alone whether missing NTP is an actual
  environment defect or a collection-policy artifact.
- The network analyst views DHCP periodicity as a primary authenticity signal; the other
  specialists accept its quantitative strength but did not independently examine that
  protocol family.

## Most Convincing Evidence

1. **Over-dense remote administration:** more than 110 SSH client launches from three
   workstations, about 46 aggregate SSH session-hours, high concurrency, and broad
   cross-role destination coverage were independently visible to three specialties.
2. **Nearly fixed DHCP cycles:** all 69 renewals repeat tight host-specific intervals with
   very little cycle jitter, producing a clear scheduler-like signature.
3. **Source-native causal integrity:** Windows process/logon semantics, Zeek protocol fan-out,
   proxy/NAT legs, and attack staging remain coherent without impossible ordering.
4. **Rotating Linux probe targets:** 81 repeated health-check or `wget` executions cover 62
   unrelated public targets instead of stable, role-specific dependencies.
5. **Independent observation texture:** the two Zeek sensors preserve different UIDs and
   observation times while agreeing on the underlying transaction.

## Most Debated Points

- Whether intense SSH/RDP usage could represent a temporary operations campaign rather than
  generated baseline behavior.
- Whether high technical fidelity should outweigh distributional signatures when no hard
  contradiction exists.
- Whether absent NTP and post-window closes describe the environment, the export policy, or
  the data-production process.

## Improvement Recommendations (Consensus)

1. **Reduce and contextualize routine SSH/RDP activity.** Give administrators stable target
   affinities and maintenance tasks, favor fewer longer-lived or multiplexed sessions, and
   limit simultaneous sessions across unrelated server roles while preserving existing
   tuple, process, PAM, and endpoint lifecycle correlation.
2. **Model DHCP renewal state rather than a private periodic timer.** Anchor T1/T2 behavior to
   lease negotiation and introduce retries, rebinds, delayed responses, clock drift, and
   broader cycle-to-cycle variance.
3. **Make Linux outbound operations role-specific and configuration-stable.** Health checks
   should reuse a small configured dependency set; database, mail, proxy, application, and
   public-web systems should have distinct destination and command profiles.
4. **Represent time synchronization or an explicit collection gap.** Add domain-hierarchy and
   Linux time-source polling with stable-but-imperfect schedules, or make the absence
   explainable by the visible collection profile.
5. **Broaden low-rate scanner texture.** Mix persistent campaigns with a larger one-off source
   tail, less rigid port specialization, retransmission variation, and changing cohorts.

## Selected Top Recommendation

**Rework routine remote-administration scheduling and role affinity first.** It is the only
major concern independently identified from threat-hunting, network, and host/EDR views, and
it affects process launches, session concurrency, target selection, and overall behavioral
realism. Preserve the current strong cross-source SSH/RDP contracts while generating fewer,
better-motivated sessions with administrator-specific destination sets and more realistic
terminal reuse.
