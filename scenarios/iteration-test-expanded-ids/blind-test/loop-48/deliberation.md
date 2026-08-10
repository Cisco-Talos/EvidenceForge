# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 76 | 39 | Inconclusive | 82 | 49 |
| Detection Engineer | Synthetic | 86 | 66 | Synthetic | 88 | 64 |
| Network Forensics | Inconclusive | 84 | 41 | Inconclusive | 88 | 43 |
| Host/EDR Forensics | Real | 72 | 34 | Inconclusive | 85 | 52 |

## Round 1 — Initial Positions

The Threat Hunter judged the collection operationally convincing but stopped at
**Inconclusive (76 confidence, 39 synthetic-confidence)**. The strongest real-data
signals were the coherent web-to-shell-to-network pivot around 13:19, later account/task/archive
continuity, and a substantial heterogeneous haystack. The main doubts were 81 direct SSH accepts
for two named users across six disparate server roles, a narrow repeated Windows maintenance
vocabulary, and a Security channel dominated by Event 5156. The retained pre-clear and post-clear
Security records were explicitly treated as collection-dependent weak evidence.

The Detection Engineer reached **Synthetic (86 confidence, 66 synthetic-confidence)**. Its
strongest observation was a repeated Windows logout construction: `explorer.exe`, `userinit.exe`,
and `winlogon.exe` terminate in the same order at exact 50 ms intervals across FILE-SRV-01,
MAIL-FIN-01, and DC-01, while `userinit.exe` implausibly remains alive until logout. It also found
specific short Linux commands (`who`, `file`, `head`, and `tail`) with in-window evidence of
execution but eCAR TERMINATE records lacking matching CREATE records. Against that, it found
high-quality source schemas, sparse rather than universal observation gaps, realistic channel
reset behavior, and complete, valid Zeek protocol-to-connection contracts.

The Network Forensics Analyst judged the data **Inconclusive (84 confidence, 41
synthetic-confidence)**. The network corpus had strong UID, tuple, timing, byte-accounting,
sensor-offset, protocol, certificate, proxy, IDS, and firewall consistency. Its main synthetic
indicator was categorical concentration: 1,040 public-origin DMZ `S0` connections came from only
11 IPs, with several unrelated sources sharing identical fixed port portfolios. Universally
established TLS observations and very narrow per-client DHCP renewal drift were down-weighted as
weak signals with plausible source-native explanations.

The Host/EDR Analyst judged the data **Real (72 confidence, 34 synthetic-confidence)**. It found
no reverse-order eCAR process or session pairs in aggregate, convincing Security/Sysmon/eCAR
correlation, coherent process ancestry, detailed SSH lifecycles, role-specific activity, and
credible lock/unlock semantics. Its doubts were distributional: 1,021 UFW blocks from only 10
sources and a small packet-attribute pool, frequent server-side `wsqmcons.exe`, two PowerShell
maintenance scripts reused across nine Windows hosts, and uniform sysstat chains.

## Round 2 — Cross-Examination

### Lifecycle evidence versus aggregate lifecycle health

The most consequential disagreement is between Detection and Host/EDR. Host/EDR's aggregate
result—1,319 visible create/terminate pairs with no reverse ordering—establishes that most lifecycle
identity and ordering is sound, but it does not answer Detection's narrower semantic claim. A
process may terminate after its create and still have an unrealistic lifetime. The repeated
`explorer.exe`/`userinit.exe`/`winlogon.exe` triplets occur at exact 50 ms offsets across unrelated
hosts and sessions, and the persistence of `userinit.exe` until logout is behaviorally suspect.
This concrete repeated pattern is stronger than the aggregate absence of reverse ordering.

Detection's Linux orphan examples likewise survive the bounded-window challenge better than an
undifferentiated count of termination-only objects. Bash history places `who -a` and
`file /tmp/rpt_0318.sql` only seconds before their termination records, so these two examples are
not left-boundary processes. Random source loss remains a production-compatible explanation, but
repetition across DB, proxy, and mail hosts makes a lifecycle-group observation gap a real contract
concern. The panel therefore distinguishes these examples from the many unmatched lifecycle edges
that legitimately cross collection boundaries.

### Strong cross-source correlation versus generated construction

All specialists agree that cross-source fidelity is exceptionally strong. Detection's 836/843
Security-to-Sysmon process matches and zero missing Zeek protocol UIDs, Network's zero tuple/timing
violations plus exact or loss-compatible ASA/proxy accounting, and Threat Hunter's coherent attack
pivots all support production-like usability. Per the collection guidance, completeness itself is
neutral. It becomes positive evidence here only where source-native differences remain—small
sensor offsets, independent UIDs, occasional source-local gaps, and non-identical accounting—rather
than copied timestamps or duplicated rows.

This evidence substantially limits the synthetic conclusion: the panel did not find a global
schema, causality, routing, or accounting failure. It does not erase the Windows teardown tell,
because exact fixed offsets and implausible process lifetime are distributional/behavioral facts,
not penalties for high correlation.

### Perimeter-noise concentration

Network and Host/EDR independently identify the same underlying weakness from different sources.
The DMZ has 1,040 external `S0` connections from 11 sources with repeated port profiles, while
WEB-EXT-01 has 1,021 UFW blocks from 10 sources and compact TTL/window/length portfolios. The
bursty, non-metronomic timing is convincing, so the issue is not cadence. Common bot families can
reuse targets and fingerprints, but the small source pool and repeated categorical profiles across
this volume form a dataset-wide synthetic pressure. This cross-specialty agreement elevates the
finding above either report's isolated wording.

### Fleet regularity and authorization texture

Threat Hunter and Host/EDR independently converge on a low-entropy fleet background: the same two
PowerShell scripts recur across nine dissimilar Windows hosts, and the Threat Hunter additionally
notes exact service-health command reuse across server and workstation roles. Host/EDR's frequent
server-side `wsqmcons.exe` and uniform sysstat chains reinforce the pattern. Central management and
distro defaults explain some repetition, but not the lack of a broader role-specific long tail.

The Threat Hunter's broad SSH-access concern is plausible but less decisive. Named administrators
can legitimately reach many systems, and Host/EDR found rich, ordered SSH/PAM detail with variable
methods, ports, and durations. Without an explicit contradiction, the panel retains broad direct
access as an environmental-plausibility concern rather than a hard authenticity discriminator.

### Conditional and weak observations

The Security-log-clear concern loses weight because Detection found a source-native EventRecordID
reset from 28262086 to 1 followed by realistic gaps; forwarding can preserve earlier records. The
5156-heavy Security mix is also compatible with audit policy. Universally established TLS rows are
compatible with analyzer activation on completed handshakes, and stable DHCP renewal cadence is
expected at T1. None of these should materially drive the final score without collection metadata
or a concrete source-native contradiction.

## Round 3 — Revised Positions

### Threat Hunter

**Final assessment: Inconclusive. Verdict confidence: 82. Synthetic-confidence: 49.** The verdict
does not change, but the score rises because the cross-host 50 ms teardown triplets and the
in-window Linux transient-process examples are more concrete than the hunter's original
environmental concerns. The coherent attack pivots, heterogeneous haystack, and lack of sampled
network/authentication inversion still prevent a Synthetic verdict.

### Detection Engineer

**Final assessment: Synthetic. Verdict confidence: 88. Synthetic-confidence: 64.** The specialist
retains its verdict and gains modest confidence because Host/EDR's aggregate checks do not rebut
the semantic lifetime and exact-offset evidence. The score falls slightly after giving full weight
to Network's source-native sensor differences and the broad agreement that most schemas,
correlations, and lifecycle ordering are sound. The conclusion rests on a repeated construction
signature, not on completeness.

### Network Forensics Analyst

**Final assessment: Inconclusive. Verdict confidence: 88. Synthetic-confidence: 43.** The network
position is reinforced: its source family remains exceptionally coherent, with scanner-pool
concentration as the only material network tell. The score moves only slightly upward after hearing
the endpoint lifecycle evidence, which is strong for the corpus overall but outside the analyst's
primary source family.

### Host/EDR Forensics Analyst

**Final assessment: Inconclusive. Verdict confidence: 85. Synthetic-confidence: 52.** This is the
largest revision. Aggregate positive ordering remains valid, but it was too broad to detect the
behavioral flaw in `userinit.exe` lifetime or the exact repeated teardown offsets. The specific
in-window bash-history/termination joins also undercut a blanket boundary explanation for all
termination-only objects. Strong process identity, ancestry, SSH ordering, and source-local gaps
keep the host evidence near the boundary rather than decisively Synthetic.

## Key Agreements

- The network evidence is highly source-native: protocol children have valid parent connections,
  tuples and time intervals agree, accounting reconciles, and cross-sensor offsets look independent.
- Windows, Sysmon, Zeek, eCAR, proxy, firewall, and syslog fields are broadly parser-safe and
  semantically useful; there is no corpus-wide schema failure.
- The visible attack path is technically coherent and huntable, with no sampled impossible
  web/process/network/authentication ordering.
- Public-DMZ/perimeter background noise has credible timing but insufficient categorical diversity:
  too few scanner sources and too much port/packet-profile reuse for the observed volume.
- Fleet background activity has a narrow repeated vocabulary across host roles, especially the two
  PowerShell maintenance scripts; this is plausible automation but lacks a production-like long tail.
- Bounded-window censoring explains many unmatched lifecycle edges, but it cannot be used to dismiss
  concrete same-window evidence for the same object or command.

## Key Disagreements

- Detection regards the repeated Windows logout triplet and `userinit.exe` lifetime as sufficient
  for a Synthetic verdict. The other roles agree it is the strongest synthetic evidence but differ
  on whether one defective lifecycle family outweighs otherwise strong source-native behavior.
- Detection treats the recurring Linux transient-process orphans as a meaningful contract gap.
  Host/EDR now accepts the specific in-window cases but gives more weight to random endpoint loss
  and the much larger population of valid lifecycle pairs.
- Threat Hunter sees broad direct SSH administration as a moderate environmental tell; Host/EDR's
  detailed source-native SSH sequences make that behavior plausible, though still unusually dense
  and role-insensitive.
- The panel cannot resolve 5156-heavy Windows collection or retained pre-clear records without
  collector/audit-policy metadata. These remain conditional, low-weight concerns.

## Most Convincing Evidence

1. **Repeated Windows teardown construction:** exact 50 ms
   `explorer.exe`/`userinit.exe`/`winlogon.exe` termination triplets recur across multiple hosts,
   users, and hours, coupled with an implausibly session-long `userinit.exe` lifetime.
2. **Independent agreement on low-diversity perimeter noise:** 1,040 DMZ `S0` connections come
   from 11 sources with repeated port portfolios, while 1,021 host UFW blocks come from 10 sources
   and compact packet profiles.
3. **Strong source-native network contracts:** zero sampled UID/tuple/interval violations, valid
   TLS/certificate relationships, exact or loss-compatible ASA/proxy accounting, and realistic
   independent-sensor timing offsets argue strongly against crude fabrication.
4. **Specific in-window process observation gaps:** bash-history starts for `who` and `file` precede
   eCAR termination by seconds, yet the same objects lack CREATE rows; similar `head`/`tail` shapes
   recur on other hosts.
5. **Coherent, heterogeneous operational evidence:** the initial web compromise and later identity,
   persistence, collection, and cleanup pivots align across sources inside a substantial baseline
   haystack without a sampled causal inversion.

## Most Debated Points

- Whether the repeated Windows teardown family is decisive enough to label the entire corpus
  Synthetic, or instead places an otherwise convincing corpus at the boundary.
- Whether short-command CREATE omissions represent realistic source loss or incoherent
  lifecycle-group observation; the concrete in-window examples favor the latter, but their scope
  is limited relative to the full host corpus.
- Whether broad named-user SSH access reflects a centralized operations team or overly
  role-insensitive activity assignment.
- Whether Security Event 5156 concentration and retained pre-clear records are realistic collector
  policy effects; no supplied evidence resolves the collection architecture.

## Consensus Assessment

**Consensus verdict: Inconclusive. Consensus verdict confidence: 84.
Consensus synthetic-confidence score: 52.**

The initial 32-point score spread is explained primarily by specialty depth, not mutually exclusive
facts. Detection found a narrow but repeated host-lifecycle construction signature that the broad
Host/EDR aggregate checks missed; Network found unusually strong source-native behavior in a
different family; Threat Hunter weighted whole-corpus operability and environmental plausibility.
After cross-examination, three roles remain at the boundary and one retains Synthetic. The panel is
confident that the corpus combines highly convincing network/correlation behavior with a material,
repeated endpoint-lifecycle tell. That supports a score just above uncertain rather than either a
production-like or decisively synthetic extreme.

## Improvement Recommendations (Consensus)

1. **Correct Windows interactive-session process lifetimes and teardown ownership.** End
   `userinit.exe` shortly after it launches the shell; do not preserve it to logout. Derive each
   process termination from its own lifecycle, and eliminate fixed, cross-host 50 ms
   shell/userinit/winlogon triplets. This is the highest-value change because it removes the
   panel's strongest repeated disbelief anchor.
2. **Make endpoint process observation coherent for short-lived commands.** For transient Linux
   commands created inside the window, retain CREATE and TERMINATE as one source-local observation
   group or omit both when collection loss applies. Specifically test same-object behavior for
   `who`, `file`, `head`, and `tail`-like short utilities while preserving legitimate boundary
   censoring for long-lived processes.
3. **Expand perimeter scanner diversity as a shared network/host family.** Add a longer-tailed,
   churned source population with per-source but overlapping port strategies and more varied TTL,
   packet length, TCP-window, burst, and one-off-source traits. Preserve the current non-periodic
   interarrival timing and coherent Zeek/ASA/UFW visibility.
4. **Diversify fleet maintenance by role and ownership.** Keep some centrally managed scripts, but
   add role-specific paths and command long tails; vary execution among Task Scheduler, management
   agents, WMI, services, and native binaries. Reduce and role-gate `wsqmcons.exe` recurrence,
   especially on servers, while retaining legitimate distro-default sysstat behavior.
5. **Strengthen administrative-access topology.** Concentrate routine direct SSH access through
   appropriate operators or jump hosts, use role-scoped authorization, and retain a smaller number
   of justified cross-role exceptions with source-host evidence. Preserve the existing rich
   SSH/PAM lifecycle and varied duration/method texture.
6. **Add collection-policy evidence only where source-native.** If the Windows feed intentionally
   emphasizes 5156 or preserves records across a Security-log clear through forwarding, expose
   plausible collector/audit-policy context. Do not distort otherwise correct event semantics to
   explain an unspecified collection mode.

