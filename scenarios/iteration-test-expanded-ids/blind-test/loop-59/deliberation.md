# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Synthetic | 82 | 74 | Synthetic | 84 | 78 |
| Detection Engineer | Synthetic | 80 | 69 | Synthetic | 84 | 76 |
| Network Forensics | Real | 82 | 24 | Inconclusive | 76 | 46 |
| Host/EDR Forensics | Synthetic | 76 | 72 | Synthetic | 84 | 79 |

The revised panel-average synthetic-confidence score is **69.75/100**. The panel did not
force unanimity: the network evidence remains credible enough for that specialist to retain an
inconclusive global position, while the other three specialists judge the repeated endpoint
contradictions sufficient for a synthetic verdict.

## Round 1 — Independent Positions

### Threat Hunter

The hunter initially assessed **Synthetic (82 confidence, 74 synthetic-confidence)**. Their
strongest evidence was a family-specific eCAR lifecycle gap: 83 of 84 `taskhostw.exe` object
identities lacked a matching termination despite abundant termination telemetry, including many
processes created well before the right boundary. They also found 45 root/system health-check
processes on four Linux server roles pointed at a shared-looking pool of public advertising,
tracking, widget, and content endpoints. Their counterweight was a highly workable intrusion trail:
web compromise, Linux credential access, Windows lateral movement and persistence, database
staging, and SCP transfer all permitted credible cross-source pivots.

### Detection Engineer

The detection engineer initially assessed **Synthetic (80 confidence, 69
synthetic-confidence)**. Their strongest hard contradiction was Chrome or Edge owning files under
desktop Outlook's private `Content.Outlook` cache. They also found 35 of 36 `wget`/`curl` creates
parented directly by PID 1, suppressing the service, timer, updater, or package-manager launcher
expected to own such diverse activity. A secondary attack-chain gap was execution of
`DeviceSyncSvc.exe` without a visible preceding file delivery/write. They nevertheless judged the
intrusion chain unusually useful for detection development because identities, tuples, files, and
process relationships mostly correlate well.

### Network Forensics Analyst

The network analyst initially assessed **Real (82 confidence, 24 synthetic-confidence)** and
found no hard network contradiction. Their strongest evidence was independent core and DMZ Zeek
observation: distinct UIDs, small sensor-relative timestamp offsets, and compatible tuples, states,
and services. Protocol fan-out, DNS cache/TTL behavior, TLS session/certificate behavior, and ASA
build/teardown lifecycles were also internally disciplined while retaining realistic gaps, resets,
partial file capture, and a boundary-open connection. Their synthetic caveats concerned the exact
six-hour boundary, concentrated actors/domain pools, and unusually tidy population-level coverage.

### Host/EDR Forensics Analyst

The host analyst initially assessed **Synthetic (76 confidence, 72 synthetic-confidence)**.
Independently of the detection engineer, they found ten Chrome/Edge file events under Outlook-only
`RoamCache` or `Content.Outlook` paths across two hosts. They also found RuntimeBroker directly
owning Office documents or browser-cache reads, suggesting that process actors and path classes
were selected independently. Exact high-frequency background command repetition was supporting
texture evidence, not a verdict driver. The analyst emphasized that explicit-credential,
SSH/SCP, service-installation, account-manipulation, and session evidence was otherwise strong.

## Round 2 — Cross-Examination

### Network realism versus endpoint impossibility

The principal disagreement was not a direct conflict about the same records. The network analyst
demonstrated that the network plane could plausibly come from real sensors; the endpoint reviewers
demonstrated that this does not establish whole-corpus authenticity. Chrome or Edge repeatedly
writing desktop Outlook-private cache locations is a source-native ownership contradiction, not
merely an unusually clean pattern. Its recurrence across hosts, and its independent discovery by
two specialists, gives it more verdict weight than the network layer's positive realism can erase.

The network analyst's evidence remains important: independent sensor UIDs, plausible sensor delay,
state-compatible protocol fan-out, and source-specific imperfections strongly argue against a
simple record-level generator. The appropriate revision is therefore from Real to Inconclusive,
not to a high-confidence Synthetic network verdict. The contradiction lies outside the network
plane, whose own fidelity remains a major counter-signal.

### Endpoint lifecycle gap versus ordinary censoring

The host analyst's aggregate lifecycle counts were compatible with long-running processes,
collection gaps, and window boundaries. The hunter's narrower `taskhostw.exe` measurement is more
probative because the missingness is conditioned on one executable family, spans nine hosts, and
includes processes created near the start of the window while 1,425 termination events are
otherwise visible. Still, the reports do not prove every `taskhostw.exe` invocation was intended to
be finite. The panel therefore classifies this as a strong contract gap requiring a family audit,
but ranks the independently corroborated Outlook ownership contradiction above it.

### Role-incoherent health checks and PID-1 download parentage

The hunter's role-incoherent health-check destinations and the detection engineer's near-universal
PID-1 ownership of `wget`/`curl` reinforce a shared concern: Linux background activity has plausible
individual command shapes but weak service/dependency ownership at population scale. Either fact
could have a local operational explanation. Their cross-host recurrence across unrelated roles
makes a shared generation rule more likely, but these remain environment/distribution evidence
rather than hard source-native impossibilities.

### Authored attack completeness

The detection engineer considered the one-window coverage of credential theft, lateral movement,
persistence, collection, exfiltration, and cleanup suspiciously complete. The hunter showed that
the individual transitions are operationally coherent, while the network analyst documented
realistic source-specific gaps. The panel therefore treats over-completeness as a soft curation tell,
not decisive evidence. Deliberately dropping attack evidence before fixing semantic contradictions
would reduce investigative value without addressing the strongest authenticity failure.

## Round 3 — Revised Positions

### Threat Hunter — Synthetic, 84 confidence, 78 synthetic-confidence

The hunter modestly increases synthetic confidence. The two endpoint specialists' independent,
cross-host confirmation of browser-owned Outlook artifacts adds a harder application-semantic
contradiction to the hunter's measured process-lifecycle and server-role findings. The coherent
intrusion trail and realistic network plane prevent a larger increase.

### Detection Engineer — Synthetic, 84 confidence, 76 synthetic-confidence

The detection engineer strengthens their synthetic position because the host analyst independently
reproduced and broadened the same ownership defect to `RoamCache` and RuntimeBroker path classes.
The network analyst's evidence increases confidence that the problem is localized to semantic
ownership and population construction rather than basic schema or protocol rendering.

### Network Forensics Analyst — Inconclusive, 76 confidence, 46 synthetic-confidence

The network analyst revises from Real to Inconclusive at the whole-corpus level. No network finding
was overturned: cross-sensor identity, state, timing, protocol, TLS, DNS, and ASA evidence remains
strongly realistic. The revision is driven by repeated endpoint impossibilities outside the
analyst's original specialty. Synthetic confidence remains below 50 because the network layer
contains substantial source-native depth and believable imperfection.

### Host/EDR Forensics Analyst — Synthetic, 84 confidence, 79 synthetic-confidence

The host analyst increases confidence after the detection engineer independently identified the
same browser-to-Outlook contradiction and after the hunter demonstrated family-conditioned process
lifecycle missingness. The network findings moderate the final score by showing that major portions
of the corpus remain technically convincing.

## Classified Evidence

| Rank | Evidence | Classification | Panel Treatment |
|---:|---|---|---|
| 1 | Chrome/Edge own `Content.Outlook` and `RoamCache` artifacts on multiple hosts | **Hard contradiction — application/source ownership** | Decisive synthetic evidence; independently reproduced by detection and host reviewers |
| 2 | 83/84 `taskhostw.exe` object identities lack eCAR termination despite broad termination coverage | **Contract gap — lifecycle completeness/observation coherence** | Strong, family-specific evidence; slightly tempered because process intent is not proven finite |
| 3 | RuntimeBroker owns Office documents and browser-cache reads | **Hard-to-explain semantic ownership mismatch** | Reinforces a cross-product actor/path assignment defect |
| 4 | 35/36 `wget`/`curl` creates have PPID 1 across unrelated jobs and hosts | **Environment/launcher plausibility** | Strong population-level tell, but locally explainable by service execution |
| 5 | Root health checks on unrelated server roles use a shared pool of ad-tech/content endpoints | **Environment/dependency plausibility** | Strong role-distribution tell, not a source-native impossibility |
| 6 | Independent Zeek identities with compatible tuples/state and realistic sensor delay | **Strong realism evidence — cross-source network contract** | Preserves a meaningful real/inconclusive minority position |
| 7 | Coherent multi-host intrusion and SCP/file pivots | **Strong realism evidence — operational causality** | Confirms high investigative utility and prevents an extreme synthetic score |
| 8 | Exact six-hour scope and broad attack observability | **Soft curation/distribution tell** | Supporting only; not prioritized over semantic defects |

## Key Agreements

- The corpus has high investigative utility: the principal intrusion pivots across process,
  identity, file, session, and network evidence are usable and usually coherent.
- Network state and cross-sensor relationships are among the strongest realism features and should
  be preserved.
- Endpoint application ownership is the highest-confidence defect. File paths must not be sampled
  independently of the process/application that owns them.
- Process lifecycle and Linux background ownership deserve family-level audits rather than isolated
  record patches.
- Population-level diversity could improve, but soft curation tells rank below hard semantic
  contradictions.

## Key Disagreements

- The network analyst found the network plane compatible with real collection, while the other
  specialists judged endpoint defects sufficient for a whole-corpus synthetic verdict. The panel
  preserves this as an informed disagreement rather than relabeling realistic network evidence.
- The `taskhostw.exe` termination deficit is highly suspicious, but the panel cannot establish from
  the blind records alone that every invocation should terminate inside the observation window.
- Attack-chain completeness looks authored to the detection engineer, whereas the other evidence
  shows realistic source-specific omissions and a genuinely huntable noise floor. It remains a
  secondary signal.

## Most Convincing Evidence

1. Repeated Chrome/Edge ownership of desktop Outlook-private caches across multiple hosts.
2. Family-conditioned absence of `taskhostw.exe` terminations despite abundant same-source process
   termination telemetry.
3. RuntimeBroker ownership of Office documents and browser-cache artifacts, reinforcing a broader
   actor/path cross-product problem.
4. Independent cross-sensor Zeek observations with distinct UIDs, small timing offsets, and
   compatible tuple/state/protocol semantics—the strongest evidence for realism.
5. Role-incoherent Linux health-check destinations and near-universal PID-1 download parentage.

## Ranked Family Improvement Targets

1. **Endpoint file actor/application ownership.** Make Outlook-private caches exclusive to Outlook
   or a specifically modeled Outlook helper; map browser artifacts to the matching browser cache or
   download location; prohibit RuntimeBroker from directly owning Office documents or browser cache
   unless a concrete mediated operation is modeled. Validate the negative actor/path cross-product
   across every host and user.
2. **Transient/background process lifecycle ownership.** Audit `taskhostw.exe`, Google Updater,
   unknown-user `sshd`, and similar repeated families. Pair finite creates with lifecycle-compatible
   terminations and apply source observation decisions coherently to the lifecycle group.
3. **Linux service launcher and dependency ownership.** Retain the systemd timer/service, package
   manager, updater, or application parent for `wget`/`curl`; select health-check targets from
   explicit host-role/application dependencies rather than a global public-domain pool.
4. **Service-binary provenance.** Materialize a correlated write/drop/rename and stable hash for
   `DeviceSyncSvc.exe` before service installation and execution, or model a coherent source-level
   observation gap.
5. **Population texture and collection shape.** Diversify high-volume proxy/CDN actors, recurring
   scheduled commands, cache states, and request cadence while preserving existing cross-sensor and
   action-lifecycle contracts.

## Selected Top Improvement

**Fix endpoint file actor/application ownership as one family-level contract.** The selected target
is the Outlook/browser/RuntimeBroker ownership family because it is a repeated, cross-host,
source-native contradiction independently identified by two reviewers. File path selection should
be conditional on the owning application family, with explicit positive mappings and negative
invariants: Outlook may own `Content.Outlook` and `RoamCache`; Chrome and Edge may own their matching
browser caches, downloads, or modeled OWA artifacts; Office documents should be owned by their
corresponding Office application or a specifically modeled shell/file operation; RuntimeBroker
must not be used as a generic actor. A cross-product regression probe should fail on every
actor/path mismatch, not only the examples observed here.

## Improvement Recommendations (Consensus)

- Implement and probe the selected actor/path ownership contract across browser, Outlook, Office,
  RuntimeBroker, host, and user combinations.
- Audit finite process families for create/terminate lifecycle ownership and coherent source-level
  observation, beginning with `taskhostw.exe`.
- Model Linux launcher and health-check dependencies from explicit service/role configuration rather
  than defaulting background downloads to PID 1 and public-domain pools.
- Preserve the current network contract: independent sensor identities, sensor-relative delays,
  compatible lifecycle/state, and realistic protocol gaps are among the corpus's best properties.
- Treat reduced attack observability and broader population diversity as later refinements, after
  the hard semantic and lifecycle contradictions are repaired.
