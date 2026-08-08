# Post-Batch-7b effectiveness gate

## Purpose

Measure whether the cumulative architecture/remediation work improved rendered realism. This is a
single assessment pass, not an iterative blind-review fix loop.

## Frozen inputs

- Branch/commit: `codex/batch7-compatibility-docs` at `53934a16`.
- Scenario: `/private/tmp/eforge-realism-review/branch-enterprise.yaml`, SHA-256
  `bf7eef77f0cb121bb0838cc4252ae19347e1a8c8304079c11426163806cc07ff`.
- Duration/profile: six hours, `enterprise_standard`.
- Primary output: `/private/tmp/eforge-post-batch7b-effectiveness/branch-enterprise`.
- Repeat output: `/private/tmp/eforge-post-batch7b-effectiveness/branch-enterprise-repeat`.
- Neutral reviewer copy: `/private/tmp/case-omega.SimlDV/data`.

The user-supplied `iteration-test-expanded` scenario was considered but no longer validates
unchanged under the current capability contract. The exact frozen integrated review benchmark was
used instead.

## Execution result

- Validation passed with the existing undeclared network-identity warning for
  `portal.northstarclaims.net`.
- Primary/repeat outputs are byte-identical across 38 data files, digest
  `911decaca74f1b2663d6508d2e99eed861a247ffbdd76c34ed6f9cbcb803e67f`.
- Evaluation parsed 53,548 records across 16 sources and scored 95.025576. Acceptance failed only
  at `causality.pivot_linkability=40`, below the current threshold of 80.
- The current realism probe reports two deterministic SSH ordering families: 9 records on PROXY
  and 28 on WEB have syslog for an sshd PID before eCAR observes that PID's process creation.
- A controlled run from Batch 7a commit `868eb35d` has one Linux PID-reversal finding and no SSH
  ordering failure. Batch 7b therefore repaired the reversal but introduced the SSH regression.

## Blind panel

Four isolated reviewers saw only the neutral data directory. All returned Synthetic:

| Specialty | Verdict confidence | Synthetic confidence |
| --- | ---: | ---: |
| Threat Hunter | 84 | 72 |
| Detection Engineer | 98 | 96 |
| Network Forensics | 97 | 96 |
| Host/EDR | 98 | 96 |

The panel average is 90.0 and the spread is 24. No deliberation was triggered. The result is 1.75
points lower than the original pre-fix 91.75 and 0.75 lower than the final gate 90.75; those small
differences do not demonstrate material aggregate improvement across independent panels.

## Validated dispositions

Five P1 families block PR readiness: the Batch 7b SSH source-order regression, inbound WFP remote
PID leakage, file/application/transport loss-accounting contradictions, clock-derived Linux PID
allocation, and missing SSH close ownership. Secondary findings include bounded Type 3 durations,
singleton service accumulation, template-shaped Linux chatter/SSH cadence, and timing/ID
quantization.

No generator fix was made and no follow-up blind assessment was started. The complete evidence,
static ownership traces, score comparison, and next dependency order are in
`docs/design/realism-review/post-batch7b-effectiveness/REPORT.md`.

## P1 blocker remediation contracts

The user authorized a single family-level remediation loop for all five validated P1 blockers,
followed by regeneration and one fresh blind panel. The public CLI, authored scenario schema, and
source format schemas remain unchanged.

### Linux PID allocation

- **Owner:** `StateManager`, because PID progression is host process-allocation state.
- **Invariant:** PIDs remain deterministic, unique, chronologically ordered under deferred and
  out-of-order generation, and fast to look up without encoding one exact wall-clock slope.
- **Entry paths:** baseline and storyline process creation, SSH responder/shell creation, causal
  process expansion, and direct internal process-generation adapters.
- **Consumers:** process state, eCAR/Sysmon/syslog renderers, parent/child lookup, lifecycle probes,
  and ground-truth references.
- **Implementation boundary:** replace the constant seconds-to-PID formula with a cached per-host
  hidden-churn schedule and O(1) prefix lookup; retain the bounded temporal allocation index.
- **Sibling risks:** PID wrap, future insertion capacity, dense same-time allocations, memory
  retention, deterministic repeats, and parent-before-child constraints.

### File, transport, and capture-loss accounting

- **Owners:** the network/file transaction plans own canonical payload and framing; the network
  observation plan owns sensor loss and source-local completeness.
- **Invariant:** application and file bytes plus protocol framing fit inside the corresponding
  directional transport payload; sensor loss reduces observed file/body completeness and appears
  in Zeek connection history without mutating canonical traffic.
- **Entry paths:** generic connections, HTTP/S, proxy, SMB/file staging, email/MIME, OCSP,
  automatic protocol attachment, and explicit file-transfer bundles.
- **Consumers:** Zeek conn/http/files/ssl/smb renderers, firewall/IDS projections, eCAR FLOW,
  evaluator checks, and ground-truth correlation.
- **Implementation boundary:** reconcile canonical accounting once before finalization, remove
  generator-invented capture loss, and freeze per-sensor protocol/file observations before
  rendering.
- **Sibling risks:** double-counting HTTP bodies, multiple files per flow, TLS certificate files,
  packet/IP-byte conservation, incomplete hash/analyzer claims, and multiplexed sensor IDs.

### Inbound Windows WFP ownership

- **Owner:** Windows source-native projection, because the canonical event already supplies both
  transport endpoints and the local receiving process.
- **Invariant:** inbound 5156 rows use the receiver's local PID/image pairing and never combine a
  local image with a remote initiating PID.
- **Entry paths:** canonical connection fan-out, direct internal WFP adapter, baseline/storyline
  connections, and higher-level SSH/RDP/remote-admin/network bundles.
- **Consumers:** Windows 5156 output, process/network pivots, evaluator identity checks, and blind
  host review.
- **Implementation boundary:** select initiating identity only for outbound rows and responding or
  local process identity for inbound rows; preserve source schema and routing.
- **Sibling risks:** System/PID 4 fallback, missing listener telemetry, DNS client overrides,
  loopback/self-connections, and IPv6 direction semantics.

### SSH source ordering

- **Owners:** the SSH action bundle and source timing planner, because they coordinate responder
  process visibility with auth/session evidence across endpoint sources.
- **Invariant:** same-host SSH syslog auth/session evidence for an sshd PID cannot precede that
  PID's eCAR process-create observation; transport remains visible before authentication.
- **Entry paths:** typed storyline SSH, Linux remote-interactive compatibility routing, baseline
  remote administration, SCP/file transfer, and direct internal SSH adapters.
- **Consumers:** syslog, eCAR FLOW/PROCESS/USER_SESSION, Zeek conn/ssh companions, lifecycle probes,
  and cross-source pivots.
- **Implementation boundary:** anchor the SSH lifecycle to the actual planned eCAR responder
  visibility window, then resolve all auth/session constraints from that anchor.
- **Sibling risks:** collection-delay groups, omitted listener identity, short transports, PAM and
  logind ordering, repeated auth attempts, and deterministic occurrence IDs.

### SSH closure ownership

- **Owner:** the SSH action bundle; callers supply boundary intent, but the bundle owns the
  transport/auth/shell/session lifecycle.
- **Invariant:** a closed in-window SSH transport produces coherent endpoint/PAM/logind/shell and
  session closure unless one source-local lifecycle group is intentionally dropped; only an
  explicit output-boundary policy may leave it open.
- **Entry paths:** the same SSH family paths listed above, including WorldPlanner bootstrap.
- **Consumers:** process/session state, syslog and eCAR lifecycle rows, Zeek close evidence,
  evaluator containment checks, and ground truth.
- **Implementation boundary:** make in-window closure the internal default and reserve explicit
  `False` for boundary-open callers; keep all close events in the bundle.
- **Sibling risks:** sessions crossing the generation window, premature source-process
  termination, double close/logoff rows, failed authentication, and explicit session-end plans.
