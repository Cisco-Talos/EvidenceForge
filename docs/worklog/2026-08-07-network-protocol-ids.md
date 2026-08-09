# Batch 3 Network, Protocol, and IDS Contracts

## Scope and authority

This worklog is the branch-local execution record for the approved Batch 3 remediation slice on
`codex/batch3-network-contracts`. The completed review, accepted contract proposals, final report,
and `TODO.md` remain authoritative. Blind-review evidence may expose siblings inside this slice,
but it does not reorder the roadmap or create an unbounded review loop.

Batch 3 resolves `REAL-005`, `REAL-007`, and `REAL-009`. It also owns the verified siblings that
share the same network-transaction boundary: dynamic PAT lifetime, inbound ICMP NAT projection,
payload-free service confirmation, source-sensor clock coherence, and protocol-child containment.

## Contract 1: sealed transport and sensor observation

- `NetworkTransactionPlan` is the only canonical owner of the final transport tuple, outcome,
  phase interval, connection state/history, directional payload/packet/IP-byte ledger, service,
  connection identity, and endpoint process references.
- `NetworkSensorObservation` is the only owner of one sensor's visible tuple, source-visible start
  and close, captured accounting, connection/file identifiers, local-origin/local-response flags,
  NAT address views, firewall close reason, and firewall close time.
- Protocol, file, firewall, endpoint-flow, and IDS projections consume the sealed transaction and
  matching observation. They must not independently reconstruct clocks, tuples, accounting,
  transport outcomes, or NAT lifetimes.
- Every child record joined by a connection UID must fall inside that sensor observation's
  half-open/closed interval according to source semantics. A child that cannot fit is dropped or
  causes the owning planned interval to expand before sealing; emitters do not silently invent a
  different parent interval.
- Dynamic NAT state contains the associated connection lifetime. For emitted ASA lifecycles:
  `xlate_build <= connection_build <= connection_teardown <= xlate_teardown`.
- Static inbound NAT exposes both public/global and translated/local address views. ASA ICMP and
  TCP projections consume those same views rather than treating the public destination as the
  local address.

## Contract 2: structured IDS eligibility

- The signature catalog owns a validated `SignaturePredicate`: direction, transport phase,
  response requirement, minimum origin/response payload, application protocol, HTTP method/status
  or semantic class where required, and inspection capability.
- The IDS action may prepare a signature intent, but final attachment occurs only after the network
  and protocol outcome is planned. Eligibility is evaluated against the sealed transaction,
  `HttpContext`/DNS/TLS/file children, and the sensor's inspection view.
- Content signatures cannot attach to S0/REJ or zero-payload traffic. Response/status claims require
  response packets and payload. Upload signatures require a body-bearing compatible method. HTTP
  signatures cannot attach to opaque TLS unless the observation declares decryption/inspection.
- Scan, flow-metadata, handshake, and ICMP signatures remain legal without application payload when
  their declared phase and protocol predicates permit it.
- Snort/Suricata emitters remain projection-only and never reinterpret eligibility from message
  text.

## Contract 3: projection independence

- Scenario/config intent and deterministic RNG scopes produce the same world, actions, state,
  ground truth, and canonical network ledger regardless of requested output formats.
- Format filtering is applied after canonical planning and source-observation decisions. Generator
  code may not gate action creation on `self.emitters` membership except for explicitly source-local
  health/status noise that is excluded from cross-source guarantees.
- For identical scenario and seed, every common output format must be byte-identical between full,
  filtered, and parallel-output runs. Ground truth and canonical-ledger hashes must also match.
- Migration proceeds family by family: network/protocol/IDS generators first, then remaining
  baseline emitter gates. Compatibility/raw paths stay documented outside cross-source guarantees.

## Incremental implementation order

1. Add the validated structured signature predicate and evaluate it at the network planner's final
   attachment boundary. Repair baseline false positives without message-substring heuristics.
2. Make sensor observations carry authoritative NAT lifetime/address views; repair dynamic PAT and
   inbound ICMP projection from those facts.
3. Route Zeek file, TLS/X.509/OCSP/PE, HTTP, DNS, and other protocol child timestamps through the
   matching frozen sensor interval. Remove independent parent-time reconstruction.
4. Enforce analyzer-confirmed service semantics for failed/payload-free connections after checking
   primary Zeek behavior.
5. Remove generation-time emitter gates from canonical network/protocol paths and add full versus
   filtered versus parallel ledger/output equivalence tests.
6. Regenerate the integrated enterprise matrix, run the review probe and evaluator, prove exact
   repeatability, and run the complete non-slow suite plus targeted scale tests.

## Acceptance criteria

- The rendered probe reports zero IDS semantic contradictions, Zeek child-interval escapes, PAT
  lifetime inversions, and inbound ICMP NAT address contradictions on the integrated matrix.
- Predicate tests cover TCP states (`S0`, `REJ`, `RSTO`, `RSTR`, `OTH`, `SF`), both payload
  directions, encrypted/cleartext inspection, HTTP method/body/status semantics, DNS response
  semantics, scan metadata, and ICMP.
- Sensor tests cover pre-/post-NAT tuple views, multiple sensors, static and dynamic NAT, observation
  jitter/loss profiles, short/absent closes, and output-window tails.
- Projection-equivalence tests compare canonical-ledger, ground-truth, and common-format bytes for
  full, filtered, and parallel runs using identical inputs.
- Configuration validation, Ruff, focused tests, the complete non-slow suite, integrated generation,
  identical-input comparison, and evaluation all pass before Batch 3 is marked complete.

## Implementation outcome

- Added a validated, frozen `SignaturePredicate` contract to the signature catalog and canonical
  IDS context. Final attachment now occurs after transport/protocol planning and rejects
  incompatible state, direction, payload, response, method/status, port, and inspection claims.
  Baseline false positives no longer infer semantics from alert-message substrings.
- Added authoritative NAT address and lifetime views to `NetworkSensorObservation`. ASA dynamic
  PAT build/teardown now brackets the owning connection, and inbound ICMP renders the same
  public/global and translated/local views as static-NAT TCP evidence.
- Sealed Zeek protocol/file projection timestamps to each sensor observation interval. DNS, HTTP,
  SMTP, TLS/X.509/OCSP/PE, and files no longer independently reconstruct the parent clock.
- Applied Zeek's analyzer-confirmation semantics by clearing non-ICMP service labels on
  payload-free connections. The primary references and disposition are recorded in
  `docs/design/realism-review/source-references.json`.
- Removed canonical-generation gates based on configured emitters from the network/protocol and
  remaining baseline paths. An integrated full-versus-filtered test proves byte-identical common
  outputs and ground truth; the existing slow parallel tests prove serial/parallel equivalence.
- Extended `scripts/realism_review_probe.py` with ASA PAT lifetime, static-NAT ICMP, and
  payload-free Zeek service checks. The probe remains read-only and has focused parser/positive
  and negative tests.
- The integrated run exposed a regression in the previously passed Linux PID gate. The temporal
  allocator now reserves enough PID-space churn and searches near its time-derived candidate
  rather than repeatedly consuming a future interval's midpoint. A second one-PID pipeline
  reversal was traced to independent eCAR floor-repair delays under a negative host clock;
  floor repair now retains the host-coherent process-create latency curve.

## Final evidence and disposition

- Frozen post-Batch-2 output reprobe: 103 Batch 3 errors — 5 dynamic PAT lifetime inversions,
  35 inbound ICMP NAT contradictions, 26 Zeek file interval escapes, and 37 unconfirmed service
  labels. Final integrated output reports zero for all four checks, IDS transport semantics,
  protocol-child containment, and Linux PID chronology.
- Final output: `/private/tmp/eforge-batch3-network-gate-v3/branch-enterprise`; identical repeat:
  `/private/tmp/eforge-batch3-network-gate-v3/branch-enterprise-repeat`. `diff -qr` returned zero;
  the relative-path data manifest SHA-256 is
  `26125f304d0670fb4e19c15e611d538339268b152459d9f1d2a362f5afc7b401`.
- Evaluation passes at 96/100 over 49,969 records from 18 sources. Spec/format conformance, IDS
  correlation integrity, causal ordering, event presence, and temporal integrity are all 100.
- Configuration validation reports zero findings across 87 files. Ruff check and format check
  pass. The targeted slow parallel suite passes 5 tests; the complete non-slow suite passes 5,153
  tests with 41 expected skips in 235.52 seconds.
- The final probe retains only two warnings already assigned to Batch 5: uniform OCSP file
  duration and universally successful AAAA answers. The scenario's known undeclared public
  hostname warning is unchanged and outside this slice.
- Batch 3 is complete. Durable machine-readable evidence is in
  `docs/design/realism-review/batch3-results.json`; Batch 4 remains next in the accepted roadmap.
