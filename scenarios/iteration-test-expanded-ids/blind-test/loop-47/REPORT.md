# Loop 47 Assessment Report

Loop 47 regenerated 80,525 records from committed `fc51a85d`. Automated
evaluation remained stable at 96.0996 and failed only pivot linkability. The
Loop 46 TLS lifecycle family passed its rendered-output probe: all 530
certificate FUID references resolve inside their own sensor zone, with zero
dangling references across 1,232 full established handshakes.

The initial blind panel was Synthetic/Real/Real/Synthetic at 67/18/27/64,
average 44.0. Verdict disagreement and a 49-point spread triggered
deliberation. The panel retained a 2-2 role split but reached a narrow
Synthetic consensus at 59 confidence 68; final role scores were 72/40/39/74.

## Fresh Findings

- Host found 96 successful SSH authentications across 20 user/source/target
  tuples; 13 tuples switched repeatedly between password and public key.
- The same client/user presented a different key fingerprint to each target
  server despite simple client commands with no visible identity selection.
- Threat Hunter independently found 91 SSH client creates concentrated on a
  small repeated command/target pool and near-invariant DHCP renewal trains.
- Network found no hard contradiction and rated the corpus Real, explicitly
  confirming coherent SSL/X.509 references, UIDs, tuples, packet accounting,
  firewall lifecycles, IDS timing, and proxy byte scopes.
- Detection found no material schema, lifecycle, or correlation defect and
  rated the corpus Real.

## Selected Improvement

**Family:** durable SSH client credential identity and tuple authentication
policy. **Classification:** `family_level` canonical identity-state repair.

Baseline SSH now derives one public-key identity from client IP plus username,
independent of destination. Authentication method is selected once from the
client/user/target policy and reused for every session on that tuple, rather
than being independently sampled per connection.

## Verification

The Loop 46 TLS family probe is clean. The focused baseline/realism suite
passes 158 tests with one expected skip, including durable cross-target key
identity, stable tuple authentication policy, and fleet-level method diversity.
Loop 48 will provide fresh rendered-output and blind confirmation.

## Prioritized Remaining Findings

- **P1:** Add stateful, disturbed DHCP renewal timing while preserving lease
  and T1 semantics.
- **P1:** Reconcile endpoint time-synchronization activity with network NTP
  visibility or an explicit collection boundary.
- **P2:** Reduce repeated SSH command/target concentration with persona- and
  role-specific session rates.
- **P2:** Add low-volume source-native incomplete TLS analyzer observations
  only where transport state supports them.
