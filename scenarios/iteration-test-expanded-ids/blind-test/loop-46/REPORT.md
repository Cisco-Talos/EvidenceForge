# Loop 46 Assessment Report

Loop 46 regenerated 80,525 records from committed `ea53038a`. Automated
evaluation scored 96.0996 and failed only pivot linkability. The Loop 45
HTTP/proxy ownership family passed its rendered-output probe: 1,684 endpoint
proxy flows, 1,678 exact HTTP tuple joins, zero User-Agent/process-family
mismatches, zero command/host mismatches, zero Postfix HTTP owners, and zero
process-lifecycle violations.

The initial blind panel was Synthetic/Real/Synthetic/Synthetic at 66/24/66/70,
average 56.5. Verdict disagreement and a 46-point spread triggered
deliberation. After evidence checking, the panel converged unanimously on
Synthetic at 72/61/71/75, average 69.75.

## Fresh Findings

- Network found 47 established, non-resumed TLS rows that referenced 70
  certificate FUIDs absent from the same sensor's x509 log.
- Threat Hunter found 22 of 64 interactive sudo commands attributed to
  service-style accounts and 29 commands using another identity's home
  directory across unrelated Linux hosts.
- Host found repetitive Linux baseline texture: exactly eight D-Bus records on
  all nine Linux hosts, rigid sysstat grids, and 904 UFW blocks drawn from a
  compact scanner/fingerprint pool.
- Network found per-packet payload randomization in 13 of 15 rapid multi-echo
  ICMP bursts.
- Detection found no hard contradiction and rated the corpus Real before
  cross-specialty evidence was presented.

## Selected Improvement

**Family:** TLS SSL-to-X.509 lifecycle-group observation integrity.
**Classification:** `family_level` contract repair.

Sensor-local projection now removes any certificate FUID from `ssl.log` when
the same sensor did not capture enough certificate bytes for X.509 analysis.
The fix uses the frozen per-sensor `FileSensorObservation` rather than
emitter-global format visibility, so references and analyzer rows agree in
each observation zone.

## Verification

The Loop 45 family probe is clean. Eighty-two focused TLS, file-observation,
and network-observation tests pass, including a new sensor-local regression
test for incomplete certificate capture. Loop 47 will provide fresh rendered
output and blind confirmation for the selected TLS family.

## Prioritized Remaining Findings

- **P1:** Bind Linux sudo identities, sessions, and working directories to
  host-specific account ownership.
- **P1:** Persist realistic per-scanner UFW TCP fingerprints and expand source
  diversity.
- **P1:** Model ICMP echo sequences as stable-payload invocation bundles.
- **P2:** Replace fixed Linux daemon quotas and unexplained cron omissions with
  activity- and collection-driven behavior.
