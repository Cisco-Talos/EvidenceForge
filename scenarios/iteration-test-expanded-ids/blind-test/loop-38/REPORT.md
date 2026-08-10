# Loop 38 Assessment Report

## Outcome

Loop 38 generated 85,068 new records from the current code and gave only
neutral copies of those records to four fresh blind reviewers. No previous-loop
finding, score, report, ground truth, evaluation, scenario, implementation, or
repository context was available to them.

The sensor-local loss probe passed on both sensors: none of the 45 incomplete
core-file observations or 56 incomplete DMZ-file observations produced an
X.509, OCSP, or PE analyzer row. The Network reviewer independently confirmed
that missing X.509 companions were now explained by incomplete certificate
files instead of contradictory full analysis. Automated evaluation scored
95.9091; acceptance still fails only the scenario's 31/62 pivot-linkability
gate.

The blind panel was unanimously Synthetic at 65/68/95/72, average 75.0. No
deliberation was required because verdicts agreed, all verdict confidences were
at least 80, and the synthetic-confidence spread was 30 points rather than more
than 30.

## Fresh Findings

- All 108 distinct RSTR flows visible across the two Zeek sensors used an
  uppercase originator-reset marker rather than the lowercase responder-reset
  marker; one S1 row also carried an observed reset despite the open state.
- Windows Security/Sysmon process-create timing had sharply triangular
  source-to-source offsets, and Sysmon CallTrace timestamps clustered at
  stable per-host offsets.
- CBS servicing writes showed a highly repeated value/type/actor pattern, while
  Linux reviewers found generic sudo command texture and implausible browser or
  PID-1 ownership for some tools.
- Failed proxy CONNECT rows retained tunnel-like byte accounting and durations,
  and the Network reviewer found secondary HTTP transaction-depth timestamp
  inversions.

## Next Backlog Family

Make Zeek connection state and packet history one canonical transport invariant.
RSTR must end in a lowercase responder reset, RSTO in an uppercase originator
reset, and S1 must not contain an observed reset or close marker. Sensor-local
observations and source-native rendering must project that same canonical truth.
