# Loop 53 Assessment Report

## Outcome

Loop 53 generated 83,084 records and scored 96.23. Fresh initial synthetic-confidence scores
were 46 (Threat Hunter), 84 (Detection), 30 (Network), and 86 (Host/EDR), averaging 61.5. The
mixed verdicts and 56-point spread triggered deliberation. After sharing only the four blind
reports, the panel unanimously assessed the corpus Synthetic at 82/89/88/93, averaging 88.0.

## Fresh Expert Findings

- Detection proved that 138 successful SMB/445 sessions across six Linux roles were owned by
  `/usr/sbin/rsyncd`, a process/protocol contradiction corroborated by Zeek `SF` flows.
- Host found a fleet-wide five-digit Windows temp-file grammar in 272/438 file records, plus
  implausible process/file and process/registry ownership and reused Thunderbird profiles.
- Threat Hunter found seven RDP sessions where eCAR shell processes precede eCAR login, while
  native Windows Security ordering remains correct.
- Network found excellent physical/accounting coherence, but all 1,118 TCP S0 scans were
  one-packet SYNs drawn from a small archetypal scanner population.

## Prioritized Improvements

1. **P0 — Linux SMB process ownership (`hard_contradiction`).** Successful SMB traffic must be
   owned by an SMB/CIFS-capable client, never native `rsyncd`.
2. **P1 — File and registry ownership (`contract_gap`).** Canonical endpoint effects must be
   compatible with the owning executable and visible command.
3. **P1 — RDP source timing (`contract_gap`).** eCAR login observation must precede dependent
   processes in the same session.
4. **P2 — Fleet texture (`distribution_texture`).** Diversify artifact identities, scheduled
   behavior, SSH use, and failed-connection ecology by entity and role.

## Implemented Fix

The shared Linux service-connection owner contract now materializes a target-bearing
`/usr/bin/smbclient` process for SMB/445, with Kerberos-authenticated share semantics. `rsyncd`
is reserved for its native protocol. Target-bearing SMB clients now receive the same exact-command
and bounded one-shot lifecycle treatment as other explicit clients. The full activity-generator
suite passes (352 tests).

## Quantitative Comparison

Parseability was 100.0, plausibility 97.27, causality 90.63, and timing 96.30. The Loop 52
external-network probe examined 36,378 source-IP observations and found zero excluded-network
hits.
