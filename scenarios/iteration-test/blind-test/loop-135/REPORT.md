# Loop 135 Assessment Report

## Summary

Loop 135 fixed the fixed SSH cross-sensor duration-cap tell introduced by Loop 134. The regenerated hard probe found zero overlapping SSH flows with exact `+0.750000s` duration deltas and all 113 overlapping SSH observations had unique duration deltas.

Automated eval passed at 96.1770 across 80,629 records. Blind reviewers still classified the dataset as synthetic, with scores: Threat Hunter 72, Detection Engineer 64, Network Forensics 88, Host/EDR 62, average 71.5.

## Hard Probe

- Matched overlapping core/DMZ flows: 1,479
- Identical metric flows: 188
- Matched overlapping SSH flows: 113
- SSH exact `+0.750000s` duration deltas: 0
- SSH exact `+0.750000s` duration deltas with identical bytes: 0
- Unique SSH duration deltas: 113

## Reviewer Findings

- Network Forensics: Zeek SSL/X509 file-analysis timing has concrete source-native contradictions. Certificate chain depth 1 rows can appear before depth 0 for the same TLS connection, and some X.509 rows precede their matching `files.json` object.
- Threat Hunter: proxy metadata has application-profile contradictions, especially HP/Dell/Lenovo updater domains paired with the wrong updater User-Agent and API/registry endpoints returning `text/html`.
- Detection Engineer: Sysmon `ProcessGuid` values carry tiny zero-padded counter suffixes across all Windows hosts, creating a source-native entropy tell.
- Host/EDR: SearchProtocolHost profile SIDs look disconnected from the domain SID base, some eCAR process lifetimes repeatedly terminate within 1-4 ms, and common signed updaters lack PE metadata.

## Score Movement

The network reviewer no longer reported the Loop 134 exact `+0.750000s` SSH duration problem, so the latest fix is verified. The high Network synthetic-confidence score is a deeper issue surfacing: SSL/X509 chain timing is a hard source-native contradiction and should outrank the more subjective proxy, SID, PE metadata, and behavioral-polish findings.

## Next Target

Loop 136 should fix Zeek SSL/X509 file-analysis ordering at the source timeline layer, then add regression probes for both invariants: X.509 rows must not precede their matching file object, and certificate depth `N+1` must not precede depth `N` within a TLS connection.
