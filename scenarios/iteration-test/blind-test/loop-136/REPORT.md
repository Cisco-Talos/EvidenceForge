# Loop 136 Blind Realism Report

## Individual Expert Summaries

Threat Hunter judged the data synthetic with 66 confidence. They found the source formats and pivots convincing, but the attack chain still felt unusually curated: `nmap`, domain recon, PsExec, service-account creation, Domain Admins membership, persistence, database dump, exfil, cleanup, and log clearing landed in a neat sequence with little attacker mess.

Detection Engineer judged the data synthetic with 72 confidence. They found Windows Security, Zeek, proxy, ASA, Snort, and syslog structure strong, and explicitly found the Zeek SSL/files/x509 UID and timing relationships source-native after the Loop 136 fix. Their remaining concrete findings centered on Sysmon `ProcessGuid` morphology and missing PE metadata for Microsoft binaries such as `runas.exe`, `msra.exe`, and `curl.exe`.

Network Forensics judged the data synthetic with 68 confidence. They found Zeek UID references, TCP state semantics, TLS versions, and certificate chains plausible, with no remaining TLS/X.509 impossible ordering. Their strongest remaining concerns were sticky-resolver realism, DNS-tunnel payload vocabulary/timing, all-TCP Kerberos on port 88, mostly single-transaction HTTP sessions, and a repeated burst of short TLS sessions from one external source.

Host/EDR Forensics judged the data synthetic with 78 confidence. They found Security/Sysmon/eCAR correlation, DC attack sequencing, Linux SSH sessions, bash histories, and role-specific user behavior convincing. Their source-native endpoint concerns were UserAssist registry value names like `HRZR_EHACNGU28`, polkit action/program mismatches, high Windows core process PIDs, compact Sysmon Event 10 call traces, and missing binary metadata.

## Fixed And Verified

- Loop 136 fixed the Zeek SSL/X.509 file-analysis timeline at the shared certificate timing layer.
- Hard probe results found zero certificate depth inversions, zero adjacent fixed `0.001s` certificate gaps, zero X.509 rows before matching files rows, and zero X.509 rows equal to matching files rows across both `zeek-core` and `zeek-dmz`.
- Focused and related tests passed (`71 passed`, `79 passed`), config validation passed, Ruff checks passed, and the full normal test suite passed with `3385 passed, 15 skipped`.

## Quantitative Eval

- Overall automated eval: `96.27698863027608`
- Records: `80,629`
- Parseability: `100.0`
- Plausibility: `96.59783744738361`
- Causality: `94.2429740156467`
- Timing: `92.83392882259253`

## Prioritized Improvements

### P1 — UserAssist Registry Value Realism

Reviewer original rating: not labeled. Score impact: high. Observed by Host/EDR.

Sysmon registry rows use placeholder-like ROT13 UserAssist value names such as `HRZR_EHACNGU28` and short synthetic-looking binary details. Real UserAssist `UEME_RUNPATH` values should encode a path-bearing value name and carry plausible value data. Owning layer is registry activity generation/rendering; fix risk is moderate because it touches Windows artifact realism but should be locally testable.

### P1 — Sysmon ProcessGuid Morphology

Reviewer original rating: not labeled. Score impact: high. Observed by Detection and Host/EDR.

Per-host `ProcessGuid` values have fixed prefixes and tiny zero-padded counter tails such as `000000000019`, creating a generator-shaped field even though the GUIDs are syntactically valid. Owning layer is Sysmon process GUID generation. Fix risk is moderate: preserve deterministic parent/child references while replacing visible low-entropy suffixes with more native-looking boot/session-scoped entropy.

### P1 — Polkit Action/Program Pairing

Reviewer original rating: not labeled. Score impact: high. Observed by Host/EDR.

Linux syslog pairs implausible policy actions and executables, such as `/usr/bin/timedatectl` receiving `org.freedesktop.login1.reboot` or `/usr/bin/nmcli` receiving `org.freedesktop.timedate1.set-timezone`. Owning layer is extra syslog message templates/config. Fix risk is low to moderate: make action/program pools typed and validated, preserving the stateful IDs added in Loop 133.

### P2 — Missing PE Metadata For Common Microsoft Binaries

Reviewer original rating: not labeled. Score impact: medium-high. Observed by Detection and Host/EDR.

Built-in binaries such as `runas.exe`, `msra.exe`, and `curl.exe` render Sysmon Event 1 fields like `FileVersion`, `Description`, `Product`, `Company`, and `OriginalFileName` as `-`. Owning layer is process metadata lookup/config. Fix risk is low if handled data-driven with coverage for common Windows binaries.

### P2 — Network Behavior Distribution Texture

Reviewer original rating: not labeled. Score impact: medium. Observed by Network.

Network found no hard Zeek timing contradiction, but highlighted distribution tells: near-even public resolver rotation by `PROXY-01`, templated DNS-tunnel TXT payload vocabulary, all-TCP Kerberos, mostly `trans_depth: 1` HTTP, and many short TLS sessions from one source. Owning layer spans DNS/HTTP/Kerberos/network activity generation. Fix risk varies; resolver stickiness is probably the best contained first target.

### P3 — Attack Storyline Cleanliness

Reviewer original rating: not labeled. Score impact: medium. Observed by Threat Hunter.

The attack is technically coherent but reads like a concise exercise: little visible credential churn, operator error, alternate tooling, abandoned pivots, or partial cleanup. Owning layer is scenario/storyline generation rather than the deterministic renderer; fix risk is higher for this current scenario because the instruction says not to modify the scenario unless approved.

## Priority Rationale

Loop 136 removed the prior hard Zeek TLS/X.509 contradiction. The next highest leverage work is endpoint source-native fidelity because multiple reviewers independently cited Sysmon/registry/host artifacts and the fixes are rooted in deterministic rendering/config rather than scenario rewriting. Network distribution polish remains valuable, but the clearest current target is the Host/Detection cluster.

## Comparison With Quantitative Eval

The automated eval remains high at `96.277`, and the blind average synthetic-confidence score improved modestly from Loop 135's `71.5` to `71.0`. Eval did not catch the UserAssist value-name morphology, Sysmon `ProcessGuid` entropy, polkit action/program mismatch, or resolver-stickiness distribution. The blind reviewers, in turn, did not emphasize quantitative causality/timing issues; they explicitly treated the fixed Zeek certificate timeline as source-native.
