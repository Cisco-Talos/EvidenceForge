# Mac-inclusive loop 71: session-specific Windows SMSS ownership

Loop71 corrected shared Windows session bootstrap ownership. The authored six scenario inputs and seed42 were preserved. A first generated candidate exposed an RDP teardown gap during the output probe; its four first-pass blind reports are retained in `pre-fix-review/` and excluded from canonical scores. After repairing the RDP owner path, the fixed-seed bundle was regenerated and assessed by four fresh independent data-only reviewers.

## Family contract and repair

The loop65 and loop68 history identified Winlogon EventID1 records for distinct terminal sessions reusing one exact SMSS parent identity. Loop70's output probe reproduced that on DC-01, MAIL-FIN-01 and FILE-SRV-01. Loop71 now gives each new interactive and RDP session a session-specific SMSS process parented by the host's boot SMSS, with Winlogon using that exact session manager.

The owning paths are canonical Windows session bootstrap and the RDP action bundle. RDP logout now includes the session-manager parent in its exact target-process close plan, even though that SYSTEM process uses the system LUID rather than the user's session LUID. The exact RDP terminal projection recognizes this SYSTEM SMSS close while retaining the process's native identity. See [family contract](family-contract.md).

The rendered-output probe found 21 Winlogon creates with visible, matching SMSS parents and no parent GUID reused across distinct terminal sessions. Sysmon and Security 4688 each show 21 SMSS and 21 Winlogon creates; eCAR shows 21 SMSS and 20 Winlogon creates. Sysmon EventID5, Security 4689 and eCAR each show 20 SMSS and 19 Winlogon terminations; remaining visible session lifetimes are treated within the bounded collection window. Details are in [session-parent-probe.json](session-parent-probe.json).

## Validation and tests

Scenario validation passed with its existing baseline-noise warning and storyline pivot notices. Config validation passed with 0 errors, warnings, or info across 101 files. The RDP deferred-production slow suite passed **70 tests**. Activity and State Manager coverage passed **637 tests**, with 2 deselected. Ruff check, Ruff format, `git diff --check`, and generation behavior manifest validation passed at revision491, digest `b677db05bc0e2a53002dd1b2a5fdab6922e22a64c6ec338498dd6d6ccba8f707`. The complete routine suite was not run.

## Quantitative evaluation

Automated evaluation passed at **96.1181** across **141,745 records**. Pillar scores: parseability **100.00**, plausibility **96.87**, causality **95.72**, timing **89.86**. See [automated evaluation](automated-eval.json).

## Final independent panel

| Expert | Verdict | Verdict confidence | Synthetic-confidence score | Main evidence |
|---|---|---:|---:|---|
| Threat Hunter | Inconclusive | 72 | 52 | Cross-source support-upload and patient-data chains agree; sparse Mac unified logs and repeated generic Linux diagnostics are weak signals. |
| Detection Engineer | Inconclusive | 67 | 33 | Windows/Sysmon/eCAR/Zeek fields and sampled RDP/SSH lifecycles are plausible; no hard contradiction found. |
| Network Forensics | Inconclusive | 62 | 54 | Zeek UIDs, protocol records, Snort alerts, ASA, and proxy views align; repeated resolver traffic and scanner probes are weak signals. |
| Host/EDR Forensics | Inconclusive | 62 | 55 | Endpoint/session correlations are strong; one self-addressed failed SSH attempt on DB-PROD-01 and routine Linux command texture are weak signals. |

Mean standalone synthetic-confidence score is **48.5** (mixed/inconclusive); mean verdict confidence is **65.75** and score spread is **22**. All verdicts agree, the mean confidence is above60, and the spread is below30, so deliberation was not triggered. See [canonical scores](scores.json). The first-pass candidate scores are kept separately in `pre-fix-review/` and are not part of trend calculations.

## Prioritized remaining work

| Priority | Finding | Category | Original reviewer rating | Expected leverage and next action |
|---|---|---|---|---|
| P2 | Browser process roots and profile-scoped instances remain an independently corroborated lifecycle candidate from earlier loops. | `contract_gap` | Not labeled in loop71; loop65/68 reports | High leverage across multiple sessions and OS paths. Next, verify live process identity reuse and lifecycle ownership in generated output, then repair at the browser/application-instance owner if still present. |
| P3 | Self-addressed SSH attempt on DB-PROD-01 (`10.10.4.10` to itself), failed password, corroborated by syslog and eCAR. | `environment_or_collection_plausibility` | Not labeled | One plausible but unusual event. Keep as a weak signal unless sibling records establish an ownership or topology contradiction. |
| P3 | Sparse macOS Unified Log relative to Endpoint Security/eCAR on a small number of hosts. | `environment_or_collection_plausibility` | Not labeled | Collection policy can explain it; do not expand native-log volume without an implied missing companion. |
| P3 | Repeated generic Linux administration commands and resolver/scanner concentrations. | `distribution_texture` | Not labeled | Low leverage without a host-role or cadence mismatch; leave unchanged pending stronger evidence. |

The next loop should test the recurrent browser-root lifecycle candidate, not chase low-confidence single samples. Loop71's code fix is verified for the fixed benchmark seed; the output probe also retains a small number of sessions whose lifecycle extends through the collection boundary.

## Artifacts

- [Family contract](family-contract.md)
- [Scores](scores.json)
- [Automated evaluation JSON](automated-eval.json)
- [Validation and test evidence](test-evidence.json)
- [Generation provenance and hashes](provenance.json)
- [Session parent and lifecycle probe](session-parent-probe.json)
- [Fresh blind reviewer reports](.)
