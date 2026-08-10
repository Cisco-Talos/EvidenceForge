# Detection Engineer — Authenticity Assessment

## Verdict

- Assessment: Synthetic
- Verdict Confidence: 64%
- Synthetic-Confidence Score: 57/100
- Rubric interpretation: Mixed, leaning synthetic

## Executive Summary

The dataset is technically strong and preserves many source-native relationships that simplistic generators miss. Zeek connection state, history, and byte fields generally obey protocol rules; Windows authentication and process records use credible schemas; and identity and lifecycle data are mostly plausible.

The synthetic judgment rests on subtler behavioral and source-native issues: several Linux messages read like approximations rather than authentic daemon output, some application-resource behavior is unusually variable for immutable assets, and enumerable protocol values recur in a pool-like fashion. These indicators are meaningful but not decisive, so the score remains in the mixed range.

## Evidence For Synthetic

### Schema and source-native wording

- Several `systemd-resolved` messages use phrasing such as `Flushed stale cache scope ens192 after DNS server 10.10.2.10 changed features.` This resembles a semantic summary, but not the usual source-native resolver diagnostics describing degraded protocol features, cache flushing, or link configuration separately.
- `unattended-upgr` records such as `Package ca-certificates kept back for phased update percentage 70` similarly read as constructed approximations of APT phased-update behavior rather than familiar unattended-upgrades output.
- These messages are correctly wrapped in RFC 5424 structure, suggesting the container schema is modeled more faithfully than every payload vocabulary.

### Rule and behavioral artifacts

- Proxy requests for content-addressed resources show changing downstream byte counts across repeated successful requests from the same client and user agent. For example, `main.3582d60d.css` is recorded with 16,410 and 16,288 server-to-client bytes within seconds; `app.1fadefe5.js` likewise varies. Proxy wire-byte accounting can vary, but repeated variability across immutable hashed assets is a mild generation indicator.
- Kerberos ticket options and encryption types are plausible individually, but concentrate into a small recurring combination pool (`0x40810000`, `0x40810010`, `0x40000000`, `0x10`; AES256/AES128/RC4). This looks more like weighted enumeration than organic policy/client variation.
- Some operational command histories are unusually generic and composable—`hostnamectl`, `free -h`, `ls -ltr`, `systemctl is-active …`, and parameterized `journalctl` checks recur across administrators and hosts. No one command is implausible; the pool-like reuse is the indicator.

### Temporal texture

- Linux PID allocation is highly orderly across the six-hour window, with many short process chains advancing through closely adjacent PIDs. This is feasible on stable systems, but its consistency across several unrelated hosts contributes modest synthetic weight.
- Recurrent activity families show randomized timing but similar internal construction, especially service checks, package maintenance, SSH administration, and routine host diagnostics.

## Evidence For Real

### Zeek rule fidelity

- `conn_state`, `history`, duration, packet, and byte semantics are credible. In both sensor datasets, duration is absent for `S0` and `REJ` connections as expected, while successful TCP and UDP records carry plausible histories and accounting.
- Protocol records preserve appropriate tuple semantics. DNS, HTTP, TLS, SMTP, and their connection records use compatible endpoints and UIDs.
- DHCP records contain credible REQUEST/ACK renewals, stable MAC-to-address-to-host identity, variable lease lengths, and renewal timing near expected lease fractions.
- TLS evidence includes reused certificate fingerprints, leaf/intermediate distinctions, certificate validity periods, SANs, file-analysis records, and OCSP timing that are structurally plausible.

### Windows schema fidelity

- Security events use credible provider GUIDs, versions, tasks, channels, SIDs, logon IDs, token elevation values, and source-specific field names.
- Kerberos 4768/4769/4771 records distinguish TGT, service ticket, and pre-authentication semantics, including machine accounts, service principals, encryption types, mapped IPv4 addresses, and appropriate success/failure fields.
- Sysmon UserAssist registry entries retain ROT13-encoded value names, correct HKU SID placement, process GUID/PID identity, and plausible binary details—a strong source-specific realism feature.
- Process creation and termination evidence generally preserves parent PID, parent image, principal, and logon context without impossible future-parent relationships.

### Identity and lifecycle fidelity

- SSH sessions preserve user, UID, source IP, source port, authentication key type/fingerprint, PAM open/close, and session identity.
- Directory users retain consistent UIDs across Linux systems, while Windows domain identities retain consistent SID namespace and domain naming.
- Process IDs are not reused in overlapping observed lifetimes, and no clear internal logout-before-login or child-before-parent contradiction was found.
- Boundary-only unmatched starts or stops were not treated as defects.

## Detailed Analysis

The strongest realism lies in protocol and operating-system structure. Zeek state machines do not show obvious impossible combinations, failed connections have appropriate missing-duration behavior, and higher-level records use compatible transport identities. Windows Security and Sysmon records contain details that require more than superficial templating, particularly Kerberos roles and UserAssist encoding.

The main weakness is native payload voice. Several Linux records encode a sensible event in wording that does not look like the daemon’s normal emitted text. This matters because authentic syslog is dominated by rigid implementation strings rather than semantic paraphrases. The same distinction appears in routine command behavior: commands are credible, yet appear selected from clean operational families.

Lifecycle and identity findings substantially restrain the synthetic score. There are unmatched terminations and logouts, but they are compatible with sessions or processes beginning before the collection boundary. I found no strong evidence of impossible PID overlap, future parentage, identity mutation, or authentication occurring before its supporting transport.

Overall, this resembles a high-quality synthetic dataset designed around canonical event relationships, with the remaining tells concentrated in source-local language and behavioral enumeration rather than gross schema failures.

## Synthetic Indicator Summary

| Category | Indicator | Weight |
|---|---|---:|
| Source-native semantics | Resolver and package-maintenance messages appear paraphrased | High |
| Behavioral rules | Variable byte counts for repeated immutable hashed resources | Medium |
| Enumerable diversity | Kerberos options and administrative commands recur in pool-like combinations | Medium |
| Temporal behavior | Similar orderly PID/process-chain texture across unrelated Linux hosts | Low |
| Identity/lifecycle | No decisive impossible contradiction found | Counterevidence |

## Realism Score by Category

| Category | Score |
|---|---:|
| Schema and field fidelity | 9/10 |
| Rule/protocol fidelity | 8/10 |
| Identity consistency | 8/10 |
| Lifecycle and temporal realism | 8/10 |
| Behavioral and source-native realism | 6/10 |

## Recommendations

- Replace paraphrased Linux payloads with version-specific daemon message grammars collected from real systemd, APT, SSH, PAM, and kernel implementations.
- Model proxy byte fields explicitly by their source-native meaning; immutable resources should have stable entity size, with separate transport-overhead fields if needed.
- Expand conditional Kerberos behavior by client version, account type, domain policy, service class, and authentication path rather than selecting from a small shared option pool.
- Increase administrator-specific command habits, shell idioms, working-directory continuity, typos, aliases, and task follow-through.
- Preserve the current protocol, identity, and lifecycle construction; those are the dataset’s strongest authenticity features.
