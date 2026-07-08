# Host/EDR Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 47

## Executive Summary

The endpoint evidence is largely coherent: Windows logon/process lifecycles, Linux SSH/PAM sessions, eCAR user sessions, and RDP source/target timing mostly line up without impossible ordering. I found no hard contradiction, but several source-native texture issues make the data feel partially generated, especially Sysmon GUID/hash regularity and one RDP companion-evidence gap.

## Evidence For Synthetic

- `schema_or_format`: Sysmon `ProcessGuid` values have a mechanically regular non-zero fourth UUID block across Windows hosts, e.g. `WS-AJOHNSON-01` Sysmon Event 22 at `2024-03-18T12:04:53.3820011Z` uses `{fd907e59-3849-65f4-5702-0010d3a22c84}` and `DC-01` around `17:41:51Z` uses `{83eb9c06-7cdf-65f8-2502-0000cbfa0e20}`. This is internally consistent but unusual for real Sysmon ProcessGuid texture.
- `distribution_texture`: Sysmon process-create hashes for core Microsoft binaries fall into very tidy repeated host buckets. `svchost.exe`, `taskhostw.exe`, `dllhost.exe`, and `conhost.exe` each show the same four SHA256 grouping pattern across the same nine Windows hosts. OS baselines can cluster, but the repeated exact grouping across unrelated binaries looks over-modeled.
- `contract_gap`: `WS-AJOHNSON-01` Security shows Type 10 RDP logon at `2024-03-18T15:00:09.714510Z` from `::ffff:10.10.1.33`; `WS-EBROOKS-01` eCAR shows `10.10.1.33:59796 -> 10.10.1.35:3389` at `2024-03-18T15:00:07.760Z`. The source host has Sysmon DNS for `WS-AJOHNSON-01` at `15:00:06Z`, but no nearby source Sysmon Event 3, Security 5156, or `mstsc.exe` process, unlike most other Windows RDP sessions.
- `weak_signal`: Linux eCAR process records use Windows-like `logon_id` values such as `0x3e7` for system processes on Linux hosts. A vendor-neutral EDR schema could normalize this, so I treat it as weak, not decisive.
- `hard_contradiction`: None found.

## Evidence For Real

- RDP source/target timing is mostly realistic. Example: `WS-MCHEN-01` Sysmon creates `mstsc.exe /v:DC-01` at `2024-03-18T12:21:35.589573Z`, Security 5156 records `10.10.1.31:50891 -> 10.10.2.10:3389` at `12:21:37.363871Z`, and `DC-01` records Type 10 logon for `marcus.chen` at `12:21:37.661358Z`.
- Linux SSH lifecycle ordering is sound. Example: `APP-INT-01` syslog PID `838507` has connection `12:38:15.940640Z`, accepted password `12:38:19.188826Z`, PAM session open `12:38:19.250037Z`, and session close `13:01:59.616445Z`; eCAR USER_SESSION login follows at `12:38:19.807Z`.
- Process lifecycle checks found no visible Sysmon process events before their Event 1 creation or after Event 5 termination, and no eCAR PROCESS activity after visible termination.
- The DC attack sequence is source-native: Security/Sysmon show PowerShell encoded command, `cmd.exe /c wevtutil cl Security`, `wevtutil.exe`, and Security 1102 at `2024-03-18T17:41:51.6978749Z`.
- Linux bash histories and syslog show plausible multi-session behavior, including out-of-order bash history appends that are explainable by shell exit ordering.

## Detailed Analysis

Windows endpoint telemetry is the strongest part of the dataset. Security 4624/4634, 4688/4689, 5156, and Sysmon 1/3/5/7/10/11/13/22 records generally preserve plausible process and session order. DC Security has large volume (`4768`, `4769`, `5156`) appropriate for a domain controller, and workstations have thinner but plausible user/process coverage.

RDP correlation is mostly convincing. Multiple Type 10 logons on `DC-01`, `FILE-SRV-01`, and `MAIL-FIN-01` have source-side `mstsc.exe`, source 5156, and eCAR flow evidence seconds before target authentication. The one weaker case is `WS-EBROOKS-01 -> WS-AJOHNSON-01` at `15:00Z`, where eCAR and target Security agree but the source-native Windows companions are absent.

Linux evidence is generally healthy. SSH syslog records preserve connection/auth/PAM/close ordering, and eCAR USER_SESSION rows carry matching user, source IP, source port, and session type. DHCP renewals and NetworkManager events are somewhat busy on `WS-LNGUYEN-01`, but intervals and lease messages remain plausible for a short slice.

The most synthetic-looking field texture is in generated-looking identifiers and hashes, not behavior. Sysmon GUIDs and hash buckets look too orderly across hosts, while the behavioral chains themselves do not show impossible ordering.

## Synthetic Indicator Summary

| Category | Source Family | Scope | Impact |
|---|---|---:|---|
| `schema_or_format` | Windows Sysmon | All Windows hosts | Moderate |
| `distribution_texture` | Windows Sysmon hashes | Core binaries across fleet | Moderate |
| `contract_gap` | RDP endpoint correlation | One observed session | Low-moderate |
| `weak_signal` | Linux eCAR | Linux system processes | Low |
| `hard_contradiction` | None | None | None |

## Realism Score by Category

- **Field format accuracy:** 72 - Mostly correct XML/syslog/eCAR fields, with Sysmon GUID texture concerns.
- **Temporal patterns:** 88 - Logon, process, SSH, and attack-chain ordering are mostly plausible.
- **Cross-source correlation:** 82 - RDP, SSH, eCAR, and Security/Sysmon align well, aside from one RDP source gap.
- **Behavioral realism:** 86 - Admin, user, service, and attacker activity fit host roles without relying on perfect linearity.
- **Environmental consistency:** 80 - Domain, host roles, Linux/Windows separation, and DC behavior are coherent.

## Recommendations

- Generate Sysmon `ProcessGuid` values using real Sysmon-compatible encoding or replayed exemplar texture.
- Tie Sysmon hashes to explicit OS/application build baselines rather than repeated tidy host buckets.
- For Windows RDP, ensure every visible eCAR source flow has the expected source-side `mstsc.exe`, Security 5156, or Sysmon Event 3 unless the collection profile explicitly models that source gap.
- For Linux eCAR, prefer OS-native session identifiers or document why Windows-style `logon_id` normalization appears on Linux records.
