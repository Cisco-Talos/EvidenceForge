# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 84  
**Synthetic-Confidence Score:** 49

## Executive Summary

The data is unusually strong at source-native formatting and cross-source correlation: Windows/Sysmon process records, eCAR lifecycles, and Zeek UID/tuple relationships are consistently parseable and coherent. The main synthetic indicator is a selective lifecycle tail beyond the stated six-hour boundary, supplemented by a small Windows unlock-field anomaly and inconsistent proxy-denial tunnel accounting.

## Evidence For Synthetic

- `[contract_gap]` The stated six-hour window appears to be 2024-03-18 12:00:00–18:00:00Z, yet only process-termination families continue afterward: 13 eCAR `PROCESS/TERMINATE` records, 11 Security 4689 records, and 11 Sysmon Event 5 records extend as late as 18:49:43Z. Zeek and ordinary activity stop before 18:00. This selective lifecycle drain resembles an export/generation boundary defect rather than ordinary clock skew.
- `[contract_gap]` The post-window records are correlated teardown tails for visible processes. For example, `MAIL-FIN-01` eCAR process object `2b2b5006-2ec6-4923-aeb8-f0355b102dc2` creates `WmiPrvSE.exe` at 17:35:40.344Z and terminates at 18:49:43.421Z; corresponding Security 4689 and Sysmon Event 5 appear at 18:49:42.6793403Z and 18:49:42.9743946Z. This is coherent causality but inconsistent collection scoping.
- `[schema_or_format]` All six Security 4624 LogonType 7 records use the unlocked user as both Subject and Target, with identical SubjectLogonId and TargetLogonId. At 2024-03-18T14:43:45.4030005Z on `WS-PPATEL-01`, both identities are `priya.patel`/`0xd8d7b28`; workstation unlock auditing ordinarily presents the trusted logon component/system context as Subject and the unlocked account as Target.
- `[contract_gap]` In `PROXY-01/proxy_access.log`, 32 of 37 `proxy_action=deny` records carry nonzero `tunnel_cs_bytes`, `tunnel_sc_bytes`, and `tunnel_duration_ms`, despite returning HTTP 403 and declaring `byte_scope=connect-control-message`. Five other deny records omit tunnel accounting, making the terminal-action contract internally inconsistent.
- `[weak_signal]` All 1,119 Security 4769 TGS events have a zero `LogonGuid`, while 239 Security 4624 records carry nonzero GUIDs, including 233 Kerberos network logons and six Kerberos remote-interactive logons. Zero GUIDs are possible, but the dataset-wide loss of this native correlation field reduces detection fidelity.

## Evidence For Real

- All inspected JSON and XML records parsed successfully. Windows/Sysmon metadata, field signatures, native values, SIDs, GUIDs, NTSTATUS values, and message-resource tokens are credible.
- Of 923 Security 4688 process creations, 921 have matching Sysmon Event 1 records within approximately -26 to +124 milliseconds, agreeing on image, command line, parent PID/image, user, and LogonId. The two unmatched records are plausible observation gaps.
- Security lifecycle checks found no visible 4634 before matching 4624 and no visible 4689 before matching 4688. Repeated LogonType 7 events reuse established interactive LogonIds and align with 4800/4801 evidence.
- eCAR contains 25,805 valid records with valid UUIDs and no directory/hostname mismatches. Visible process lifecycles have no duplicate CREATE, terminate-before-create ordering, or PID/image disagreement. All 2,995 resolvable non-FLOW actor relationships agree on source UUID, PID, image, and principal.
- Every examined Zeek DNS, HTTP, SMTP, and SSL UID resolves to a conn record at the same sensor with matching four-tuple and compatible timing; file, certificate, and X.509 references also resolve correctly.
- TLS semantics are accurate, Security values show credible diversity, and Security Event 1102 uses the correct provider and structure with an appropriate record-ID reset.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---:|---|
| `contract_gap` | eCAR, Security, Sysmon | 35 post-18:00 records across correlated termination families | High: selectively extends lifecycle teardown beyond the declared collection window |
| `schema_or_format` | Windows Security 4624 | All six LogonType 7 records | Medium: likely incorrect Subject ownership for workstation unlock events |
| `contract_gap` | Proxy access | 32 of 37 deny actions | Medium: denied CONNECT records inconsistently report nonzero tunnel accounting |
| `weak_signal` | Windows Security 4769 | All 1,119 TGS events | Low: zero LogonGuid prevents native Kerberos-to-logon GUID correlation |

## Realism Score by Category

- **Field format accuracy:** 8
- **Temporal patterns:** 7
- **Cross-source correlation:** 10
- **Behavioral realism:** 8
- **Environmental consistency:** 8

## Recommendations

- Enforce the collection cutoff after lifecycle expansion and source timing: events after 18:00Z should either be excluded consistently or the declared collection window should explicitly include the teardown tail.
- Model Security 4624 LogonType 7 Subject fields from the trusted logon/system context while retaining the unlocked user and reused session identifier in Target fields.
- Define one terminal proxy contract for denied CONNECT requests and do not emit established-tunnel counters for a denied transaction.
- Populate 4769 `LogonGuid` when the corresponding Kerberos/4624 activity has a usable native GUID.
