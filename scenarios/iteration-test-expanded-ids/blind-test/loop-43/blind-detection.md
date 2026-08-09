# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 94  
**Synthetic-Confidence Score:** 87

## Executive Summary

The dataset is technically sophisticated and highly usable in a SIEM, with strong Windows, Sysmon, eCAR, and Zeek schemas. However, two dataset-wide authentication artifacts—dynamic Logon IDs for built-in service principals and extreme machine-account TGT churn with randomly varying ticket properties—are strong synthetic fingerprints inconsistent with normal Windows/AD behavior.

## Evidence For Synthetic

- `[hard_contradiction]` All 296 Windows Security 4624 Type 5 logons for `SYSTEM`, `LOCAL SERVICE`, or `NETWORK SERVICE` use newly allocated, high-valued `TargetLogonId` values rather than their well-known authentication LUIDs. Examples include `NETWORK SERVICE` with `0x5388765` on DC-01 at `2024-03-18T12:10:12.2028004Z`, `LOCAL SERVICE` with `0x538d766` at `12:12:44.3846401Z`, and `SYSTEM` with `0x5392ffd` at `12:15:42.6590054Z`. Their expected built-in LUIDs are `0x3e4`, `0x3e5`, and `0x3e7`, respectively.
- `[contract_gap]` The incorrect service Logon IDs propagate into companion 4672 and 4634/eCAR session records, making detections and joins treat every built-in service activation as an independent authenticated session. This is a systemic identity-model defect rather than a missing-data or collection-boundary issue.
- `[distribution_texture]` DC-01 records 515 successful 4768 TGT requests in six hours. Eight major Windows machine accounts generate 484 of them: `MAIL-FIN-01$` 94, `FILE-SRV-01$` 91, and six workstations 44–58 each—roughly one fresh machine TGT every four to eight minutes despite normal multi-hour ticket caching.
- `[distribution_texture]` Identical machine account/client pairs repeatedly obtain new TGTs seconds or fractions of a second apart while ticket options and encryption types vary. `WS-EBROOKS-01$` receives RC4 (`0x17`) and AES256 (`0x12`) TGTs only 0.199 seconds apart at `2024-03-18T15:38:27.2905918Z` and `15:38:27.4898560Z`. `FILE-SRV-01$` receives two TGTs 3.002 seconds apart at `12:41:34.6092997Z` and `12:41:37.6108198Z`, with `TicketOptions` changing from `0x40810000` to `0x10`.
- `[weak_signal]` Type 5 service-logon volume is unusually high: DC-01 has 114, FILE-SRV-01 67, and MAIL-FIN-01 71 in the six-hour window. DC-01 repeatedly creates built-in service sessions only seconds apart, reinforcing the dynamic-LUID defect.

## Evidence For Real

- Windows event envelopes are unusually accurate: provider GUIDs, EventID versions, Task/Opcode/Keywords values, field names, SID syntax, hexadecimal PID formatting, and seven-digit `SystemTime` precision generally match their source-native forms.
- The DC-01 1102 event correctly switches to the `Microsoft-Windows-Eventlog` provider, uses `UserData/LogFileCleared`, resets `EventRecordID` to 1 at `2024-03-18T17:42:15.8336571Z`, and is followed by post-clear record IDs beginning at 3 with plausible gaps.
- All 900 paired Security 4688/Sysmon Event 1 records examined agree on PID, image, parent PID/image, user, and Logon ID. Their timestamps are generally within roughly ±21 milliseconds; no visible child or dependent event occurs before a matching visible process creation or after its termination.
- eCAR process and session lifecycles showed no visible create-after-use, terminate-before-use, login-after-logout, or other bounded-window ordering contradiction.
- Zeek records use plausible typed JSON fields and source-native optional-field behavior. Protocol UIDs and tuples consistently resolve to `conn.json`, and protocol timestamps remain within connection intervals.
- TLS handling is notably realistic: all 409 non-resumed TLS 1.2 handshakes contain `cert_chain_fuids`, while TLS 1.3 records omit visible certificate chains, consistent with TLS 1.3 encrypting post-ServerHello handshake messages for a passive sensor.

## Detailed Analysis

### Windows Security schemas and authentication identity

The XML parses cleanly and the event-specific field sets are consistent with their versions. Event 4624 version 2 contains the expected 27 fields; 4688 version 2 includes `CommandLine`, target fields, `ParentProcessName`, and `MandatoryLabel`; 5156 version 1 has the expected WFP tuple and layer fields. Direction tokens and WFP layer tokens are internally correct—for example, DC-01 receives DNS traffic with `Direction=%%14592` and `LayerName=%%14610`, while clients emit outbound traffic with `%%14593` and `%%14611`.

The service-authentication identity is nevertheless materially wrong. Across every Windows host, all 296 Type 5 events assign unique dynamic Logon IDs to SIDs `S-1-5-18`, `S-1-5-19`, and `S-1-5-20`. Those identities normally use the well-known SYSTEM, Local Service, and Network Service authentication LUIDs. The generated records then issue 4672 privileges against the invented LUIDs, so a rule grouping privilege assignment, process execution, and logoff by Logon ID receives a coherent but source-inaccurate session model.

### Kerberos behavior

The individual 4768/4769 shapes are plausible: IPv4-mapped addresses, service names, status values, pre-auth type, and AES/RC4 identifiers are correctly formatted. The aggregate behavior is not. Machine accounts repeatedly request full TGTs throughout the window rather than reusing cached tickets and requesting service tickets.

The per-client cryptographic texture is especially implausible. `MAIL-FIN-01$` alone uses at least twelve `TicketOptions`/`TicketEncryptionType` combinations across 94 TGTs, including AES256, AES128, and RC4. The same random-looking mixture appears independently on each workstation and server. Different applications can legitimately request different service tickets, but repeated full machine TGT issuance with rapidly changing encryption choices is not normal domain-member LSASS behavior.

### Process and endpoint telemetry

Security 4688 and Sysmon Event 1 are structurally strong. I matched 900 cross-source process starts: PID, image, parent identity, principal, and Logon ID agreed without contradictory values. Sysmon Events 3, 5, 7, 8, 10, 11, 13, and 22 use expected field names and data shapes. GUIDs are syntactically valid, hashes have correct encodings, process paths align with host operating systems, and visible dependencies stay inside process lifetimes when the initiating process is present in the collection window.

One Security 4688 `gpupdate.exe` record on WS-AJOHNSON-01 lacks a nearby Sysmon Event 1. I did not score that as synthetic because selective observation and source loss are plausible, and it creates no visible contradiction.

### Network and parser utility

Zeek `conn`, DNS, HTTP, SSL, X.509, files, DHCP, SMTP, and OCSP records are readily ingestible. Every DNS, HTTP, SSL, and SMTP UID checked maps to a corresponding connection with matching tuple fields. Source-native nuances such as absent duration on S0 connections, empty DNS answer fields for NODATA/NXDOMAIN responses, TLS resumption behavior, and certificate visibility by protocol version are handled credibly.

Proxy, ASA, Snort, web access, and RFC 5424-style syslog records also have plausible parser-facing forms. The major defects are therefore concentrated in authentication semantics and distributions, not general serialization quality.

### Bounded-window causality

I treated the corpus as a six-hour slice. Pre-window process terminations, unmatched logouts, and sessions without visible starts were not considered synthetic indicators. For identifiers whose initiators are visible, I found no dependent-before-create, use-after-termination, transport-after-authentication, or logout-before-login contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `hard_contradiction` | Windows Security 4624/4672/4634 and eCAR sessions | All 296 built-in Type 5 logons | Well-known built-in principals receive impossible dynamic authentication LUIDs, directly affecting SIEM correlation. |
| `distribution_texture` | Windows Security 4768 | Dataset-wide; 515 TGTs in six hours | Machine accounts repeatedly obtain full TGTs at minute-scale cadence instead of using ticket caches. |
| `distribution_texture` | Windows Security 4768/4769 | Repeated per account and client | Ticket options and AES/RC4 choices vary rapidly and randomly for otherwise stable machine identities. |
| `weak_signal` | Windows Security service-logon population | Concentrated on three servers | Service-session creation rates are abnormally high and reinforce the LUID defect. |

## Realism Score by Category

- **Field format accuracy:** 6 — Most serialization is excellent, but Type 5 Logon IDs violate a central Windows identity convention.
- **Temporal patterns:** 5 — Process and connection timing is convincing, while machine-account TGT cadence is highly artificial.
- **Cross-source correlation:** 9 — Shared identifiers and values are consistent without visible impossible ordering.
- **Behavioral realism:** 4 — Repeated machine TGT acquisition and service-session recreation materially diverge from normal AD behavior.
- **Environmental consistency:** 7 — Host roles, paths, protocols, and collection surfaces fit together, though authentication volume is inconsistent with the environment.

## Recommendations

- If this were synthetic, assign `0x3e7`, `0x3e5`, and `0x3e4` consistently to SYSTEM, Local Service, and Network Service tokens, and propagate those canonical identities through 4624, 4672, 4634, process, and eCAR session records.
- Model Kerberos ticket caches per host, principal, logon session, realm, encryption policy, and ticket lifetime. Emit new 4768 TGTs only for cache misses, expiry, renewal, explicit purge, credential changes, or genuinely separate authentication contexts.
- Keep a stable encryption capability/preference profile per account and client. Do not independently randomize `TicketOptions` and `TicketEncryptionType` for every request.
- Reduce service logon creation to actual service lifecycle transitions. Routine child-process starts or periodic service activity should reuse the existing built-in service token rather than create another Type 5 session.
