# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 64

## Executive Summary

This dataset is unusually well-structured and would ingest cleanly into a SIEM: Windows XML, Zeek JSON, eCAR JSONL, syslog, proxy, firewall, and Snort records are mostly schema-valid and cross-source timing is coherent. The main synthetic indicator is not broad correlation completeness, but source-native field generation artifacts, especially Sysmon `ProcessGuid` values that have non-native, low-entropy suffix patterns across every Windows host.

## Evidence For Synthetic

- `*/windows_event_sysmon.xml`: all sampled Sysmon process GUID references follow a generator-like suffix pattern such as `000000000009`, `00000000000e`, `000000000011`, etc.; across the parsed Sysmon corpus, 5,428/5,428 GUID references had this tiny zero-padded final component.
- `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml` at `2024-03-18T12:01:20.7663206Z`: `SourceProcessGUID={fd907e59-3850-65f4-f880-000000000011}` and `TargetProcessGUID={fd907e59-385c-65f4-b094-000000000012}` show the pattern clearly.
- `DC-01.meridianhcs.local/windows_event_sysmon.xml` around `2024-03-18 12:04:12.697`: `ProcessGuid={83eb9c06-2dbc-65f8-8050-00000000000e}` is syntactically valid but low-entropy.
- Windows Security 4624 non-network logons repeatedly render `IpPort` as `0` and `WorkstationName` as the local host, for example DC-01 LogonType 5 rows shaped as `WorkstationName=DC-01`, `IpAddress=-`, `IpPort=0`.

## Evidence For Real

- Zeek logs are structurally strong: `dns`, `http`, `ssl`, `files`, `x509`, `ocsp`, and `dhcp` rows use expected field names and JSON types.
- Zeek companion links are internally valid: DNS/HTTP/SSL UIDs resolve to matching `conn.json` tuples; HTTP `resp_fuids` resolve to `files.json`; TLS certificate `cert_chain_fuids` resolve to `files.json`/`x509.json` when present.
- Windows event semantics are mostly convincing: Security 4688/4689, 4624/4634, 4768/4769, 4648, 4697, 4698, 4720/4728/4726, and Sysmon 1/3/5/7/8/10/11/13/22 have plausible field sets.
- The audit-log-clear sequence on `DC-01` is coherent: visible process creation for `wevtutil.exe`/PowerShell, Event ID 1102 using `Microsoft-Windows-Eventlog`, record ID reset, and later process termination events.
- Network perimeter logs agree at a source-native level: ASA NAT/build/teardown records, Zeek DMZ visibility, web access logs, proxy access logs, and Snort alerts line up without obvious impossible ordering.

## Detailed Analysis

The Windows XML parses cleanly and covers 12,004 Windows events. Security event IDs include realistic domain-controller activity: 4768/4769 Kerberos volume, 4624/4634 session lifecycle, 4648 explicit credentials, 4697 service install, 4698 scheduled task creation, 1102 audit log clear, and account lifecycle events for `svc_mhsync`.

The strongest synthetic signal is Sysmon GUID construction. Native Sysmon GUIDs are not just arbitrary display GUIDs; in real fleets they have high-entropy, source-generated structure. Here, every process-related GUID checked has a host-specific prefix, changing middle fields, and a final 12-hex component that is almost entirely zeros with a small counter.

Zeek quality is high. `zeek-core` and `zeek-dmz` use expected JSON field names like `id.orig_h`, `id.resp_p`, `conn_state`, `history`, `trans_depth`, `resp_fuids`, `cert_chain_fuids`, and `basic_constraints.ca`.

## Realism Score by Category

- **Field format accuracy:** 8 — Most source schemas are correct; Sysmon GUID generation is the main native-format weakness.
- **Temporal patterns:** 8 — Ordering is coherent, with realistic companion timing and no clear impossible visible dependency.
- **Cross-source correlation:** 9 — Zeek, firewall, proxy, Windows, eCAR, and syslog largely agree without relying on completeness as a clue.
- **Behavioral realism:** 8 — User, admin, service, perimeter, and attack-like activity are plausible and varied.
- **Environmental consistency:** 9 — Hostnames, IPs, domains, NAT, service roles, and account usage remain consistent.

## Recommendations

Improve Sysmon `ProcessGuid` generation so it matches native Sysmon structure and entropy more closely, not just GUID syntax. Also tune Windows 4624 non-network logon rendering against real exported XML from the target OS versions, especially `WorkstationName`, `IpAddress`, and `IpPort` defaults for LogonType 2/5/7/11.
