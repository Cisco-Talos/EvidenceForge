# Detection Engineer - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 82

## Executive Summary

The dataset has strong cross-source correlation and many correctly shaped Windows, Sysmon, Zeek, proxy, firewall, and eCAR records. However, several Linux syslog values are not just unusual but operationally implausible, especially random six-digit polkit `unix-session` identifiers and six-digit rsyslog file descriptors, which look generated rather than emitted by real daemons.

## Evidence For Synthetic

- `WS-LNGUYEN-01.meridianhcs.local/syslog.log:2` at `2024-03-18T12:01:25.513814Z` reports `rsyslogd ... imuxsock: Acquired UNIX socket ... fd 695673`; `DB-PROD-01.meridianhcs.local/syslog.log:13` similarly reports `fd 691267`. File descriptors are process-local small integers under normal daemon limits; repeated six-digit fd values are highly unrealistic.
- `WS-LNGUYEN-01.meridianhcs.local/syslog.log:1` has `polkitd ... Registered Authentication Agent for unix-session:725762`, while nearby logind sessions on this host use normal session IDs such as `New session 725762` never appears. Similar random six-digit polkit sessions recur across hosts, e.g. `DB-PROD-01...:32 unix-session:942854` and `WS-OHADDAD-01...:23 unix-session:790570`.
- Polkit register/unregister events reuse bus names such as `:1.203`, `:1.417`, and `:1.42` across many unrelated random sessions in `DB-PROD-01.meridianhcs.local/syslog.log`; that breaks normal session/bus-name lifecycle expectations and would make SIEM session correlation unreliable.
- eCAR ICMP flows encode non-port protocols as port strings: `PROXY-01.meridianhcs.local/ecar.json` at `timestamp_ms=1710763219395` records `protocol:"icmp"` with `src_port:"0"` and `dst_port:"0"`. Zeek correctly represents the same class of ICMP using `id.orig_p:8` and `id.resp_p:0`, so the eCAR representation is a synthetic simplification likely to confuse port-based analytics.
- The Linux behavioral noise has generator-like breadth: repeated random typo commands (`car`, `xat`, `exho`, `llsmod`, `unme`, `catt`, `lss`) appear across many users and hosts with otherwise tidy timestamped histories. Individually plausible, collectively patterned.

## Evidence For Real

- Windows Security XML is schema-shaped and uses realistic Event IDs and field names: `4688`, `4689`, `4624`, `4634`, `4672`, `4768`, `4769`, `4776`, `5156`, `4697`, `4720`, `4728`, `4698`, `1102`.
- Sysmon records have correct event-specific fields: Event ID `1` has `ProcessGuid`, `ProcessId`, `Image`, `CommandLine`, `ParentProcessGuid`; Event ID `3` has `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`; Event ID `22` has DNS fields; Event ID `10` has source/target process access fields.
- Strong cross-source correlation exists for proxy traffic: `WS-AJOHNSON-01.meridianhcs.local/ecar.json` at `1710763362790` records `10.10.1.35:65315 -> 10.10.3.20:8080`; Sysmon Event ID `3` on the same host at `2024-03-18T12:02:43.025Z` has the same tuple and `ProcessId=4500`; `zeek-core/conn.json` UID `CzDRpul5zElrsGjJHp4` and `zeek-core/http.json` record the same CONNECT to `ctldl.windowsupdate.com:443`; `PROXY-01.../proxy_access.log` logs the same request at `2024-03-18 12:02:42`.
- Zeek internal references are consistent: sampled `dns`, `http`, `ssl`, and `files` UIDs all resolve to matching `conn.json` UIDs for both `zeek-core` and `zeek-dmz`.
- The DC Security log clearing sequence is plausible: `DC-01.../windows_event_security.xml` has Event ID `1102` at `2024-03-18T17:42:12.0190916Z` with `EventRecordID=2`, followed by `4689` for `wevtutil.exe` at `17:42:15.5612441Z` with `EventRecordID=3`.

## Detailed Analysis

Windows Event Logs: The Security channel is mostly convincing. Event ID counts and fields align with expected audit semantics: `4624/4634` logon lifecycle, `4768/4769` Kerberos activity, `4688/4689` process creation/termination, `5156` filtering-platform connections, and domain object changes like `4720` and `4728`. The suspicious administrative sequence on `DC-01` is internally coherent: `svc_mhsync` is created at `2024-03-18T16:14:32.2236378Z`, added to `Domain Admins` at `16:14:33.7238971Z`, and later deleted at `17:49:46.5820567Z`.

Sysmon: Event layouts are credible. Example: `WS-AJOHNSON-01.../windows_event_sysmon.xml` Event ID `3` at `2024-03-18T12:02:43.0257773Z` records `Image=C:\Windows\System32\svchost.exe`, `User=NT AUTHORITY\NETWORK SERVICE`, `SourceIp=10.10.1.35`, `SourcePort=65315`, `DestinationIp=10.10.3.20`, `DestinationPort=8080`. The same activity appears in eCAR, Zeek, and proxy logs. Process-create timing between Security `4688` and Sysmon `1` is offset by tens to hundreds of milliseconds, which is acceptable.

Zeek: The Zeek JSON logs are one of the strongest realistic areas. `conn`, `http`, `dns`, `ssl`, `files`, `x509`, and `ocsp` records use plausible field names, timestamp precision, UID relationships, byte counts, and service labels. Certificate validity windows in sampled `x509.json` records bracket the observed timestamps. The main weakness is not Zeek itself but the mismatch in eCAR's ICMP representation.

eCAR: The eCAR records are coherent enough for endpoint correlation: object/action pairs such as `PROCESS/CREATE`, `PROCESS/TERMINATE`, `FLOW/CONNECT`, `USER_SESSION/LOGIN`, `MODULE/LOAD`, and `REGISTRY/MODIFY` are plausible and timestamp ordered. However, the simplified protocol treatment for ICMP and some very clean create/terminate pairing patterns are more synthetic than native endpoint telemetry.

Linux syslog: This is the decisive synthetic indicator. Normal RFC5424 framing and timestamps look fine, but daemon payloads contain impossible-looking runtime values. Six-digit file descriptors in rsyslog `imuxsock` messages and random six-digit polkit `unix-session` identifiers repeated across multiple hosts are not consistent with normal Linux service behavior. These are concrete field-value realism failures, not merely missing context.

Network/security appliance logs: Cisco ASA, proxy, web access, and Snort lines are mostly plausible and correlate with Zeek DMZ traffic. ASA connection IDs, NAT formatting, web access lines, and Snort signatures look SIEM-ingestible.

## Realism Score by Category

- **Field format accuracy:** 7/10 - Windows, Sysmon, Zeek, proxy, and ASA fields are mostly correct; Linux syslog payload values and eCAR ICMP ports are weak.
- **Temporal patterns:** 8/10 - Cross-source ordering is usually plausible, with realistic precision differences across sources.
- **Cross-source correlation:** 9/10 - Multiple records correlate cleanly across eCAR, Sysmon, Zeek, proxy, firewall, and web logs.
- **Behavioral realism:** 7/10 - Attack and admin activity are coherent, but Linux noise and typo distribution feel generated.
- **Environmental consistency:** 7/10 - Hostnames, IP ranges, domains, and roles are consistent; daemon-internal Linux identifiers are not.

## Recommendations

- Replace random polkit `unix-session` values with session IDs that match visible or pre-existing `systemd-logind` sessions, and keep register/unregister lifecycle stateful.
- Generate rsyslog file descriptors as realistic small process-local integers, not arbitrary large numbers.
- For eCAR ICMP flows, omit TCP/UDP port fields or encode ICMP type/code explicitly rather than using string `"0"` ports.
- Add per-daemon state models for Linux logs so session IDs, bus names, process IDs, and file descriptors evolve consistently.
- Keep the current cross-source correlation model; it is the strongest part of the dataset.
