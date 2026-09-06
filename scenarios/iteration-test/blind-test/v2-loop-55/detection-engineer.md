# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 88  
**Synthetic-Confidence Score:** 72

## Executive Summary

The dataset is technically sophisticated and mostly SIEM-parseable, with strong Windows schemas, realistic timestamp formats, and extensive cross-source consistency. However, every visible RDP Type 10 logon contains incorrect `winlogon.exe` ownership, and three of four place the process creation after the logon it supposedly performed; widespread Windows-specific logon identifiers on Linux eCAR records provide a second dataset-wide synthetic indicator.

## Evidence For Synthetic

- `[hard_contradiction]` Three of four RDP Type 10 logons occur before the corresponding visible `winlogon.exe` creation:

  - `DC-01`: 4624 at `2024-03-18T17:09:36.5123538Z`, followed by 4688 at `17:09:36.7381117Z`.
  - `MAIL-FIN-01`: 4624 at `17:06:18.1136458Z`, followed by 4688 at `17:06:18.1650523Z`.
  - `WS-AJOHNSON-01`: 4624 at `15:01:34.4642748Z`, followed by 4688 at `15:01:34.6040937Z`.

  These are visible same-session sequences, not missing pre-window initiators.

- `[hard_contradiction]` All four Type 10 events identify a `ProcessId` that does not match the nearby `winlogon.exe` process:

  - `DC-01`: 4624 `ProcessId=0x9dc`; 4688 creates `NewProcessId=0x1618`.
  - `MAIL-FIN-01`: `0xa80` versus `0x14d0`.
  - `WS-AJOHNSON-01`: `0x12a4` versus `0x171c` and later `0x175c`.

  By contrast, all nine examined Type 2 logons correctly match the `winlogon.exe` PID.

- `[hard_contradiction]` The two overlapping RDP sessions on `WS-AJOHNSON-01` reuse `ProcessId=0x12a4` in their 4624 records at `15:01:34.4642748Z` and `15:20:10.7284018Z`, despite separate session Logon IDs and separately created `winlogon.exe` processes. The first session remains active until approximately `17:59`, so this is not ordinary PID reuse after termination.

- `[contract_gap]` Every Type 10 `winlogon.exe` 4688 is attributed to creator PID `0x4`, `ParentProcessName=System`. The local Type 2 paths correctly show `smss.exe` as creator. Per-session RDP `winlogon.exe` creation should follow the session-manager path rather than being invented directly by System.

- `[schema_or_format]` Linux eCAR records use the Windows well-known SYSTEM authentication LUID `0x3e7` as `logon_id`. I counted 811 such records across all 11 Linux/syslog hosts, including `/bin/sh`, `debian-sa1`, `sssd`, and Linux backup-agent processes. This is a cross-OS semantic leak that would distort platform-aware SIEM rules.

- `[contract_gap]` Seven in-window Zeek application records reference FUIDs absent from the corresponding `files.json`:

  - `zeek-core`: six missing references, including HTTP FUID `FYWhyKFB7F1RYERyAdq` at `1710766507.148166` and SMB FUID `FFAKild69TwHvFFvFi` at `1710771989.843812`.
  - `zeek-dmz`: HTTP FUID `FhDKwfsXqUCXFhsk3G` at `1710768541.480163`.

  This affects 7 of 977 inspected file references. Partial collection could explain it, so it carries less weight than the RDP defects.

## Evidence For Real

- Windows event XML is structurally strong. The examined Security events use correct providers, channels, versions, tasks, keywords, field names, and native value forms for IDs 1102, 4624, 4625, 4634, 4648, 4656, 4658, 4663, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4779, 4800, 4801, 5140, 5145, and 5156.

- The `DC-01` Security log-clear sequence is source-native: Event 1102 at `17:42:10.9908924Z` uses `Microsoft-Windows-Eventlog`, places actor fields in `UserData/LogFileCleared`, and resets `EventRecordID` from `28260985` to `1`.

- Across 947 matched process creations, Security 4688 and Sysmon Event 1 agree on PID and image. Their timestamps differ by 35–648 milliseconds with a skewed latency distribution rather than a fixed offset.

- No visible 4689 termination preceded its matching 4688 creation. No matched 4634 logoff preceded its 4624 logon, and matched logon/logoff identities and `LogonType` values remained consistent.

- Sysmon schemas are credible for Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22. Process GUIDs are unique; visible parent GUID references match parent PID and image; executable hashes remain stable for the same host and path.

- Zeek UID integrity is excellent: 19,215 `conn.json` UIDs are unique, and every DNS, HTTP, SSL, SMB, and SMTP record examined has a matching connection UID and tuple. No application record preceded its connection opening or fell more than two seconds beyond the connection close.

- TLS certificate relationships are coherent. All 1,037 `cert_chain_fuids` examined resolve in both `files.json` and `x509.json`, with consistent fingerprints, serials, subjects, issuers, validity intervals, and chain depth.

- Firewall, Zeek, endpoint, and web evidence align plausibly. For example, the inbound connection from `76.44.118.248:53672` is built by the ASA at `12:00:03`, appears in `zeek-dmz/conn.json` at `1710763203.920960`, in WEB-EXT-01 eCAR at `1710763204.422`, and in the web access log at `12:00:04`.

- The dataset contains realistic source-specific entropy: Zeek packet loss and varied TCP histories, failed and successful connections, DHCP renewals with jitter, variable process lifetimes, mixed TLS versions/resumption states, and properly structured RFC 5424 syslog.

## Detailed Analysis

### Dataset and parsing

I examined only the provided data directory. It contains approximately 64 MB spanning 20 endpoint directories, three Zeek sensors, Cisco ASA logs, Snort alerts, proxy logs, web access logs, syslog, bash history, and eCAR.

The structured records parsed without JSON or XML errors:

- 18,044 Windows Security events.
- 4,976 Sysmon events.
- 31,119 eCAR records.
- 32,825 Zeek records.

### Windows Security schemas

I parsed examples of every present Event ID and compared field sets and value forms. Notable valid examples include:

- 5156 on `DC-01` at `12:00:13.0517258Z`: decimal WFP `ProcessID`, device-form application path, tokenized direction/layer names, numeric protocol, and appropriate remote null SIDs.
- 4624 at `12:03:13.7656648Z`: Type 5 service logon with `NETWORK SERVICE`, LUID `0x3e4`, `Advapi`, and `Negotiate`.
- 4688 at `12:04:11.4835458Z`: hexadecimal process IDs, elevation token, command line, parent name, and integrity SID.
- 4768/4769: IPv4-mapped IPv6 source addresses, native hexadecimal ticket options and encryption types, and appropriate certificate placeholders.
- 5140/5145 and 4656/4663/4658: correct share, object, handle, access-mask, and access-list fields.
- 4698: a well-formed task XML payload embedded in the event.
- 1102: correctly represented using the Eventlog provider and namespaced `UserData`.

The principal Windows defect is confined to the RDP Type 10 lifecycle, but it is severe. Nine Type 2 logons provide a useful control: each has `winlogon.exe` created before authentication and the 4624 `ProcessId` equals that created PID. None of the four Type 10 records meets that identity contract.

### Sysmon and process correlation

The Sysmon provider metadata and EventData layouts are consistent with the represented schema versions. I verified Event 1 process creation, Event 3 network connection, Event 5 termination, Event 7 image load, Event 8 remote thread, Event 10 process access, Event 11 file creation, Event 13 registry modification, and Event 22 DNS query records.

Security-to-Sysmon process correlation is strong:

- 947 Security 4688 events matched Sysmon Event 1 by host, PID, image, and near timestamp.
- No matched image disagreed.
- No visible process termination occurred before its process creation.
- Visible parent process GUIDs agreed with the parent PID and image.
- Repeated executable hashes were stable within a host.

The Security event follows its matching Sysmon event in all 947 matched cases. The delay distribution is concentrated at the low end—median 148 milliseconds, 90th percentile 393 milliseconds—so I treated this as a plausible provider/collection ordering rather than synthetic evidence.

### RDP lifecycle

All four Type 10 sessions have plausible TCP/3389 transport before authentication. For example, the `DC-01` session from `10.10.1.31:62227` appears in Zeek at `1710781770.959617`, endpoint FLOW telemetry follows, and the 4624 occurs at `17:09:36.5123538Z`.

The endpoint logon implementation then breaks source-native process semantics. The 4624 names one `winlogon.exe` PID, while a different `winlogon.exe` is generated around the same instant and becomes parent of `userinit.exe` and `explorer.exe`. Three sessions authenticate before that process exists. The fourth reverses those two events but still uses the wrong PID. This repeated, type-specific defect is the strongest authenticity indicator.

### eCAR

eCAR records are valid JSON with monotonic millisecond timestamps and unique record IDs. Process object IDs generally persist from creation to termination, and source/target UUID relationships are internally coherent for process-open and remote-thread activity.

The primary semantic problem is Linux `logon_id=0x3e7`. Examples include:

- `APP-INT-01` `/bin/sh` and `/usr/lib/sysstat/debian-sa1` at `1710763201076` and `1710763201170`.
- `DB-PROD-01` `/usr/local/sbin/database-backup-agent` at `1710763724314`.
- `LT-MRIVERA-02` `/usr/sbin/sssd` at `1710763733394`.

Because `0x3e7` is Windows’ well-known SYSTEM LUID, using it across Linux process telemetry exposes Windows-specific identity modeling in a cross-platform source.

### Zeek and network telemetry

I verified UID and tuple relationships across `conn`, `dns`, `http`, `ssl`, `smtp`, `smb_mapping`, and `smb_files`. All application UIDs had corresponding connections, all compared tuples agreed, and protocol timestamps fell within plausible connection intervals.

Certificate chains were particularly strong: SSL FUIDs resolve through files and X.509 records, with repeated certificates retaining stable fingerprints while receiving per-observation FUIDs. DNS rows use correct scalar/list types, names, flags, answer/TTL relationships, and response codes.

The seven missing application-file FUIDs are concrete reference gaps. They are sparse and could result from collection filtering, parser loss, or files.log observation gaps, so they are not independently decisive.

### Distribution and environment

Periodic sysstat activity appears every 30 minutes with host-specific minute offsets and subsecond jitter. Several expected occurrences are absent on individual hosts. That pattern could reflect collection loss or task execution variance, so I did not count periodicity or omissions as synthetic indicators.

Network traffic includes substantial long-tail texture: failed handshakes, variable `conn_state` and `history`, nonzero `missed_bytes`, internal and external traffic, realistic protocol mixes, and varied source-specific timestamps. Record volumes are plausible for a six-hour enterprise slice and are not implausibly dominated by a single source family.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `hard_contradiction` | Windows Security/Sysmon RDP | 3 of 4 Type 10 sessions | The authenticating logon visibly precedes creation of the session’s generated `winlogon.exe`. |
| `hard_contradiction` | Windows Security RDP | 4 of 4 Type 10 sessions | 4624 `ProcessId` does not identify the nearby `winlogon.exe`; two overlapping sessions reuse one PID. |
| `contract_gap` | Windows process lifecycle | All 4 Type 10 sessions | RDP `winlogon.exe` is attributed directly to System rather than the observed `smss.exe` session path used for Type 2. |
| `schema_or_format` | Linux eCAR | 811 records across 11 hosts | Windows SYSTEM LUID `0x3e7` leaks into Linux process identity fields. |
| `contract_gap` | Zeek HTTP/SMB/files | 7 of 977 FUID references | Application records reference absent in-window file objects; possible but unexplained collection loss. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Sysmon, Zeek, syslog, proxy, and firewall records are generally source-native and parser-friendly.
- **Temporal patterns:** 7 — Most lifecycle timing is credible, but three RDP logons visibly precede their session process creation.
- **Cross-source correlation:** 8 — Process, network, certificate, and authentication joins are strong; RDP ownership and seven FUID references fail.
- **Behavioral realism:** 8 — Traffic, process, authentication, and administrative activity have convincing variety and lifecycle depth.
- **Environmental consistency:** 7 — Host roles and volumes are plausible, but Windows LUID semantics appear throughout Linux endpoint telemetry.

## Recommendations

If this were synthetic, the highest-value improvements would be:

- Make the RDP action/session owner create a unique per-session `winlogon.exe` through `smss.exe` before the 4624 event. Set the 4624 `ProcessId` to that exact process and retain it through the session lifecycle.
- Add a regression test covering simultaneous Type 10 sessions on one host: distinct Logon IDs, session IDs, `winlogon.exe` PIDs, process GUIDs, and parent chains must remain aligned.
- Use OS-native Linux session identity in eCAR. Represent audit session ID, login UID, systemd session ID, or an explicit non-user/system-session value instead of the Windows-only `0x3e7` LUID.
- Ensure an emitted HTTP, SMTP, or SMB FUID remains resolvable in `files.json`, or model a clearly coherent files-source observation drop so missing references reflect collection behavior rather than orphaned correlation.
- Preserve the existing Windows field schemas, Event 1102 record-ID reset behavior, skewed provider-delay distribution, Zeek UID/tuple integrity, and certificate-chain consistency; these are among the dataset’s strongest realism features.
