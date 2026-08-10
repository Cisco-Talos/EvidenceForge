# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 66

## Executive Summary

The dataset is highly usable in a SIEM: Windows/Sysmon field sets are source-appropriate, 836 of 843 Security 4688 records have exact PID/image/command-line matches in Sysmon Event 1, and every sampled Zeek protocol UID resolves to the local `conn.json`. However, repeated Windows RDP/session teardown triplets with near-identical 50 ms spacing and short-lived Linux utilities that terminate without any in-window eCAR create record expose lifecycle construction patterns that are difficult to reconcile with independent production telemetry.

## Evidence For Synthetic

- `[hard_contradiction]` Windows session teardown repeatedly keeps `userinit.exe` alive until logout and terminates `explorer.exe`, `userinit.exe`, and `winlogon.exe` as a tightly scripted triplet. On `FILE-SRV-01`, eCAR records the three terminations at `2024-03-18T12:08:09.977Z`, `12:08:10.027Z`, and `12:08:10.077Z`; the same exact 50 ms cadence recurs at `12:55:29.396/.446/.496Z`, `13:45:24.080/.130/.180Z`, `15:19:49.240/.290/.340Z`, `17:14:55.365/.415/.465Z`, and `17:47:46.275/.325/.375Z`. `userinit.exe` ordinarily launches the shell and exits near logon, rather than remaining for the interactive session and terminating at logoff.
- `[distribution_texture]` The same shutdown template crosses unrelated Windows servers and users. `MAIL-FIN-01` has `explorer.exe`/`userinit.exe`/`winlogon.exe` terminations at `2024-03-18T14:12:39.744/.794/.844Z` and `15:57:44.247/.297/.347Z`; `DC-01` shows the corresponding triplet at `13:11:36.847/.897/.947Z`. Repeated source-native millisecond offsets of this precision are a stronger tell than mere event completeness.
- `[contract_gap]` eCAR has termination-only records for commands demonstrably started inside the six-hour window. `DB-PROD-01` bash history timestamps `who -a` at epoch `1710768045` (`13:20:45Z`), while eCAR terminates `/usr/bin/who` at `13:20:53.488Z` with object ID `c9055211-b58b-478e-be55-06e32aa606d2` but contains no PROCESS/CREATE for that object. The same occurs for `file /tmp/rpt_0318.sql` at history timestamp `1710782282` (`17:18:02Z`) and eCAR termination at `17:18:09.667Z` for object `8f38889f-9415-4876-86d3-506c881611ed`.
- `[contract_gap]` This is not confined to the beginning boundary: `PROXY-01` terminates `/usr/bin/head` at `13:06:49.461Z` without a matching create object, and `MAIL-CLIN-01` has two termination-only `/usr/bin/tail` objects at `12:33:11.464Z` and `12:44:56.706Z`. Source loss can explain isolated orphan events, but the recurring short-command lifecycle shape across hosts weakens detector-contract realism.

## Evidence For Real

- Windows event metadata and data fields are notably accurate. Security 4624 is Version 2/Task 12544, 4688 is Version 2/Task 13312, 5156 is Version 1/Task 12810, and the examined Sysmon Event IDs use coherent versions and canonical field names (including Event 1 Version 5 and Event 10 Version 3).
- Cross-source process detection is strong without being literally complete: 836/843 Security 4688 tuples match Sysmon Event 1 on PID, image, and command line. The seven unmatched Security creates include plausible source-specific observation gaps such as `WmiPrvSE.exe` on `MAIL-FIN-01` at `12:11:23.4514426Z` and `mstsc.exe /v:DC-01` on `WS-MCHEN-01` at `17:09:29.1305396Z`.
- Zeek detector contracts are internally sound in the inspected files. All 2,258 core and 751 DMZ DNS UIDs, all 931 core and 1,120 DMZ HTTP UIDs, all 112 core and 1,602 DMZ SSL UIDs, and all 67 SMTP UIDs resolve to a same-sensor connection record. The core and DMZ `conn.json` sets share no UIDs, as expected for independent sensors.
- Windows log clearing is represented with convincing native behavior: on `DC-01`, Event 1102 at `2024-03-18T17:41:50.0757699Z` receives EventRecordID 1 after record 28262086, followed by record IDs 2, 3, 4, and 6. That reset and subsequent gap preserve realistic channel semantics.
- Values inspected across the major families are parser-safe: SIDs and GUIDs are correctly shaped, Security process IDs are hexadecimal while Sysmon/eCAR PIDs are numeric, Sysmon timestamps carry source-appropriate precision, Zeek connection tuples use numeric ports and booleans, and RFC 5424-style Linux syslog records are structurally consistent.

## Detailed Analysis

### Windows Security and Sysmon schema

The Windows corpus contains 15,787 Security records and 4,016 Sysmon records across nine hosts. I enumerated Event IDs, versions, System metadata, and EventData field sequences rather than relying on text search. The present Security types use consistent provider metadata and source-native field sets: 4624 includes the Version 2 extended token fields; 4688 includes `NewProcessId`, `TokenElevationType`, target fields, `ParentProcessName`, and `MandatoryLabel`; 4768/4769 have the expected Kerberos ticket fields; and 5156 contains the expected application, direction, tuple, protocol, filter, and layer fields. Sysmon Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22 likewise have stable, recognizable schemas.

Process correlation is unusually good but not itself an authenticity defect. Across all Windows hosts, 836 of 843 Security 4688 events exactly match a Sysmon Event 1 on process ID, full image path, and command line. The mismatches are sparse rather than concentrated around the suspicious activity. Logon lifecycle ordering is also sound in the sampled window: I found no LogonID with a visible 4634 preceding its visible 4624. A small number of 4634 IDs have no in-window 4624, but those are compatible with sessions opened before the six-hour boundary.

The material Windows defect is process lifecycle behavior. Repeated RDP-like logout groups terminate `explorer.exe`, `userinit.exe`, and `winlogon.exe` in the same order and, very often, at exactly 50 ms intervals. This appears in both eCAR PROCESS/TERMINATE and the corresponding Windows process-termination evidence. The recurrence across hosts, users, and hours makes a generic collector batching explanation weak; batching would not also explain why `userinit.exe` persists to logout so consistently.

### eCAR detector contracts

The eCAR JSON is structurally uniform and uses stable UUID-shaped `id`, `objectID`, and `actorID` values with numeric `timestamp_ms` and PID fields. Process create/terminate object identity is often preserved: for example, `APP-INT-01` has 101 creates, 93 terminations, and 90 shared object IDs; `WS-AJOHNSON-01` has 123 creates, 114 terminations, and 94 shared IDs. Long-lived processes can legitimately produce termination-only rows when creation predates the window.

That boundary explanation does not cover the short-lived command examples on `DB-PROD-01`. Bash history places `who -a` and `file /tmp/rpt_0318.sql` only seconds before their matching eCAR terminations, yet eCAR has no create for either object ID. Similar late-window orphan terminations occur for `head` and `tail` elsewhere. A SIEM correlation rule requiring PROCESS/CREATE before PROCESS/TERMINATE would therefore produce recurrent orphan-object failures. Random endpoint loss is possible in production, so this is a contract gap rather than an impossible schema value, but it reinforces the templated Windows lifecycle evidence.

### Zeek and network-facing schemas

The two Zeek sensors cover a six-hour window and use plausible JSON shapes for connection, DNS, HTTP, SSL, files, X.509, OCSP, DHCP, and SMTP records. Focused UID validation found zero protocol UIDs missing from their same-sensor connection table. DNS timestamps equal connection start at request observation, while SSL is delayed by approximately 5–653 ms and HTTP ranges from connection start to about 5.34 seconds later; those relationships are source-plausible. Sensor-local identity is respected: none of the 6,174 core connection UIDs collide with the 5,230 DMZ connection UIDs.

The proxy access rows also preserve detector-useful distinctions such as CONNECT control-message byte counts versus tunnel byte counts, with parseable timestamps and conventional request-line/status fields. I found no network schema contradiction strong enough to raise the synthetic score.

### Temporal and environmental texture

The log families consistently span roughly `12:00Z–18:00Z` on 2024-03-18, with source-dependent first and last observations rather than identical hard edges. Volumes vary materially by role: the domain controller has 7,566 Security events and 6,162 eCAR rows, while endpoint and Linux-server volumes are lower and heterogeneous. Background DNS, SMB, Kerberos, service, package, sudo, multipath, rsyslog, browser, mail, and proxy activity provides credible detector noise. These features weigh toward production realism, but they do not nullify the repeated source-native lifecycle signature.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Windows Security/Sysmon/eCAR process lifecycle | Repeated server-side interactive-session teardown | `userinit.exe` is retained to logout and terminated in a scripted shell/userinit/winlogon group. |
| `distribution_texture` | Windows process termination | Multiple hosts, users, and hours | Recurring exact 50 ms offsets and identical three-process ordering resemble a shared generation template. |
| `contract_gap` | Linux eCAR plus bash history | DB, proxy, and mail hosts | Short-lived commands begun inside the window have termination UUIDs but no corresponding PROCESS/CREATE. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Windows, Sysmon, Zeek, eCAR, proxy, and syslog records are broadly parser-safe and source-shaped.
- **Temporal patterns:** 6/10 — Overall timing is varied, but exact recurring 50 ms shutdown sequences are a strong synthetic fingerprint.
- **Cross-source correlation:** 8/10 — Process and Zeek UID correlation are excellent, offset by orphan eCAR transient-process lifecycles.
- **Behavioral realism:** 6/10 — Background and user activity are credible, while the repeated `userinit.exe`-at-logoff behavior is not.
- **Environmental consistency:** 9/10 — Host roles, source volumes, protocol mix, and collection coverage are mutually plausible.

## Recommendations

- If this were synthetic, model Windows interactive session teardown from real process lifetimes: terminate `userinit.exe` shortly after it launches the shell, and do not recreate one fixed `explorer.exe`/`userinit.exe`/`winlogon.exe` termination bundle at logout.
- If this were synthetic, replace fixed inter-event offsets with source-native timing derived independently for each process and collection source; specifically remove the repeated 50 ms cadence across unrelated hosts and sessions.
- If this were synthetic, apply eCAR observation decisions coherently to each process lifecycle. A transient command should either retain both CREATE and TERMINATE or lose the lifecycle group together; validate this against bash-history timestamps for commands such as `who`, `file`, `head`, and `tail`.
