# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 95
**Synthetic-Confidence Score:** 77

## Executive Summary

The records are structurally convincing and most explicit identity and protocol relationships survive programmatic checks. My synthetic verdict rests on two measurable timing fingerprints: all 115 Linux sudo command/PAM-open pairs preserve exactly the same sub-millisecond timestamp remainder, and 41 of 100 macOS ES fork observations occur in repeated microsecond-phase groups. These are strong distribution artifacts, rather than demonstrated impossible lifecycles or missing-source assumptions.

## Evidence For Synthetic

- [distribution_texture] Across **115** same-PID sudo command → PAM session-open pairs on **11 Linux hosts**, every elapsed interval is an exact integer number of milliseconds, although the RFC5424 timestamps contain six fractional digits. The intervals range from 13 to 298 ms and have 94 distinct values: this is not simply a source that records everything at millisecond precision. For example, `MAIL-EDGE-01.meridianhcs.local/syslog.log:52–53` records `.533206` → `.551206` (18 ms), lines 55–56 `.615859` → `.747859` (132 ms), and lines 58–59 `.800402` → `.865402` (65 ms). Independent native log emissions repeatedly inheriting the same last three microsecond digits across all these hosts strongly suggests timestamp arithmetic.
- [distribution_texture] Both macOS ES exports repeatedly give different fork occurrences the **identical microsecond fraction**, separated by whole seconds. In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson:14,17,20`, the forks occur at `13:11:38.945637000Z`, `13:12:01.945637000Z`, and `13:12:49.945637000Z`; these lead to `sw_vers`, `uname`, and `pwd` executions on lines 15, 18, and 21. The same effect occurs at lines 64, 67, and 70 (`14:27:22.241357000Z`, `14:27:35.241357000Z`, `14:28:08.241357000Z`) in a different SSH shell. This is a repeated timing pattern across distinct commands and sessions, not an inference from narrative completeness.
- [distribution_texture] The macOS timing artifact also appears in browser process construction on both machines: `MAC-MROSS-01.../macos_endpoint_security.ndjson:17,20,22,24` uses `.864983000` for the main Chrome fork and helper forks exactly 2, 3, and 5 seconds later; `MAC-MROSS-02...:25,28,30,32` repeats that offset pattern at `.689694000`. In total there are 16 repeated-fraction fork groups: 17 of 51 fork rows on MAC-MROSS-01 and 24 of 49 on MAC-MROSS-02. Millisecond padding alone would be neutral; repeated nonzero microsecond phases across separate native observations is the relevant defect.

## Evidence For Real

- All supplied JSON/NDJSON records parsed as individual JSON objects, and all 20 Windows XML exports parsed successfully. Windows records use the expected namespace, provider/channel distinction, EventData names, hexadecimal Security PIDs and decimal Sysmon PIDs in the sampled event families.
- Programmatic Sysmon checks found **no same-ProcessGuid dependent event before its visible create or after its visible termination**, and no same-GUID PID/image disagreement. Visible parent create records also agreed with child `ParentUser` fields. Executable hashes did not vary within a host/image/version group.
- Every checked Zeek DNS, HTTP, SSL, SMTP, SMB mapping and SMB file row had a matching connection UID and matching overlapping tuple/protocol fields in its own sensor directory. No checked protocol timestamp was earlier than connection start by more than 10 ms or later than connection end by more than 10 seconds. This is a broad consistency check, not proof that every fine-grained protocol ordering is correct.
- Zeek file observations did not claim more `seen_bytes` than their single referenced connection's corresponding directional payload, and connection IP-byte totals were never smaller than payload bytes.
- Specific Windows session and process identities survive their lifecycle: DC-01 Security lines 3617 and 3795 pair MAIL-FIN-01$ Type 3 login/logoff under `0x53865f2`; DC-02 Sysmon lines 812 and 32731 create/terminate PID 7136 with the same GUID, image and SYSTEM user.
- macOS records distinguish actor and exec target audit tokens, retain PID across exec while changing pidversion, and use detailed executable metadata. For the SSH flow on MAC-MROSS-02, the accepted-login Unified Log message at `14:25:25.698688` precedes the session-user forks and shell exec at ES lines 61–63, while the shell and sshd-session exits appear later at lines 73–75. I found no same-token executable contradiction.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed 30,448 Windows events, 35,078 normalized eCAR records, 21,549 Zeek connection rows, and 302 macOS ES rows, alongside the protocol logs and Linux syslog records. The checks used exact host-local process/session identities and sensor-local connection identities. XML line references identify the opening `<Event>` line; NDJSON and syslog references identify physical lines. All timestamps cited are UTC.

I did not score missing Sysmon types, absent out-of-window initiators or closures, anonymized domain names, complete source alignment, thin collection coverage, or the ease of describing suspicious activity. There is no demonstrated hard contradiction underpinning this verdict.

### Source-native parsing and Windows event samples

The following is a representative field-level review across 18 Windows event types. Paths beginning `DC-02/` below abbreviate `DC-02.meridianhcs.local/`; other host abbreviations expand the same way. The observations support SIEM ingest usability. They are not a claim that every field in the entire dataset has been checked against a product-version manifest.

| Event | File and opening line | Field observations |
|---|---|---|
| Sysmon 1 | DC-02/windows_event_sysmon.xml:812 | Decimal PID `7136`; brace-delimited ProcessGuid; `Image`, `CommandLine`, `ParentProcessGuid`, `ParentUser`, hashes and session identity present. |
| Sysmon 3 | DC-02/windows_event_sysmon.xml:3 | Protocol, initiated direction, source/destination IP and port fields, process identity and UTC event time present. |
| Sysmon 5 | DC-02/windows_event_sysmon.xml:584 | Termination has process GUID/PID/image/user rather than process-create metadata. |
| Sysmon 8 | DC-02/windows_event_sysmon.xml:75374 | Separate source and target process identities plus thread/start-address fields. |
| Sysmon 10 | DC-02/windows_event_sysmon.xml:474 | SourceProcessGUID/TargetProcessGUID, GrantedAccess and CallTrace present; preserved native capitalization. |
| Sysmon 22 | DC-02/windows_event_sysmon.xml:403 | QueryName, QueryStatus, QueryResults and process identity present. |
| Security 4624 | DC-02/windows_event_security.xml:575 | NETWORK SERVICE SID `S-1-5-20`, LUID `0x3e4`, Type 5, Advapi and no remote IP form a coherent service-login record. |
| Security 4625 | WS-AJOHNSON-01/windows_event_security.xml:44 | Type 2 failure uses User32, local winlogon, absent remote endpoint; `Status=0xc000006d`, `SubStatus=0xc000006a` and failure Keywords. |
| Security 4634 | DC-02/windows_event_security.xml:4693 | Target account, target logon ID and logon type are present. |
| Security 4648 | DC-01/windows_event_security.xml:2227 | Separate subject and explicit target credentials, caller process and target server fields. |
| Security 4688 | DC-02/windows_event_security.xml:1280 | Version 2 creator/target fields, hex process IDs, mandatory label and token elevation fields. |
| Security 4689 | DC-02/windows_event_security.xml:917 | Subject identity, process ID/name and exit Status. |
| Security 4768 | DC-02/windows_event_security.xml:993 | Account SID, krbtgt service, ticket/pre-auth fields and client endpoint. |
| Security 4769 | DC-02/windows_event_security.xml:167 | Service account/SID, ticket options/encryption and client endpoint. |
| Security 4771 | DC-02/windows_event_security.xml:124186 | Failure record includes Status, PreAuthType and client endpoint. |
| Security 5140 | DC-02/windows_event_security.xml:5721 | Share name/local path and subject/network identity present. |
| Security 5145 | FILE-SRV-01/windows_event_security.xml:550 | RelativeTargetName, AccessMask/AccessList, share and client endpoint fields. |
| Security 5156 | DC-02/windows_event_security.xml:3 | Decimal ProcessID and numeric protocol, device application path, direction and filtering-layer fields. |

Windows Security events use Level 0 and appropriate success/failure Keywords in the inspected samples; Sysmon uses Level 4 and its Operational channel. Security timestamps retain seven fractional digits, while Sysmon UtcTime has millisecond precision. These differences are plausible source conventions.

The matching DC-01 `0x53865f2` login at `13:09:06.9681522` and logout at `13:09:15.6024530` maintain both the computer-account SID and Type 3. The visible DC-02 WmiPrvSE process at `13:05:25.8562446` and its `14:21:51.0752622` termination maintain GUID `{d55311aa-8a95-6ae8-0200-0010c5d19a98}`. Broad host-local checks also found no subject account disagreement with a visible matching login or subject activity after a visible matching logout. These checks are scoped to identities present in the window; they do not penalize records without a visible initiator.

### Linux timing texture

The sudo pattern is the strongest finding because its scope is much larger than a few sampled rows. I matched successful command messages to later `pam_unix(sudo:session): session opened` messages using the same syslog host and sudo PID. Pair counts were MAIL-EDGE 15, DB-PROD 8, LT-MRIVERA 6, WEB-EXT 12, LOG-MON 10, PROXY 15, MAIL-CLIN 15, WS-LNGUYEN 5, WS-OHADDAD 5, FILE-LNX 18 and APP-INT 6.

All 115 deltas were divisible by 1,000 microseconds. For an independent example, APP-INT lines 12–13 show `13:04:01.225190` → `13:04:01.423190` (198 ms); lines 20–21 show `13:07:07.922549` → `13:07:08.144549` (222 ms), crossing a second boundary while retaining the last three microsecond digits. Ordinary timestamp truncation to milliseconds cannot explain timestamps ending in `190` or `549`. A transformation that deliberately calculates PAM timestamps from another record could explain it, but no such transformation is evidenced in the supplied export.

This does not make any single session impossible. It makes the dataset's source timing distribution highly unlikely to be an unmodified collection of independent native emissions.

### macOS timing and semantics

The ES files declare message `version=11`. I treated them as native notification-style observations, not normalized EDR FLOW records. I did not infer policy denial from an ES notification result, nor require file-write or launch-item evidence merely because those facilities exist.

The repeated fork fractions occur in local shell commands, remote shell commands and GUI helper construction. They therefore extend beyond one unusual automation tool. For example, MAC-MROSS-01 lines 54, 57 and 60 launch `df`, `ps` and `find` from shell PID 42188 at `14:38:14.721760000`, `14:38:51.721760000`, and `14:39:43.721760000`. Their exec observations have distinct fractions, making the fork-level phase reuse particularly conspicuous.

The matching actor/target identity and coherent launchd→xpcproxy→application, terminal/login/shell and sshd helper sequences are substantial strengths. However, that semantic detail does not remove the repeated source timestamp arithmetic.

### Network and normalized records

Protocol references and tuple checks passed across zeek-core, zeek-dmz and zeek-db. For example, zeek-core files line 1 attributes a 5,359,834-byte SMB object to UID `Cljp2zAewMfpXP8gvH`; SMB mapping line 1 names the FILE-LNX ClinicalResearch share, and SMB files lines 1–2 open/read the matching filename and FUID. The matching byte accounting survived checks against the transport record.

Proxy records explicitly distinguish CONNECT control-message bytes from tunnel bytes, avoiding a common erroneous comparison of the HTTP 200 response body with encrypted tunnel payload. `PROXY-01.../proxy_access.log:1` and `zeek-core/http.json:1` both identify the CONNECT for `gateway.zscaler.net:443`, while the proxy separately supplies tunnel duration and byte totals. These facts help detections ingest and join the records correctly. Complete joins themselves did not increase the synthetic score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux sudo/PAM syslog | 115/115 matched pairs across 11 hosts; 94 distinct delays, all integer milliseconds | Strong evidence of derived timestamps despite microsecond presentation. |
| distribution_texture | macOS ES fork timing | 41/100 fork rows in 16 repeated-fraction groups across both Macs | Strong evidence of repeated activity anchors carried into native observation times. |
| distribution_texture | macOS Chrome helper construction | Both Macs reuse main-process fraction at exact +2/+3/+5-second fork offsets | Additional scope within the preceding finding; not counted as an independent third defect. |

The score stays below the hard-contradiction band because process/session/protocol integrity is strong and the principal issues are timing distributions. The high verdict confidence reflects the breadth of those timing artifacts, not an assertion that 77% of records are defective.

## Realism Score by Category

- **Field format accuracy:** 9 — Broad parser success and convincing sampled Windows, Zeek, Linux and ES field structures.
- **Temporal patterns:** 4 — Systematic sub-millisecond remainder reuse in Linux and macOS native observations.
- **Cross-source correlation:** 9 — Checked UID/tuple, process identity, file-byte and session relationships are coherent.
- **Behavioral realism:** 8 — Plausible services, sessions and helper-process structures; timing texture limits authenticity.
- **Environmental consistency:** 8 — Source-local identities and platform-specific paths are coherent in the checked records; narrow collection choices were treated neutrally.

## Recommendations

- If this were synthetic, give each sudo command and PAM observation source-appropriate independent emission timing. Avoid deriving every PAM-open timestamp by adding an integer number of milliseconds to a six-digit command timestamp.
- If this were synthetic, model distinct shell-command and GUI-helper fork times with independent subsecond scheduling and observation latency. Preserve causal ordering while removing repeated microsecond phases and identical Chrome helper fork offsets across machines.
- If this were synthetic, retain the existing host-local identity, protocol-reference and directional-byte consistency. Correct the timing distributions at the observation layer without weakening those correlations.
