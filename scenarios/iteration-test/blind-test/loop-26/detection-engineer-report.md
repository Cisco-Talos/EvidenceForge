# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 32

## Executive Summary

The supplied telemetry is predominantly production-like in its field shapes, platform distinctions, and visible identity/lifecycle relationships. I found one concrete but isolated SMB reference gap; it is insufficient to distinguish sophisticated synthetic data from a production export with collection loss, and I found no demonstrated impossible lifecycle or source-native identity contradiction in the checks performed.

## Evidence For Synthetic

- [contract_gap] `zeek-core/smb_mapping.json:93` records UID `C4bqaKVpaYQLPkuTrz` at **2026-11-02 17:35:24.871449 UTC**, tuple `10.10.1.22:59392 → 10.10.2.20:445`, share `\\FILE-SRV-01\ClinicalExports`, but that UID occurs nowhere else in the supplied data, including all three sensors' `conn.json` files. This is an actual missing join rather than an inference from generally thin coverage. The initiating `/usr/bin/smbclient` is visibly created at 17:35:20.133 and terminates at 17:35:29.396 in `WS-OHADDAD-01.meridianhcs.local/ecar.json:524,528`; its FLOW at line 527 uses the exact tuple. Thus an ordinary pre-window connection is not a satisfactory explanation for this particular short-lived client. Independent record loss or export filtering remains plausible, so this receives modest weight and is not a hard contradiction.

## Evidence For Real

- Windows auditing uses meaningful event-specific metadata rather than one generic XML envelope. For example, DC-01 Security 4688 is version 2/task 13312, 4768 is version 0/task 14339, failure 4771 uses `0x8010000000000000`, and 1102 correctly changes provider and places identity in namespaced `UserData/LogFileCleared`.
- Across the ten Windows hosts, the checked Sysmon ProcessGuid references retained one PID/image identity per GUID. Visible parent-create, access-before-create, and terminate-before-create comparisons produced no impossible ordering; checked process observations did not occur after their same-GUID termination.
- Protocol joins generally work with source-native identifiers. All **4,385 DNS**, **5,547 HTTP**, **3,668 SSL**, **79 SMTP**, and **224 SMB-file** records with a UID joined a connection on the same sensor without a tuple mismatch or a protocol timestamp more than 1 ms before its connection timestamp. The isolated SMB mapping gap is separated from these successful checks.
- The two Mac hosts distinguish native ES fork/exec/exit observations from normalized eCAR operations. For instance, MAC-MROSS-01 PID 25527 forks as a launchd child, executes xpcproxy, and retains its PID while its audit-token PID version advances; eCAR represents the exec as PROCESS/MODIFY rather than inventing a second process creation.
- SSH authentication has credible transport-before-authentication order. For MAC-MROSS-01, Zeek opens `10.10.1.42:54545 → 10.10.1.41:22` at 16:02:02.087110, the target eCAR FLOW appears at 16:02:04.360, Unified Log accepts the public key at 16:02:08.243284, and eCAR LOGIN appears at 16:02:10.018.
- Ordinary operational noise has platform-specific vocabulary: RFC5424 Linux service messages, network-service machine authentication, Windows lock/unlock, SMB object-handle auditing, DHCP REQUEST/ACK renewals, proxy CONNECT transactions, and both successful and unsuccessful network states. None requires treating suspicious activity's narrative shape as an authenticity indicator.

## Detailed Analysis

### Scope and method

I examined the supplied data files only, using XML and JSON parsing, source-family counts, targeted raw-record inspection, and identifier/time comparisons. Paths below are relative to the supplied `data` directory. eCAR contains **37,414 records across 23 hosts**, with visible timestamps from **2026-11-02 13:00:01.033 to 18:59:51.224 UTC**. The three Zeek sensors contain **23,141 connection records**. Windows Security contains **17,780 records**; Sysmon contains **11,606 records**. Native Mac ES contains **307 records**, and Unified Log contains six selected records.

These are bounded checks of an exported collection, not certification against every possible OS or product schema. I did not infer an OS build solely from network rows, impose uncollected Sysmon event families, or assume every process/session must begin and end within this six-hour window.

### Record-level schema and semantic checks

The following table documents twenty inspected event shapes. Times are on November 2, 2026, UTC. “Consistent” means the visible fields agree with the inspected event semantics; it does not establish provenance.

| Source / event | Time | Fields checked and result |
|---|---|---|
| DC-01 Security 4689 | 13:00:05.3779607 | `ProcessId=0xb64`, `Status=0x0`, SYSTEM subject, task 13313: consistent termination shape. |
| DC-01 Security 4776 | 13:00:05.5841888 | `PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation, account, status: appropriate credential-validation fields. |
| DC-01 Security 5156 | 13:00:18.3670663 | Decimal `ProcessID=2336`, native device application path, protocol 17, inbound direction, destination 88: coherent WFP shape. |
| DC-01 Security 4769 | 13:00:18.3707849 | IPv4-mapped client, hexadecimal ticket options/encryption/status, service SID and LogonGuid: consistent TGS fields. |
| DC-01 Security 4688 | 13:01:37.2023469 | Version 2, hexadecimal new/creator PIDs, parent image, token elevation and mandatory SID: consistent process-create shape. |
| DC-01 Security 4768 | 13:03:23.7991453 | `ServiceName=krbtgt`, domain SID ending 502, `PreAuthType=2`, client endpoint and certificate placeholders: consistent TGT fields. |
| DC-01 Security 4624 | 13:10:16.4138675 | Type 5 NETWORK SERVICE, SID S-1-5-20, LUID 0x3e4, services.exe, absent remote endpoint: coherent service logon. |
| DC-01 Security 4672 | 13:10:16.4406977 | Same NETWORK SERVICE SID/LUID and privilege names: identity agrees with the preceding service logon. |
| DC-01 Security 4634 | 13:10:49.8084721 | `TargetLogonId`, target identity and type 3: consistent network-logoff shape. |
| DC-01 Security 4648 | 13:26:35.3357958 | Distinct subject and target credentials, target server, explicit-credential process: event-specific shape retained. |
| DC-01 Security 5140 | 14:06:57.1114610 | `ShareName=\\*\NETLOGON`, native local share path, client source port and subject LUID: coherent share auditing. |
| DC-01 Security 4697 | 17:00:12.2938629 | PSEXESVC, service executable, service type 0x10, start type 3 and LocalSystem: coherent installation fields. |
| DC-01 Security 4720 | 17:15:05.8149075 | Target account/SID separated from SYSTEM creator, account-control fields and primary group: appropriate account-create shape. |
| DC-01 Security 4728 | 17:15:13.8607171 | Member DN/SID separated from Domain Admins group SID ending 512: group/member roles are distinct. |
| DC-01 Security 4698 | 17:19:47.7438924 | Task XML preserved as escaped text with task namespace, principals, repetition and command: parsable task payload. |
| DC-01 Security 1102 | 18:42:20.0702537 | Microsoft-Windows-Eventlog provider, level 4, task 104, record ID 1, namespaced LogFileCleared: not incorrectly rendered as ordinary EventData. |
| DC-01 Sysmon 1 | 13:01:36.8896748 | Version 5, decimal PID 3656, ProcessGuid/parent GUID, hash labels, LogonId and SYSTEM integrity: coherent process record. |
| DC-01 Sysmon 10 | 13:01:54.3493599 | Version 3, `SourceProcessGUID`/`TargetProcessGUID`, access mask 0x1400, call trace and users: correct source/target field distinction. |
| FILE-SRV-01 Security 4656/4663/4658 | 13:00:05.9709815–13:00:09.7044244 | One handle 0xb013d0ff, SYSTEM process PID 4, consistent requesting user's LUID; requested rights precede write access and handle close. |
| MAIL-FIN-01 Security 4625 | 14:43:18.7251932 | Failure keyword, type 4, status 0xc000006d/substatus 0xc0000072, Advapi and local endpoint placeholders: internally coherent failure record. |

Security and Sysmon PID representations remain appropriately different: hexadecimal in 4688 payloads and decimal in Sysmon. Event 4624 version-2 expansion fields are present, and Windows token resource strings use their native `%%` representation. I found no basis to penalize these formats.

### Windows identities and visible lifecycle

I compared same-host Sysmon create records to parent GUIDs, termination GUIDs, and process-access source/target GUIDs. I also compared observations of terminated identities against the payload `UtcTime`, avoiding a false ordering claim based only on source publication delay. These checks found no same-identity use after termination or visible initiating process after its dependent event.

A naive “first visible 4624 must precede every process” rule produces false alerts here. WS-AJOHNSON-01 uses LUID `0x254febf` in processes from 13:02 onward, while its visible 4624 at 16:20:40.9385034 is **type 7 unlock**, not the original creation of that interactive session. The lock/unlock records and collection boundary make pre-window session existence a valid interpretation. I excluded these cases from synthetic evidence.

### Network and protocol integrity

For each sensor I joined UID-bearing protocol records to its own conn table, compared available four-tuples, and checked protocol timestamps against connection start. Different sensors may legitimately assign different UIDs to the same traffic; I did not require sensor-global UID identity.

All **2,550 files.json records** had resolvable supplied `conn_uids`. Checks found no TCP payload byte count greater than the corresponding IP byte count, no positive TCP payload with zero packets, and no S0 connection with responder packets. Checked UID-bearing protocol timestamps were not more than 0.5 seconds after the corresponding connection interval. Repeated certificate fingerprints did not conflict on certificate or SAN fields within a sensor.

The SMB mapping at 17:35:24 is the exception. Endpoint evidence establishes a new, short-lived process and contemporaneous FLOW on both ends; FILE-SRV-01 Security 4624 at 17:35:24.5922775 authenticates `omar.haddad` by NTLM V2 with the same source port. Security 5140 and 5145 then use LUID `0xf851f57` and the corresponding share/file. That is strong evidence the activity itself is coherent, while its Zeek mapping-to-connection join is incomplete. This could harm connection-enrichment rules, but independent export loss is a credible production explanation.

### macOS source interpretation

The ES rows declare message version 11 and use event types 11/fork, 9/exec and 15/exit, all as notifications. I inspected actor/child/target separation, PID and PID-version changes, executable/signing identity, nanosecond-shaped timestamp strings, and visible termination ordering. I found no observation of the same exact process token after a visible exit in the checks performed.

MAC-MROSS-01's first records show launchd forking PID 25527 at 13:07:32.811343 and that process executing xpcproxy at 13:07:32.820534; the target token advances from PID version 2482477 to 2482478. This is semantically richer than treating every exec as a new PID. Native ES is not expected to contain normalized EDR FLOW records.

The MAC-MROSS-01 Unified Log security-policy message at 15:42:09 names MeetingAssist and says policy “would not allow” it. I do not convert that wording into a proven denied execution or demand child-process effects. Likewise, sparse Unified Log and ES event-family selection alone does not demonstrate unrealistic collection. The available rows do not justify claiming exhaustive validation of version-11 schemas.

### Distribution and confidence limits

The conn-state distribution includes SF, S0, OTH, reset, rejection and partial-close states; it is not exclusively clean successful traffic. Different hosts have different process, module, registry and session volumes. A six-hour, selected-source extract does not support reliable judgments about weekend behavior, long-term patch cadence, or the full operational event long tail.

The one missing reference slightly raises synthetic appearance. The many coherent records lower it, but sophisticated generation could reproduce these relationships, and ordinary production collection can lose individual rows. This is why the score is in the mostly-realistic band while the origin verdict remains inconclusive.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Zeek SMB mapping / conn; corroborating endpoint and Security evidence | One of 129 core SMB mapping rows; UID C4bqaKVpaYQLPkuTrz at 17:35:24.871449 | Modest increase: a reproducible broken connection join for a visibly short-lived in-window client. Record loss/filtering remains plausible; not an impossible event or dataset-wide fingerprint. |

No demonstrated hard contradiction, generator identity leak, or substantiated dataset-wide timing/command-distribution artifact was found in this review.

## Realism Score by Category

- **Field format accuracy:** 9 — The inspected Windows, Zeek, eCAR and Mac records preserve meaningful source-specific structure; exhaustive schema certification was outside this review.
- **Temporal patterns:** 9 — Checked visible lifecycles and sampled SSH transport/authentication order are coherent; the short window limits broader temporal judgments.
- **Cross-source correlation:** 8 — Identity and protocol joins are strong, with one specific SMB connection-reference gap.
- **Behavioral realism:** 8 — Plausible operational and administrative activity is visible; long-term population behavior cannot be established from six hours.
- **Environmental consistency:** 9 — Platform paths, session types, authentication mechanisms and service-specific evidence generally agree.

## Recommendations

- If this were synthetic, preserve the connection companion for SMB UID `C4bqaKVpaYQLPkuTrz`, or make deliberate observation loss coherent across that sensor's conn/protocol group. Keep the existing endpoint and NTLM account/tuple relationships intact.
- If the missing conn row instead reflects production extraction, retain the export/filter explanation with the collection so detection engineers can distinguish a reference gap from a failed SIEM join. This recommendation addresses the observed UID gap and does not call for adding unrelated source families.
