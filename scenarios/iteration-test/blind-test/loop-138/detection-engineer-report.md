# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Confidence:** 82

## Executive Summary

The dataset is high quality and would mostly parse cleanly in a SIEM: Windows, Sysmon, Zeek, eCAR, and bash-history structures are generally plausible. The deciding issue is repeated Kerberos source-native causality inversion on the DC: visible 4769 TGS events occur milliseconds before matching 4768 TGT events for the same principal, client IP, and source port.

## Evidence For Synthetic

- `DC-01.meridianhcs.local/windows_event_security.xml` has 26 Kerberos cases where Event ID `4769` precedes the matching `4768` on the same client socket. Example: `2024-03-18T17:50:51.8112770Z` 4769 for `FILE-SRV-01$@MERIDIANHCS.LOCAL`, `ServiceName=cifs/DC-01`, `IpAddress=::ffff:10.10.2.20`, `IpPort=59595`, followed by `2024-03-18T17:50:51.8252778Z` 4768 for `FILE-SRV-01$`, `ServiceName=krbtgt`, same IP and port.
- More examples of the same inversion: `2024-03-18T12:22:53.0401916Z` 4769 `ldap/DC-01` before `2024-03-18T12:22:53.0581910Z` 4768 for `FILE-SRV-01$`; `2024-03-18T14:41:27.2696505Z` 4769 `cifs/FILE-SRV-01` before `2024-03-18T14:41:27.2766500Z` 4768 for `marcus.chen`.
- All observed Windows Filtering Platform `5156` records are outbound-style: `Direction=%%14593` and `LayerName=%%14611` across 2,821 records. That is suspiciously one-sided for servers visibly receiving SMB, RDP, Kerberos, and HTTP traffic.
- Sysmon Event 1 metadata is a little too sparse for known signed applications: `OneDriveStandaloneUpdater.exe`, `DropboxUpdate.exe`, and `AdobeARMservice.exe` often show `Company=-` / `Product=-`, which weakens source-native fidelity.

## Evidence For Real

- Windows Security schemas are mostly correct: `4624` v2, `4688` v2, `4768/4769`, `4672`, `4697`, `4698`, `4720`, `4728`, `5156` all use plausible field names, provider/channel metadata, task IDs, keywords, and timestamp precision.
- The DC log clear behavior is realistic: Event `1102` at `2024-03-18T17:42:15.5173613Z` resets EventRecordID from `11621038` to `3`, with `UserData/LogFileCleared` showing `SYSTEM`.
- Zeek JSON is structurally strong. `dns`, `http`, `ssl`, and `files` UIDs all resolve back to `conn.log`; DMZ inbound TLS has `local_orig=false`, `local_resp=true`; SSL `cert_chain_fuids` all resolve into `x509.json`.
- Endpoint behavior has realistic noise: DHCP renewals, machine-account Kerberos, service logons, process create/terminate pairs, Sysmon DNS through `svchost.exe`, shell typos like `hostnaem`, `systtemctl`, and `hitsory`.

## Detailed Analysis

Windows Security is the main tell. A normal Kerberos flow can have 4769 without a visible 4768 if the TGT was obtained before the slice. That is not what happens in the repeated bad cases: the matching 4768 is visible after the 4769, on the same `IpAddress` and `IpPort`, within 2-40 ms. This is a source-native ordering contradiction, not just missing context.

Some Kerberos sequences are correct, which makes the bad ones stand out. For example, `2024-03-18T12:01:57.7644284Z` has 4768 for `FILE-SRV-01$`, followed by `2024-03-18T12:01:57.8544282Z` 4769 for `host/DC-01`. But many later sequences reverse that order.

Sysmon is generally credible. Event IDs `1`, `3`, `5`, `7`, `8`, `10`, `11`, `13`, and `22` use expected field names; Event 22 correctly attributes DNS to `C:\Windows\System32\svchost.exe`. Process GUIDs, PID references, and create/terminate ordering did not show obvious impossible visible ordering in my checks.

Zeek is also credible. `zeek-dmz/ssl.json` entry `CuKde0Uqa39ObEX7C` ties cleanly to `conn.json` with external origin `56.70.196.254` to internal `10.10.3.10:443`, and its certificate FUIDs resolve in `x509.json`. HTTP proxy records also look SIEM-friendly: CONNECT requests use proxy destination `10.10.3.20:8080`, host/URI fields are populated, and response/status fields are consistent.

The weaker realism areas are distributional/source-native polish rather than parser breakage. The WFP `5156` direction monoculture and sparse file-version metadata would not necessarily break detections, but they would make a detection engineer suspicious when combined with the Kerberos ordering defect.

## Realism Score by Category

- **Field format accuracy:** 8 — schemas mostly match Windows, Sysmon, Zeek, and JSON expectations.
- **Temporal patterns:** 6 — broad timing is plausible, but repeated Kerberos 4769-before-4768 ordering is a hard flaw.
- **Cross-source correlation:** 8 — UID, process, auth, and certificate references generally correlate well.
- **Behavioral realism:** 7 — user, service, DHCP, shell, and attack activity feel plausible, with some templated edges.
- **Environmental consistency:** 7 — host roles and naming are coherent, but WFP direction coverage is unnaturally narrow.

## Recommendations

If this were synthetic, I would fix Kerberos causal ordering first: ensure AS/TGT `4768` precedes same-socket TGS `4769`, or omit the visible 4768 when modeling cached-TGT usage.

Add inbound WFP `5156` examples where server-side Security logs are present, especially for FILE-SRV SMB, DC Kerberos/LDAP, and RDP listeners.

Improve Sysmon file-version metadata for common signed binaries, especially Microsoft, Adobe, Dropbox, OneDrive, VPN, and browser updaters.
