# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

The dataset is unusually strong at source-native formatting and cross-source correlation, and most Security/Sysmon/Zeek records would parse cleanly in a detection pipeline. I would still call it synthetic because several low-level realism fingerprints appear generated: especially fleet-wide Sysmon ProcessGuid boot-time regularity and toy-like DNS TXT/DKIM payloads.

## Evidence For Synthetic

- Sysmon ProcessGuid timestamps imply multiple Windows hosts booted at almost exactly `12:00:00Z` on different days. Examples: `DC-01` services.exe ProcessGuid `{83eb9c06-43c4-65f0-1c44-000000000009}` decodes to `2024-03-12T12:00:04Z`; `FILE-SRV-01` services.exe decodes to `2024-02-26T12:00:04Z`; `WS-AJOHNSON-01` services.exe decodes to `2024-03-15T12:00:03Z`; `WS-MCHEN-01` svchost.exe decodes to `2024-03-09T12:00:12Z`.
- DNS TXT answers in `zeek-core/dns.json` look semantically fake. At `2024-03-18T17:21:42.282937Z`, `k1._domainkey.microsoft.com` returns `v=DKIM1; k=rsa; p=8c47226d437dd0ec25c2aa122c438dcb259e`, which is far too short and hex-like for an RSA DKIM public key. `mail._domainkey.zoom.us` at `17:22:07.718981Z` has the same issue.
- All Sysmon events I sampled use `RuleName = -`; across a dataset with mature endpoint telemetry, zero rule-tag variation feels overly neutral and lab-like, even though it is schema-valid.
- The environment has a curated quality: hostnames, user names, attack artifacts, proxy traffic, Windows Update traffic, DNS tunneling, and bash history all line up cleanly without much accidental local mess.

## Evidence For Real

- Windows Event Log schema details are mostly accurate: Security `4624` v2, `4688` v2, `5156` v1, Kerberos `4768/4769`, and Sysmon `1/3/10/13/22` field names and versions are plausible.
- Cross-source timing is convincing. For `WS-MCHEN-01` source port `49477`, Security `5156`, Sysmon `3`, eCAR `FLOW CONNECT`, Zeek `conn.json`, and Zeek `http.json` all agree on `10.10.1.31:49477 -> 10.10.3.20:8080` around `2024-03-18T12:00:35Z`.
- The audit-clearing sequence is very realistic: `DC-01` Sysmon logs `wevtutil cl Security` at `17:41:41.9405176Z`, eCAR records the same process at `17:41:42.300Z`, and Security `1102` appears at `17:41:42.8093377Z` with `LogFileCleared` UserData and a reset `EventRecordID` of `3`.
- Zeek references are internally coherent: HTTP/DNS/SSL records reference existing `conn.uid` values, SSL `cert_chain_fuids` map to `files.json` and `x509.json`, and packet/byte fields are consistent with protocol header expectations.
- Bash histories use normal `HISTTIMEFORMAT`-style `#epoch` lines, monotonic command order, typos like `journactl`/`tal`, and mundane admin commands mixed with suspicious activity.

## Detailed Analysis

### Windows And Sysmon Fidelity

The Windows event records are high-quality. The Security provider GUID `{54849625-5478-4994-a5ba-3e3b0328c30d}` is used correctly, common Event IDs have plausible versions, and the field names are detection-friendly. For example, `DC-01` Kerberos `4768` at `2024-03-18T12:00:25.3283560Z` uses IPv4-mapped `IpAddress = ::ffff:10.10.1.32`, `TicketOptions = 0x40810000`, and `TicketEncryptionType = 0x11`, followed by `4769` at `12:00:25.4743562Z`.

The strongest synthetic indicator is not the visible event content but the Sysmon ProcessGuid internals. The GUID timestamp component repeatedly encodes boot-era process starts at exactly noon UTC across unrelated hosts. A real fleet can have scheduled reboots, but `services.exe`, `lsass.exe`, and `svchost.exe` clustering at `12:00:03Z`, `12:00:04Z`, `12:00:12Z`, etc. across many hosts is too regular.

### Zeek And DNS

Zeek JSON field format is generally convincing: dotted field names, UID propagation, `local_orig/local_resp`, protocol histories, SSL certificate file IDs, and x509 fields are all usable by normal detections. The `WS-MCHEN-01` proxy connection through `CfdaLLOOrtK0cVF2l2` is an excellent example of source agreement.

The DNS TXT content is weaker. DKIM records with short hex `p=` values are not source-native realistic; real RSA DKIM keys are long base64 public keys. This is the kind of field-level issue that a detection pipeline may not reject syntactically, but an analyst familiar with DNS telemetry would notice.

### Behavioral And Environmental Realism

The six-hour window has believable density: DC Kerberos volume, workstation 5156/Sysmon noise, proxy CONNECT traffic, DHCP renewals, web access, OCSP/x509, and bash history all appear in reasonable proportions. The attack chain is also detection-useful: PsExec-like service activity, domain account creation and group membership, scheduled task persistence, encoded PowerShell, DNS tunneling, and log clearing.

The main behavioral weakness is that everything feels intentionally represented. There are few truly messy artifacts: no malformed records, almost no partial parser oddities, very normalized Sysmon rule names, and few source-specific wrinkles beyond the modeled attack.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Sysmon, Zeek, and eCAR parse well, with DNS TXT semantics as the biggest flaw.
- **Temporal patterns:** 7 — Event timing is plausible, but Sysmon ProcessGuid boot-time regularity is a strong synthetic fingerprint.
- **Cross-source correlation:** 9 — Host, network, proxy, and endpoint evidence line up cleanly without concrete contradictions.
- **Behavioral realism:** 7 — User/admin/attack behavior is believable but somewhat curated.
- **Environmental consistency:** 7 — The environment is coherent, though whole-fleet noon boot artifacts and uniformly neutral Sysmon RuleName values reduce realism.

## Recommendations

If this is synthetic, improve realism by randomizing host boot times and ensuring Sysmon ProcessGuid timestamp components reflect organic uptime patterns. Replace DNS TXT/DKIM placeholder values with source-native-valid payloads, especially long base64 DKIM keys. Add more benign collection quirks, such as heterogeneous Sysmon rule tagging, occasional optional-field variance, and small source-specific imperfections that do not break parser correctness.
