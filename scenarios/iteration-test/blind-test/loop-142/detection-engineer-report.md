# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

The dataset is high-quality and mostly source-native: Windows Security/Sysmon fields, Zeek JSON, ASA, Snort, proxy, and syslog formats are largely plausible. My synthetic verdict comes from repeated Linux eCAR SSH session contradictions: eCAR login events line up with syslog opens, but eCAR logout events consistently fail to line up with `pam_unix(sshd:session): session closed` records and sometimes use different apparent session object IDs.

## Evidence For Synthetic

- Linux eCAR SSH logouts do not correlate with syslog closes. Across SSH session events I checked, 22/23 eCAR logins matched syslog opens, but 23/23 eCAR `LOGOUT` events lacked a matching `pam_unix(sshd:session): session closed` within a few seconds.
- Example: `APP-INT-01.meridianhcs.local/ecar.json` has `aisha.johnson` SSH `LOGIN` at `2024-03-18T13:00:23.133Z` and `LOGOUT` at `13:03:52.925Z`; syslog has the open for `sshd 839041` at `13:00:23`, but no corresponding close for that PID/session.
- The same APP-INT eCAR session appears to change object identity: login `objectID=bb89d6b3-5c93-470b-b22c-c7629ca0f580`, logout `objectID=9ea3d06f-fa50-4453-8a46-8cf7ab4a4d56`.
- Example: `DB-PROD-01.meridianhcs.local/ecar.json` logs `lina.nguyen` SSH `LOGOUT` at `2024-03-18T12:26:33.687Z`, while `DB-PROD-01.meridianhcs.local/syslog.log` shows Lina sessions opened at `12:21:50` and `12:26:42`, with actual closes later at `12:41:47`, `12:49:00`, and `12:53:41`.
- Source time windows are uneven in a curated way: Zeek/ASA/proxy activity largely stops around `18:01:28Z`, while `WEB-EXT-01` eCAR/bash continue to `19:54:25Z`. This is not impossible, but it reads like separately rendered source windows.
- The corpus is unusually parse-clean: JSON, XML, syslog, proxy, ASA, and Snort records were all structurally valid in sampled/parsed checks, with very little collector noise or malformed residue.

## Evidence For Real

- Windows Event Log metadata is strong: Security event versions/tasks/keywords match expected patterns for 4624, 4625, 4688, 4689, 4768, 4769, 5156; Sysmon event versions and fields also look source-native.
- Cross-source network correlation is convincing. At `2024-03-18T12:01:58Z`, DC-01 Security 5156, Sysmon 3, Zeek core/dmz conn+http, and ASA all agree on `10.10.2.10:54617 -> 10.10.3.20:8080` with proxy CONNECT to `ctldl.windowsupdate.com:443`.
- Windows process correlation is solid: Security 4688 and Sysmon 1 agree on process IDs/images/command lines across 826 matching PID groups with no image mismatches in my check.
- DC log clear behavior is plausible: Security log reset around Event ID 1102 at `2024-03-18T17:42:25Z`, followed by low EventRecordIDs, consistent with audit log clearing.
- Zeek fields are credible: UIDs, byte/packet math, conn histories, DNS flags, TLS 1.3 lack of visible cert chains, and ASA NAT/teardown pairing all look technically aware.
- Behavioral noise is good: bash histories include typos (`ks`, `ct`, `nmli`), admin checks, package/update chatter, DHCP renewals near T/2, external scans, and stale-auth style failures.

## Detailed Analysis

Windows schema fidelity is one of the strongest parts of the dataset. Security 4624 uses Version 2 and Task 12544; 4688 uses Version 2 and includes `CommandLine`, `ParentProcessName`, and `MandatoryLabel`; Sysmon hashes have correct SHA1/MD5/SHA256/IMPHASH lengths. The malicious chain on DC-01 around `15:59-16:20Z` is internally coherent: PSEXESVC service install, `net.exe` account creation, Domain Admins membership, service creation, and scheduled task creation all appear with plausible Security/Sysmon timing.

Zeek and firewall data are also strong. ASA connection IDs pair cleanly: 5,539 built connections, 5,538 teardowns, no teardown-before-build cases. Zeek conn/http records match ASA for several sampled flows, and DNS records show realistic internal authoritative answers versus recursive external answers.

The primary defect is Linux session lifecycle correlation. eCAR records SSH logins at the same time as syslog `Accepted`/`session opened` messages, so the source clearly attempts correlation. But logout timing is systematically disconnected from syslog `session closed` messages. That is a stronger synthetic signal than mere incompleteness because the visible initiator and dependent lifecycle evidence disagree inside the window.

Temporal behavior is otherwise plausible: timestamps have realistic precision by source, network activity has bursts rather than fixed cadence, and DHCP renewals mostly track half-life lease timing. The exception is source-window unevenness, especially WEB-EXT continuing eCAR/bash activity nearly two hours after perimeter/network sources end.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Sysmon, Zeek, ASA, Snort, and syslog schemas are mostly correct; eCAR session identity weakens it.
- **Temporal patterns:** 7 — Good jitter and bursts, but Linux eCAR logout timing and source-window drift stand out.
- **Cross-source correlation:** 7 — Excellent Windows/network correlation; repeated Linux eCAR/syslog logout mismatch is the main flaw.
- **Behavioral realism:** 8 — Admin behavior, scans, auth failures, DNS tunneling, and endpoint noise are plausible.
- **Environmental consistency:** 7 — OS-aware paths and topology are good; collection windows and curated cleanliness feel synthetic.

## Recommendations

- Anchor Linux eCAR SSH `LOGOUT` events to the actual syslog/PAM session close time, not an independent session duration.
- Preserve the same eCAR `USER_SESSION.objectID` from login through logout, and carry sshd PID or systemd session ID where possible.
- Define source collection windows intentionally; if host logs extend beyond network visibility, make that look like a real collector artifact rather than a clean per-source cutoff.
- Add small amounts of realistic collector imperfection: occasional rotated-file boundary artifacts, harmless dropped syslog closes, or benign parser gaps, but avoid breaking source-native schemas.
