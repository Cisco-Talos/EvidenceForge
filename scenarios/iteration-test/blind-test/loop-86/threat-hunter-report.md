# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 72  
**Synthetic-Confidence Score:** 29

## Executive Summary

Several cross-source activity chains are coherent, including a database dump moved from DB-PROD-01 to APP-INT-01 and written to a file share, plus a support-log upload with a matching proxy response. No hard contradiction was established. A large Citrix installer download to DC-02 and a blocked MeetingAssist launch warrant context, but neither shows successful execution.

## Evidence For Synthetic

- **[environment_or_collection_plausibility]** At 15:53:26Z, Zeek DMZ records a 124,385,593-byte `CitrixWorkspaceApp.exe` download by DC-02, with a matching file record and SHA-1. This is unusual for a domain controller, but administrative staging is possible and execution is not shown.
- **[weak_signal]** MAC-MROSS-01 Unified Log records System Policy denying a MeetingAssist launch at 15:42:05Z. The record proves neither how the app arrived nor successful execution.

## Evidence For Real

- DB-PROD-01 records an SSH session from APP-INT-01, `mysqldump` creation/compression, and an `scp` transfer. APP-INT-01 records the received file and SMB upload; FILE-LNX-01 records successful open/write/close for the same file under `svc_mhsync`.
- Lina Nguyen's shell history shows packaging two connector logs and uploading them; the proxy records a matching HTTP 200 response and byte count.
- Linux sysstat entries recur at ten-minute intervals with small timestamp variation, consistent with scheduled collection.
- Cross-source file, tuple, and outcome evidence is coherent in the examined chains.

## Detailed Analysis

The database dump sequence appears across SSH, process/file activity and SMB auditing. It is high-risk data handling, but the identities (`root` and `svc_mhsync`) remain distinct and do not prove authorization or a single operator. The support upload similarly has matching host-side command history and proxy outcome. The Citrix installer transfer and blocked MeetingAssist event should be treated as transfer/attempt evidence only. The six-hour slice limits conclusions about events outside the window.

## Synthetic Indicator Summary

| Category | Finding |
|---|---|
| hard_contradiction | None identified |
| contract_gap | None established |
| distribution_texture | None identified; sysstat cadence fits its schedule |
| schema_or_format | No concrete error identified |
| environment_or_collection_plausibility | Large Citrix installer download to DC-02 is unusual, but possible |
| weak_signal | Blocked app launch and BitTorrent alert are investigative context only |

## Realism Score by Category

- **Field format accuracy: 9/10** — Source-specific records retain consistent file, address, identity, and outcome fields.
- **Temporal patterns: 8/10** — SSH, file, and SMB operations have plausible order and timing.
- **Cross-source correlation: 9/10** — The transfer and upload chains align across host, network, and file-server evidence.
- **Behavioral realism: 7/10** — Actions are credible; authorization is not visible.
- **Environmental consistency: 7/10** — The host and sensor mix is coherent; DC-02's installer download is unusual but not contradictory.

## Recommendations

- Verify authorization for the database dump/share placement and support archive upload.
- Check why DC-02 downloaded the Citrix installer and seek separate execution evidence.
- Treat MeetingAssist as a blocked attempt unless other records establish successful execution.
