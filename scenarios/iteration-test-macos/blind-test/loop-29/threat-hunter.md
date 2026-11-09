# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 75
**Synthetic-Confidence Score:** 30

## Executive Summary

The sampled intrusion and administrative activity supports practical, technically coherent hunting pivots across Windows, Linux, macOS, proxy and network telemetry. I found a weak repeated-command texture in the two Mac shell histories, but no demonstrated impossible lifecycle or cross-source contradiction in the bounded checks; the evidence does not justify confidently classifying the collection as synthetic.

## Evidence For Synthetic

- [weak_signal] The two `MAC-MROSS-*/zsh_history/maya.ross.zsh_history` files contain 41 commands altogether. Six invoke SSH; the other 35 come from eleven repeated diagnostic command templates, including `id`, `sw_vers`, `uname`, `pwd`, `ls`, `du`, `df`, `ps`, `find`, `ifconfig` and `dscl`. For concrete examples, MAC-MROSS-01 lines 4–6 repeat directory inspection, and lines 20–21 revisit the same Documents directory and PDF search; MAC-MROSS-02 lines 4–7 and 13–18 use the same small vocabulary. This can resemble a generated command menu. It has little weight because these are the same user operating two Macs, and troubleshooting or training activity can explain the repetition. I found no fixed-interval requirement or impossible command effect that would strengthen it.

## Evidence For Real

- The database extraction preserves shell-versus-process semantics: `DB-PROD-01.../bash_history/root.bash_history:2` includes `> /tmp/rpt_0318.sql`, while `ecar.json:582` records the executed `mysqldump` arguments without the shell redirection. Lines 583–595 then connect SQL output, compression and an SCP read to their owning processes.
- The SCP pivot is operationally usable: `DB-PROD-01.../ecar.json:593` identifies `10.10.4.10:58931 → 10.10.2.30:22`; `APP-INT-01.../syslog.log:207–208` accepts root's key on that tuple; `APP-INT-01.../ecar.json:723–726` supplies the receiver session, destination file and logout. Zeek observes an established transport with substantial client payload, rather than a tiny failed flow.
- A plausible diagnostic upload provides a useful competing hypothesis to exfiltration. `WS-LNGUYEN-01.../ecar.json:350–358` creates a support archive and reads it with curl; proxy line 1740 and Zeek HTTP records identify the same case attachment, multipart types and successful response. The client-to-proxy request uses an absolute URI while the upstream request uses an origin-form URI.
- The DC Security event stream handles log clearing coherently: Event 1102 at `18:41:52.1514680Z` resets its EventRecordID to 1, and subsequent account deletion has a post-clear RecordID of 422. A low later record number therefore has a visible cause.
- Bounded same-identity checks found no observed eCAR actor use before its visible PROCESS/CREATE or after its visible PROCESS/TERMINATE. Equivalent checks on visible Sysmon process identities and parent/source references also found no ordering violations. This is supporting coherence, not proof of production origin.

## Detailed Analysis

### Scope and method

I inventoried only the supplied data directory. It has 23 endpoint host directories, three Zeek observation points, perimeter firewall logs and two Snort alert feeds. Endpoint sources comprise Windows Security/Sysmon XML, Linux syslog and bash histories, normalized eCAR, and two Mac Endpoint Security/unified-log/zsh collections. Observed activity covers approximately `2026-11-02 13:00–19:00 UTC`.

Record volumes differ substantially by host role: DC-01 and DC-02 have 5,358 and 4,709 eCAR rows, the proxy has 4,700, and the two Macs have 556 and 511. Network connection files contain 11,497 core, 8,791 DMZ and 453 database rows. These counts do not independently establish authenticity, but they do not make the suspicious activity the only available material to investigate. XML line counts were not treated as event counts.

The review combined representative command and native-event reads with narrowly defined identity-ordering checks. The latter covered eCAR PROCESS identities and actor references, and Windows Sysmon visible create/terminate, parent and source-process relationships. I did not equate a process with a reused PID, require pre-window parents, or require missing Sysmon event families. I also checked the three Zeek connection files for payload bytes exceeding their corresponding IP-byte totals or TCP totals smaller than minimum IP/TCP headers; neither bounded predicate found failures. This was not an exhaustive validation of every protocol field.

### Windows credential access and account manipulation

On WS-AJOHNSON-01, `ecar.json:618–643` shows PowerShell followed by `whoami /all`, domain-user/group queries and domain browsing. At `16:44:46.740 UTC`, line 701 creates PID 5964 running `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`. Line 710 opens LSASS PID 4292 with granted access `0x1FFFFF`; line 711 records a remote thread, and line 713 terminates the source process. These are suspicious observations, not an authenticity defect.

The native Sysmon event begins at `WS-AJOHNSON-01.../windows_event_sysmon.xml:9495` (EventID 1, RecordID 31133), timestamp `16:44:46.6785607Z`, and gives the same PID, command and parent PID 5872. Its IntegrityLevel is `High`, so I did not infer that a necessarily unprivileged process had inexplicably obtained LSASS access. The logs do not establish whether credentials were successfully recovered merely because memory access occurred.

On DC-01, native Security Event 4720 creates `svc_dirsync` at `17:15:20.2301594Z` (XML line 181585, RecordID 28256847). Event 4728 adds the same SID ending `-4533` to Domain Admins at `17:15:24.6964380Z` (line 182002, RecordID 28256857). The corresponding command processes occur earlier in `ecar.json:3549–3574`. The group SID ends `-512`, while the account SID is distinct. Deletion at `18:50:15.8464084Z` is Event 4726 (XML line 261309, RecordID 422), following the visible Event 1102 at XML line 253104. These provide viable identity and chronology pivots.

### Linux database extraction and transfer

`DB-PROD-01.../ecar.json:578–581` records an incoming root SSH connection from APP-INT-01 (`10.10.2.30:46218`), a successful session and a bash process before the dump. The root history records a redirection-capable dump command, gzip and SCP. Consequently, absence of `>` in the dump process's argv is expected shell behavior, not a missing output instruction.

SCP runs as PID 1089068 at line 592. The transport is corroborated by `zeek-db/conn.json:409`, UID `CuijuC1DdxTurXwpoP1`, timestamp `1793643336.476882`, duration `37.013589`, state `SF`, 143,728 originator bytes and 7,221 responder bytes. `zeek-core/conn.json:10177` observes the same tuple and payload accounting with a different sensor UID and a modest timestamp difference. I did not treat independent sensor UIDs as an integrity failure.

On the receiver, `APP-INT-01.../ecar.json:724` creates `/tmp/.cache/rpt_0318.sql.gz` under the SSH receiver process. Authentication precedes file creation, and a logout follows at line 726. The visible relationships are compatible with a noninteractive transfer. I did not claim that the data proves a particular SCP/SFTP subsystem configuration.

### Diagnostic upload and proxy boundaries

The support archive on WS-LNGUYEN-01 is created by tar at `16:31:52.540 UTC` (`ecar.json:351`). Curl starts at `16:32:18.188` (line 354) and later reads that archive (line 358). `zeek-core/http.json:1147` observes client `10.10.1.21:45159` contacting proxy `10.10.3.20:8080`, with request body length 1,573,258 and two request MIME parts (`application/json`, `application/gzip`).

`zeek-dmz/http.json:1275` shows a separate upstream tuple from the proxy to `52.44.186.73:80`, an origin-form case-attachment URI, the same body length and a 200 response. `PROXY-01.../proxy_access.log:1740` attributes the POST to lina.nguyen and reports 96 response bytes, matching the HTTP response-body length. The proxy's larger `cs_bytes=1573595` is not itself a contradiction with the HTTP body length; wire/request accounting can include headers. This is a useful example where suspicious upload mechanics alone cannot establish malicious intent or synthetic origin.

### Mac evidence and uncertainty

I treated the two Mac native streams separately from normalized eCAR. In the sampled `find` exec at `MAC-MROSS-01.../macos_endpoint_security.ndjson:56`, argv ends in `-name`, `*.pdf`, while the shell history quotes the wildcard. That is compatible with shell quote removal. SSH exec rows carry distinct targets, and the Mac-to-Mac histories include a deliberately forced-PTY `ssh -tt` invocation on MAC-MROSS-02 line 10.

The repeated diagnostic vocabulary is the only retained authenticity concern. It is a limited texture observation, not an OS-schema finding. I did not infer execution from a downloaded file, infer denial solely from policy-related text, or penalize the small unified-log exports for their size. No documented OS/version-specific native schema claim is needed for the verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Mac zsh histories, with sampled eCAR/ES confirmations | 35 non-SSH diagnostic commands across two hosts operated by maya.ross | Small upward pressure: narrow repeated vocabulary resembles a menu, but same-user troubleshooting is a credible explanation. |
| None demonstrated | Cross-source process/session/transport relationships | Defined identity checks and representative Windows, Linux and proxy pivots | No hard contradiction or contract gap established; does not prove real origin. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled native Windows fields, process argv and network tuple/accounting fields are credible; this was not a complete schema audit.
- **Temporal patterns:** 9 — Sampled prerequisites and effects are ordered coherently; defined visible same-identity lifecycle checks found no violations.
- **Cross-source correlation:** 9 — SSH/SCP and HTTP proxy pivots preserve practical endpoint, identity and transport relationships.
- **Behavioral realism:** 8 — Credential-access, administration, extraction and support-upload actions are technically intelligible; Mac diagnostic vocabulary is somewhat narrow.
- **Environmental consistency:** 9 — Source/host volumes vary plausibly, proxy boundaries are explicit, and the DC record-number reset has a visible cause.

## Recommendations

- If this were synthetic, broaden the Mac shell workload beyond the observed diagnostic vocabulary when the intended collection represents normal daily work. Retain repeated diagnostics when justified by troubleshooting or automation; do not add arbitrary commands simply to increase entropy.
- Preserve the demonstrated shell-redirection semantics, SSH transport/auth/file sequence, proxy request-form distinction and Security-log-clear RecordID behavior. No specific repair to those sampled relationships is supported by this review.
