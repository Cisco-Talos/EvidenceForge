# Loop 139 Blind Assessment Report

## Individual Expert Summaries

Threat Hunter assessed the data as synthetic with 72 synthetic-confidence. They found the attack chain coherent and huntable, especially the workstation credential theft, PsExec/domain-admin sequence, SMB archive staging, proxy upload, and DB-to-app SSH transfer. Their main authenticity break was proxy updater traffic where Dell, Lenovo, and HP domains/paths were repeatedly paired with the wrong updater User-Agent, plus isolated shell-history typos that felt injected.

Detection Engineer assessed the data as synthetic with 72 synthetic-confidence. They found Windows, Zeek, proxy, ASA, and syslog schemas broadly parser-friendly and praised cross-source upload accounting. Their strongest finding was repeated backward movement of visible Linux `sshd` connection child PIDs on the same host without PID wrap, especially on `WEB-EXT-01`, `DB-PROD-01`, `APP-INT-01`, and `PROXY-01`.

Network Forensics assessed the data as synthetic with 72 synthetic-confidence. They found Zeek UID/FUID correlation, DNS/proxy/TLS/firewall alignment, DHCP renewals, and inbound internet noise convincing. Their top hard contradiction was a Snort TLS handshake-failure alert for a flow that Zeek rendered as `conn_state:"SF"` with `ssl.established:true`, plus Rapid POP3 threshold alerts unsupported by visible POP3 flow volume.

Host/EDR Forensics assessed the data as synthetic with 72 synthetic-confidence. They found process trees, logon lifecycles, PsExec artifacts, DC account changes, and Linux SSH/PAM records internally plausible. Their top endpoint findings were uniform Windows `\device\harddiskvolume1\...` 5156 application paths, SearchProtocolHost command lines containing SIDs outside the observed domain SID namespace, and missing file-drop evidence for `DeviceSyncSvc.exe`.

## Prioritized Improvements

| Priority | Issue | Reviewer rating(s) | Score impact | Description |
| --- | --- | --- | --- | --- |
| P0 | Snort TLS failure contradicts established Zeek SSL | Network P0 | High | Snort reports `ET INFO TLS Handshake Failure` for `145.78.103.167:58172 -> 203.14.220.10:443`, while Zeek shows the same flow as successful TLS with `conn_state:"SF"`, `established:true`, `resumed:true`, and a negotiated cipher. Fix at the canonical IDS/network event layer so alert semantics agree with the rendered protocol state. |
| P1 | Linux `sshd` child PIDs move backward per host | Detection P1 | High | Visible new SSH initiator records repeatedly use lower child PIDs after higher child PIDs on the same host, without reboot or plausible PID wrap. Fix Linux daemon/session PID allocation so sshd connection children are host-local, time-ordered, and only reuse after realistic wrap/reboot conditions. |
| P1 | OEM updater traffic is not bound to host/software inventory | Threat P1 | High | Proxy records pair Dell domains with HP/Lenovo updater UAs, Lenovo URLs with Dell Command Update, and HP CAB paths with Dell updater UAs. Bind updater domains, paths, and User-Agents to a per-host OEM/software inventory rather than drawing request fields independently. |
| P1 | Endpoint source-native identity templates | Host P1/P1 | Medium | WFP 5156 `Application` values always use `\device\harddiskvolume1\...`, and SearchProtocolHost command lines include profile SIDs outside the observed account SID namespace. Vary NT device volume mappings by host and make SearchIndexer profile SID tokens come from known local/domain identities. |
| P2 | Threshold IDS alerts lack supporting visible volume | Network P1 | Medium | Rapid POP3 alerts fire where Zeek shows only one visible POP3 connection from each source. Threshold-style IDS events should either emit supporting flows or use alert names that do not imply a volume condition. |
| P2 | Shell typo/history and attacker flow still feel curated | Threat P2/P3, Host P3, Detection P2/P3 | Medium | Bash typo commands are short, isolated, and spread broadly, while the attack path remains compact and highly legible. Replace typo sprinkling with user-specific command-history sequences and add more operator hesitation, retries, access denials, and partial residue. |
| P3 | Large upload/exfil timing remains aggressive | Threat P3, Network P2 | Low | The packet accounting defect is fixed, but a 313 MB upload still completes in about 5-6 seconds. Consider stretching selected WAN/proxy exfil flows or adding congestion/segmentation artifacts. |

## Comparison With Quantitative Eval

Automated eval improved to `96.6267/100` across `77,465` parsed records. The hard Loop 139 probe verified zero large TCP reverse-ACK packet floor violations across six large uploads and five large downloads, so the previous large-transfer packet-count issue appears fixed.

The blind panel surfaced source-native and distributional issues that the quantitative eval does not currently score: Snort alert semantics versus Zeek protocol state, monotonic Linux `sshd` PID allocation, OEM updater inventory binding, and SearchProtocolHost SID provenance. These should drive Loop 140 because all four reviewers converged at 72 synthetic-confidence, indicating the prior obvious packet-accounting issue is gone but a new set of concrete authenticity tells is now visible.
