# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 94  
**Synthetic-Confidence Score:** 82

## Executive Summary

The records support useful investigations across endpoint, authentication, file-sharing, and network sources, with generally credible background volume and many coherent pivots. My verdict rests primarily on a visibly inverted SSH process lifecycle on NS-MAC-02, reinforced by repeated application-to-network attribution mismatches. These are specific record relationships, rather than judgments about how neatly suspicious activity forms a narrative.

## Evidence For Synthetic

- **[hard_contradiction] SSH processes execute before their own visible forks.** In `NS-MAC-02.northstar.example/ecar.json`, PID **45580**, object ID `54f5c1e1-773d-4259-8050-40ea65da994d`, executes `sshd-auth` at **15:07:59.799** and changes service credentials at **15:07:59.802** (lines **392–393**), but its `PROCESS/CREATE`, explicitly marked `operation:"fork"`, occurs at **15:08:01.165** (line **399**). PID **45591** drops privileges **688 ms before its fork**, and PID **45592** executes its shell **660 ms before its fork** (lines **395–402**). These are matching process identities with visible initiators inside the window.
- **[contract_gap] Process ownership repeatedly disagrees with the apparent network activity.** On NS-MAC-01, `docker images`, PID **7744**, owns a TLS connection whose SNI is `graph.microsoft.com`: endpoint line **96**, `office-span/conn.json:158`, and `office-span/ssl.json:56`. On NS-MAC-02, `docker ps`, PID **34165**, similarly owns an established TLS connection to `api.atlassian.com`: endpoint line **128**, connection line **287**, and SSL line **111**. Either could have an unusual explanation individually; their recurrence across simple local Docker inspection commands weakens the ownership model.
- **[contract_gap] Browser-style traffic is assigned to a Kubernetes CLI process.** NS-MAC-01 endpoint lines **218** and **220** assign both an established TLS connection with SNI `i.redd.it` and a subsequent OCSP request to PID **14466**, command `/opt/homebrew/bin/kubectl get pods`. The latter request carries a **Firefox/158.0** user agent (`office-span/http.json:7`). This combines command, process, tuple, TLS, and HTTP evidence; it is not an objection to whether a domain resolves publicly.
- **[weak_signal] Some shell-history timestamps disagree substantially with matching process starts.** NS-MAC-01’s `zsh_history/maya.chen.zsh_history:15` dates an `emacs -nw` invocation to **14:14:18**, while the matching visible process starts at **14:09:34.200** (`ecar.json:208`). The `nano` invocation also differs by about **22 seconds** (history line **12**, endpoint line **161**). These could reflect history processing or a separate unobserved invocation, so they receive little weight.

## Evidence For Real

- **A successful SSH pivot has credible transport, authentication, and shell ordering.** Maya’s client starts at **13:47:20.493** (`NS-MAC-01.northstar.example/ecar.json:156`). The corresponding network connection opens at **13:47:30.116**, tuple `10.42.0.11:57969 → 10.42.0.31:22`, UID `CRTWxzjBQ9CVpkDUpo` (`office-span/conn.json:264`). Linux syslog then records connection, public-key acceptance, and PAM session opening at **13:47:31.583**, **13:47:33.819**, and **13:47:33.938** (lines **119–121**), followed by the target shell at **13:47:35.091** (Linux endpoint line **143**).
- **SMB evidence agrees on direction, identity, path, and byte accounting.** UID `CVOCtOJ581SiLpeAg3` connects the Windows workstation to the Linux share server. `smb_files.json:2` records a read of **878,226 bytes**; `files.json:1` identifies the Linux server as transmitter and Windows as receiver; `conn.json:3` contains **880,920 responder bytes**, sufficient for the transfer plus protocol overhead. Linux endpoint line **11** attributes the corresponding server-side read to `smbd` acting for `nora.ellis`.
- **Credential boundaries are represented meaningfully.** Windows Security record **245384** records a Type **9** logon retaining local identity `nora.ellis` while setting outbound identity `nora.ellis-admin`. Linux syslog line **275** independently records successful authentication as `nora.ellis-admin`. This supports a realistic `/netonly` investigation.
- **Background traffic has variation and failure texture.** The 1,994 connection records include established connections, resets, rejects, unanswered SYNs, and partial states. **122** records report nonzero `missed_bytes`; source volumes and hourly activity differ among hosts.
- **The data is structurally usable.** All examined JSON lines parsed, endpoint event IDs were unique within each host, and my checks found no dependent process evidence after a matching visible termination.

## Detailed Analysis

### Environment and collection scope

The visible endpoint window runs approximately **2026-10-20 13:00:00–18:59:26 UTC**.

| Host | Apparent address | Log-supported role | Normalized endpoint records |
|---|---|---|---:|
| NS-MAC-01 | 10.42.0.11 | Developer workstation, primarily Maya | 939 |
| NS-MAC-02 | 10.42.0.12 | Developer workstation, primarily Owen | 938 |
| NS-WIN-01 | 10.42.0.21 | Development and administration workstation, primarily Nora | 2,068 |
| NS-BUILD-01 | 10.42.0.31 | Linux build and Samba server | 834 |

Additional addresses appear as external or infrastructure destinations; the evidence does not establish them as fully collected endpoints.

The dataset contains Windows Security and Sysmon XML, Linux syslog, normalized eCAR endpoint records, shell histories, two small Unified Log exports, and Zeek-style network/protocol records. The Unified Log exports contain one loginwindow entry per Mac. I treat that as selected coverage, without inferring a native macOS schema defect or requiring additional event families.

The overall source volume is believable for a selected six-hour collection from four hosts. I found no basis to penalize the dataset simply for being relatively small.

### SSH lifecycle coherence

The Windows-to-Mac SSH connection itself is plausible:

1. Windows endpoint line **1045** starts `ssh.exe owen.patel@NS-MAC-02.northstar.example`.
2. `office-span/conn.json:757` opens `10.42.0.21:54061 → 10.42.0.12:22` at **15:07:57.712**, UID `CKBTkWaa6k8MWPNsIB`.
3. Mac endpoint line **388** observes inbound transport at **15:07:57.980**.
4. Line **398** records successful SSH login as Owen at **15:08:01.164**.
5. Line **403** later creates `/usr/bin/uname -a` under the resulting shell.

The internal process construction is the decisive defect:

| Process | Dependent action | Timestamp | Visible fork | Inversion |
|---|---|---|---|---:|
| PID 45580 | Exec into `sshd-auth` | 15:07:59.799 | 15:08:01.165 | 1.366 s |
| PID 45591 | Drop privileges to UID 501 | 15:08:00.480 | 15:08:01.168 | 0.688 s |
| PID 45592 | Exec into `-zsh` | 15:08:00.505 | 15:08:01.165 | 0.660 s |

The matching object IDs and execution identities exclude ordinary PID reuse. A pre-window process cannot explain these relationships because each matching fork is explicitly visible.

A collector could deliver records out of order. Here, however, the contradiction is in the recorded timestamps, not merely file order, and there is no separate occurrence timestamp that restores causality. I therefore score the stream as presented, while acknowledging that an undocumented receipt-time interpretation would reduce the finding’s strength.

### Network ownership and pivot reliability

Tuple correlation is strong, but correct tuples do not guarantee correct process attribution.

The Docker examples and the `kubectl` example repeatedly attach browser or SaaS traffic to commands whose visible purpose does not explain those requests. The `kubectl` OCSP request is particularly useful evidence because its Firefox user agent provides an independent application-level clue.

These are plausibility and ownership defects, rather than proof that such programs could never contact unusual destinations. Wrappers, injected code, unusual configuration, and sanitization could explain individual cases. The recurrence across different programs and both Macs makes a systematic attribution problem more likely.

### Hunting conclusions and boundaries

NS-MAC-01 contains activity worth investigating: a release-manifest download, execution of `/usr/local/libexec/northstar-maintenance`, creation of `/Library/LaunchDaemons/com.northstar.assetcheck.plist`, and later execution of `northstar-assetcheck --once` (endpoint lines **100–104**, **598–600**, and **622**).

Those observations do **not** establish that the downloaded manifest executed, that the plist was registered or loaded, or that the later process was launched by that plist. I did not use the apparent compactness of this sequence as an authenticity indicator.

Likewise, SSH sessions beginning late in the slice need not have completed Zeek connection records before collection ends. Their absence alone is not a causality defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Mac normalized process telemetry | Three process identities in one SSH session | Largest contribution: exec and credential changes precede matching visible forks |
| `contract_gap` | Mac endpoint plus TLS/HTTP | Multiple commands across both Macs | Repeated implausible application ownership undermines process-to-network pivots |
| `weak_signal` | Zsh history versus endpoint | Three matching command examples | Small contribution because history handling or unobserved repetitions remain possible |

## Realism Score by Category

- **Field format accuracy:** 9 — Records parse cleanly and expose useful source-specific fields; no demonstrated broad formatting failure.
- **Temporal patterns:** 6 — Background timing varies credibly, but the SSH process lifecycle contains explicit inversions.
- **Cross-source correlation:** 7 — SSH and SMB joins work well; application ownership is less trustworthy than tuple alignment.
- **Behavioral realism:** 6 — Much developer and administrative activity is plausible, with recurring CLI-to-browser traffic mismatches.
- **Environmental consistency:** 8 — Host roles, account boundaries, and collection volume mostly fit the visible environment.

## Recommendations

- If this were synthetic, preserve **fork → credential change/job control → exec → child activity** ordering for each durable process identity.
- If timestamps represent collector receipt rather than occurrence, expose both meanings so an analyst can reconstruct causality.
- Assign network connections to the actual socket-owning process. Docker inspection commands and Kubernetes API queries should not inherit unrelated browser traffic.
- Generate HTTP user agents from the responsible application and its actual request path; review the Firefox OCSP request attributed to `kubectl`.
- Derive shell-history timestamps from the same command occurrence as endpoint execution, while explicitly modeling any history rewriting or duplicate suppression.
