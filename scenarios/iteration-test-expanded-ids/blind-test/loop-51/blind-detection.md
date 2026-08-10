# Assessment

Synthetic

# Verdict Confidence

82

# Synthetic-Confidence Score

68/100 — likely synthetic

# Executive Summary

The dataset is a strong synthetic corpus with unusually good source-native formatting, broad background texture, and mostly coherent cross-source correlation. The decisive concern is not its completeness or narrative clarity, but a concrete Windows lifecycle contradiction during the RDP sequence on `WS-AJOHNSON-01`: one Type 10 session produces two parallel `userinit.exe → explorer.exe` shell-init chains under the same Winlogon PID, Logon GUID, Logon ID, and terminal session within milliseconds. The attack PowerShell is also introduced under `services.exe` and the new interactive user token before either shell-init chain completes. These are ownership/lifecycle artifacts characteristic of two generation paths independently expanding the same session.

# Evidence For Synthetic

- **[Lifecycle / duplicate ownership]** At `2024-03-18 15:20:00–15:20:02`, `WS-AJOHNSON-01` records one 4624 Type 10 logon for `aisha.johnson`, Logon ID `0x2700aee`, Logon GUID `{47d9f745-42e3-4a6b-8f11-f16974effe6e}`, terminal session 4. It then emits two `userinit.exe` processes, PIDs 6624 and 6660, both parented by the same `winlogon.exe` PID 6604, followed by two `explorer.exe` processes, PIDs 6652 and 6676. Both branches carry the identical session identity. A normal single RDP session should not initialize two parallel user shells this way.
- **[Identity / execution ownership]** The same session creates PowerShell PID 6700 as `aisha.johnson`, but its parent is the long-running SYSTEM `services.exe` PID 4284. It appears before the duplicate `userinit.exe`/Explorer chains complete and becomes the parent of the tightly staged `whoami`, `net user`, `net group`, and `net view` discovery sequence. This is not a credible ordinary interactive process lineage absent explicit service or scheduled-task semantics.
- **[Cross-source persistence of artifact]** The duplicate shell-init defect is reproduced in ECAR, Security 4688, and Sysmon Event ID 1 rather than being a rendering typo in one source. That strongly suggests duplicated canonical activity expansion.
- **[Behavioral generation texture]** Linux background logs repeatedly use highly templated pseudo-operational messages such as frequent `systemd-resolved` cache-state changes and rsyslog queue/checkpoint status lines across hosts. Individually plausible, their repeated construction and wording feel pool-generated.
- **[Attack construction]** The malicious chain is mechanically staged into small, fully attributed steps—discovery, credential dumping, account creation, persistence, archive creation, database dump, SCP, history clearing, encoded PowerShell, log clearing, and cleanup. Narrative neatness alone is not evidence, but combined with the duplicate ownership defect it reinforces a deterministic action-expansion origin.

# Evidence For Real

- **[Schema]** Windows event provider names, channels, Event IDs, versions, tasks, keyword masks, native field names, hexadecimal PIDs, SIDs, and Logon IDs are broadly credible. All reviewed XML files are well formed.
- **[Protocol semantics]** Zeek connection records generally use plausible states, histories, packet/byte accounting, services, DNS fields, TLS versions/ciphers, certificate chains, OCSP records, and SMB file metadata.
- **[Cross-source correlation]** SSH transport, authentication, PAM session creation, shell creation, and close behavior align well among Zeek, syslog, and ECAR. Proxy CONNECT/control-message records are sensibly separated from tunneled HTTPS requests.
- **[Background diversity]** The corpus includes ordinary Kerberos, SMB, DHCP renewal, mail, package-management, browser, service-health, administrative SSH, web scanning, firewall, and endpoint activity with variable timing and counts.
- **[Observation realism]** The dataset contains failed authentication, blocked external scans, unanswered DNS records, partial lifecycles at the capture boundary, source-specific timing offsets, and uneven source coverage. Those imperfections favor realism.

# Detailed Analysis

- **Schema and rule semantics:** Strong overall. Windows Security and Sysmon records use appropriate providers and broadly correct event-specific fields. Zeek JSON and RFC 5424-like syslog are consistently parseable. No verdict was based on absent event families.
- **Identity semantics:** Most Logon IDs, process UUIDs/GUIDs, PIDs, SSH tuples, users, and host addresses correlate correctly. The RDP duplicate initialization is therefore particularly salient: it is not random background corruption, but two complete process branches bound to exactly the same session identity.
- **Lifecycle semantics:** SSH sessions and many process create/terminate pairs are credible. Capture-boundary closures without visible opens were treated as valid. The RDP session is the main failure: duplicate `userinit` and Explorer instances imply competing lifecycle owners.
- **Temporal semantics:** Network-before-auth and auth-before-shell timing is generally plausible, with reasonable source-observation offsets. The RDP PowerShell lineage is temporally and causally strained because a service-owned process begins the interactive discovery before normal shell initialization.
- **Network and application semantics:** DNS, proxy, TLS, SMTP, firewall, web, and IDS records show good diversity and correlation. No invalid reliance was placed on sanitized domains or complete narrative correlation.
- **Behavioral realism:** The baseline is substantially more convincing than a simple random log generator. Nevertheless, repeated reusable message families and the almost storyboard-like malicious sequence expose generation structure once combined with the lifecycle defect.

# Synthetic Indicator Summary

- High: Duplicate RDP `userinit.exe → explorer.exe` chains for one Logon ID/GUID/session.
- High: Interactive attacker PowerShell attributed to a user token but parented by SYSTEM `services.exe`, preceding normal shell readiness.
- Medium: The same duplicate lifecycle survives across three endpoint representations.
- Low–Medium: Recurrent pool-like Linux operational-message wording.
- Low: Highly staged attack sequencing; supporting only, not independently dispositive.

# Realism Categories

1. Schema and source-native formatting: 8/10
2. Cross-source correlation and identity: 8/10
3. Temporal and causal behavior: 7/10
4. Entity and lifecycle semantics: 5/10
5. Background and behavioral realism: 7/10

# Recommendations

- Ensure one and only one owner expands each RDP session into `winlogon → userinit → explorer`; reject duplicate shell initialization for the same host, Logon ID, Logon GUID, and terminal session.
- Anchor interactive attack commands to a credible shell parent, or explicitly model the service/task/WMI mechanism that creates them. Do not simply assign a user token to a child of `services.exe`.
- Add invariant checks for duplicate session-bootstrap roles and for process creation before session shell readiness.
- Expand Linux background messages from verified daemon-native templates and correlate messages to actual state transitions rather than independently sampled text.
- Preserve the existing strong protocol and cross-source correlation while introducing more organically incomplete or incidental malicious evidence after lifecycle correctness is fixed.
