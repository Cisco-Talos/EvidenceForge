# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 95  
**Synthetic-Confidence Score:** 92

## Executive Summary

The endpoint telemetry is unusually strong in schema fidelity, source-to-source correlation, and causal ordering, but several dataset-wide artifacts reveal synthetic construction. The strongest findings are binary hashes apparently derived from usernames or installation paths rather than file content, escaped Windows path separators leaking into native command lines, and implausible service-process concurrency on the Exchange host.

## Evidence For Synthetic

- `[hard_contradiction]` Identical application releases have different SHA1, MD5, SHA256, and IMPHASH values on each user’s workstation. For example, Slack 4.38.125 has five distinct complete hash sets on five hosts, while the executable’s version, description, product, company, and original filename are identical. The same pattern affects `Slack_elf.dll`, Zoom 6.0.11.39959, `zVideoApp.dll`, Teams, and OneDrive. Vendor rebuilds can occasionally preserve a version number, but repeated per-user divergence—including IMPHASH—across several unrelated products is a generator-like content-identity leak.

- `[hard_contradiction]` `winlogon.exe` and `userinit.exe` have identical hashes across hosts representing multiple Windows builds, while other Microsoft binaries correctly vary by operating-system build. All 26 records also have `-` for every PE metadata field. For example, every `userinit.exe` instance has SHA256 `91665FC0325F4DE548C15AAFB5C01CD83C3A50136038AE6B7BB2DC31330399A9`, despite neighboring system binaries indicating builds 17763, 19041, 20348, and 22621.

- `[schema_or_format]` MAIL-FIN process command lines contain literal doubled separators in local drive paths. At `2024-03-18T12:10:55.4333864Z`, Sysmon records the image as `C:\Program Files\Microsoft\Exchange Server\V15\Bin\Microsoft.Exchange.Imap4.exe` but the command line as `"C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\Microsoft.Exchange.Imap4.exe"`. This occurs systematically in 17 IMAP4 and 14 EdgeTransport process creations and propagates through Security, Sysmon, and eCAR.

- `[contract_gap]` MAIL-FIN shows implausible long-running concurrency among what should normally be singleton Exchange service processes. EdgeTransport PID 3588 runs from `12:24:18.123Z` to `13:02:07.193Z`, while PID 3500 starts at `12:30:26.981Z` and remains until `14:58:28.789Z`. Later, PID 4148 and PID 4160 overlap for more than an hour. The host records 14 EdgeTransport and 17 IMAP4 starts in six hours, with several established overlaps lasting tens of minutes.

- `[contract_gap]` All six visible `TiWorker.exe` starts use `svchost.exe -k netsvcs` as their immediate parent, including WS-AJOHNSON at `2024-03-18T12:04:28.8807785Z` and DC-01 at `12:14:04.695Z`. The expected Windows Modules Installer/`TrustedInstaller.exe` process layer is absent from every repeated chain.

- `[distribution_texture]` Ten Linux hosts produce 470 `snapd` records using the same six-package vocabulary—`core20`, `core22`, `lxd`, `microk8s`, `snapd-desktop-integration`, and related snapd activity—across highly dissimilar mail, proxy, database, web, file, monitoring, application, and workstation roles.

- `[environment_or_collection_plausibility]` The Linux fleet also emits 492 `irqbalance` messages using essentially the same mixed hardware vocabulary (`ens160`, `ens192`, `mlx5_comp*`, `nvme0q*`, `ahci`, and `virtio-input`) on otherwise unrelated systems. This looks more like a shared record pool than observations from distinct hardware profiles.

## Evidence For Real

- Security 4688, Sysmon Event 1, and eCAR PROCESS/CREATE records agree on image, command line, parent PID and image, principal, and logon identifier. Of 1,029 Security 4688 and 1,027 Sysmon Event 1 records, 1,024 matched within 1.2 seconds without a field-level contradiction.

- Cross-source delays are realistic rather than bit-identical. Security-to-Sysmon median delays vary by host from approximately 121–163 milliseconds, while Sysmon-to-eCAR delays range from approximately 128–225 milliseconds.

- No visible process lifecycle inversion was found. Sysmon children with visible parent creations occur after their parent, no parent visibly terminates before its dependent child, and no Sysmon Event 5 precedes the corresponding visible Event 1.

- eCAR actor relationships are similarly coherent: no dependent record precedes the visible actor creation, and no actor visibly terminates before its dependent activity.

- Windows logon types are appropriately mixed by host role. Workstations contain interactive, network, service, unlock, new-credential, and remote-interactive logons; domain controllers are dominated by service and network activity. No same-identifier 4634 logoff precedes a visible 4624 logon.

- Linux SSH telemetry has credible sequencing: transport arrival, authentication several seconds later, PAM opening within hundreds of milliseconds, and systemd-logind session creation shortly afterward. Key fingerprints remain consistent for the same users across destinations.

- User behavior is role-aware. Lina Nguyen’s workstation contains development tools, Git, npm, Docker, editors, and support-bundle activity; database and infrastructure users show SQL, service-management, and journal-inspection commands rather than sharing one universal command sequence.

- Windows process trees are usually plausible: Explorer launches user applications, `csrss.exe` launches console hosts, services originate from `services.exe`, and browser subprocesses descend from their expected browser parents.

- The data contains source-native operational texture such as Defender activity, Windows Update components, SearchIndexer/SearchFilterHost, Group Policy processing, scheduled tasks, SMB auditing on FILE-SRV-01, mail services on Linux mail hosts, and UFW activity on WEB-EXT.

- DC-01 contains a credible Security log-clear event: Event 1102 at `2024-03-18T17:42:26.1855251Z`, followed by an EventRecordID reset from 28,261,376 to 1 with SYSTEM as the subject.

## Detailed Analysis

### Binary identity and PE metadata

The most consequential defect is the treatment of binary identity. Sysmon hashes are internally stable for a given image path on one host, but they are not stable for apparently identical binary content across hosts.

Slack 4.38.125 illustrates the pattern:

- WS-AJOHNSON, `2024-03-18T13:04:20.4722059Z`: SHA256 `31CDFFAACC8CAF640722A78AAF76B801937EFAF7D469EF0A8842ED9C0F50D93F`, IMPHASH `181DD27DB1F11D9480F391825E3EFCF9`.
- WS-DRAMIREZ, `14:25:20.6389561Z`: SHA256 ending `D11426A`, with a different IMPHASH.
- WS-MCHEN, `16:07:34.7496372Z`: SHA256 ending `537B84`, with a third IMPHASH.
- WS-PPATEL, `16:33:38.7427319Z`: SHA256 ending `3798D`, with a fourth IMPHASH.
- WS-SMARTINEZ, `14:31:43.2990442Z`: SHA256 ending `90F3`, with a fifth IMPHASH.

All five identify the same version, product, company, description, and original filename. `Slack_elf.dll` repeats the same five-way divergence. Zoom 6.0.11.39959 and `zVideoApp.dll` likewise produce three workstation-specific hash sets.

A real vendor could publish distinct binaries under an unchanged display version, but the repeated relationship between installation user/path and every hash algorithm is not credible across this many products. IMPHASH divergence is especially important because it implies different PE import structures, not merely signing timestamps or mutable overlay data.

The inverse problem appears in core Windows binaries. `winlogon.exe` and `userinit.exe` have the same respective hash on hosts whose other system binaries demonstrate four different Windows build families. Their PE version metadata is entirely absent, while `explorer.exe`, `cmd.exe`, `conhost.exe`, `svchost.exe`, and `taskhostw.exe` correctly vary by build. Together, these patterns indicate synthetic hash and metadata assignment rather than observed file content.

### Native command-line representation

MAIL-FIN repeatedly leaks escaped path notation into process command lines. The image fields contain normal Windows paths, but Security 4688, Sysmon Event 1, and eCAR retain `\\` between every local path component for Exchange IMAP4 and EdgeTransport.

This is not a question of XML escaping: backslash is not an XML escape character, and the parsed field value still contains the duplicate characters. It is also distinguishable from legitimate UNC paths, which account for four other doubled-separator command lines. The affected Exchange strings begin with a drive letter and duplicate every separator.

Because the same malformed value propagates through three source families, the likely defect is in canonical event construction rather than one renderer. The records correlate perfectly, but they correlate around an implausible source value.

### Process trees and service lifecycle

Most process trees are structurally convincing. Explorer-launched Office, browser, VPN, and administrative programs match workstation use; console programs generally have `conhost.exe`; and service applications descend from `services.exe`.

MAIL-FIN is the principal exception. Thirty-one Exchange service starts occur during the six-hour window, with multiple long overlaps visible between both creation and termination events. This is not based on processes extending beyond the collection boundary: several overlap intervals are completely established inside the window. Ordinary service recycling can briefly overlap old and new workers, but the repeated 30–90 minute overlaps and accumulation of additional instances are inconsistent with normal singleton Exchange service behavior.

The `TiWorker.exe` chains are another repeated modeling weakness. Six unrelated hosts show the same direct `svchost.exe -k netsvcs` parent and no `TrustedInstaller.exe` layer. One anomalous chain could result from partial visibility, but identical treatment on all six visible instances makes collection loss a weak explanation.

### Windows logon and system activity

The Windows logon mix is broadly realistic. WS-AJOHNSON, for example, includes service, network, remote-interactive, local-interactive, new-credential, and unlock logons. Other workstations show comparable but non-identical mixtures, while the domain controllers emphasize service and network activity.

No impossible visible session ordering was identified. Fixed system logon identifiers such as `0x3e7`, `0x3e5`, and `0x3e4` are reused in source-native ways. Sessions or processes without visible initiators were not penalized because the collection is explicitly a slice rather than boot-to-shutdown telemetry.

The systems also have credible background activity: Defender, Windows Update, scheduled tasks, Group Policy, indexing, service activity, and SMB auditing are represented. EventRecordID gaps and the DC-01 Event 1102/reset are particularly convincing operational details.

### Sysmon, Security, and eCAR correlation

The three endpoint families exhibit strong semantic correlation without impossible ordering. Of 1,027 Sysmon Event 1 records, 1,018 match an eCAR PROCESS/CREATE record; the matched records agree on process and parent identity, command line, user, and session context.

The small number of unmatched records is consistent with ordinary observation loss. Source delays also vary by host and source family rather than collapsing onto one global constant. Process termination and actor-reference checks found no visible dependent event after its actor had already terminated.

This materially improves the dataset’s realism. It does not offset the hash and command-line contradictions, however: correct correlation demonstrates that the sources share canonical state, while the defects show that some canonical state was generated incorrectly.

### Linux endpoint evidence

The SSH evidence is one of the strongest portions of the dataset. Successful sessions have reasonable transport-to-authentication delays, PAM and systemd-logind ordering, stable user key fingerprints, and coherent close activity. Syslog content is also differentiated by role: file servers show SMB activity, mail systems show Postfix and Dovecot, and the exposed web system records UFW events.

Bash histories are substantially role-specific. Developer, database, and infrastructure accounts use distinct toolsets, and bash-to-eCAR command delays differ by host. For example, APP-INT matched commands at a median offset of approximately 1.68 seconds, DB-PROD at 1.25 seconds, and FILE-LNX at 2.58 seconds. These host-specific offsets look like collection latency rather than timestamp cloning.

The fleet-wide daemon texture is less credible. Ten machines share the same narrow Snap package catalog despite sharply different roles, and the `irqbalance` messages repeatedly draw from one mixed device-name pool. The issue is not merely high or low syslog coverage; it is the repetition of software and hardware vocabulary where heterogeneous hosts should differ.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Sysmon process creation/image load | Slack, Zoom, Teams, OneDrive, and associated DLLs across multiple workstations | Different full hash sets, including IMPHASH, for identical release metadata strongly indicate path- or user-derived synthetic hashes. |
| `hard_contradiction` | Sysmon PE metadata | `winlogon.exe` and `userinit.exe` across four apparent Windows build families | Identical hashes and blank PE metadata conflict with the build-specific variation correctly shown by neighboring system binaries. |
| `schema_or_format` | Security, Sysmon, eCAR | 31 MAIL-FIN Exchange process starts; 43 affected eCAR records | Literal JSON/YAML-style doubled separators leaked into native local Windows command lines. |
| `contract_gap` | Sysmon/eCAR process lifecycle | MAIL-FIN Exchange services | Numerous long-lived overlapping IMAP4 and EdgeTransport instances violate plausible service cardinality and recycle behavior. |
| `contract_gap` | Sysmon process lineage | Six Windows hosts | Every visible `TiWorker.exe` has the same simplified `svchost.exe` parent chain with no TrustedInstaller layer. |
| `distribution_texture` | Linux syslog | Ten hosts, 470 snapd records | One six-package vocabulary is reused across heterogeneous server and workstation roles. |
| `environment_or_collection_plausibility` | Linux syslog | Eleven hosts, 492 irqbalance records | Unrelated systems repeatedly expose the same mixed network, NVMe, AHCI, Mellanox, and virtual-device vocabulary. |

## Realism Score by Category

- **Field format accuracy:** 6/10 — Most Security, Sysmon, syslog, and eCAR structures are convincing, but escaped local paths and impossible binary-identity behavior are substantial defects.
- **Temporal patterns:** 7/10 — Source delays and same-identifier lifecycles are coherent, but Exchange process churn and sustained service overlap are implausible.
- **Cross-source correlation:** 9/10 — Security, Sysmon, and eCAR agree closely without visible causal inversions, while preserving realistic source-specific delay and occasional loss.
- **Behavioral realism:** 6/10 — User, administrator, SSH, and background-system behavior are role-aware, but several service and fleet-wide daemon patterns remain generator-like.
- **Environmental consistency:** 5/10 — Host-specific roles are visible, but cross-build system-file identity and the shared Linux software/hardware vocabulary undermine the modeled environment.

## Recommendations

- If this were synthetic, derive hashes from a canonical binary artifact identity, not from host, username, or installation path. Exact release binaries should share hashes; Windows system binaries should vary with the modeled OS build.

- Validate PE metadata and hashes as one atomic profile. Known Microsoft and third-party executables should either receive internally consistent version resources or be omitted according to a modeled collection policy.

- Preserve command-line values as raw native strings through canonical event construction and rendering. Add validation that rejects doubled separators in drive-letter paths while allowing genuine UNC paths.

- Model service cardinality and recycling explicitly. Exchange service replacements should have bounded handoff overlap, a plausible reason for restart, and one active long-lived instance after the transition.

- Route Windows servicing through a realistic TrustedInstaller process chain when generating `TiWorker.exe`, with partial visibility controlled by the collection profile rather than by removing the process layer everywhere.

- Bind Snap packages and daemon activity to each host’s role and installed-software inventory. Server roles should not inherit desktop integration, LXD, or MicroK8s activity unless those packages are explicitly installed.

- Give each Linux host a stable hardware profile and derive `irqbalance` device messages from it. Also model daemon verbosity per host so unrelated machines do not emit the same diagnostic vocabulary at similar volumes.
