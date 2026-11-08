# Mac background process research

Reviewed November 6, 2026 against the existing macOS 27 arm64 catalog. The aim is
to add a useful, bounded background population, with operational ownership and
native evidence that agree. The catalog currently has 48 application IDs without
the `macos-` prefix, plus the OS, terminal, SSH and native helper entries below.
This is a research/implementation decision record, separate from the deferred
public documentation revision pass.

## OS families worth including

Apple distinguishes systemwide daemons, per-user agents, app-scoped XPC services
and children directly launched by an app. Launchd manages on-demand XPC services;
these are not uniformly children of the requesting application. Lifetime and
privilege isolation are part of the model, not optional process-tree decoration.
See [Apple XPC](https://developer.apple.com/documentation/XPC),
[daemon lifecycle](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Lifecycle.html)
and [background item management](https://support.apple.com/en-gb/guide/deployment/depdca572563/web).

| Family | Existing catalog candidates | Trigger and owner to model | First-slice value |
| --- | --- | --- | --- |
| Desktop session | Finder, Dock, WindowServer, usernoted | GUI login and logout, with separate user/system identities; resident processes often predate collection | High: makes an ordinary desktop environment recognizable |
| Preferences and IPC | cfprefsd, distnoted, launchservicesd, runningboardd | User/application demand and service lifetime; do not create one new daemon per app launch | High: common shared services and correct ancestry |
| Network and trust | mDNSResponder, configd, trustd, securityd, nsurlsessiond, apsd | DNS, network configuration, trust evaluation, background transfer and push activity; consumers must reuse the actual service instance | High, especially when tied to existing network actions |
| Indexing | mds, corespotlightd, mdworker_shared | Existing or newly changed file populations, bounded worker jobs, backpressure and idle retirement | High for file-oriented exercises; avoid a worker for every file operation |
| Audio and sharing | coreaudiod, sharingd | Audio-device/session use and explicitly enabled sharing features | Medium; only when those activities are modeled |
| Installation and policy | installd, smd, tccd, syspolicyd | Explicit installation, service-management, privacy or policy activity | Conditional; ordinary idle noise must not imply an installation or policy decision |

These names already have catalog paths, but catalog presence does not establish
native start/exit qualification. User principals, launch domain, audit origin,
static image/signature, runtime outcome, descriptors and known terminal cause
must be supplied through canonical owners before enabling in-window ES starts.
Pre-existing inventory and an observable startup are different cases.

Background transfers are a particularly useful ownership case: Apple's
[URLSession documentation](https://developer.apple.com/documentation/foundation/downloading-files-in-the-background)
describes a separate process performing a background transfer. That supports a
service-owned transport model, not blindly assigning every app transfer to the
foreground main process. Platform-specific details still need qualification.

## Application catalog inventory

The table covers every current non-OS Mac application ID. Candidate roles are
research targets, not a claim that every listed helper is already qualified for
the selected installed build. A framework's general architecture does not prove
an individual product's executable path, signature, argv or helper count.

| Catalog IDs | Candidate background work | Evidence and implementation boundary |
| --- | --- | --- |
| `chrome`, `edge` | Browser main, renderers, GPU, network/utility and crash reporting | [Chromium process architecture](https://www.chromium.org/developers/design-documents/multi-process-architecture/), [user-data roots](https://github.com/chromium/chromium/blob/main/docs/user_data_dir.md). Reuse one main per executable/user-data root; separate profiles within that root do not justify additional persistent mains. Existing Chrome renderer/GPU/network contracts are the immediate safe surface. Edge needs its own helpers and installed metadata. |
| `firefox`, `thunderbird` | Content, socket/network, media/data-decoder and utility roles | [Mozilla process model](https://firefox-source-docs.mozilla.org/dom/ipc/process_model.html). Firefox architecture is primary evidence for Firefox; Thunderbird's exact enabled roles need its own build check. Do not copy Chrome arguments or helper signatures. |
| `vscode` | Renderer, extension host, shared/file-watcher/PTY services, language servers and debugger children when used | [VS Code extension hosts](https://code.visualstudio.com/api/advanced-topics/extension-host) and [remote placement](https://code.visualstudio.com/api/advanced-topics/remote-extensions). Remote extension hosts run on the remote machine. Extension-specific children require a declared workspace/tool deployment. |
| `slack`, `postman` | Renderer/GPU/network/utility roles, optional updater/crash reporter | [Electron process model](https://www.electronjs.org/docs/latest/tutorial/process-model), [utility processes](https://www.electronjs.org/docs/latest/api/utility-process), [Slack engineering](https://slack.engineering/building-hybrid-applications-with-electron/). The Slack article establishes helper usage historically, not current per-workspace counts. Postman's exact framework/build is still a product-specific qualification item. |
| `teams`, `zoom`, `webex` | Meeting/media, screen-sharing, web-content and update roles | Product/build/component-specific research remains necessary. Do not assume all three use the same Electron/CEF tree, that Windows helper names exist on Mac, or that a native app must advertise Chrome/Edge/Firefox on every request. |
| `outlook`, `word`, `excel` | Shared update/licensing services and optional web/document services | [Microsoft AutoUpdate deployment](https://learn.microsoft.com/en-us/microsoft-365-apps/mac/deploy-updates-for-office-for-mac), [licensing helper](https://learn.microsoft.com/microsoft-365-apps/mac/licensing-helper-tool). Installation channel matters: the licensing helper is not used for Mac App Store installations. A shared updater should not be recreated as an app child on every launch. |
| `acrobat` | CEF services, collaboration, update and licensing work | [Adobe background process guidance](https://helpx.adobe.com/sg/acrobat/desktop/troubleshoot/performance-issues/app-process-errors.html). Select exact Acrobat/Reader product and Mac build; do not reuse Windows `.exe` templates. |
| `onedrive`, `dropbox`, `google_drive_desktop` | Sync engine, File Provider extension, updater and Finder integration when installed | [Apple File Providers](https://support.apple.com/en-ca/guide/deployment/dep4acafe8a7/web), [Google Drive on Mac](https://support.google.com/drive/answer/12178485), [OneDrive distributions](https://support.microsoft.com/en-us/onedrive/why-do-i-have-two-versions-of-onedrive-on-my-mac). Installation channel and enabled provider determine identities. Dropbox's exact selected-build executables remain to be qualified independently. |
| `docker` | Desktop backend, VM/VMM, network forwarding and version-dependent privileged helpers | [Docker permissions](https://docs.docker.com/desktop/setup/install/mac-permission-requirements/), [networking](https://docs.docker.com/desktop/features/networking/). The existing catalog executable is the Docker CLI. Desktop installation/running state is an additional dependency; Linux containers and daemons must not appear as Mac host processes. Privileged helper behavior is version-dependent. |
| `cisco_secure_client`, `globalprotect`, `citrix_workspace` | Separate UI, agent/service, optional network/system extension and authentication components | [Cisco Mac changes](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1/b-cisco-secure-client-admin-guide-5-1_appendix1.pdf), [GlobalProtect Mac directory structure](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNPbCAO). Vendor service/module enablement matters. Citrix's exact helper inventory remains open. A GUI launch does not establish a connected VPN or remote desktop session. |
| `intellij`, `sublimetext`, `dbeaver`, `tableau_desktop` | Conditional file watcher/JCEF, plugin host, database/extract or external-tool work | [JetBrains file watcher](https://support.jetbrains.com/hc/en-us/articles/40482569261202-Compiling-File-Watcher), [Sublime plugin host](https://www.sublimetext.com/docs/api_reference.html). The file-watcher reference documents Linux and cannot qualify a Mac executable. Do not invent an external Java child just because an app uses a JVM. DBeaver/Tableau exact child sets need product/build/workflow qualification. |
| `msbuild`, `dotnet`, `nodejs`, `npm`, `pytest`, `pip` | Build workers, test children, script processes and package work only for matching commands | The installed runtime owns module execution. `dotnet --info`, Python `-m pip --version`, npm version queries and pytest version queries do not imply a build, package installation or generic worker tree. Existing bounded query semantics stay authoritative. |
| `git`, `ssh`, `curl`, `kubectl`, `sqlcmd`, `mysql`, `psql`, `redis_cli`, `powershell_query`, `ldapsearch` | Transport, credential, SSH/proxy or external-command children only when actual intent needs them | Literal command and canonical network/session contracts decide effects. Do not spawn sshd for a client version query, a remote shell for every network connection, or a second native runtime merely because it is used internally. Existing Apple SSH has a separately qualified native chain; Homebrew SSH is a different installation. |
| `7zip`, `vim`, `nano`, `emacs`, `make`, `gcc`, `cargo` | Optional editor plugins, shell/tool stages, compilers/linkers, test executables or archive work | Execution plans and actual commands govern child activity. Help/version invocations and simple edits do not justify a generic build tree. Exact installed helpers and command outcomes remain required. |

Native catalog additions such as Safari, Finder, Terminal, iTerm2, login, zsh,
Bash, the collector and Apple SSH are covered separately from those 48 IDs.
Safari's web-content/network/GPU roles follow
[WebKit's multiprocess model](https://docs.webkit.org/Getting%20Started/Introduction.html)
but require the selected Mac build's own executable/launch facts; Cryptex paths
must not be guessed. Existing Terminal/iTerm2 and SSH startup graphs remain
separate qualified contracts.

## Concrete vendor findings and version boundaries

- Zoom's [Mac allowlist](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0058758)
  names `CptHost`, `airhost`, `aomhost`, `ZoomAutoUpdater` and distinct CEF helper
  bundles, including GPU and renderer roles. It also distinguishes Workplace,
  Rooms and VDI, and explicitly limits one CEF plugin layout to versions
  6.5.0–7.0.5. These are useful component leads. The list does not establish which
  components a simple app launch starts, their exact executable argv, or native
  ownership for our selected release. Do not turn the whole allowlist into a
  startup tree.
- Dropbox explicitly identifies `DropboxMacUpdate` and `Dropbox Web Helper` in
  its [Mac process guidance](https://help.dropbox.com/installs/configuring-firewall).
  Its [updater documentation](https://help.dropbox.com/installs/update-mac) says
  update checks can run while the main app is closed, and applying an update
  waits until the user finishes a task. This makes a shared scheduled updater
  model more appropriate than a child on every application launch. Exact launch
  registration and current installed metadata remain open.
- Citrix's [Mac background-item guidance](https://support.citrix.com/external/article?articleUrl=CTX691439-citrix-workspace-for-mac-does-not-function-with-background-elements-are-disabled&language=en_US)
  identifies `Citrix Workspace Helper` and connects login items to account,
  session-launch and update functionality. Model enabled login items separately
  from the GUI. Its [authentication documentation](https://docs.citrix.com/us/en/citrix-workspace-app-for-mac/security-authentication/authenticate.html)
  also distinguishes app, embedded-webview and system-browser requests; one
  application-wide inferred User-Agent would lose that distinction.
- Microsoft's [architecture account](https://techcommunity.microsoft.com/blog/microsoftteamsblog/microsoft-teams-advantages-of-the-new-architecture/3775704)
  distinguishes classic Electron Teams from the new WebView2 architecture, but
  describes Windows first and future Mac support. It cannot alone qualify the
  current Mac helper tree. The [Mac deployment guide](https://learn.microsoft.com/en-us/microsoftteams/teams-client-mac-install-prerequisites)
  does not fill that native-process gap. Keep current Mac module/helper paths
  unqualified rather than importing classic or Windows process templates.
- Tableau's [Hyper API](https://tableau.github.io/hyper-db/docs/hyper-api/hyper_process/)
  documents `hyperd` as a separate local database process, recommends reusing it
  across operations, and exposes explicit shutdown. That supports a bounded
  extract/database-work owner, but is not proof that every Tableau Desktop launch
  creates it. DBeaver's [Mac command-line documentation](https://dbeaver.com/docs/dbeaver/Command-Line/)
  identifies its app executable; bundled Java does not by itself establish a
  separate `java` child.
- Cisco's older [Webex Meetings deployment guide](https://www.cisco.com/c/dam/en/us/td/docs/collaboration/webex_centers/esp/cisco_webex_meetings_it_administrator_mass_deployment_guide.pdf)
  names the Productivity Tools `com.webex.pluginagent` login agent. That is an
  older optional product component, not qualification for today's Webex app.
  Current Webex app helpers remain an explicit research gap.

## Recommended finite inclusion sequence

1. Repair resident browser ownership and reuse the qualified Chrome helper roles.
   Reopening a window may create a renderer, but must not manufacture another
   persistent main/GPU/network startup tree. Preserve exact parent/session identity,
   filtering and recovery. This is the immediate implementation slice.
2. Extend the already qualified Finder chain with one small OS set: Dock, shared
   preferences, and DNS/trust services. Start with explicit pre-window resident
   inventory and one measured on-demand lifecycle. Share services across requesting
   apps; bind their existing actions rather than adding timer-driven arbitrary
   process churn. Existing Finder qualification does not qualify these siblings.
3. Qualify one Electron-family app, preferably VS Code for its developer coverage
   and documented extension-host ownership. Use its own public static helper images
   and one bounded launch/close reference. Additional language servers and tool
   children require the corresponding workspace/deployment. Keep updater and
   privileged-service ownership separate. Framework similarity is a reusable
   contract lead, not signature proof; Slack is a useful subsequent sibling.
4. Add one sync/File Provider or updater family when the scenario actually models
   that installation and operation. VPN/media/VM families have higher dependency
   and attribution costs and should follow those first additions.

Before enabling a new native family, define its trigger, exact deployment,
parent/responsible/audit/principal ownership, fork/exec sequence, FD/env facts,
completion and observation policy. Use existing canonical owners and data-driven
profiles; retain unsupported facts as explicit blockers. No additional personal
log inspection or native collection was performed for this research.

## November 6 implementation boundary

The bounded Code slice now selects **1.143.0** for the Mac catalog, matching the
independent reference host. It qualifies the main's existing xpcproxy application
launch mechanism and three direct generic-helper roles: GPU, network service and
shared Node process. Static signing identifiers, Microsoft team and entitlements
were independently read from those selected installed public binaries. The two
saved controlled runs supply runtime validation/descriptor observations. Native
hashes, inode values and UUIDs remain modeled release/host identities.

The Node shared process selects its actual `VSCODE_ESM_ENTRYPOINT` role through
canonical environment policy. Its stdin is a vnode; stdout/stderr use two distinct
State-allocated pipes at descriptors 1/2, with last_fd 2. The sandbox roles retain
vnode standards plus one explicit pipe; selected slots 21/29 are simulation policy,
not a universal claim about Code. GPU/network/shared roles are resident children
of the exact main and are reused on repeat activity. Counts/delays remain nominal
spawn policy. The renderer's higher descriptor layout, extension hosts, watcher,
agent/PTY roles, two unclassified descendants and terminal-result generalization
remain excluded. This is useful qualified coverage, not a whole-Code graph claim.

The initial OS slice seeds one shared **root cfprefsd daemon** and one shared
**root launchservicesd** through the existing boot inventory owner. A read-only
reference check confirmed their exact selected paths, launchd parent relationship
and root command classes; static signing metadata came from those public binaries.
Both exist before collection, reuse the same canonical identities across app
activity and use normal State/checkpoint/lifetime ownership. They add no periodic
noise and assert no observed startup, shutdown or runtime validation. Their native
execution outcomes remain unknown. Dock and the user cfprefsd/trustd instances,
mDNSResponder's service account and demand-driven activity remain separate work;
none is fabricated as a new child on each app launch.

Docker's host references remain preserved, but native Desktop family admission is
deferred. No further capture or open-ended helper expansion was performed for this
increment. The next native filesystem producer integration remains distinct from
catalog/background population expansion; see the follow-through worklog.
