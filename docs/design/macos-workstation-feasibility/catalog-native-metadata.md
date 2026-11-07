# Existing catalog launches: metadata and model boundaries

November 4, 2026. This closes concrete launch-owner/catalog defects found in the
user's MacOS-test workload. It does not qualify every catalog application or
reopen launchd Unified Log collection. Native records are not stored here.

## Ownership fixes

- Literal shell arguments admit adjacent quoted word segments, including
  `--execute="SELECT 1"`. Expansions, substitutions, operators and globs remain
  unsupported. The process owner receives one exact argument vector.
- An authored Mac root process without an explicit parent uses the declared
  pre-existing root-shell context. The world model requests that context and the
  initial fleet transaction owns it before collection. Its elevation, original
  startup mechanism and authentication are not newly generated. The in-window
  child has a real canonical fork/exec, inherited credentials and descriptors.
  This is an explicit model assumption, not a recovered fact about a real attack.
- Explicit root system jobs with installed native images use the shared retained
  launchd → xpcproxy → target owner even when `launch_profile` is omitted. The
  original loaded plist identity and arguments remain authoritative. Native
  executable qualification is independent of that canonical mechanism.
- The existing regular-GUI catalog entries below use the shared LaunchServices
  startup owner. Each app keeps its own binary identity and metadata gaps; the
  reference app/Chrome signer or entitlements are never copied into another app.
- The source admission owner checks signing availability for fork, exec and
  known exit phases. A missing executable or signing fact becomes an explicit
  unavailable observation, rather than an exception in the renderer. The complete
  coverage guard still rejects missing native process starts.

## Four Homebrew command references

The public macOS 27 arm64 package layers were fetched anonymously from Homebrew's
registry, with digest verification before opening the archives. Only their exact
main executable members were read. No package was installed or executed. Apple's
read-only `codesign --verify` independently accepted all four extracted signatures.
No installed Homebrew code, personal directory, profile, capture or log was read.

| Formula / executable | Version inspected | Public bottle SHA256 |
| --- | --- | --- |
| sqlcmd / sqlcmd | 1.10.0 | `d2f8ffec85fc77eaadf636f6614b131c4171649f89f8fbff15f9d0923ed74005` |
| curl / curl | 8.23.0 | `16b951fa8ecede2c254441c26e34814fed37c1e97382dad3016012aa2cbf20ac` |
| libpq / psql | 18.6, bottle revision 2 | `e15f512613e8e0eda46a495fda44ee79ee4c9f1ec2ea12db9b9963dec769a252` |
| mysql-client / mysql | 26.7.0 | `879cf3513eef1d90621cc6c1a69c0ffa7c1b2987b73c13b6010392d7259a3747` |

Public manifests: [sqlcmd](https://ghcr.io/v2/homebrew/core/sqlcmd/manifests/1.10.0),
[curl](https://ghcr.io/v2/homebrew/core/curl/manifests/8.23.0),
[libpq](https://ghcr.io/v2/homebrew/core/libpq/manifests/18.6_2),
[mysql-client](https://ghcr.io/v2/homebrew/core/mysql-client/manifests/26.7.0).
Their layer URLs are the corresponding repository's `/blobs/sha256:<digest>`.

All four are native generic arm64, ad-hoc signed, with no team identifier and no
XML or DER entitlement slots. sqlcmd's CodeDirectory identifier is `a.out`, and its
static flags include ADHOC and LINKER_SIGNED. The other three have ADHOC and an
identifier consisting of the executable name, `-55554944`, and the image UUID in
lowercase hexadecimal. The UUID relationship was checked against each public
image's separate LC_UUID command, rather than inferred from the filename.

Generation uses its own release-owned UUID and CodeDirectory/file digests; it does
not copy the reference binary hashes or UUIDs into synthetic events. The bounded
`{macho_uuid_hex}` catalog token resolves once in the deployment compiler, from
that same canonical image. There is no arbitrary template evaluation.

Runtime flags are **selected model outcomes, not observed executions**. The frozen
policy selects successful ad-hoc validation (SIGNED, ADHOC, VALID, category NONE),
retaining sqlcmd's LINKER_SIGNED attribute. This uses the existing ad-hoc execution
model and [Apple's flag definitions](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h).
It does not claim every installation/relocation, build revision or runtime security
state has identical flags. Unlisted binaries keep unknown metadata.

## Two Apple command references

The user explicitly authorized one fixed-output, collector-free static check of
`/bin/sh` and `/bin/sleep`. The sandboxed signature checks were inconclusive; the
same approved checker outside the sandbox verified both signatures. It returned
only fixed comparisons: expected Apple identifiers, absent team identifiers,
absent entitlements, arm64e/ptrauth slices, and no selected static option bits.
Neither command was run, and no native log, profile or capture was opened.

The catalog declares `com.apple.sh` and `com.apple.sleep`. Runtime validation remains
explicit frozen model policy: the existing ordinary platform-command outcome for
the root shell and the existing platform system-job target outcome for sleep.
These runtime flags were not measured by the static check. The initial foothold
has an explicitly modeled unattributed root audit origin inherited from the initial
system context, no terminal and null standard streams; it is not an asserted sudo
or GUI-login observation.

## Regular GUI application declarations

These explicit bundle/image declarations select the shared launch mechanism for
the existing workload. The separately inspected public main-image templates below
now supply their own signer and complete bounded entitlement dictionary. No
additional helper graph is implied, and no app inherits another app's signature.

| Existing application | Selected bundle identifier | Public vocabulary basis |
| --- | --- | --- |
| Firefox | `org.mozilla.firefox` | [Homebrew packaging](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/f/firefox.rb) |
| Word | `com.microsoft.Word` | [Homebrew packaging](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/m/microsoft-word.rb) |
| Outlook | `com.microsoft.Outlook` | [Homebrew packaging](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/m/microsoft-outlook.rb) |
| OneDrive | `com.microsoft.OneDrive` | [Homebrew packaging](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/o/onedrive.rb) |
| Adobe Acrobat | `com.adobe.Acrobat.Pro` | [Adobe administration guide](https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide_Mac/predeployment_configuration_advanced.html) |
| Slack | `com.tinyspeck.slackmacgap` | [Homebrew packaging](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/s/slack.rb) |
| Zoom | `us.zoom.xos` | [Homebrew packaging](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/z/zoom.rb) |
| Webex | `Cisco-Systems.Spark` | [Homebrew packaging](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/w/webex.rb) |
| Dropbox | `com.getdropbox.dropbox` | [Homebrew packaging](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/d/dropbox.rb) |
| DBeaver | `org.jkiss.dbeaver.core.product` | [Homebrew packaging](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/d/dbeaver-community.rb) |
| Google Drive | `com.google.drivefs` | [Homebrew packaging](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/g/google-drive.rb) |
| Citrix Workspace | `com.citrix.receiver.nomas` | [Citrix MDM schema](https://docs.citrix.com/us/en/citrix-workspace-app-for-mac/mobile-device-management.html) |
| Cisco Secure Client | `com.cisco.secureclient.gui` | Verified public main image below; the old AnyConnect preference domain was not this executable's identifier |
| Tableau Desktop | `com.tableausoftware.tableaudesktop` | [Homebrew saved-application-state vocabulary](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/t/tableau.rb) |
| GlobalProtect | `com.paloaltonetworks.GlobalProtect.client` | [Vendor preference domain](https://docs.paloaltonetworks.com/globalprotect/release-notes/6-3/known-issues-related-to-gp-app/globalprotect-6-3-3-h6-windows-and-macos-known-issues) |

Preference/state domains were initial vocabulary evidence, not signature proof.
The public package checks independently verified each main executable's signature,
arm64 slice, signing identifier, team, entitlement dictionary and Info.plist bundle
identifier. A native xpcproxy row alone does not satisfy the app-start contract.

## Fifteen public GUI main-image templates

Public packages were downloaded into an isolated temporary directory outside Git.
Disk images were mounted read-only with browsing/auto-open disabled and detached.
`pkgutil --expand-full` extracted payloads without installing them or executing
installer scripts. No downloaded executable was run, and no installed application,
profile, native log or private capture was inspected. The same-named Acrobat helper
and the x86 Google Drive payload were explicitly excluded from main-image selection.

| Application | Public reference release | Public artifact SHA256 |
| --- | --- | --- |
| Firefox | 158.0 | `dfe8508ee8880cec1578253eb02b9154b5971a55e832d97396f463cd07b5ef67` |
| Slack | 4.52.178 | `8a5bd759b91478c19f23deef1f21b870a5c3c55b631e3341be32f1c297260331` |
| Dropbox | 274.4.4905 | `8371409c1941e7a5e425568ae7f1a765d1c54ab8bf0084c4d522b20866dd5644` |
| DBeaver | 26.2.2 | `7f47579bc583571ca0ccef9fdce7d6cc56f84b74844e4e700ab7a46d1e501ec5` |
| Outlook | 16.114.26101123 | `85c44957c44f223797b2a2cda48c096897274678ac8cf1adae14ec947f0f54ca` |
| Word | 16.114.26101123 | `594a85317fb20b6fe9cc2b1e08aa8dacce0adafd167593230200f8a5f1937366` |
| OneDrive | 26.173.0906.0008 | `cc0270130dc32cf92d27a52a145639a6cbbf0e88287a1b5603be4292af9da66a` |
| Zoom | 7.2.2.88465 | `ff15d926ef5a714c6683cc23ed628a7c2fc43d080a88ac54af4e200ba03a2456` |
| Citrix Workspace | 26.09.0.17 | `c0c9d44f622226b019e6406f3df8012da351b17e86f2dc42b62039df17d0a3df` |
| Webex | 46.11.0.36194 | `f7565acf44c4a4012f2fef5824016595ed89872f5d89bf1f72c1484dc61e4b1b` |
| Google Drive | 133.0.2 | `edfe08e00728c5084366f68a9e086a8ccafa3087bb0b47c2998148ac5db16661` |
| Cisco Secure Client | 5.1.20.2493 | `7c2d9da63b46aad12e085c5b0e29c26e8f014010022ab9ba96cc216855a0a69c` |
| GlobalProtect | 6.3.3-1199 | `a0b5dbe7b58fad6eaa5d8ca1f6d12623af18548002ec8671bb92bf1ccd266ab0` |
| Tableau Desktop | 2026.3.0, build 20263.26.1022.1645 | `e1724f98347f43cb613620bac329d026925ca46ddb159f82b5d000cf5b00113e` |
| Acrobat Pro | 26.002.22031 | `2c36119095065e2c78c4fe2bcf3d8440536b1c4a113185fc8f509164aa94b46d` |

Artifact sources: [Mozilla release](https://download-installer.cdn.mozilla.net/pub/firefox/releases/158.0/mac/en-US/Firefox%20158.0.dmg),
[Slack release](https://downloads.slack-edge.com/desktop-releases/mac/arm64/4.52.178/Slack-4.52.178-macOS.dmg),
[Dropbox release](https://edge.dropboxstatic.com/dbx-releng/client/Dropbox%20274.4.4905.arm64.dmg),
[DBeaver release](https://dbeaver.io/files/26.2.2/dbeaver-ce-26.2.2-macos-aarch64.dmg),
[Outlook package](https://res.public.onecdn.static.microsoft/mro1cdnstorage/C1297A47-86C4-4C1F-97FA-950631F94777/MacAutoupdate/Microsoft_Outlook_16.114.26101123_Installer.pkg),
[Word package](https://res.public.onecdn.static.microsoft/mro1cdnstorage/C1297A47-86C4-4C1F-97FA-950631F94777/MacAutoupdate/Microsoft_Word_16.114.26101123_Installer.pkg),
[OneDrive package](https://oneclient.sfx.ms/Mac/Installers/26.173.0906.0008/universal/OneDrive.pkg),
[Zoom package](https://cdn.zoom.us/prod/7.2.2.88465/arm64/zoomusInstallerFull.pkg),
[Citrix package](https://downloadplugins.citrix.com/ReceiverUpdates/Prod/Receiver/Mac/CitrixWorkspaceAppUniversal26.09.0.17.pkg),
[Webex image](https://binaries.webex.com/webex-macos-apple-silicon/Webex.dmg),
[Google Drive image](https://dl.google.com/drive-file-stream/5-percent/GoogleDrive.dmg),
[Cisco university distribution](https://secure.nis.vt.edu/resources/downloads/vpn/cisco-secure-client-macos.dmg),
[GlobalProtect university distribution](https://vpn.upenn.edu/global-protect/getmsi.esp?platform=mac&version=none),
[Tableau image](https://downloads.tableau.com/esdalt/2026.3.0/TableauDesktop-2026-3-0-arm64.dmg),
[Adobe image](https://trials.adobe.com/AdobeProducts/APRO/Acrobat_HelpX/osx10/Acrobat_DC_Web_WWMUI.dmg).
Some URLs roll forward; the measured digest binds the reference inspected here.
The two university-distributed VPN images additionally passed Apple-anchored
requirements for the exact expected vendor team and main identifier.

The Tableau image's measured checksum **differs** from the published Homebrew cask
checksum `b9d89df8cb1310657077310c3c4d14e71ae95423d72a2d6d7ee09a00773dc4ea`.
It is not called a Homebrew-verified artifact. Its static template instead comes
directly from the vendor's HTTPS image, with independently verified Apple-anchored
main signing and `com.tableausoftware.tableaudesktop` identifier. The discrepancy
does not establish why packaging changed. The measured build and both digests are
retained explicitly; no published checksum was silently replaced.

These are **synthetic catalog templates**, not exact installed-build parity claims.
Tableau, Cisco Secure Client, GlobalProtect, Webex and Google Drive references differ
from the selected catalog builds; Acrobat previously had no exact release declaration.
The scenario's existing applications, images, versions, commands and timing remain
unchanged. The reference templates define each modeled release's explicit metadata;
synthetic content/CodeDirectory hashes and image UUIDs remain release-owned derivations.
No real image hash or UUID is inserted into generated events.

All public mains have generic arm64 slices and the static RUNTIME option; Slack also
declares REQUIRE_LV. Successful Developer ID validation/category 6 and the runtime
security flag sets are **selected model outcomes, not observed runtime measurements**.
The explicit per-image policy retains hard/kill/enforcement/restriction, successful
signed/dyld validation and RUNTIME; it selects entitlement validation when the object
is nonempty and removes REQUIRE_LV only for explicit true disable-library-validation.
False remains false, an empty object remains distinct from absence, and unlisted
images retain unknown facts. This bounded ordinary-main policy does not establish
sandbox transitions, helper graphs, app-specific ULF or Gatekeeper outcomes.

Word's `com.apple.security.scripting-targets` contains a nested dictionary, exactly
as [Apple's entitlement reference](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
documents. Apple's [ES entitlement API](https://developer.apple.com/documentation/endpointsecurity/es_exec_entitlements(_:))
returns the exec entitlement dictionary. The v11 codec/property-object capability
preserves that dictionary recursively, rather than deleting or flattening keys.
This is an API-derived extension of the existing JSON object representation, not a
new captured wire sample. It admits only exact Boolean/int64/string/string-array/
dictionary values with depth, node, entry and UTF-8 bounds. Prior narrower source
profiles still reject nested objects. Canonical storage distinguishes empty objects
from arrays, preserves Boolean versus integer identity at every depth, and uses a
new explicit checkpoint tag without changing old flat encodings.

## November 7 reachable-launch repair

The launch-support query in `generation/macos_launch_support.py` combines exact
compiled installation/binary identity with frozen launch and validation policy.
Validation checks potentially selected baseline apps and installed authored targets
before sampling; execution rechecks installed targets before process allocation.
Selected output emitters do not determine this qualification. Explicit partial
coverage retains the existing diagnostic path. Complete coverage never silently
filters unsupported applications, substitutes another browser family or invents
missing signing facts. Broader developer-tool metadata gaps now fail preflight;
this repair does not qualify that entire catalog.

Ordinary Finder activity uses its catalog-declared per-session singleton, with
one canonical startup when first needed and reuse while that process remains live.
This is a lazy desktop-process model, not measured login-start timing. Authored
explicit process launches remain explicit; session closure and subsequent launches
still use the existing lifecycle owners. Safari, Edge, Teams and Excel main launches
use the existing bounded regular-GUI contract. No app helper graph, sandbox transition
or app-specific Unified Log behavior is newly qualified.

Bounded static inspection on the authorized second Mac (macOS 27.0.1, build 26A434,
arm64) supplied Finder 27.0 and Safari 27.0.1 main-image signer/entitlement/slice facts.
Executable SHA256 values are `5b2f4100170ca2ddf7fb738c2faeeeb3e56e622349328dd193965a8b4f6799b2`
and `773bfd818b5b924d34a8749248203a6bab1c9af3b6aa8c2c93bef3ae6ce9dc79`, respectively.
No personal logs, application data or ambient process capture was read.

Public packages were downloaded into new owner-only temporary directories on that
host, checked against Homebrew's published SHA256, and statically inspected without
installation or executable launch. Edge's DMG was mounted read-only and detached;
Teams/Excel PKGs were expanded without executing installer scripts. Homebrew bottles
were extracted without pouring or running post-install actions.

| Main executable | Inspected reference | Artifact SHA256 | Descriptor |
| --- | --- | --- | --- |
| Microsoft Edge | 157.0.4341.42 | `045d56a56c4ea29f31a60ad4afdcbd0c961b15da834c6b32b880ac11b682b516` | [Homebrew API](https://formulae.brew.sh/api/cask/microsoft-edge.json) |
| MSTeams | 26289.204.5281.6363 | `393e25369198068c2715f3f32ad200de712a74d9184934c39ce1d5c42b39cc2c` | [Homebrew API](https://formulae.brew.sh/api/cask/microsoft-teams.json) |
| Microsoft Excel | 16.114.4 | `ba9fbc27f3c33fcc4732bd9ce3538613fbe6c4faaf269a681e064d9d39dd257c` | [Homebrew API](https://formulae.brew.sh/api/cask/microsoft-excel.json) |
| Homebrew ssh | 10.6p2, arm64_golden_gate | `c420fda22de5514ea105cf753099f41ff47a31fb2bb5ecd041e3debbe451373f` | [Homebrew API](https://formulae.brew.sh/api/formula/openssh.json) |
| Homebrew nano | arm64_golden_gate bottle | `2791d87741b8f65529a08b22be01a73bbaf5a744521fa62699794c16601bd2e9` | [Homebrew API](https://formulae.brew.sh/api/formula/nano.json) |

Descriptor URLs roll forward; the measured digests bind these inspections. Both
Homebrew mains have ad-hoc signatures and verified absent entitlements. Their signing
identifiers retain the existing release-owned UUID derivation. Apple's nano is a
separate binary and is **not** the metadata source for `/opt/homebrew/bin/nano`.
The catalog's pre-existing selected versions remain unchanged. As with the earlier
GUI additions, these are explicit synthetic templates, not installed-build parity.
Runtime flags/categories remain declared successful model outcomes, not measurements
inferred from a static signature or a claim that native execution was collected.

Safari's full dictionary has 177 top-level entries and two integer arrays. The
version-two property-object capability retains those arrays as exact int64 values
and raises the per-object entry bound to 256; depth, aggregate node/text and other
bounds remain enforced. It has a new checkpoint encoding tag. Older source
capabilities reject the extended shapes, and old signature encodings remain unchanged.
Finder's 107-entry dictionary and nested objects are preserved separately. Unknown,
verified absent and empty entitlements remain distinct. No dictionary is truncated.

The nominal Code filesystem workload now samples from an independent stable stream
scoped by generation seed, host and hour. It cannot consume the system-traffic stream
and resample later application selection even when no eligible editor is active.

The exact `/opt/homebrew/bin/ssh -V` completion is declared status zero through the
existing command-completion policy. [Upstream OpenSSH's option handler](https://github.com/openssh/openssh-portable/blob/master/ssh.c)
prints its version and exits zero for `-V`; no network session is opened by that
option. This selector does not certify other SSH invocations or failed transports.


## November 7 standard-persona catalog completion

The user explicitly accepted provisional desktop metadata based on public research
and existing knowledge, without installing IntelliJ IDEA, Sublime Text, Postman or
Thunderbird. Their main images now select the existing regular-GUI owner. Bundle/
signing vocabulary and team IDs are based on public installer configuration:

| Application | Bundle/signing ID | Team ID | Public installer source |
| --- | --- | --- | --- |
| IntelliJ IDEA | `com.jetbrains.intellij` | `2ZEFAR8TH3` | [Installomator](https://github.com/Installomator/Installomator/blob/main/fragments/labels/jetbrainsintellijidea.sh) |
| Sublime Text | `com.sublimetext.4` | `Z6D26JE4Y4` | [Installomator](https://github.com/Installomator/Installomator/blob/main/fragments/labels/sublimetext.sh) |
| Postman | `com.postmanlabs.mac` | `H7H8Q7M5CK` | [Installomator](https://github.com/Installomator/Installomator/blob/main/fragments/labels/postman.sh) |
| Thunderbird | `org.mozilla.thunderbird` | `43AQ936H96` | [Installomator](https://github.com/Installomator/Installomator/blob/main/fragments/labels/thunderbird.sh) |

These four entitlement dictionaries, runtime flags and ordinary main-launch
relationships are **selected provisional models**, not measured vendor-build facts.
IntelliJ/Thunderbird select JIT, unsigned executable memory and library-validation
exceptions; Postman selects the two executable-memory exceptions. Sublime selects
an empty dictionary, which is a model choice, not verified absence. Public signing
identities do not establish the exact entitlement sets. Their content hashes, UUIDs
and code digests remain synthetic release identities. No new helper trees, sandbox
transitions, app-specific ULF or full vendor-build parity are implied.

The P2 whole-catalog audit in `TODO.md` requires specific installs and execution
tests on Windows, Linux and macOS, including these provisional choices. The older
reference-backed templates above keep their own evidence status; they are not
relabelled as measured desktop installations by this increment.

### Installed command-line and runtime references

On the authorized macOS 27.0.1 arm64 reference host, Homebrew installed sevenzip,
kubernetes-cli, make, vim, emacs, gcc, rust, dotnet, python@3.14, redis, openldap and
powershell. Existing Git, Node and Docker Desktop's CLI were used in place. Homebrew
auto-update/automatic cleanup were disabled; required dependencies were installed
normally. No shell profiles, application accounts or credentials were changed,
no containers were created, and no launchd service was enabled or started by the tests.

The finite scratch experiment passes **37 controls**: 35 functional tests plus
PowerShell's expected failure without DOTNET_ROOT and success with it. Tests cover
7-Zip creation/integrity, an isolated Git repository, kubectl client information,
editor batch writes, Make, C and Rust builds/execution, Node/npm, Python, pip,
pytest in an isolated temporary virtual environment, .NET SDK/MSBuild/offline
build, Docker CLI version, Redis/LDAP client versions and PowerShell arithmetic.
The pytest environment is separate from the Homebrew-managed global Python site;
the synthetic catalog still assumes the requested Python modules are available in
its modeled deployment. That broader package/workspace state belongs to the P2 audit.

Only the selected executables' static signer/entitlement/slice facts were read.
No privileged native event capture was run. All signatures verify under strict
checking except Python's enclosing app resource seal: ordinary strict verification
reports `code has no resources but signature indicates they must be present`.
A separate strict check ignoring bundle resources verifies the main executable,
and the Python/pip/venv/pytest execution tests pass. This resource qualification is
retained explicitly; neither the reference installation nor its signature was
modified to make a check pass.

| Executable | Inspected build / package | Executable SHA256 |
| --- | --- | --- |
| `7zip` | sevenzip 26.05 | `110c6bc1a5a36a0cdf91dfbf62154830e4bd1f6eba380bfc8348668236b623dd` |
| `git` | git 2.56.0_1 | `40163333061f7223ecb604ed0f12988cfc8096d57ca8b1db006d410d4aeb700e` |
| `docker` | Docker Desktop CLI (existing installation) | `e6bb967adc3e97c9a9027aa7a1b83691789630cb26a4bbcddd2e8353a8a89ea4` |
| `kubectl` | kubernetes-cli 1.37.2 | `4d19946c0d0a567019bf81cd5a2820f2d8899fe7dcbcb8b4d0de4767ca50ab70` |
| `make` | make 4.4.1 | `0672c75e5ea2153469ef2fdd14b518d4b6b4db704cc38130caa4c3267680d188` |
| `vim` | vim 9.2.1302 | `2a2d312d233656c1d8e164d01b43f5efa36ad67c546406d1b636aa6007200cf5` |
| `emacs` | emacs 31.1_1 | `36cd929f5f8c970efab5a7ac5e522e6d6ac6c14e51cbddebccae3fd1d6fb067a` |
| `gcc` | gcc 16.2.0 | `e6e12f73dbc937615843ba4b4ed64955e50ef289e668896aa4f5437bc6617a80` |
| `cargo` | rust 1.99.1 | `f6f1ae30e327d6ee1df89485871ec7a971d7c3bc34616fc8cd17ddded0489fbc` |
| `dotnet` | dotnet 10.0.403 | `6787fad6f5c105dd96501a9bf62e0978dc35d9cb8ed318fcd39122fd8e426a86` |
| `nodejs` | node 26.12.0 | `4d9aea129d56f18e6b3b48792aa5ba13f17dfc8c84d3a37841d14f54d59e1d1a` |
| `python3` | python@3.14 3.14.10 | `e550ffe3966a0224068563a74dc26531c7d2ece6e522308bd9c9584c5fb75e55` |
| `redis_cli` | redis 8.10.3 | `24f6e01653bc9d20d7fab3c30efadf485ce163304721e564abd9721cf30122e8` |
| `ldapsearch` | openldap 2.7.2 | `335bf04741663aa91b160849651712eb7418f144b2110eaf71cd7841df323902` |
| `powershell` | powershell 7.6.9_1 | `1e7dfb43e179cf95d5169565b1eaa66e9fe44d9183b614a818750684caf04d64` |

Git/Vim/Emacs/Cargo/.NET/Node/Python/Redis/LDAP signing identifiers have a measured
UUID component; the catalog uses its existing `{macho_uuid_hex}` substitution from
the exact synthetic release identity. Fixed identifiers (`7zz`, `a.out`, `make`,
`xgcc`, `apphost`) remain literal. Homebrew tools are ad-hoc signed; Docker's CLI
retains its measured `docker` signing ID, team `9BNSXJN65R` and application-group
entitlement. .NET's own measured entitlement dictionary is retained independently.

The fifteen CLI/runtime startup flags and validation categories were then measured
twice using unprivileged `csops` status/category queries on only the probe's own
start-suspended children. Each child was resumed and reaped; all thirty version
invocations exited zero, both snapshots agreed exactly, and no signing or security
state was modified. Apple documents the read operations in
[`codesign.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
and the start-suspended flag in
[`spawn.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/spawn.h).
This is startup-field evidence, not an Endpoint Security event capture or proof of
every later runtime state.

Measured flags are `0x22000201` for the ordinary ad-hoc group, `0x22020201`
for 7-Zip/kubectl/Make/GCC, `0x22000205` for .NET and `0x22011311` for Docker.
All categories are 10 except Docker's 6; none is a platform binary. These
replace the initial inferred static-to-runtime policy for these fifteen images.
The provisional desktop flags above remain explicit model choices. Selected catalog versions
remain the pre-existing simulated releases; the reference builds above supply
bounded templates and do not establish exact version parity. The P2 audit covers
that remaining distinction and command/helper/completion semantics.

Homebrew's `bin/pwsh` is a shell wrapper, not the native image. The catalog now
addresses `/opt/homebrew/opt/powershell/libexec/pwsh` directly, with the required
`DOTNET_ROOT=/opt/homebrew/opt/dotnet/libexec` default owned by canonical execution
metadata. It preserves supplied environment values and does not fill an unknown
environment. This normalizes the wrapper's target/default into the modeled launch;
it does not reproduce or claim coverage of the wrapper's separate Bash exec phase.
PowerShell's measured main identifier is `apphost`, not an assumed Microsoft
Developer ID signature. Python uses its existing explicit shell launch rule even
though its native interpreter path is inside `Python.app`.

Preflight includes query-category candidates, so PowerShell, Redis CLI and
ldapsearch cannot escape the same early metadata checks as ordinary apps. These
repairs preserve complete native process coverage rather than remove candidates.
