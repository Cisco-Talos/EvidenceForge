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
