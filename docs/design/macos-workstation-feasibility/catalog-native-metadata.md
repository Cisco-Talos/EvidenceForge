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

These are explicit bundle/image declarations for the existing workload, used to
select the shared launch mechanism. They **do not supply signing identities,
entitlements or runtime validation**. Those target facts remain unknown until
qualified independently. No additional helper graph is implied.

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
| Cisco Secure Client | `com.cisco.anyconnect.gui` | [Cisco deployment guide](https://www.cisco.com/c/en/us/products/collateral/security/secure-access/secure-client-tamper-resistance-guide.html) |
| Tableau Desktop | `com.tableausoftware.tableaudesktop` | [Homebrew saved-application-state vocabulary](https://github.com/Homebrew/homebrew-cask/blob/master/Casks/t/tableau.rb) |
| GlobalProtect | `com.paloaltonetworks.GlobalProtect.client` | [Vendor preference domain](https://docs.paloaltonetworks.com/globalprotect/release-notes/6-3/known-issues-related-to-gp-app/globalprotect-6-3-3-h6-windows-and-macos-known-issues) |

Preference/state domains are vocabulary evidence for the declared model, not a
signature or complete packaged-Info.plist verification. The remaining GUI signer,
entitlement and runtime-policy work is still required for complete target ES
publication. A native xpcproxy row alone does not satisfy the app-start contract.
