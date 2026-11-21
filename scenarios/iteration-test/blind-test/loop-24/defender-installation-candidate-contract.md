# Candidate: scheduled Defender tool uses the installed host release

Unselected preparation from21Host; no source changes while559generation/post22
is frozen. Native21shows12System32MpCmdRun launches/all10Windowshosts with no
version resources and services.exeparent. Microsoft documents ProgramFilesWindows
Defender and versionedProgramDataMicrosoftWindowsDefenderPlatform locations:
https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
This qualifies a modeled default-placement mismatch, not impossibility of a copied
executable or customized deployment. Do not claim a known current live-world
Defender version: use this project's existing installed-release policy.

Existing owner inventory: scheduled_tasks.windows-defender-command currently
usesSystem32/productmicrosoft-windows/parentservices. The native binary catalog
ALREADY has MpCmdRun and MsMpEng underProgramDataMicrosoftWindowsDefenderPlatform,
productmicrosoft-defender-antivirus and defender-platform native-release variant.
The shared edr_pools.defender_platform_version(host_key) and
normalize_defender_platform_path already own host-stable platform versions and
are used by EDR file/module/process-access evidence. Do not add a second version
pool or fix only Sysmon fields. Materialized scheduled-task dict and compiled
ScheduledTaskEntry paths both use _resolve_host_placeholders; route explicit new
Defender version placeholder through that existing owner, preserving frozen
System32taskdefinitions and unrelated paths. Validate the placeholder in shared
config validation and keep task deployment product identity consistent.

A bounded future adapter could select the existing installed Defender path/product,
materialize its host version once in canonical task intent, then let shared binary
release metadata provide matching description/version/company/hash/module truth.
Parent the scheduled utility through a qualified seeded scheduler/service host,
not blindly SCM; inspect existing svchost_netsvcs versus svchost_local_system
identity contracts before choosing. A bare argv0 need not equal a full image path,
so do not call that alone a contradiction. Existing explicit/raw copied binaries
remain possible; no scenario blanket path rewriting.

Consumers: compiled/uncompiled scheduled task generation, native Windows Security,
Sysmon/eCAR process identity/version/hash and Defender module/file/process-access
siblings, checkpoint/frozen effective config. Tests must prove task image and
native metadata use the same already-installed host release across workstation,
server andDC; distinct hosts/seed scopes deterministic; frozen old path behavior;
no new unknown-placeholder validator warnings. Follow with actual native output
probe rather than a filename-only assertion.

CryptSvc netsvcs/SYSTEM remains a separate qualified hypothesis. Do not silently
fix every service by random group/account selection; it requires service-name,
service-host group and principal to be bound together with a primary-qualified
OS/service configuration contract.

Deeper compiler audit: NativeSystemBinaryDescriptor/SystemBinaryEntry currently
permit only host_build/unspecified, and _release_for_descriptor always uses the
Windows OS build for VERSIONINFO, including already-labeled defender-platform
entries. A path-only task edit would inherit wrong10.xDefenderversion metadata.
A proper family repair needs an explicit optional Defender-product release policy
in typed catalogs/loaders/validation, using existing host-owned4.18versionpool.
Resolve that policy centrally in native/capability release compilation so both
MsMpEng and scheduledMpCmdRun share installed product version and releasevariant;
OS-native and frozenhost_builddefinitions keep exact old behavior. No emitter
version rewrite. New policy must be restricted to WindowsDefender product entries,
with clear rejection of incompatible policy/product/platform combinations.
Data/module paths and release keys/hashes need sibling tests before selection.
MpClient currentunknown-package module metadata remains unknown unless separately
qualified; don't manufacture PE metadata or inherit an executable filename forDLL.

Deeper qualification while24generation is frozen: existing defender_platform_version
actually chooses from a preexisting hardcoded3tuple in activity/edr_pools.py, NOT
a YAML-derived version pool (correction to earlier preparation). A proper extension
should preserve frozen legacy behavior while moving default product-release pools
to validated config, avoiding a second independent version owner. Moreover seeded
svchost_schedule aliases svchost_netsvcs, which currently has NETWORK SERVICE, so
naively selecting that parent for a SYSTEM Defender scheduled task is not a
qualified scheduler fix. Preserve current parent until a role/group/account
contract is independently qualified. These increase scope; candidate remains
unselected and should not be presented as a trivial path edit.
