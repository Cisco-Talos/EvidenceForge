# Purpose-aware Windows policy repository catalog — draft

Finding:14Threat's generic SYSVOL/NETLOGON directory/stem/extension products,
carried through15. Distribution texture, not an assertion that custom files cannot
exist. Highest bounded next family after16task/file binding. No17source yet;
16behavior550remains frozen through generation and post-processing.

Owner: _StorageWorldCompiler plus typed, optional, data-driven policy-repository
layout in existing storage_catalog. Model semantic repository role before compiling
automatic names; renderers must not rewrite emitted paths. A Windows DC's known
SYSVOL/NETLOGON purpose is available at share compilation, unlike generic vocabulary
or filename suffix alone. Existing explicit seeds/paths/sizes stay authoritative.

Proposed invariant: eligible automatic SYSVOL files use domain/Policies/GPO-GUID
folders with semantically linked GPT.INI, Machine/User and preference basenames;
NETLOGON contains coherent scripts relative to its scripts root. Root paths of
automatically synthesized shares reflect documented SYSVOL and NETLOGON locations.
Custom share roots remain explicit truth. Generic dc_policy file sets/custom shares,
Linux Samba member servers, domain-unknown environments and old frozen catalogs
without the optional policy retain existing behavior. No Samba AD-DC extension.

Entry inventory: automatic DC presets; generated-share overrides; explicit shares
using recognized policy purpose; host file-set generic catalogs; authored seed
files; bounded compiler collision/capacity fallback. Consumers: compiled manifest,
SMB selector/task planning, canonical file/process identities, Security5140/5145,
Samba server audits, eCAR and Zeek SMB/files. No emitted source triggers siblings.

Design to qualify: finite typed template space, domain-scoped GPO identifiers and
base metadata, no unbounded retry; exact requested/realizable/seed counts and stable
replay. Missing whole subtree keeps historical names/roots/RNG. Present malformed
policy fails validator; partial overlays and named validation paths must agree.
New paths must use native Windows semantics and be disjoint generated subsets for
SYSVOL policy and NETLOGON scripts. Explicit aliases and live AD/DFSR replication
are not introduced by a filename repair; content identity and cross-replica changes
require particular care before any claim that hashes are shared.

Primary sources reviewed:
- Microsoft Group Policy Storage: GPO GUID and domain Policies/GPT layout.
  https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-storage
- Microsoft missing SYSVOL/NETLOGON article: SYSVOL domain subfolder, GUID policy
  directories, and NETLOGON scripts share.
  https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/missing-sysvol-and-netlogon-shares
- Microsoft rebuild tree: SYSVOL/sysvol/domain junction and two default policy GUIDs.
  https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/rebuild-sysvol-tree-and-content-in-a-domain
These older FRS discussions establish directory semantics; they do not mean the
modeled modern servers should emit FRS replication traffic.

Gates: actual compiled-world before-failure; both recognized share roles, seed and
custom/file-set sibling preservation, domain isolation/stability, frozen legacy,
capacity/duplicate paths/malformed config, native SMB evidence and checkpoint replay.
No engine/source edits until16post completes; no scenario/reviewer changes.

## Selected scope after isolated qualification

One actual before test fails on default SYSVOL root/path semantics. Isolated full
compiler/model prototype now91passes, including22new model checks,4compiled-world
cases and65existing storage cases. Earlier prototype failures are retained: a new
fixture used an invalid implicit volume then collided with generated share IDs;
explicit custom roots use presets:[] plus declared volume. An old test assumed no
bounded default catalog could cap; it now verifies cap accounting only for native
policy shares while preserving the no-cap expectation for ordinary catalogs.

Select this bounded repository-path family. Domain-scoped GUIDs, initial sizes and
MIMEs agree across DCs; physical file-object and existing content identity semantics
remain separate. Do not claim a live AD/DFSR replication or content-mutation model.
Generated SYSVOL policy and NETLOGON script candidates are disjoint modeled subsets,
not a new filesystem alias feature. Missing/disabled policy keeps legacy catalog
branches; known-domain Windows DC purpose gates the new branch. Qualified malformed
configuration and snapshot/native/checkpoint gates still required in production.

16generation9889andpost82641bothEXIT0before17production changes.16eval98.4043239783,
140042records;freshstudy4dgivg84/four experts active.16nativecat/teeOfficePDF0rows,
text/JSONinstead. No authored or reviewer-instruction edits.

## Generation failure and second owning family

Actual551generation exited21in baseline hour4, before any evaluation or panel.
Entire failed bundle, logs, progress and input provenance are preserved under
failed-attempt-1. Error: RDP reconnect transport budget exceeds logical budget.

Owner: DeferredRdpApplicationIntent initial logical-session provisioning and the
RdpSessionActionBundle's shared physical traffic support. Current code gives a
logical session first-transport bytes multiplied by8, while all subsequent physical
connections independently draw50k–500k initiator and100k–2M responder bytes. A small
first connection therefore does not provision even one valid later high-volume
connection. The manager correctly rejects the inconsistent declaration.

Proposed invariant: a bounded logical session provisions the configured per-
generation traffic envelope across its existing logical operation allowance. All
initial, reconnect and compatibility paths sample from that same typed support;
logical capacity must not depend on a lucky first draw. Preserve actual wire
accounting, cumulative byte/operation guards, logical operation allowance8, exact prepared
admission/publication/recovery and source lifecycle ownership. Do not enlarge an
opaque manager/retention ceiling, clip counters or bypass the validation guard.

Move the three existing identical traffic ranges into optional typed network
parameters with historical-support fallback for old frozen catalogs. Keep draw
order/bounds unchanged. Compute logical byte provision from the declared support
(and actual first canonical transport floor) times the existing generation bound.
Tests: min first/max reconnect reproducer, 8generations with actual semantic operation/cumulative accounting,
unchanged ninth logical-operation rejection, custom bounds/legacy draws/invalid policy,
native deferred RDP/replay/recovery and checkpoint controls. No scenario changes.

Manager contract refinement: the completed private transport sentinel consumes a
common-channel slot but no logical payload/operation quota. Physical reconnect
count is distinct from the logical operation budget. The regression exercises one
real bounded operation in each of8connections, then verifies ninth logical
operation rejection on another valid transport. Do not invent a physical limit.
