# Next private GUI launch reference: proposal only

No collection, GUI launch or private-file access is authorized by this document. The current
work used invented synthetic data only. The next human-assisted experiment targets **macOS 27
arm64 GUI application launch**, beginning with Finder; Dock and Spotlight are distinct follow-ups.

## Why this reference is needed

The canonical login already owns the user's audit identity. Existing references establish
same-login inheritance and distinguish audit sessions from POSIX sessions. They do not establish
which process owns a Finder/Dock/Spotlight launch, which process is responsible, or the exact
descriptor, environment, terminal and image facts required by the selected native exec export.
The current native projector rejects unknown required facts. A generic eCAR process birth is
useful normalized evidence but cannot substitute for an observed native relationship.

## Minimum experiment, to prepare after scope approval

1. Use one disposable, clearly named harmless test app containing a tiny own-process reporter.
   It should perform no network access, enumerate no personal files and produce no document
   content. Keep the kit and every result outside the repository in an owner-only directory.
2. Establish a same-content command-line control, then launch the app by Finder. The person
   records the launch method and visible outcome privately. Quarantine/policy outcomes must
   remain separate from a successful GUI launch; this is not another Gatekeeper denial test.
3. A bounded ES filter would retain only the exact test executable and its explicitly selected
   lifecycle. Filtering must happen before persistence; an unfiltered machine-wide capture is
   outside scope. Any parent/responsible identity necessary for linkage stays private locally.
4. An offline checker would compare own-process audit identity and native export relationships,
   then report fixed labels for linkage, responsible/parent distinction, source version,
   descriptor kinds/access, tty presence, argv/environment shape, exec and exit agreement.
   No paths, account names, identifiers, argument/environment values or raw records are shared.
5. The person reviews the report. Unexpected schema fields are identified by technical field
   name and value *type* only. Values stay private. Only technical constants, checker logic and
   accepted relationship contracts may become repository fixtures.

Before running anything, specify the app behavior, capture filter, duration/size bounds, cleanup
and exact fixed-output report for approval. Native collection and log reads require explicit
permission. No system service, privacy setting, security control or application needs to be
changed merely to prepare the proposal.

## Admission after a successful reference

Implement the qualified launch contract in canonical process/session ownership and explicit
metadata producers; render through the existing ES ingress and publication journal. Verify
before/after image identity, actor/target/responsible linkage, inherited audit origin, ordered
native sequences, known exit, filtering equivalence and exact checkpoint recovery. Reuse these
contracts across authored and baseline GUI launches. Do not generalize Finder evidence to Dock,
Spotlight, Apple Terminal, different signing/entitlement classes or other macOS versions.

Other experiments remain independent: shell/helper and PTY descriptor inventories, populated
entitlements/full-hash representations, broader native file/auth callbacks and additional Unified
Log or policy families. The existing bounded kernel refusal template requires no repeat capture.
