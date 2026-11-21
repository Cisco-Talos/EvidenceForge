# Canonical native process generations include existing hidden birth history

READ-ONLY investigation; no20code.17Detection+Host reproduced gapless12–112/
12–128native pidversions on old Mac boots. Native read-only self-only libproc17
probe onmacOS27.2.1arm64 returns valid56byte struct, selfversion542463; singlehost
example not rate calibration. No process enumeration/UUID/commands captured.
Apple XNU kern_fork.c and kern_exec.c increment shared nextpidversion for fork/exec.

IMPORTANT ROOT: State _preview_macos_audit_pid_version allocates opaque reservation
HANDLES. Final MacosAuditIdentityLedger.seal() deliberately resolves chronology via
row_number()OVER(PARTITIONBYhost ORDERBYat,handle). That dense resolution—not merely
State's handlecounter—owns emitted native/eCAR versions. ChangingStatehandles or
rendering random gaps would miss the owner and could corrupt authenticated proofs.
Both nativeES/eCAR already consume one resolved map; preserve those joins.

Existing canonical POSIX PID planner ALREADY models hidden host process births:
State._linux_pid_weekly_churn_prefixes + _linux_pid_hidden_churn_from_prefix,
registeredbootepoch, includingMacos paths.20should reuse that exact history as a
monotone native-generation offset, plus the count of committed visible canonical
fork/exec allocations sorted chronologically. No freshrandomgaps/pools/caches/rate
calibration or resource/retention ceiling. Hidden exec history is not guessed;
existing hidden births alone are sufficient legitimate version consumption.
Preserve reservedhandleproofs, Stateallocator, scope, rollback, journal/capsules,
checkpoints and source filtering. Handle order can differ from time; finalmap must
remain unique strictly chronological perhost with same-time deterministic ties.
Differenthosts'boots/historymustnotshareoffsets. uint32 exhaustion rejects, no wrap.

Proposedoptional frozen macos_execution_metadata policy selects existing POSIX
hidden-birth history. Whole absence retains exact olddense resolution. Need shared
State/bundle seal adapter called BOTH engine/core._close_emitters (ecar-only too)
and macos_es_ingress.finalize (native-only too), before any renderer. Raw legacy
fixtures withoutknownboot/history need explicit compatibility behavior; do not
invent an epoch. Normalengine modeledMacbootmust be present orfailclearly.

Ledger seal can take a validated pure per-host/time canonical history view. Build
resolved SQLite table atomically in bounded streaming batches; canonicalfacts remain
unchanged and sealed only on success. Validate nonnegative integer/nondecreasing
offsets, uint32bounds and no accidental new trust input. No UDF opaque exceptions
or source-row-triggered generation. Existing checkpoint stores canonicalfactledger,
boot/hiddenprefix; finalmappingcanrebuildidenticallyafterrestore. No newcheckpoint
schema needed if no durable new policy state is added; verify ratherthanassume.

Inventory: State materializationdirect/cohort/fork/exec, baseline/storyline/causal /
boot; chronologicalledger; native ingress/project_native alltokenpositions; eCAR
project_ecar current/previouspidversion; filtered/non-native-only runs, checkpoint
restore/finalize/retry/abortedpublication. Rootinode and filesystempopulation are
separatefamilies.20must wait19andactual18outcomes; source553currentlyfrozen through
18gen+postEXIT0. No20enginechangesnow.

Primary sources:
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h

18Detection independently reproduces223newidentities exactly12–112/12–133and
corresponding PIDjumps (25541→26203whileversion24→25). Selectthissharedfamilyfor20.
Root19adapterremains separateboundedrepair.20implementationmustnotchangeStateopaque
handles: onlycanonicalresolvednativegeneration map consumes already-modeledhidden
POSIXbirthhistory. A config-selected sharedState sealing adapter serves BOTH core
andnativeingress; direct/raw unknown-boot fixtures retainexplicitlegacycompatibility,
normalengineclose requiresknownboot. Frozenmissingpolicy usesoldrow_numberexactly.
SQLstreamedresolution validatesintegernonnegative/nondecreasing offsets perhost,
uint32extent and atomicrollbackonfailedoffset; no scalarSQLiteUDFopaqueerrors.
Callers do not choose arbitraryoffsetvalues: normalowner derives onlyfromState's
canonicalboot+existinghiddenPIDprefix. One bounded1024rowpage reuses existingledger
admissionpage size. No newpersistentStatefield/opaqueowner/cache/retentionceiling.
Existingcanonicalledger/boot/prefix checkpoint state rebuilds map afterrestore.
