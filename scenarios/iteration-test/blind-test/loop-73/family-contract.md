# Loop 73 family contract — Linux logind session identity allocation

- **Owning abstraction:** `StateManager`'s canonical per-host logind identity allocator and its
  checkpoint state.
- **Invariant:** a session ID is unique on its host, stable across all evidence for that modeled
  session, and ordered consistently with the session's actual creation time; ID advances reflect
  modeled session allocations/hidden allocations rather than a near-constant function of wall-clock
  minutes.
- **Entry paths:** SSH session bundle (`ssh_session.py`), local Linux interactive logon
  (`activity/generator.py`), and baseline source-local logind sessions (`engine/baseline.py`).
- **Consumers:** systemd-logind `New session`/`Removed session` syslog rows, SSH/PAM session
  lifecycle rows, canonical session contexts, eCAR session references, and incremental/native
  checkpoint restore.
- **Layer rationale:** the ID is shared session identity allocated before source rendering, so
  `StateManager` owns uniqueness, chronology and durable continuation; an emitter edit would leave
  SSH/local/baseline paths inconsistent.
- **Sibling risks:** out-of-order planning, pre-window/hidden allocations, same-timestamp sessions,
  deterministic seed scope, rollback, exact checkpoint/resume and cross-source ID identity must
  remain valid. The visible fit should lose its wall-clock slope without breaking chronological
  order or source-local lifecycle pairing.
- **Evidence:** loop64's host reviewer reported near-exact 8–9 IDs/minute fits on three Linux hosts.
  A loop72 fixed-seed repro now finds 8 hosts with at least four sessions; MAIL-CLIN has slope
  8.0033 IDs/minute, R² 0.9999992 and max residual 1.37, and DB-PROD has slope 7.9995, R²
  0.9999993 and max residual 1.12. Current allocator code explicitly calculates candidate IDs
  from elapsed minutes with a stable 8/9-per-minute stride. This is `sibling_defect` / confirmed
  `distribution_texture`, not a source-native error.
