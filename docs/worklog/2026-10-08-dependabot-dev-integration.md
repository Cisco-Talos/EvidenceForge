# Dependabot integration into dev

## Scope

After PR #441 merged, the user authorized applying every currently open Dependabot update
to `dev` and merging after successful CI. The integration branch starts at dev commit
`602ec2f159de3df276455ed5cdfd8a499a635598` and retains each original PR head through merge
commits so the original updates remain traceable.

| PR | Update | Original head |
| --- | --- | --- |
| #426 | actions/upload-artifact 7.0.1 | `bddc4cb7090af557298b20b342848d007adf8bc1` |
| #431 | astral-sh/setup-uv 10.2.0 | `d63d24e070f26351c57e529a5f951de91ac788f5` |
| #433 | pytest-mock 3.16.0 | `6280b1754bf54d0be27b2ad46b2fd0f1651ec4df` |
| #436 | virtualenv 21.7.13, python-discovery 1.6.1 | `9c7d01bb683152084df08aa44748d79f39e555d2` |
| #437 | cryptography 50.0.2 | `7e8b806ee6f28a0bffb2ad717cf7505a32136a08` |
| #438 | websockets 17.2 | `7761bfddad21c5cbd1dc31a62fb209912490c707` |
| #439 | pytz 2026.5 | `b599ce8189b57b634c17961caf8e83636e2fd27f` |
| #440 | Ruff 0.16.10 | `c5282f8333a7f541ad57559fe62225d473d2c835` |

PR #436 originally targeted main and was retargeted to dev before integration. All merges
were clean. The implementation diff changes only dependency metadata and existing CI-action
pins; this worklog records the integration. The application version stays 2.1.2. No product
code, generation behavior declaration, or test assertions change.

## Validation and merge gate

- Locked all-extras dependency installation succeeds.
- Ruff 0.16.10 lint and formatting pass across the repository (1,009 Python files).
- Generation behavior declaration remains revision 160 with digest
  `0114d1bad6b5748c549a4da2ae71298e4c51b1852c11bfaf0b81e1d0d33cab60`.
- Diff whitespace checks pass; the seven changed lockfile package versions match the exact
  expected updates, and all eight original heads are ancestors of the integration branch.
- All 121 focused checks pass with the combined installed dependency set: 119 timezone,
  cryptographic contract, and Studio service tests, plus two real helper tests. The helper
  tests require local loopback access and pass outside the restrictive command sandbox.
- Merge only after current combined PR CI is green, including Linux/Windows engine suites,
  macOS Studio packaging/state recovery, Windows checkpoint durability, and Required CI.
- Verify dev contains the eight original heads and reconcile the original PR states after merge.
  Final CI and merge evidence belong in the integration PR.
