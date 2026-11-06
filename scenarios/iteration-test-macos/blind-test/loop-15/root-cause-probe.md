# Loop 15 root-cause probe

The affected persona is Aisha Johnson (`help_desk`). Before this change, `help_desk` on Linux servers fell through to the broad `sysadmin` command pool. `_get_role_pool` now routes non-workstation help desk sessions to the YAML-backed `help_desk_server` pool and retains the desktop `help_desk` pool on workstation-like hosts.

Observed output in the fresh loop 15 bundle:

- `DB-PROD-01.meridianhcs.local/bash_history/aisha.johnson.bash_history`: 13 commands, including `loginctl list-sessions`, `getent passwd`, `resolvectl status`, `journalctl -u sshd`, and service-specific `mysql` status/log checks, plus disk and uptime checks.
- Across Aisha's server histories, loop 15 has 68 commands in 7 files; loop 14 had 56 commands in 5 files. Selection varies across hosts, and repeated exact commands remain possible when the support task is the same.
- A direct unit assertion verifies workstation routing remains `help_desk`, server routing resolves to `help_desk_server`, and the server pool contains support-oriented resolver diagnostics.

Validation: 15 tests in `tests/unit/test_expert_round4.py` passed; `eforge validate-config` reported 0 errors, one pre-existing Chrome Helper catalog warning, and an informational validator message that does not yet recognize the derived pool key. Ruff, formatting, and generation behavior revision/digest checks passed. The fresh generation was evaluated once and the 117-file blind copy was byte-identical.
