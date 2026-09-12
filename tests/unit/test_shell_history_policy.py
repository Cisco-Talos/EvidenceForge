"""Shared shell eligibility stays independent of generation imports."""

import subprocess
import sys

import pytest

from evidenceforge.config.shell_history_policy import is_noninteractive_bash_user


@pytest.mark.parametrize(
    ("username", "excluded"),
    [
        ("apache", True),
        ("WWW-DATA", True),
        ("nginx", True),
        ("httpd", True),
        ("tomcat", True),
        ("root", False),
        ("alice", False),
        (" nginx", False),
    ],
)
def test_shell_eligibility_preserves_account_matching(username: str, excluded: bool) -> None:
    assert is_noninteractive_bash_user(username) is excluded


def test_shell_policy_import_does_not_load_generation() -> None:
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import evidenceforge.config.shell_history_policy; "
            "assert 'evidenceforge.generation' not in sys.modules",
        ],
        check=True,
    )
