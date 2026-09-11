# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Contracts for explicit pack publisher identity configuration."""

from pathlib import Path

import pytest

import evidenceforge.composition.publisher as publisher_module
from evidenceforge.composition.publisher import (
    PublisherIdentity,
    PublisherIdentityRequiredError,
    clear_publisher,
    effective_publisher,
    set_publisher,
)
from evidenceforge.models.exceptions import PackError


class _TemporaryHomePath(type(Path())):
    """Path implementation whose home is owned by one test."""

    _home: Path

    @classmethod
    def home(cls) -> Path:
        return cls._home


def _use_test_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    _TemporaryHomePath._home = home
    monkeypatch.setattr(publisher_module, "Path", _TemporaryHomePath)
    return home


def test_project_publisher_overrides_user_and_clear_reveals_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Project identity wins without mutating the user default."""

    _use_test_home(monkeypatch, tmp_path)
    user = PublisherIdentity(publisher="user-publisher", publisher_display_name="User Publisher")
    project = PublisherIdentity(
        publisher="project-publisher",
        publisher_display_name="Project Publisher",
    )
    set_publisher(tmp_path, user, scope="user", force=False)
    set_publisher(tmp_path, project, scope="project", force=False)

    assert effective_publisher(tmp_path) == (project, "project")
    _path, cleared = clear_publisher(tmp_path, scope="project")
    assert cleared is True
    assert effective_publisher(tmp_path) == (user, "user")


def test_publisher_replacement_requires_force_and_writes_private_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A different configured identity cannot be replaced accidentally."""

    _use_test_home(monkeypatch, tmp_path)
    first = PublisherIdentity(publisher="first", publisher_display_name="First")
    second = PublisherIdentity(publisher="second", publisher_display_name="Second")
    path = set_publisher(tmp_path, first, scope="project", force=False)
    with pytest.raises(PackError, match="--force"):
        set_publisher(tmp_path, second, scope="project", force=False)
    set_publisher(tmp_path, second, scope="project", force=True)

    assert effective_publisher(tmp_path) == (second, "project")
    assert path.stat().st_mode & 0o777 == 0o600


def test_missing_and_symlinked_publisher_configuration_fail_safely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No identity is derived and configuration cannot escape through a symlink."""

    _use_test_home(monkeypatch, tmp_path)
    with pytest.raises(PublisherIdentityRequiredError, match="publisher identity is required"):
        effective_publisher(tmp_path, required=True)

    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".eforge").symlink_to(outside, target_is_directory=True)
    identity = PublisherIdentity(publisher="safe", publisher_display_name="Safe")
    with pytest.raises(PackError, match="symlink"):
        set_publisher(tmp_path, identity, scope="project", force=False)
    assert list(outside.iterdir()) == []
