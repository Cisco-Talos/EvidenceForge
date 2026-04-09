# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the centralized config data directory module."""

from evidenceforge.config import (
    get_activity_directory,
    get_config_directory,
    get_evaluation_directory,
    get_formats_directory,
    get_personas_directory,
)


class TestGetConfigDirectory:
    def test_returns_existing_directory(self):
        d = get_config_directory()
        assert d.is_dir()

    def test_is_parent_of_subdirectories(self):
        root = get_config_directory()
        assert get_formats_directory().parent == root
        assert get_evaluation_directory().parent == root
        assert get_activity_directory().parent == root
        assert get_personas_directory().parent == root


class TestGetFormatsDirectory:
    def test_returns_existing_directory(self):
        assert get_formats_directory().is_dir()

    def test_contains_yaml_files(self):
        yaml_files = list(get_formats_directory().glob("*.yaml"))
        assert len(yaml_files) > 0


class TestGetEvaluationDirectory:
    def test_returns_existing_directory(self):
        assert get_evaluation_directory().is_dir()

    def test_contains_yaml_files(self):
        yaml_files = list(get_evaluation_directory().glob("*.yaml"))
        assert len(yaml_files) > 0


class TestGetActivityDirectory:
    def test_returns_existing_directory(self):
        assert get_activity_directory().is_dir()

    def test_contains_yaml_files(self):
        yaml_files = list(get_activity_directory().glob("*.yaml"))
        assert len(yaml_files) > 0


class TestGetPersonasDirectory:
    def test_returns_existing_directory(self):
        assert get_personas_directory().is_dir()

    def test_contains_yaml_files(self):
        yaml_files = list(get_personas_directory().glob("*.yaml"))
        assert len(yaml_files) > 0
