# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Safe YAML construction with unambiguous mapping semantics."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode


class DuplicateKeySafeLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects repeated keys in one mapping."""


def _construct_unique_mapping(
    loader: DuplicateKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    """Construct a mapping while retaining source locations for duplicate diagnostics."""

    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


DuplicateKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_yaml_text(content: str, *, source: str = "<string>") -> Any:
    """Parse YAML using only safe constructors and reject duplicate mapping keys."""

    try:
        return yaml.load(content, Loader=DuplicateKeySafeLoader)
    except yaml.YAMLError as exc:
        if source and source not in str(exc):
            exc.args = (f"{source}: {exc}",)
        raise


def load_yaml_file(path: Path, *, encoding: str = "utf-8") -> Any:
    """Read and parse one YAML file with duplicate-key rejection."""

    return load_yaml_text(path.read_text(encoding=encoding), source=str(path))
