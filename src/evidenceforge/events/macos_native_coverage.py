# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded native coverage diagnostics derived from committed canonical cohorts."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NativePhase = Literal["aggregate_birth", "fork", "exec", "exit"]
NativeReason = Literal[
    "supported",
    "not_recorded",
    "aggregate_birth_only",
    "entitlements_unknown",
    "entitlements_present",
    "descriptors_unknown",
    "thread_replacement_unknown",
    "exit_outcome_unknown",
]


class MacosNativeCoverageCount(BaseModel):
    """One counted source decision with its independent qualification reason."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    phase: NativePhase
    reason: NativeReason
    status: Literal["visible", "delayed", "dropped", "filtered", "out_of_window"]
    count: int = Field(gt=0)


class MacosNativeActionCoverage(BaseModel):
    """Source-phase coverage for one authored storyline cluster."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    storyline_cluster_id: str
    observations: tuple[MacosNativeCoverageCount, ...]


class MacosNativeHostCoverage(BaseModel):
    """Accounted canonical process phases on one profiled host."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    hostname: str
    source_profile: str
    observations: tuple[MacosNativeCoverageCount, ...]
    authored_actions: tuple[MacosNativeActionCoverage, ...] = ()


class MacosNativeCoverage(BaseModel):
    """Coverage is a workload diagnostic, separate from native reference qualification."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    scope: Literal["exact_process_cohorts_and_authored_births"] = (
        "exact_process_cohorts_and_authored_births"
    )
    hosts: tuple[MacosNativeHostCoverage, ...] = ()
