# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Supported evaluation-corpus capacity envelope."""

from pydantic import BaseModel, ConfigDict, Field


class EvaluationLimits(BaseModel):
    """Default limits that bound the evaluator's retained parsed corpus."""

    max_corpus_bytes: int = Field(default=512 * 1024 * 1024, gt=0)
    max_files: int = Field(default=10_000, gt=0)
    max_records: int = Field(default=500_000, gt=0)

    model_config = ConfigDict(frozen=True, extra="forbid")


class EvaluationCapacity(BaseModel):
    """Measured input counters for one evaluation run."""

    files: int
    corpus_bytes: int
    parsed_records: int = 0
    limits_overridden: bool = False

    model_config = ConfigDict(frozen=True, extra="forbid")
