# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""EvidenceForge data models.

This package contains all data models for the EvidenceForge project:
- Scenario models (Pydantic, validation)
- Runtime state models (dataclasses, mutable)
- Exception hierarchy
"""

from .exceptions import (
    ConfigurationError,
    EvidenceForgeError,
    GenerationError,
    InsufficientDiskSpaceError,
    SchemaValidationError,
    SemanticValidationError,
    StateError,
    ValidationError,
)
from .scenario import (
    BaselineActivity,
    Environment,
    Group,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    OutputSpec,
    Persona,
    RedHerringEvent,
    Scenario,
    StaleAccount,
    StorylineEvent,
    System,
    TimeWindow,
    Timezone,
    User,
)
from .state import ActiveSession, GeneratorState, OpenConnection, RunningProcess

__all__ = [
    # Exception hierarchy
    "EvidenceForgeError",
    "ValidationError",
    "SchemaValidationError",
    "SemanticValidationError",
    "ConfigurationError",
    "GenerationError",
    "StateError",
    "InsufficientDiskSpaceError",
    # Scenario models
    "Scenario",
    "TimeWindow",
    "Environment",
    "User",
    "System",
    "Group",
    "Persona",
    "BaselineActivity",
    "StorylineEvent",
    "RedHerringEvent",
    "StaleAccount",
    "Timezone",
    "OutputSpec",
    "NetworkSegment",
    "NetworkSensor",
    "NetworkConfig",
    # State models
    "GeneratorState",
    "ActiveSession",
    "RunningProcess",
    "OpenConnection",
]
