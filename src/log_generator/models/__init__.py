"""EvidenceForge data models.

This package contains all data models for the EvidenceForge project:
- Configuration models (Pydantic, immutable)
- Scenario models (Pydantic, validation)
- Runtime state models (dataclasses, mutable)
- Exception hierarchy
"""

from .config import AppConfig, AWSConfig, BedrockConfig, LoggingConfig, OutputConfig
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
    OutputSpec,
    Persona,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    Timezone,
    User,
)
from .state import ActiveSession, GeneratorState, OpenConnection, RunningProcess

__all__ = [
    # Config models
    "AppConfig",
    "AWSConfig",
    "BedrockConfig",
    "LoggingConfig",
    "OutputConfig",
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
    "Timezone",
    "OutputSpec",
    # State models
    "GeneratorState",
    "ActiveSession",
    "RunningProcess",
    "OpenConnection",
]
