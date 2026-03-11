"""Custom exceptions for EvidenceForge.

This module defines the exception hierarchy used throughout the application
for clear, structured error handling.
"""


class EvidenceForgeError(Exception):
    """Base exception for all EvidenceForge errors."""


class ValidationError(EvidenceForgeError):
    """Base validation error.

    Raised when input data fails validation checks, either schema-based
    or semantic validation.
    """


class SchemaValidationError(ValidationError):
    """Pydantic schema validation failed.

    Raised when input fails Pydantic model validation (type errors,
    missing required fields, pattern mismatches, etc.).
    """


class SemanticValidationError(ValidationError):
    """LLM-based semantic validation failed.

    Raised when input passes schema validation but fails semantic
    consistency checks (e.g., user references non-existent system,
    timeline doesn't make sense, etc.).

    Note: This is implemented in Phase 2+. Phase 1 only has schema validation.
    """


class ConfigurationError(EvidenceForgeError):
    """Configuration file loading or parsing failed.

    Raised when config.yaml or .env files cannot be loaded, parsed,
    or contain invalid values.
    """


class FormatDefinitionError(ConfigurationError):
    """Format definition loading or validation failed.

    Raised when a format definition YAML file cannot be loaded,
    parsed, or is invalid according to the FormatDefinition schema.
    """


class GenerationError(EvidenceForgeError):
    """Error during log generation.

    Base class for errors that occur during the log generation process.
    """


class StateError(GenerationError):
    """Invalid state during generation.

    Raised when the generation engine encounters an impossible or
    inconsistent state (e.g., process without parent, session without logon).
    """


class InsufficientDiskSpaceError(GenerationError):
    """Insufficient disk space for output.

    Raised when the output directory lacks the required disk space
    for the estimated log dataset size.
    """
