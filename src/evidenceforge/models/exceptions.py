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


class ScenarioIncludeError(ConfigurationError):
    """Scenario include expansion failed.

    Raised when a scenario YAML file references invalid include syntax,
    missing include files, circular includes, or conflicting included fields.
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
