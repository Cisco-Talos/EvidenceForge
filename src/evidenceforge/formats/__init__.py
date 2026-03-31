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

"""Format definitions package.

Provides declarative YAML-based log format definitions with comprehensive validation.
"""

from .format_def import (
    FieldConstraint,
    FieldDefinition,
    FieldType,
    FormatDefinition,
    OutputTemplate,
)
from .loader import clear_cache, get_format, load_all_formats, load_format
from .validator import ValidationResult, validate_event, validate_field

__all__ = [
    # Core models
    "FieldType",
    "FieldConstraint",
    "FieldDefinition",
    "OutputTemplate",
    "FormatDefinition",
    # Loader functions
    "load_format",
    "load_all_formats",
    "get_format",
    "clear_cache",
    # Validator functions
    "validate_field",
    "validate_event",
    "ValidationResult",
]
