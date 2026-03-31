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

"""Causal expansion engine for generating prerequisite events.

Centralizes the logic for emitting causally-related events (e.g., DNS before
connections, Kerberos before logons) into a composable, rule-based system.
"""

from evidenceforge.generation.causal.engine import (
    CausalExpansionEngine,
    ExpandedEvent,
    ExpansionContext,
)
from evidenceforge.generation.causal.registry import default_rules
from evidenceforge.generation.causal.rules import ExpansionRule
from evidenceforge.generation.causal.timing import TimingSpec

__all__ = [
    "CausalExpansionEngine",
    "ExpandedEvent",
    "ExpansionContext",
    "ExpansionRule",
    "TimingSpec",
    "default_rules",
]
