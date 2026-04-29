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

"""Canonical event model for cross-log consistency by construction.

This package provides the intermediate representation layer between
ActivityGenerator (which builds events) and emitters (which render them).
"""

from evidenceforge.events.base import RawLogEntry, SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    FileContext,
    HostContext,
    IdsContext,
    ImageLoadContext,
    KerberosContext,
    NetworkContext,
    ProcessAccessContext,
    ProcessContext,
    RawContext,
    RegistryContext,
    ShellContext,
)

__all__ = [
    "SecurityEvent",
    "RawLogEntry",
    "HostContext",
    "AuthContext",
    "ProcessContext",
    "ProcessAccessContext",
    "NetworkContext",
    "DnsContext",
    "FileContext",
    "RegistryContext",
    "IdsContext",
    "ImageLoadContext",
    "KerberosContext",
    "ShellContext",
    "RawContext",
]
