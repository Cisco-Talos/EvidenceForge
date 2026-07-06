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

"""Log emitters for generating output in various formats."""

from evidenceforge.generation.emitters.base import LogEmitter
from evidenceforge.generation.emitters.bash_history import BashHistoryEmitter
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.proxy import ProxyEmitter
from evidenceforge.generation.emitters.snort import SnortEmitter
from evidenceforge.generation.emitters.syslog import SyslogEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.web import WebEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.emitters.zeek_dhcp import ZeekDhcpEmitter
from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter
from evidenceforge.generation.emitters.zeek_ntp import ZeekNtpEmitter
from evidenceforge.generation.emitters.zeek_ocsp import ZeekOcspEmitter
from evidenceforge.generation.emitters.zeek_packet_filter import ZeekPacketFilterEmitter
from evidenceforge.generation.emitters.zeek_pe import ZeekPeEmitter
from evidenceforge.generation.emitters.zeek_reporter import ZeekReporterEmitter
from evidenceforge.generation.emitters.zeek_smtp import ZeekSmtpEmitter
from evidenceforge.generation.emitters.zeek_ssl import ZeekSslEmitter
from evidenceforge.generation.emitters.zeek_weird import ZeekWeirdEmitter
from evidenceforge.generation.emitters.zeek_x509 import ZeekX509Emitter

__all__ = [
    "LogEmitter",
    "CiscoAsaEmitter",
    "WindowsEventEmitter",
    "ZeekEmitter",
    "SensorMultiplexEmitter",
    "ZeekDnsEmitter",
    "ZeekHttpEmitter",
    "ZeekSmtpEmitter",
    "ZeekSslEmitter",
    "ZeekFilesEmitter",
    "ZeekDhcpEmitter",
    "ZeekNtpEmitter",
    "ZeekWeirdEmitter",
    "ZeekX509Emitter",
    "ZeekOcspEmitter",
    "ZeekPeEmitter",
    "ZeekPacketFilterEmitter",
    "ZeekReporterEmitter",
    "EcarEmitter",
    "SyslogEmitter",
    "BashHistoryEmitter",
    "ProxyEmitter",
    "SnortEmitter",
    "SysmonEventEmitter",
    "WebEmitter",
]
