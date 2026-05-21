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

"""Unit tests for activity helper utilities."""

from random import Random

from evidenceforge.generation.activity.helpers import _parameterize_command


def test_parameterize_command_replaces_linux_query_placeholders() -> None:
    """Linux query placeholders should resolve to concrete command content."""
    rng = Random(1234)

    mysql_cmd = _parameterize_command(rng, "mysql --defaults-extra-file=~/.my.cnf {mysql_db}")
    psql_cmd = _parameterize_command(rng, "psql -U postgres -d {psql_db}")
    redis_cmd = _parameterize_command(rng, "{redis_cmd}")

    assert "{mysql_db}" not in mysql_cmd
    assert "{psql_db}" not in psql_cmd
    assert "{redis_cmd}" not in redis_cmd


def test_parameterize_command_uses_c_source_for_gcc() -> None:
    """GCC templates should not compile Python or JavaScript placeholders."""
    rng = Random(42)

    cmd = _parameterize_command(rng, "gcc -o output {c_source_file}")

    assert "{c_source_file}" not in cmd
    assert cmd.endswith(".c")
