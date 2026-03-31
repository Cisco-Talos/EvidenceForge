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

"""Tests for work hours parsing utility.

Phase 2.4: Tests parse_work_hours() function for temporal activity distribution.
"""

import pytest

from evidenceforge.utils.time import parse_work_hours


class TestParseWorkHours:
    """Tests for parse_work_hours() function."""

    def test_basic_work_hours(self):
        """Test basic 9am-5pm parsing."""
        result = parse_work_hours("9am-5pm")

        assert result["start"] == 9
        assert result["end"] == 17
        assert result["lunch"] is None
        assert result["hours"] == [9, 10, 11, 12, 13, 14, 15, 16]
        assert 10 in result["peak_hours"]  # Mid-morning
        assert 11 in result["peak_hours"]
        assert 14 in result["peak_hours"]  # Mid-afternoon
        assert 15 in result["peak_hours"]

    def test_work_hours_with_lunch(self):
        """Test work hours parsing with lunch break."""
        result = parse_work_hours("9am-5pm (lunch 12pm-1pm)")

        assert result["start"] == 9
        assert result["end"] == 17
        assert result["lunch"] == (12, 13)
        # Lunch hour excluded
        assert result["hours"] == [9, 10, 11, 13, 14, 15, 16]
        assert 12 not in result["hours"]
        # Peak hours should not include lunch
        assert 12 not in result["peak_hours"]

    def test_half_hours(self):
        """Test half-hour parsing (8:30am-5:30pm)."""
        result = parse_work_hours("8:30am-5:30pm")

        assert result["start"] == 8.5
        assert result["end"] == 17.5
        assert result["lunch"] is None
        # Hours are still integer hours
        assert result["hours"] == [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]

    def test_early_morning_shift(self):
        """Test early morning shift (6am-2pm)."""
        result = parse_work_hours("6am-2pm")

        assert result["start"] == 6
        assert result["end"] == 14
        assert result["hours"] == [6, 7, 8, 9, 10, 11, 12, 13]

    def test_afternoon_shift(self):
        """Test afternoon shift (2pm-10pm)."""
        result = parse_work_hours("2pm-10pm")

        assert result["start"] == 14
        assert result["end"] == 22
        assert result["hours"] == [14, 15, 16, 17, 18, 19, 20, 21]

    def test_lunch_with_half_hours(self):
        """Test lunch break with half-hour times."""
        result = parse_work_hours("8:30am-5:30pm (lunch 12:30pm-1:30pm)")

        assert result["start"] == 8.5
        assert result["end"] == 17.5
        assert result["lunch"] == (12.5, 13.5)
        # Integer hours: 12 and 13 are excluded (lunch overlaps with both)
        assert 12 not in result["hours"]  # Overlaps with lunch start
        assert 13 not in result["hours"]  # Overlaps with lunch end
        # Hours before and after lunch are included
        assert 11 in result["hours"]
        assert 14 in result["hours"]

    def test_short_workday(self):
        """Test short 4-hour workday."""
        result = parse_work_hours("9am-1pm")

        assert result["start"] == 9
        assert result["end"] == 13
        assert result["hours"] == [9, 10, 11, 12]
        # Peak hours for short day
        assert len(result["peak_hours"]) > 0

    def test_long_workday(self):
        """Test long 12-hour workday."""
        result = parse_work_hours("7am-7pm")

        assert result["start"] == 7
        assert result["end"] == 19
        assert result["hours"] == [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
        assert len(result["peak_hours"]) == 4  # 2 morning + 2 afternoon

    def test_twelve_noon(self):
        """Test 12pm (noon) parsing."""
        result = parse_work_hours("8am-12pm")

        assert result["start"] == 8
        assert result["end"] == 12
        assert result["hours"] == [8, 9, 10, 11]

    def test_twelve_midnight(self):
        """Test 12am (midnight) parsing."""
        result = parse_work_hours("12am-8am")

        assert result["start"] == 0
        assert result["end"] == 8
        assert result["hours"] == [0, 1, 2, 3, 4, 5, 6, 7]

    def test_case_insensitive(self):
        """Test that AM/PM are case-insensitive."""
        result1 = parse_work_hours("9AM-5PM")
        result2 = parse_work_hours("9am-5pm")
        result3 = parse_work_hours("9Am-5Pm")

        assert result1["start"] == result2["start"] == result3["start"] == 9
        assert result1["end"] == result2["end"] == result3["end"] == 17

    def test_whitespace_tolerance(self):
        """Test tolerance for extra whitespace."""
        result1 = parse_work_hours("9am - 5pm")
        result2 = parse_work_hours("9am-5pm")
        result3 = parse_work_hours("  9am  -  5pm  ")

        assert result1["start"] == result2["start"] == result3["start"] == 9
        assert result1["end"] == result2["end"] == result3["end"] == 17

    def test_invalid_format_no_dash(self):
        """Test invalid format without dash."""
        with pytest.raises(ValueError, match="Invalid work hours format"):
            parse_work_hours("9am 5pm")

    def test_invalid_format_bad_time(self):
        """Test invalid time format."""
        with pytest.raises(ValueError):
            parse_work_hours("25am-5pm")

    def test_invalid_format_empty(self):
        """Test empty string."""
        with pytest.raises(ValueError):
            parse_work_hours("")

    def test_peak_hours_excludes_lunch(self):
        """Test that peak hours calculation excludes lunch period."""
        result = parse_work_hours("9am-5pm (lunch 11am-12pm)")

        # Lunch is 11-12, so if 11 would be peak, it should be excluded
        assert result["lunch"] == (11, 12)
        assert 11 not in result["hours"]
        assert 11 not in result["peak_hours"]

    def test_quarter_hours(self):
        """Test quarter-hour parsing (e.g., 8:15am, 5:45pm)."""
        result = parse_work_hours("8:15am-5:45pm")

        assert result["start"] == 8.25
        assert result["end"] == 17.75
        # Hours still integer
        assert result["hours"] == [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
