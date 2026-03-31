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

"""Tests for day-of-week variation in baseline generation."""

from evidenceforge.generation.engine.baseline import (
    _DAY_OF_WEEK_MULTIPLIERS,
    _WEEKEND_ACTIVE_PERSONAS,
    BaselineMixin,
)


class TestDayOfWeekMultipliers:
    def test_weekend_multipliers_near_zero(self):
        assert _DAY_OF_WEEK_MULTIPLIERS[5] < 0.1  # Saturday
        assert _DAY_OF_WEEK_MULTIPLIERS[6] < 0.1  # Sunday

    def test_monday_higher_than_thursday(self):
        assert _DAY_OF_WEEK_MULTIPLIERS[0] > _DAY_OF_WEEK_MULTIPLIERS[3]

    def test_friday_lower_than_midweek(self):
        assert _DAY_OF_WEEK_MULTIPLIERS[4] < _DAY_OF_WEEK_MULTIPLIERS[1]
        assert _DAY_OF_WEEK_MULTIPLIERS[4] < _DAY_OF_WEEK_MULTIPLIERS[2]

    def test_all_weekdays_present(self):
        for day in range(7):
            assert day in _DAY_OF_WEEK_MULTIPLIERS
            assert _DAY_OF_WEEK_MULTIPLIERS[day] > 0


class TestWorkHourMultiplierWithWeekday:
    def _make_mixin(self):
        """Create a minimal BaselineMixin instance for testing."""

        class FakeMixin(BaselineMixin):
            pass

        obj = object.__new__(FakeMixin)
        return obj

    def test_weekday_scales_work_hour_multiplier(self):
        mixin = self._make_mixin()
        whp = {"start": 9, "end": 17, "lunch": (12, 13), "peak_hours": []}

        # Tuesday at 10am (core work hours, base should be ~1.0)
        tue_mult = mixin._work_hour_multiplier(10, whp, weekday=1)
        # Saturday at 10am (same hour, but weekend scaling)
        sat_mult = mixin._work_hour_multiplier(10, whp, weekday=5)

        assert tue_mult > sat_mult * 5  # Tuesday should be much higher than Saturday

    def test_no_weekday_leaves_multiplier_unchanged(self):
        mixin = self._make_mixin()
        whp = {"start": 9, "end": 17, "lunch": (12, 13), "peak_hours": []}

        # Without weekday, should return base multiplier
        base = mixin._work_hour_multiplier(10, whp, weekday=None)
        # Should be close to 1.0 during core hours
        assert 0.9 <= base <= 1.1

    def test_monday_morning_boost(self):
        mixin = self._make_mixin()
        whp = {"start": 9, "end": 17, "lunch": (12, 13), "peak_hours": []}

        mon = mixin._work_hour_multiplier(10, whp, weekday=0)
        thu = mixin._work_hour_multiplier(10, whp, weekday=3)
        assert mon > thu  # Monday should be higher than Thursday


class TestWeekendActivePersonas:
    def test_sysadmin_active_on_weekends(self):
        assert "sysadmin" in _WEEKEND_ACTIVE_PERSONAS

    def test_security_analyst_active_on_weekends(self):
        assert "security_analyst" in _WEEKEND_ACTIVE_PERSONAS

    def test_developer_not_active_on_weekends(self):
        assert "developer" not in _WEEKEND_ACTIVE_PERSONAS

    def test_executive_not_active_on_weekends(self):
        assert "executive" not in _WEEKEND_ACTIVE_PERSONAS
