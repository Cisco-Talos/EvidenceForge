"""Tests for network visibility engine.

Phase 2.5: Tests NetworkVisibilityEngine for sensor-based connection filtering.
"""

from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.scenario import (
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    System,
)


def _make_systems():
    """Create test systems across multiple subnets."""
    return [
        System(hostname="WS-01", ip="10.10.10.1", os="Windows 10", type="workstation"),
        System(hostname="WS-02", ip="10.10.10.2", os="Windows 10", type="workstation"),
        System(hostname="SRV-01", ip="10.10.30.1", os="Windows Server 2019", type="server"),
        System(hostname="SRV-02", ip="10.10.30.2", os="Linux Ubuntu 22.04", type="server"),
        System(hostname="DMZ-01", ip="10.10.50.1", os="Linux Ubuntu 22.04", type="server"),
    ]


def _make_config(segments, sensors):
    """Helper to create NetworkConfig."""
    return NetworkConfig(segments=segments, sensors=sensors)


class TestNoNetworkConfig:
    """Tests for backward compatibility when no network config is provided."""

    def test_no_config_all_visible(self):
        """All connections should be visible when no network config."""
        engine = NetworkVisibilityEngine(None, [])
        assert engine.is_connection_visible("10.0.0.1", "10.0.0.2") is True
        assert engine.is_connection_visible("192.168.1.1", "8.8.8.8") is True

    def test_no_config_default_formats(self):
        """Default log formats should include all Zeek formats when no config."""
        engine = NetworkVisibilityEngine(None, [])
        formats = engine.get_log_formats_for_connection("10.0.0.1", "8.8.8.8")
        assert "zeek_conn" in formats
        assert "zeek_dns" in formats
        assert "zeek_http" in formats
        assert "zeek_ssl" in formats

    def test_no_config_no_observing_sensors(self):
        """No observing sensors when no config."""
        engine = NetworkVisibilityEngine(None, [])
        assert engine.get_observing_sensors("10.0.0.1", "8.8.8.8") == []


class TestBidirectionalSensor:
    """Tests for bidirectional sensor monitoring."""

    def _make_engine(self):
        systems = _make_systems()
        config = _make_config(
            segments=[
                NetworkSegment(
                    name="workstations", cidr="10.10.10.0/24", systems=["WS-01", "WS-02"]
                ),
                NetworkSegment(name="servers", cidr="10.10.30.0/24", systems=["SRV-01", "SRV-02"]),
            ],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="ws-tap",
                    monitoring_segments=["workstations"],
                    direction="bidirectional",
                    log_formats=["zeek"],
                ),
            ],
        )
        return NetworkVisibilityEngine(config, systems)

    def test_workstation_to_external_visible(self):
        """Workstation → external should be visible (src in monitored segment)."""
        engine = self._make_engine()
        assert engine.is_connection_visible("10.10.10.1", "8.8.8.8") is True

    def test_external_to_workstation_visible(self):
        """External → workstation should be visible (dst in monitored segment)."""
        engine = self._make_engine()
        assert engine.is_connection_visible("8.8.8.8", "10.10.10.1") is True

    def test_server_to_external_not_visible(self):
        """Server → external should NOT be visible (sensor only on workstations)."""
        engine = self._make_engine()
        assert engine.is_connection_visible("10.10.30.1", "8.8.8.8") is False

    def test_workstation_to_server_visible(self):
        """Workstation → server should be visible (src in monitored segment)."""
        engine = self._make_engine()
        assert engine.is_connection_visible("10.10.10.1", "10.10.30.1") is True

    def test_intra_segment_visible(self):
        """Traffic within monitored segment should be visible."""
        engine = self._make_engine()
        assert engine.is_connection_visible("10.10.10.1", "10.10.10.2") is True

    def test_external_to_external_not_visible(self):
        """External → external should NOT be visible."""
        engine = self._make_engine()
        assert engine.is_connection_visible("8.8.8.8", "1.1.1.1") is False


class TestDirectionFiltering:
    """Tests for outbound-only and inbound-only sensors."""

    def _make_engine(self, direction):
        systems = _make_systems()
        config = _make_config(
            segments=[
                NetworkSegment(
                    name="workstations", cidr="10.10.10.0/24", systems=["WS-01", "WS-02"]
                ),
            ],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="sensor",
                    monitoring_segments=["workstations"],
                    direction=direction,
                    log_formats=["zeek"],
                ),
            ],
        )
        return NetworkVisibilityEngine(config, systems)

    def test_outbound_src_in_segment_visible(self):
        """Outbound sensor: src in segment → visible."""
        engine = self._make_engine("outbound")
        assert engine.is_connection_visible("10.10.10.1", "8.8.8.8") is True

    def test_outbound_dst_in_segment_not_visible(self):
        """Outbound sensor: dst in segment → NOT visible."""
        engine = self._make_engine("outbound")
        assert engine.is_connection_visible("8.8.8.8", "10.10.10.1") is False

    def test_inbound_dst_in_segment_visible(self):
        """Inbound sensor: dst in segment → visible."""
        engine = self._make_engine("inbound")
        assert engine.is_connection_visible("8.8.8.8", "10.10.10.1") is True

    def test_inbound_src_in_segment_not_visible(self):
        """Inbound sensor: src in segment → NOT visible."""
        engine = self._make_engine("inbound")
        assert engine.is_connection_visible("10.10.10.1", "8.8.8.8") is False


class TestMultiSensorMultiFormat:
    """Tests for multiple sensors with different formats."""

    def _make_engine(self):
        systems = _make_systems()
        config = _make_config(
            segments=[
                NetworkSegment(
                    name="workstations", cidr="10.10.10.0/24", systems=["WS-01", "WS-02"]
                ),
                NetworkSegment(name="servers", cidr="10.10.30.0/24", systems=["SRV-01", "SRV-02"]),
                NetworkSegment(name="dmz", cidr="10.10.50.0/24", systems=["DMZ-01"]),
            ],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="core-tap",
                    monitoring_segments=["workstations", "servers"],
                    direction="bidirectional",
                    log_formats=["zeek"],
                ),
                NetworkSensor(
                    type="ids",
                    name="perimeter-ids",
                    monitoring_segments=["dmz"],
                    direction="inbound",
                    log_formats=["snort_alert"],
                ),
                NetworkSensor(
                    type="network",
                    name="dmz-tap",
                    monitoring_segments=["dmz"],
                    direction="bidirectional",
                    log_formats=["zeek"],
                ),
            ],
        )
        return NetworkVisibilityEngine(config, systems)

    def test_workstation_to_external_zeek_only(self):
        """Workstation → external: only core-tap sees it → zeek formats."""
        engine = self._make_engine()
        formats = engine.get_log_formats_for_connection("10.10.10.1", "8.8.8.8")
        assert "zeek_conn" in formats

    def test_external_to_dmz_zeek_and_snort(self):
        """External → DMZ: perimeter-ids (inbound, snort) + dmz-tap (bidir, zeek)."""
        engine = self._make_engine()
        formats = engine.get_log_formats_for_connection("8.8.8.8", "10.10.50.1")
        assert "zeek_conn" in formats and "snort_alert" in formats

    def test_dmz_to_external_zeek_only(self):
        """DMZ → external: perimeter-ids is inbound-only (no), dmz-tap bidir (yes)."""
        engine = self._make_engine()
        formats = engine.get_log_formats_for_connection("10.10.50.1", "8.8.8.8")
        assert "zeek_conn" in formats

    def test_server_to_dmz_all_formats(self):
        """Server → DMZ: core-tap (servers bidir, zeek) + perimeter-ids (dmz inbound, snort) + dmz-tap (dmz bidir, zeek)."""
        engine = self._make_engine()
        formats = engine.get_log_formats_for_connection("10.10.30.1", "10.10.50.1")
        assert "zeek_conn" in formats and "snort_alert" in formats

    def test_invisible_connection_empty_formats(self):
        """Connection not seen by any sensor should return empty formats."""
        engine = self._make_engine()
        # External to external: no sensor sees it
        formats = engine.get_log_formats_for_connection("8.8.8.8", "1.1.1.1")
        assert formats == set()

    def test_multiple_observing_sensors(self):
        """Should return all sensors that observe a connection."""
        engine = self._make_engine()
        sensors = engine.get_observing_sensors("8.8.8.8", "10.10.50.1")
        sensor_names = {s.name for s in sensors}
        assert "perimeter-ids" in sensor_names
        assert "dmz-tap" in sensor_names
        assert "core-tap" not in sensor_names


class TestCIDRAutoInference:
    """Tests for auto-inferring segment membership from CIDR."""

    def test_auto_infer_from_cidr(self):
        """Systems without explicit segment list should be inferred from CIDR."""
        systems = _make_systems()
        config = _make_config(
            segments=[
                # No explicit systems list - infer from CIDR
                NetworkSegment(name="workstations", cidr="10.10.10.0/24"),
                NetworkSegment(name="servers", cidr="10.10.30.0/24"),
            ],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="sensor",
                    monitoring_segments=["workstations"],
                    direction="bidirectional",
                    log_formats=["zeek"],
                ),
            ],
        )
        engine = NetworkVisibilityEngine(config, systems)

        # WS-01 (10.10.10.1) auto-inferred into workstations
        assert engine.is_connection_visible("10.10.10.1", "8.8.8.8") is True
        # SRV-01 (10.10.30.1) not in workstations
        assert engine.is_connection_visible("10.10.30.1", "8.8.8.8") is False

    def test_unmapped_ip_checked_against_cidr(self):
        """IPs not pre-mapped should fall back to CIDR containment check."""
        systems = _make_systems()
        config = _make_config(
            segments=[
                NetworkSegment(
                    name="workstations", cidr="10.10.10.0/24", systems=["WS-01"]
                ),  # Only WS-01 explicit
            ],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="sensor",
                    monitoring_segments=["workstations"],
                    direction="bidirectional",
                    log_formats=["zeek"],
                ),
            ],
        )
        engine = NetworkVisibilityEngine(config, systems)

        # 10.10.10.99 not in systems list but in CIDR → should be visible
        assert engine.is_connection_visible("10.10.10.99", "8.8.8.8") is True
        # 10.10.20.1 not in CIDR → not visible
        assert engine.is_connection_visible("10.10.20.1", "8.8.8.8") is False


class TestTapVsSpanPlacement:
    """Tests for TAP vs SPAN sensor placement."""

    def _make_engine(self, placement):
        systems = _make_systems()
        config = _make_config(
            segments=[
                NetworkSegment(
                    name="workstations", cidr="10.10.10.0/24", systems=["WS-01", "WS-02"]
                ),
                NetworkSegment(name="servers", cidr="10.10.30.0/24", systems=["SRV-01", "SRV-02"]),
            ],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="sensor",
                    monitoring_segments=["workstations"],
                    direction="bidirectional",
                    placement=placement,
                    log_formats=["zeek"],
                ),
            ],
        )
        return NetworkVisibilityEngine(config, systems)

    def test_span_sees_intra_segment(self):
        """SPAN sensor sees desktop→desktop (intra-segment) traffic."""
        engine = self._make_engine("span")
        assert engine.is_connection_visible("10.10.10.1", "10.10.10.2") is True

    def test_tap_skips_intra_segment(self):
        """TAP sensor does NOT see desktop→desktop (intra-segment) traffic."""
        engine = self._make_engine("tap")
        assert engine.is_connection_visible("10.10.10.1", "10.10.10.2") is False

    def test_tap_sees_cross_segment(self):
        """TAP sensor sees desktop→server (cross-segment) traffic."""
        engine = self._make_engine("tap")
        assert engine.is_connection_visible("10.10.10.1", "10.10.30.1") is True

    def test_tap_sees_to_external(self):
        """TAP sensor sees desktop→external traffic."""
        engine = self._make_engine("tap")
        assert engine.is_connection_visible("10.10.10.1", "8.8.8.8") is True
