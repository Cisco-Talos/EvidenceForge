"""Installer navigation must observe page transitions without queued double clicks."""

from scripts.verify_studio_windows import _MaintenanceNavigation


def test_each_native_page_advances_once_while_controls_change() -> None:
    navigation = _MaintenanceNavigation()
    assert navigation.advance(101, ["Welcome to EvidenceForge Studio Setup"], "next >")
    assert not navigation.advance(101, ["Welcome to EvidenceForge Studio Setup", "Ready"], "next >")
    assert not navigation.advance(101, [], "next >")
    assert navigation.advance(202, ["License agreement"], "i agree")
    assert not navigation.advance(202, ["License agreement", "MIT"], "i agree")
    assert not navigation.maintenance_seen


def test_unknown_or_initializing_scope_page_never_advances() -> None:
    navigation = _MaintenanceNavigation()
    assert not navigation.advance(101, [], "next >")
    assert not navigation.advance(101, [], "i agree")
    assert not navigation.advance(101, ["Choose what you want to do."], "next >")
    assert navigation.advance(101, ["Install / Reinstall (preserve user data)"], "next >")
    assert navigation.maintenance_seen
    assert not navigation.advance(202, [], "next >")
    assert not navigation.advance(202, ["Install for anyone using this computer"], "next >")
    assert not navigation.advance(202, ["Install for me", "Install for everyone"], "next >")


def test_unavailable_next_caption_does_not_consume_page_transition() -> None:
    navigation = _MaintenanceNavigation()
    content = ["Install / Reinstall (preserve user data)"]
    assert not navigation.advance(101, content, "")
    assert navigation.advance(101, content, "next >")
    assert not navigation.advance(101, content, "next >")
