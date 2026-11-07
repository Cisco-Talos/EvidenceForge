"""Browser ownership follows executable, user data and live canonical state."""

import json
import random
import shlex
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.generation.activity.browser_instances import browser_instance_key
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml


@pytest.mark.parametrize(
    "platform,image,root",
    [
        (
            "macos",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Users/alex/Library/Application Support/Google/Chrome",
        ),
        (
            "windows",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Users\alex\AppData\Local\Google\Chrome\User Data",
        ),
        ("linux", "/usr/bin/google-chrome", "/home/alex/.config/google-chrome"),
    ],
)
def test_default_and_explicit_default_directories_share_only_one_browser(
    platform: str, image: str, root: str
) -> None:
    implicit = browser_instance_key(
        image, f'"{image}" --new-window https://example.test', platform, "alex"
    )
    explicit = browser_instance_key(
        image, f'"{image}" --user-data-dir="{root}" --profile-directory=Other', platform, "alex"
    )
    assert implicit is not None and implicit == explicit
    assert implicit != browser_instance_key(
        image, f'"{image}" --user-data-dir="{root}/independent"', platform, "alex"
    )
    assert (
        browser_instance_key(image, f'"{image}" --user-data-dir=relative', platform, "alex") is None
    )
    assert browser_instance_key(image, f'"{image}" --type=renderer', platform, "alex") is None


def test_posix_canonical_argv_preserves_explicit_profile_with_spaces() -> None:
    image = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    root = "/Users/alex/Library/Application Support/Google/Separate Chrome"
    key = browser_instance_key(
        image, shlex.join((image, f"--user-data-dir={root}")), "macos", "alex"
    )
    assert key == (image, root)
    assert key != browser_instance_key(image, shlex.join((image,)), "macos", "alex")
    assert (
        browser_instance_key(image, shlex.join((image, "--user-data-dir")), "macos", "alex") is None
    )


def test_firefox_profiles_and_explicit_independent_launches_remain_distinct() -> None:
    image = "/Applications/Firefox.app/Contents/MacOS/firefox"
    default = browser_instance_key(image, image, "macos", "alex")
    named = browser_instance_key(image, f'"{image}" -P work', "macos", "alex")
    assert default != named
    assert browser_instance_key(image, f'"{image}" -no-remote', "macos", "alex") is None


def test_native_mac_browsing_reuses_main_and_preserves_navigation_time_and_app_binding(
    tmp_path: Path,
) -> None:
    payload = load_yaml(Path("tests/fixtures/scenarios/macos-native-smoke.yaml"))
    payload["environment"]["deployment_overrides"][0]["user_applications"][0]["applications"] = [
        "macos-terminal",
        "chrome",
        "zoom",
    ]
    scenario = Scenario.model_validate(payload)
    engine = GenerationEngine(scenario, tmp_path)
    engine._chronological_es_delivery = True
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = scenario.environment.users[0], scenario.environment.systems[0]
        logon = generator.generate_logon(user, system, engine.start_time - timedelta(minutes=5))
        image = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        first_time = engine.start_time + timedelta(minutes=2)
        first = generator.generate_process(
            user, system, first_time, logon, image, f'"{image}" --new-window https://example.test'
        )
        later = first_time + timedelta(minutes=1)
        second = generator.generate_process(
            user, system, later, logon, image, f'"{image}" --new-window https://other.example.test'
        )
        assert first == second > 0
        assert engine.state_manager.get_process(system.hostname, first).last_activity_time == later
        session = engine.state_manager.get_session(logon)
        browser = engine.world_planner.ensure_connection_process(
            user, system, session, later, "ssl", random.Random(7), browser_intent=True
        )
        assert engine.state_manager.get_process(system.hostname, browser).image == image
        zoom = engine.world_planner.ensure_connection_process(
            user,
            system,
            session,
            later,
            "ssl",
            random.Random(7),
            application_ids=["zoom"],
            browser_intent=True,
        )
        assert engine.state_manager.get_process(system.hostname, zoom).image.endswith("/zoom.us")
        engine._finalize_macos_process_coverage()
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("application", ["edge", "macos-safari"])
def test_out_of_order_browser_requests_reuse_the_lifetime_active_at_their_time(
    tmp_path: Path, application: str
) -> None:
    from evidenceforge.events.process_outcome import PosixProcessExit

    payload = load_yaml(Path("tests/fixtures/scenarios/macos-native-smoke.yaml"))
    payload["environment"]["deployment_overrides"][0]["user_applications"][0]["applications"] = [
        "macos-terminal",
        application,
    ]
    engine = GenerationEngine(Scenario.model_validate(payload), tmp_path)
    engine._chronological_es_delivery = True
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        logon = generator.generate_logon(user, system, engine.start_time - timedelta(minutes=5))
        image = engine.deployment_registry.application_descriptor(application, "macos").image_path
        command = shlex.join((image,))
        first = generator.generate_process(
            user, system, engine.start_time + timedelta(minutes=2), logon, image, command
        )
        identity = engine.state_manager.get_process_identity(system.hostname, first)
        generator.generate_process_termination(
            user,
            system,
            engine.start_time + timedelta(minutes=10),
            first,
            image,
            logon,
            expected_process=identity,
            exit_outcome=PosixProcessExit(exit_code=0),
        )
        assert engine.state_manager.get_process(system.hostname, first) is None
        assert engine.state_manager.is_process_active_at(
            system.hostname, first, engine.start_time + timedelta(minutes=3)
        )
        historical = generator.generate_process(
            user, system, engine.start_time + timedelta(minutes=3), logon, image, command
        )
        assert historical == first
        another_logon = generator.generate_logon(
            user, system, engine.start_time + timedelta(minutes=4), allow_local_session_reuse=False
        )
        forwarded = generator.generate_process(
            user, system, engine.start_time + timedelta(minutes=5), another_logon, image, command
        )
        assert forwarded == first
        socket_time = engine.start_time + timedelta(minutes=5, seconds=1)
        connection_owner, connection_image = generator._ensure_user_connection_owner_process(
            source_system=system,
            time=socket_time,
            service="ssl",
            dst_port=443,
            os_category="macos",
            hostname="example.test",
            ssh_attempted_username=None,
            source_visible_by=socket_time,
            owner_spec=(image, command),
            session_info=(user, engine.state_manager.get_session(another_logon)),
        )
        assert (connection_owner, connection_image) == (first, image)
        generator.generate_connection(
            src_ip=system.ip,
            dst_ip="198.51.100.77",
            time=socket_time,
            dst_port=443,
            service="ssl",
            duration=0.05,
            pid=connection_owner,
            source_system=system,
            process_image=connection_image,
        )
        assert (
            engine.state_manager.get_process_identity_at(
                system.hostname, first, engine.start_time + timedelta(minutes=5)
            ).object_id
            == identity.object_id
        )
        fresh = generator.generate_process(
            user, system, engine.start_time + timedelta(minutes=11), another_logon, image, command
        )
        assert fresh > 0 and fresh != first
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.complete and census.aggregate_births == 0
    finally:
        engine._close_emitters()
    flows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
        if json.loads(line).get("object") == "FLOW"
    ]
    assert flows and all(row.get("pid") == first for row in flows)


def test_network_owner_browser_classification_preserves_helpers_and_independent_intent() -> None:
    from evidenceforge.generation.activity.browser_instances import browser_main_intent

    main = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    helper = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/155.0.8059.80/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
    assert browser_main_intent(main, shlex.join((main, "--new-instance")))
    assert browser_instance_key(main, shlex.join((main, "--new-instance")), "macos", "alex") is None
    assert not browser_main_intent(main, shlex.join((main, "--type=renderer")))
    assert not browser_main_intent(helper, shlex.join((helper, "--type=utility")))


@pytest.mark.parametrize("application", ["edge", "macos-safari"])
def test_pending_browser_root_defers_flexible_work_and_refuses_an_earlier_deadline(
    tmp_path: Path, application: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.unit.test_macos_finder_generation import _finder_engine

    engine = _finder_engine(tmp_path, monkeypatch, native=True, gui_application=application)
    try:
        from evidenceforge.config.provider import effective_config_scope

        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        logon = generator.generate_logon(user, system, engine.start_time - timedelta(minutes=5))
        image = engine.deployment_registry.application_descriptor(application, "macos").image_path
        command = shlex.join((image,))
        at = engine.start_time + timedelta(minutes=8)
        first = generator.generate_process(user, system, at, logon, image, command)
        earlier = engine.start_time + timedelta(minutes=2)
        bounded = generator.generate_process(
            user, system, earlier, logon, image, command, source_visible_by=earlier
        )
        assert bounded == 0
        flexible = generator.generate_process(user, system, earlier, logon, image, command)
        assert flexible == first > 0
        session = engine.state_manager.get_session(logon)
        ready = engine._baseline_browser_ready_time(
            system=system,
            user=user,
            session=session,
            pid=flexible,
            candidate_time=earlier,
            current_hour=engine.start_time,
            planned_logoffs=None,
        )
        identity = engine.state_manager.get_process_identity(system.hostname, first)
        assert ready > identity.execution_started_at
        assert engine.state_manager.is_process_active_at(system.hostname, first, ready)
        generator.generate_connection(
            src_ip=system.ip,
            dst_ip="198.51.100.77",
            time=ready,
            dst_port=443,
            service="ssl",
            duration=0.05,
            pid=first,
            source_system=system,
            process_image=image,
        )
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.complete and census.expected_forks == 1 and census.expected_execs == 2
    finally:
        engine._close_emitters()
    flows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
        if json.loads(line).get("object") == "FLOW"
    ]
    assert flows and all(row.get("pid") == first for row in flows)


def test_profile_traffic_plans_an_hour_before_committing_browser_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.config.provider import effective_config_scope
    from tests.unit.test_macos_finder_generation import _finder_engine

    engine = _finder_engine(tmp_path, monkeypatch, native=True, gui_application="edge")
    engine.scenario.baseline_activity.traffic_rates = {"persona_connections": [12, 12]}
    monkeypatch.setattr(
        "evidenceforge.generation.activity.traffic_profiles.get_role_connections", lambda *args: []
    )
    monkeypatch.setattr(
        "evidenceforge.generation.activity.traffic_profiles.get_persona_connections",
        lambda *args: [{"role": "_external", "port": 443, "service": "ssl", "weight": 1}],
    )
    monkeypatch.setattr(
        engine, "_resolve_role", lambda *args, **kwargs: ("198.51.100.77", "example.test")
    )
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        engine.activity_generator.generate_logon(
            user, system, engine.start_time - timedelta(minutes=5)
        )
        observed: list[datetime] = []
        original = engine.world_planner.ensure_connection_process

        def owner(**kwargs: Any) -> int:
            observed.append(kwargs["time"])
            return original(**kwargs)

        monkeypatch.setattr(engine.world_planner, "ensure_connection_process", owner)
        engine._generate_profile_traffic(
            engine.start_time, system, random.Random(42), "macos", {}, local_dt=engine.start_time
        )
        assert len(observed) >= 2 and observed == sorted(observed)
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.complete and census.expected_forks == 1 and census.expected_execs == 2
    finally:
        engine._close_emitters()
