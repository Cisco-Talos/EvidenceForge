# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Integration tests: spillage generates varied credentials across surfaces with
accurate ground truth, passes `eforge eval`, and validates safely."""

import datetime
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.config.secret_families import get_family
from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml
from evidenceforge.validation import ScenarioValidator

runner = CliRunner()


def _generate(scenario_data: dict, out: Path) -> Path:
    GenerationEngine(Scenario(**scenario_data), out).generate()
    return out


def _read(out: Path, pattern: str) -> str:
    matches = list(out.rglob(pattern))
    assert matches, f"no file matching {pattern} under {out}"
    return matches[0].read_text()


_NON_LOG = (
    "COLLECTION_PROFILE",
    "GROUND_TRUTH",
    "OBSERVATION_MANIFEST",
    "OUTPUT_TARGET",
    "generation.log",
)


def _data_files(out: Path) -> list[Path]:
    return [
        p for p in out.rglob("*") if p.is_file() and not any(p.name.startswith(s) for s in _NON_LOG)
    ]


def _all_data_text(out: Path) -> str:
    return "\n".join(p.read_text(errors="replace") for p in _data_files(out))


def _document(out: Path) -> dict:
    return json.loads((out / "GROUND_TRUTH.json").read_text())


def _flatten_event(event: dict, *, schema_version: int) -> dict:
    record = {k: v for k, v in event.items() if k != "attributes"}
    record["type"] = record["kind"]
    record["schema_version"] = schema_version
    record.update(event.get("attributes", {}))
    return record


def _records(out: Path) -> list[dict]:
    document = _document(out)
    return [
        _flatten_event(event, schema_version=document["schema_version"])
        for event in document["events"]
    ]


def _records_or_empty(out: Path) -> list[dict]:
    p = out / "GROUND_TRUTH.json"
    return _records(out) if p.exists() else []


def _spill_records(out: Path) -> list[dict]:
    return [record for record in _records(out) if record.get("kind") == "spillage"]


def _spill_records_or_empty(out: Path) -> list[dict]:
    return [record for record in _records_or_empty(out) if record.get("kind") == "spillage"]


def _iso(epoch: int) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_windows_log(file_path: Path) -> list[dict]:
    with open(file_path) as f:
        content = f.read()

    root = ET.fromstring(content if "<Events>" in content else f"<Events>{content}</Events>")
    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

    events = []
    for event_elem in root.findall("ns:Event", ns):
        event: dict[str, str | datetime.datetime] = {}
        system = event_elem.find("ns:System", ns)
        if system is not None:
            event["EventID"] = system.findtext("ns:EventID", namespaces=ns) or ""
            time_created = system.find("ns:TimeCreated", ns)
            if time_created is not None:
                time_str = time_created.get("SystemTime")
                if time_str:
                    event["TimeCreated"] = datetime.datetime.fromisoformat(
                        time_str.replace("Z", "+00:00")
                    )
            event["Computer"] = system.findtext("ns:Computer", namespaces=ns) or ""

        event_data = event_elem.find("ns:EventData", ns)
        if event_data is not None:
            for data in event_data.findall("ns:Data", ns):
                name = data.get("Name")
                if name:
                    event[name] = data.text or ""

        events.append(event)

    return events


def _ecar_records(out: Path) -> list[dict]:
    rows: list[dict] = []
    for path in out.rglob("ecar.json"):
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


@pytest.fixture
def spillage_scenario(scenarios_dir: Path) -> dict:
    return load_yaml(scenarios_dir / "spillage.yaml")


class TestSpillageGeneration:
    def test_every_label_lands_on_disk(self, spillage_scenario, tmp_path):
        out = _generate(spillage_scenario, tmp_path / "out")
        corpus = _all_data_text(out)
        for rec in _records(out):
            # No phantom labels: every ground-truth credential is actually present.
            assert rec["rendered_value"] in corpus, f"missing on disk: {rec['record_id']}"

    def test_ground_truth_shape_and_regex(self, spillage_scenario, tmp_path):
        out = _generate(spillage_scenario, tmp_path / "out")
        recs = _records(out)
        assert len(recs) == 8
        assert {r["surface"] for r in recs} == {
            "shell_history",
            "process_command_line",
            "syslog_message",
            "http_request_url",
            "http_referrer",
        }
        for r in recs:
            assert r["kind"] == "spillage" and r["schema_version"] == 1
            assert r["surface"] in (
                "shell_history",
                "process_command_line",
                "syslog_message",
                "http_request_url",
                "http_referrer",
            )
            if r["family"]:  # synthesized values match their family regex
                rx = get_family(r["family"])["regex"]
                assert re.search(rx, r["value"]), f"{r['family']}: {r['value']!r} !~ {rx}"

    def test_values_are_varied_not_repeated_literals(self, spillage_scenario, tmp_path):
        out = _generate(spillage_scenario, tmp_path / "out")
        recs = _records(out)
        # Every spill is a distinct credential (the two aws_iam events differ too).
        assert len({r["rendered_value"] for r in recs}) == len(recs)
        aws = [r["value"] for r in recs if r["family"] == "aws_iam"]
        assert len(aws) == 2 and aws[0] != aws[1]

    def test_md_does_not_splash_full_secret(self, spillage_scenario, tmp_path):
        out = _generate(spillage_scenario, tmp_path / "out")
        md = (out / "GROUND_TRUTH.md").read_text()
        for rec in _records(out):
            assert rec["value"] not in md  # only redacted preview + hash in the human report

    def test_generation_is_deterministic(self, spillage_scenario, tmp_path):
        a = _generate(spillage_scenario, tmp_path / "a")
        b = _generate(spillage_scenario, tmp_path / "b")
        assert (a / "GROUND_TRUTH.json").read_text() == (b / "GROUND_TRUTH.json").read_text()

    def test_window_edge_shell_spill_is_not_a_phantom_label(self, tmp_path):
        # A shell_history spill whose dwell-shifted time lands past the scenario
        # window emits no bash line; the canonical document must mark it as not emitted rather
        # than claiming the value landed on disk.
        scenario = dict(_linux_scenario([]))
        scenario["time_window"] = {"start": "2024-03-18T14:00:00Z", "duration": "1h"}
        scenario["storyline"] = [
            {
                "id": "edge-spill",
                "time": "+59m59s",
                "actor": "nina",
                "system": "APP-SRV-01",
                "activity": "edge spill",
                "events": [{"type": "spillage", "surface": "shell_history", "family": "aws_iam"}],
            }
        ]
        out = _generate(scenario, tmp_path / "out")
        corpus = _all_data_text(out)
        recs = _spill_records_or_empty(out)
        assert len(recs) == 1
        assert recs[0]["kind"] == "spillage"
        # No phantom: skipped labels are explicit, and emitted labels still land on disk.
        if recs[0]["emitted"]:
            assert recs[0]["rendered_value"] in corpus, f"phantom label: {recs[0]['record_id']}"
        else:
            assert recs[0]["skipped_reason"]
            assert "rendered_value" not in recs[0]

    def test_overwrite_without_spills_replaces_canonical_ground_truth(self, tmp_path):
        # The canonical GROUND_TRUTH.json file participates in the CLI overwrite
        # swap and remains present even for baseline-only runs.
        import yaml

        out = tmp_path / "out"
        spill = _linux_scenario(
            [
                {
                    "type": "spillage",
                    "surface": "syslog_message",
                    "value": "EvidenceForgeFake_STALE_v1",
                }
            ]
        )
        p1 = tmp_path / "spill.yaml"
        p1.write_text(yaml.safe_dump(spill))
        r1 = runner.invoke(app, ["generate", str(p1), "--output", str(out), "--force"])
        assert r1.exit_code == 0, r1.output
        assert (out / "GROUND_TRUTH.json").exists()  # canonical document written for the spill run

        nospill = _linux_scenario([])  # empty storyline — canonical document still exists
        p2 = tmp_path / "nospill.yaml"
        p2.write_text(yaml.safe_dump(nospill))
        r2 = runner.invoke(app, ["generate", str(p2), "--output", str(out), "--force"])
        assert r2.exit_code == 0, r2.output
        assert (out / "GROUND_TRUTH.json").exists()


class TestSpillageEval:
    def test_eval_acceptance_passes(self, spillage_scenario, tmp_path):
        out = _generate(spillage_scenario, tmp_path / "out")
        report = EvaluationEngine(output_dir=out, scenario=Scenario(**spillage_scenario)).run()
        hard = [c for c in report.acceptance_criteria if c.level == "hard"]
        assert hard and all(c.passed for c in hard), [
            (c.name, c.actual) for c in hard if not c.passed
        ]

    def test_eval_reads_canonical_ground_truth_not_synthesis(self, spillage_scenario, tmp_path):
        # Eval must rely on GROUND_TRUTH.json; with it removed, spillage cannot be matched.
        out = _generate(spillage_scenario, tmp_path / "out")
        (out / "GROUND_TRUTH.json").unlink()
        report = EvaluationEngine(output_dir=out, scenario=Scenario(**spillage_scenario)).run()
        ep = next(
            (s for p in report.pillars for s in p.sub_scores if s.key == "event_presence"),
            None,
        )
        assert ep is not None and ep.score < 85  # cannot find traces without the canonical document
        assert "ground_truth.json" in ep.details.lower()  # and the 0 is explained, not mysterious


class TestSpillageAccuracy:
    def test_process_command_line_lands_in_ecar(self, spillage_scenario, tmp_path):
        out = _generate(spillage_scenario, tmp_path / "out")
        ecar = "\n".join(p.read_text() for p in out.rglob("*") if "ecar" in p.name.lower())
        proc_recs = [r for r in _records(out) if r["surface"] == "process_command_line"]
        assert proc_recs
        for r in proc_recs:
            assert r["rendered_value"] in ecar  # credential on the process command line

    def test_syslog_spill_line_is_rfc5424_wellformed(self, spillage_scenario, tmp_path):
        out = _generate(spillage_scenario, tmp_path / "out")
        # Multiple hosts each emit a syslog.log; read them all to find the spill host.
        syslog = "\n".join(p.read_text() for p in out.rglob("syslog.log"))
        token = next(r["rendered_value"] for r in _records(out) if r["surface"] == "syslog_message")
        line = next(line for line in syslog.splitlines() if token in line)
        assert re.match(r"^<\d{1,3}>1 \S+ \S+ \S+ - - - ", line)
        assert "\t" not in line and "\n" not in line

    def test_http_surfaces_land_in_web_access_with_client_and_target(
        self, spillage_scenario, tmp_path
    ):
        out = _generate(spillage_scenario, tmp_path / "out")
        web_lines = [ln for p in out.rglob("web_access.log") for ln in p.read_text().splitlines()]
        web_files = [str(p) for p in out.rglob("web_access.log")]
        http_recs = [r for r in _records(out) if r["surface"].startswith("http")]
        assert {r["surface"] for r in http_recs} == {"http_request_url", "http_referrer"}
        for r in http_recs:
            # Find the specific web_access line carrying THIS credential.
            line = next((ln for ln in web_lines if r["rendered_value"] in ln), None)
            assert line, f"missing in web_access: {r['record_id']}"
            # client_ip (the leading combined-log field) is the actor's host — bound
            # to the credential line, not a whole-file substring (a direct request,
            # never the proxy or server IP).
            assert line.split()[0] == "192.168.20.30"
            # Ground truth records the destination web server's FQDN, and the access
            # log actually lives under that FQDN directory.
            assert r["target_system"].startswith("WEB-APP-01")
            assert any(r["target_system"] in p for p in web_files)

    def test_http_request_url_in_path_referrer_in_referer_field(self, spillage_scenario, tmp_path):
        out = _generate(spillage_scenario, tmp_path / "out")
        web_lines = [
            line for p in out.rglob("web_access.log") for line in p.read_text().splitlines()
        ]
        recs = {
            r["surface"]: r["rendered_value"]
            for r in _records(out)
            if r["surface"].startswith("http")
        }
        # URL spill: value sits inside the request-target (before the trailing " HTTP/..").
        url_line = next(line for line in web_lines if recs["http_request_url"] in line)
        request_target = url_line.split('"', 2)[1]  # the "METHOD path proto" field
        assert recs["http_request_url"] in request_target
        # Referrer spill: value sits inside the quoted Referer field, not the path.
        ref_line = next(line for line in web_lines if recs["http_referrer"] in line)
        assert recs["http_referrer"] in ref_line.split('"')[3]  # 2nd quoted field = referer

    def test_http_and_process_spills_land_from_a_windows_actor(self, tmp_path):
        # http_* and process_command_line are cross-OS: a Windows actor host must
        # still leak the credential (http_* into the web server's access log,
        # process_command_line into ecar). Exercises the cross-OS claim end-to-end.
        scenario = _linux_scenario(
            [
                {"type": "spillage", "surface": "http_request_url", "family": "gcp_api_key"},
                {"type": "spillage", "surface": "process_command_line", "family": "bearer_token"},
            ],
            logs=[{"format": "web_access"}, {"format": "ecar"}],
            web_server=True,
            actor_os="Windows 11 Pro",
        )
        out = _generate(scenario, tmp_path / "out")
        recs = {r["surface"]: r for r in _records(out)}
        web = "\n".join(p.read_text() for p in out.rglob("web_access.log"))
        ecar = "\n".join(p.read_text() for p in out.rglob("*") if "ecar" in p.name.lower())
        # URL spill from the Windows host lands on the (Linux) web server's access log…
        url_line = next(
            ln for ln in web.splitlines() if recs["http_request_url"]["rendered_value"] in ln
        )
        assert url_line.split()[0] == "192.168.20.30"  # client_ip = the Windows actor host
        # …and the process-command-line spill lands in EDR/ecar telemetry.
        assert recs["process_command_line"]["rendered_value"] in ecar

    def test_windows_process_spill_uses_visible_session_logon_context(self, tmp_path):
        scenario = _linux_scenario(
            [{"type": "spillage", "surface": "process_command_line", "family": "bearer_token"}],
            logs=[{"format": "windows_event_security"}, {"format": "ecar"}],
            actor_os="Windows 11 Pro",
        )
        scenario["storyline"].insert(
            0,
            {
                "id": "login",
                "time": "+5m",
                "actor": "nina",
                "system": "APP-SRV-01",
                "activity": "remote interactive login",
                "events": [{"type": "logon", "logon_type": 10, "source_ip": "203.0.113.10"}],
            },
        )
        out = _generate(scenario, tmp_path / "out")
        rec = next(r for r in _records(out) if r["surface"] == "process_command_line")

        windows_events = [
            event
            for path in out.rglob("windows_event_security.xml")
            for event in _parse_windows_log(path)
        ]
        proc_event = next(
            event
            for event in windows_events
            if event.get("EventID") == "4688"
            and rec["rendered_value"] in str(event.get("CommandLine") or "")
        )
        subject_logon_id = str(proc_event.get("SubjectLogonId") or "")
        assert subject_logon_id not in {"", "-", "0x0", "0x3e4", "0x3e5", "0x3e7"}
        assert any(
            event.get("EventID") == "4624"
            and event.get("TargetLogonId") == subject_logon_id
            and str(event.get("TargetUserName") or "").lower() == "nina"
            for event in windows_events
        )

        ecar_rows = _ecar_records(out)
        proc_row = next(
            row
            for row in ecar_rows
            if row.get("object") == "PROCESS"
            and row.get("action") == "CREATE"
            and rec["rendered_value"] in str(row.get("properties", {}).get("command_line") or "")
        )
        assert proc_row.get("principal") == "nina"
        assert any(
            row.get("object") == "USER_SESSION"
            and row.get("action") == "LOGIN"
            and row.get("principal") == "nina"
            and int(row.get("timestamp_ms", 0)) <= int(proc_row.get("timestamp_ms", 0))
            for row in ecar_rows
        )

    def test_http_spillage_with_normalized_web_server_role_lands_on_disk(self, tmp_path):
        scenario = _linux_scenario(
            [{"type": "spillage", "surface": "http_request_url", "family": "gcp_api_key"}],
            logs=[{"format": "web_access"}],
            web_server=True,
            web_server_roles=["web-server"],
        )
        out = _generate(scenario, tmp_path / "out")
        rec = next(r for r in _records(out) if r["surface"] == "http_request_url")
        web = "\n".join(p.read_text() for p in out.rglob("web_access.log"))

        assert rec["expected_sources"] == ["web_access"]
        assert rec["rendered_value"] in web

    def test_db_uri_through_http_url_is_percent_encoded_on_disk(self, tmp_path):
        # db_uri is the heaviest-encoding family (:// @ : /). Through http_request_url
        # the on-disk form must be percent-encoded and the raw value absent unencoded.
        scenario = _linux_scenario(
            [{"type": "spillage", "surface": "http_request_url", "family": "db_uri"}],
            logs=[{"format": "web_access"}],
            web_server=True,
        )
        out = _generate(scenario, tmp_path / "out")
        rec = next(r for r in _records(out) if r["surface"] == "http_request_url")
        web = "\n".join(p.read_text() for p in out.rglob("web_access.log"))
        assert "%3A%2F%2F" in rec["rendered_value"]  # :// percent-encoded
        assert rec["rendered_value"] in web  # the encoded form is on disk…
        assert rec["value"] not in web  # …and the raw db URI (with :// @) is not
        report = EvaluationEngine(output_dir=out, scenario=Scenario(**scenario)).run()
        ep = next(s for p in report.pillars for s in p.sub_scores if s.key == "event_presence")
        assert ep.score >= 85  # eval traces the percent-encoded credential

    def test_fqdn_web_server_target_matches_dir_without_doubling(self, tmp_path):
        # A web_server whose hostname is already an FQDN must not get the domain
        # doubled; target_system must equal the actual web_access output directory.
        scenario = _linux_scenario(
            [{"type": "spillage", "surface": "http_request_url", "family": "gcp_api_key"}],
            logs=[{"format": "web_access"}],
            web_server=True,
            web_server_hostname="cdn.internal.example.com",
        )
        out = _generate(scenario, tmp_path / "out")
        rec = next(r for r in _records(out) if r["surface"] == "http_request_url")
        assert rec["target_system"] == "cdn.internal.example.com"  # not ….example.com.example.com
        web_dirs = {p.parent.name for p in out.rglob("web_access.log")}
        assert rec["target_system"] in web_dirs  # equals the actual output directory
        report = EvaluationEngine(output_dir=out, scenario=Scenario(**scenario)).run()
        ep = next(s for p in report.pillars for s in p.sub_scores if s.key == "event_presence")
        assert ep.score >= 85  # eval still resolves the host and traces the credential

    def test_referrer_ua_is_os_coherent_with_actor(self, tmp_path):
        # http_referrer uses a browser UA matched to the actor's OS (AGENTS.md rule 3),
        # not a uniformly-random pool that would emit a Windows/iPhone UA from Linux.
        scenario = _linux_scenario(
            [{"type": "spillage", "surface": "http_referrer", "family": "jwt"}],
            logs=[{"format": "web_access"}],
            web_server=True,
        )
        out = _generate(scenario, tmp_path / "out")
        rec = next(r for r in _records(out) if r["surface"] == "http_referrer")
        line = next(
            ln
            for p in out.rglob("web_access.log")
            for ln in p.read_text().splitlines()
            if rec["rendered_value"] in ln
        )
        ua = line.rsplit('"', 2)[1]  # the quoted User-Agent field
        assert "Mozilla" in ua  # browser-class, not a tool client
        assert "Linux" in ua or "X11" in ua  # OS-coherent with the Linux actor host

    def test_http_scheme_is_cleartext_and_https_scheme_keeps_secret_out_of_zeek_http(
        self, tmp_path
    ):
        scenario = _linux_scenario(
            [
                {
                    "type": "spillage",
                    "surface": "http_request_url",
                    "family": "gcp_api_key",
                    "scheme": "http",
                },
                {
                    "type": "spillage",
                    "surface": "http_referrer",
                    "family": "jwt",
                    "scheme": "https",
                },
            ],
            logs=[{"format": "web_access"}, {"format": "zeek"}, {"format": "proxy_access"}],
            web_server=True,
            web_server_services=["http", "https"],
            network=_app_web_zeek_network(),
        )
        out = _generate(scenario, tmp_path / "out")
        recs = {r["surface"]: r for r in _records(out) if r["surface"].startswith("http")}
        http_rec = recs["http_request_url"]
        https_rec = recs["http_referrer"]
        assert http_rec["scheme"] == "http"
        assert https_rec["scheme"] == "https"

        web_access = "\n".join(p.read_text() for p in out.rglob("web_access.log"))
        zeek_http = "\n".join(p.read_text() for p in out.rglob("http.json"))
        zeek_ssl = "\n".join(p.read_text() for p in out.rglob("ssl.json"))
        proxy_access = "\n".join(p.read_text() for p in out.rglob("proxy_access.log"))
        conn_rows = [
            json.loads(line)
            for p in out.rglob("conn.json")
            for line in p.read_text().splitlines()
            if line.strip()
        ]
        ssl_rows = [
            json.loads(line)
            for p in out.rglob("ssl.json")
            for line in p.read_text().splitlines()
            if line.strip()
        ]

        assert http_rec["rendered_value"] in web_access
        assert https_rec["rendered_value"] in web_access
        assert http_rec["rendered_value"] in zeek_http
        assert https_rec["rendered_value"] not in zeek_http
        assert https_rec["rendered_value"] not in zeek_ssl
        assert http_rec["rendered_value"] not in proxy_access
        assert https_rec["rendered_value"] not in proxy_access
        assert any(
            row.get("id.orig_h") == "192.168.20.30"
            and row.get("id.resp_h") == "192.168.20.40"
            and row.get("id.resp_p") == 80
            for row in conn_rows
        )
        https_conn_uids = {
            row.get("uid")
            for row in conn_rows
            if row.get("id.orig_h") == "192.168.20.30"
            and row.get("id.resp_h") == "192.168.20.40"
            and row.get("id.resp_p") == 443
        }
        assert https_conn_uids
        assert any(row.get("uid") in https_conn_uids for row in ssl_rows)

    def test_omitted_scheme_auto_uses_http_for_http_only_web_server(self, tmp_path):
        scenario = _linux_scenario(
            [{"type": "spillage", "surface": "http_request_url", "family": "gcp_api_key"}],
            logs=[{"format": "web_access"}, {"format": "zeek"}],
            web_server=True,
            web_server_services=["http"],
            network=_app_web_zeek_network(),
        )
        out = _generate(scenario, tmp_path / "out")
        rec = next(r for r in _records(out) if r["surface"] == "http_request_url")
        zeek_http = "\n".join(p.read_text() for p in out.rglob("http.json"))
        assert rec["scheme"] == "http"
        assert rec["rendered_value"] in zeek_http

    def test_omitted_scheme_auto_prefers_https_for_generic_web_server(self, tmp_path):
        scenario = _linux_scenario(
            [{"type": "spillage", "surface": "http_request_url", "family": "gcp_api_key"}],
            logs=[{"format": "web_access"}, {"format": "zeek"}],
            web_server=True,
            web_server_services=["nginx"],
            network=_app_web_zeek_network(),
        )
        out = _generate(scenario, tmp_path / "out")
        rec = next(r for r in _records(out) if r["surface"] == "http_request_url")
        web_access = "\n".join(p.read_text() for p in out.rglob("web_access.log"))
        zeek_http = "\n".join(p.read_text() for p in out.rglob("http.json"))
        conn_rows = [
            json.loads(line)
            for p in out.rglob("conn.json")
            for line in p.read_text().splitlines()
            if line.strip()
        ]
        assert rec["scheme"] == "https"
        assert rec["rendered_value"] in web_access
        assert rec["rendered_value"] not in zeek_http
        assert any(
            row.get("id.orig_h") == "192.168.20.30"
            and row.get("id.resp_h") == "192.168.20.40"
            and row.get("id.resp_p") == 443
            for row in conn_rows
        )

    def test_process_command_line_spills_survive_interactive_session(self, tmp_path):
        # Regression: multiple process_command_line spills run while the actor has a
        # busy interactive SSH session must all land in eCAR and be matched. They
        # run as standalone processes (not foreground children of the shell), so
        # eCAR post-flush normalization cannot shift/drop them into a phantom.
        spills = [
            "db_uri",
            "stripe_key",
            "bearer_token",
            "password_generic",
            "gcp_api_key",
            "db_uri",
        ]
        scenario = {
            "version": "1.0",
            "name": "proc-survive",
            "description": "process spills during an interactive session",
            "environment": {
                "description": "admin SSH session to a busy server",
                "users": [
                    {
                        "username": "nina",
                        "full_name": "N",
                        "email": "n@example.com",
                        "primary_system": "WS-01",
                        "enabled": True,
                    }
                ],
                "systems": [
                    {
                        "hostname": "WS-01",
                        "ip": "192.168.70.10",
                        "os": "Ubuntu 22.04 LTS",
                        "type": "workstation",
                        "assigned_user": "nina",
                    },
                    {
                        "hostname": "SRV-01",
                        "ip": "192.168.70.20",
                        "os": "Ubuntu 22.04 LTS",
                        "type": "server",
                        "services": ["SSH"],
                    },
                ],
            },
            "time_window": {"start": "2024-10-01T13:00:00Z", "duration": "2h"},
            "baseline_activity": {
                "description": "busy",
                "intensity": "medium",
                "variation": "medium",
            },
            "output": {
                "logs": [{"format": "ecar"}, {"format": "bash_history"}, {"format": "syslog"}],
                "destination": "./output",
                "compression": False,
            },
            "storyline": [
                {
                    "id": "ssh",
                    "time": "+10m",
                    "actor": "nina",
                    "system": "SRV-01",
                    "activity": "ssh login",
                    "events": [{"type": "ssh_session", "source_ip": "192.168.70.10"}],
                }
            ]
            + [
                {
                    "id": f"p{i}",
                    "time": f"+{12 + i // 3}m{(i * 13) % 60:02d}s",
                    "actor": "nina",
                    "system": "SRV-01",
                    "activity": "credentialed command",
                    "events": [
                        {"type": "spillage", "surface": "process_command_line", "family": fam}
                    ],
                }
                for i, fam in enumerate(spills)
            ],
        }
        out = _generate(scenario, tmp_path / "out")
        recs = [r for r in _spill_records(out) if r["surface"] == "process_command_line"]
        assert len(recs) == len(spills)
        ecar = "\n".join(p.read_text() for p in out.rglob("*") if "ecar" in p.name.lower())
        missing = [r["record_id"] for r in recs if r["rendered_value"] not in ecar]
        assert not missing, f"process_command_line spills dropped from eCAR: {missing}"
        report = EvaluationEngine(output_dir=out, scenario=Scenario(**scenario)).run()
        ep = next(s for p in report.pillars for s in p.sub_scores if s.key == "event_presence")
        assert ep.score >= 85

    def test_http_spill_renders_web_access_when_network_sensor_does_not_observe(self, tmp_path):
        # If no sensor observes the actor->web-server path, generate_connection is
        # filtered and nothing lands; ground truth must NOT label it (no phantom).
        scenario = {
            "version": "1.0",
            "name": "phantom-guard",
            "description": "no sensor observes actor->web",
            "environment": {
                "description": "segmented",
                "users": [
                    {
                        "username": "nina",
                        "full_name": "N",
                        "email": "n@example.com",
                        "primary_system": "APP-SRV-01",
                        "enabled": True,
                    }
                ],
                "systems": [
                    {
                        "hostname": "APP-SRV-01",
                        "ip": "10.20.10.30",
                        "os": "Ubuntu 22.04 LTS",
                        "type": "server",
                        "assigned_user": "nina",
                    },
                    {
                        "hostname": "WEB-APP-01",
                        "ip": "10.20.20.40",
                        "os": "Ubuntu 22.04 LTS",
                        "type": "server",
                        "roles": ["web_server"],
                    },
                    {
                        "hostname": "MGMT-01",
                        "ip": "10.20.40.10",
                        "os": "Ubuntu 22.04 LTS",
                        "type": "server",
                    },
                ],
                "network": {
                    "segments": [
                        {"name": "app", "cidr": "10.20.10.0/24", "exposure": "internal"},
                        {"name": "web", "cidr": "10.20.20.0/24", "exposure": "internal"},
                        {"name": "mgmt", "cidr": "10.20.40.0/24", "exposure": "internal"},
                    ],
                    "sensors": [
                        {
                            "name": "zeek-mgmt",
                            "type": "network",
                            "placement": "span",
                            "monitoring_segments": ["mgmt"],
                            "direction": "bidirectional",
                            "log_formats": ["zeek"],
                        }
                    ],
                },
            },
            "time_window": {"start": "2024-03-18T14:00:00Z", "duration": "1h"},
            "baseline_activity": {"description": "x", "intensity": "low", "variation": "low"},
            "output": {
                "logs": [{"format": "web_access"}],
                "destination": "./output",
                "compression": False,
            },
            "storyline": [
                {
                    "id": "s-url",
                    "time": "+20m",
                    "actor": "nina",
                    "system": "APP-SRV-01",
                    "activity": "leak",
                    "events": [
                        {"type": "spillage", "surface": "http_request_url", "family": "gcp_api_key"}
                    ],
                },
                {
                    "id": "s-ref",
                    "time": "+30m",
                    "actor": "nina",
                    "system": "APP-SRV-01",
                    "activity": "leak",
                    "events": [{"type": "spillage", "surface": "http_referrer", "family": "jwt"}],
                },
            ],
        }
        out = _generate(scenario, tmp_path / "out")
        # Web access is application/server evidence, so it still renders even when
        # no network sensor observes the path.
        http_recs = [r for r in _spill_records_or_empty(out) if r["surface"].startswith("http")]
        assert http_recs and all(rec["emitted"] is True for rec in http_recs)
        assert all(rec["rendered_value"] in _all_data_text(out) for rec in http_recs)

    def test_jsonl_time_matches_emitted_bash_line(self, tmp_path):
        scenario = _linux_scenario(
            [
                {"type": "spillage", "surface": "shell_history", "family": "github_pat"},
                {"type": "spillage", "surface": "shell_history", "family": "github_pat"},
            ],
            same_time=True,
        )
        out = _generate(scenario, tmp_path / "out")
        bash = [line for p in out.rglob("*.bash_history") for line in p.read_text().splitlines()]
        sh = [r for r in _records(out) if r["surface"] == "shell_history"]
        assert len(sh) == 2
        epochs = {
            _iso(int(bash[i][1:]))
            for r in sh
            for i, line in enumerate(bash)
            if line.startswith("#") and i + 1 < len(bash) and r["rendered_value"] in bash[i + 1]
        }
        assert {r["time"] for r in sh} == epochs
        assert len({r["time"] for r in sh}) == 2  # dwell shifted the second event

    def test_spillage_traces_despite_dwell_drift_beyond_tolerance(self):
        # In a busy scenario, bash dwell scheduling can shift a spill well past the
        # storyline time (>120s match tolerance). The eval anchors to the canonical document's
        # emitted time, so the credential is still found. Regression for a realistic
        # multi-event dataset where the storyline time alone missed it.
        from evidenceforge.evaluation.context import EvaluationContext
        from evidenceforge.evaluation.parsers import ParsedRecord
        from evidenceforge.evaluation.pillars.causality import CausalityScorer

        scenario = Scenario(
            **_linux_scenario(
                [
                    {
                        "type": "spillage",
                        "surface": "shell_history",
                        "value": "EvidenceForgeFake_DRIFT",
                    }
                ]
            )
        )
        storyline_time = datetime.datetime(2024, 3, 18, 14, 20, 0, tzinfo=datetime.UTC)
        emitted = storyline_time + datetime.timedelta(seconds=200)  # > 120s tolerance
        rec = ParsedRecord(
            source_format="bash_history",
            raw="#... \nexport X=EvidenceForgeFake_DRIFT",
            fields={
                "hostname": "APP-SRV-01",
                "username": "nina",
                "command": "export X=EvidenceForgeFake_DRIFT",
            },
            timestamp=emitted,
        )
        ctx = EvaluationContext(
            spillage_ground_truth={"e0": {"values": ["EvidenceForgeFake_DRIFT"], "time": emitted}}
        )
        pillar = CausalityScorer().score({"bash_history": [rec]}, scenario, ctx)
        ep = next(s for s in pillar.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0  # found despite the 200s drift, via GT-time anchoring

    def test_multiple_spills_in_one_step_each_must_be_observed(self):
        # When one storyline step contains multiple spillage events, finding one
        # credential must NOT vouch for the others — each labeled spill must appear
        # independently for the event to count as present.
        from evidenceforge.evaluation.context import EvaluationContext
        from evidenceforge.evaluation.parsers import ParsedRecord
        from evidenceforge.evaluation.pillars.causality import CausalityScorer

        base = _linux_scenario([])
        base["storyline"] = [
            {
                "id": "multi",
                "time": "+20m",
                "actor": "nina",
                "system": "APP-SRV-01",
                "activity": "two creds in one step",
                "events": [
                    {
                        "type": "spillage",
                        "surface": "shell_history",
                        "value": "EvidenceForgeFake_AAA",
                    },
                    {
                        "type": "spillage",
                        "surface": "shell_history",
                        "value": "EvidenceForgeFake_BBB",
                    },
                ],
            }
        ]
        scenario = Scenario(**base)
        t = datetime.datetime(2024, 3, 18, 14, 20, 0, tzinfo=datetime.UTC)

        def _rec(cmd):
            return ParsedRecord(
                source_format="bash_history",
                raw="#...\n" + cmd,
                fields={"hostname": "APP-SRV-01", "username": "nina", "command": cmd},
                timestamp=t,
            )

        gt = {"multi": {"values": ["EvidenceForgeFake_AAA", "EvidenceForgeFake_BBB"], "time": t}}

        # Only the first spill landed -> the step is NOT fully present.
        p1 = CausalityScorer().score(
            {"bash_history": [_rec("export A=EvidenceForgeFake_AAA")]},
            scenario,
            EvaluationContext(spillage_ground_truth=gt),
        )
        ep1 = next(s for s in p1.sub_scores if s.key == "event_presence")
        assert ep1.score < 100.0  # the missing second spill is not masked

        # Both spills landed -> fully present.
        p2 = CausalityScorer().score(
            {
                "bash_history": [
                    _rec("export A=EvidenceForgeFake_AAA"),
                    _rec("export B=EvidenceForgeFake_BBB"),
                ]
            },
            scenario,
            EvaluationContext(spillage_ground_truth=gt),
        )
        ep2 = next(s for s in p2.sub_scores if s.key == "event_presence")
        assert ep2.score == 100.0

    def test_duplicate_value_spills_require_distinct_landings(self):
        # Two spills of the SAME credential in one step must each be matched by a
        # DISTINCT trace — one landed copy cannot satisfy both (multiset collapse).
        from evidenceforge.evaluation.context import EvaluationContext
        from evidenceforge.evaluation.parsers import ParsedRecord
        from evidenceforge.evaluation.pillars.causality import CausalityScorer

        base = _linux_scenario([])
        base["storyline"] = [
            {
                "id": "dup",
                "time": "+20m",
                "actor": "nina",
                "system": "APP-SRV-01",
                "activity": "same cred twice",
                "events": [
                    {
                        "type": "spillage",
                        "surface": "shell_history",
                        "value": "EvidenceForgeFake_X",
                    },
                    {
                        "type": "spillage",
                        "surface": "shell_history",
                        "value": "EvidenceForgeFake_X",
                    },
                ],
            }
        ]
        scenario = Scenario(**base)
        t = datetime.datetime(2024, 3, 18, 14, 20, 0, tzinfo=datetime.UTC)

        def _rec(cmd):
            return ParsedRecord(
                source_format="bash_history",
                raw="#...\n" + cmd,
                fields={"hostname": "APP-SRV-01", "username": "nina", "command": cmd},
                timestamp=t,
            )

        gt = {
            "dup": {
                "values": ["EvidenceForgeFake_X", "EvidenceForgeFake_X"],
                "records": [
                    {"value": "EvidenceForgeFake_X", "expected_sources": ["bash_history"]},
                    {"value": "EvidenceForgeFake_X", "expected_sources": ["bash_history"]},
                ],
                "time": t,
            }
        }
        # Only ONE landed copy -> the two labeled spills are NOT both present.
        p1 = CausalityScorer().score(
            {"bash_history": [_rec("export A=EvidenceForgeFake_X")]},
            scenario,
            EvaluationContext(spillage_ground_truth=gt),
        )
        ep1 = next(s for s in p1.sub_scores if s.key == "event_presence")
        assert ep1.score < 100.0
        # TWO distinct landed copies -> fully present.
        p2 = CausalityScorer().score(
            {
                "bash_history": [
                    _rec("export A=EvidenceForgeFake_X"),
                    _rec("export B=EvidenceForgeFake_X"),
                ]
            },
            scenario,
            EvaluationContext(spillage_ground_truth=gt),
        )
        ep2 = next(s for s in p2.sub_scores if s.key == "event_presence")
        assert ep2.score == 100.0

    def test_value_spilled_to_one_surface_is_not_credited_by_another(self):
        # A value spilled to http_request_url (expected in web_access) must NOT be
        # credited by the same string appearing in a syslog line (cross-surface
        # false credit). The per-record expected_sources binds value -> format.
        # Exercises the presence matcher directly (the surface-binding fix lives in
        # _all_spillage_values_traced, downstream of trace collection).
        from types import SimpleNamespace

        from evidenceforge.evaluation.parsers import ParsedRecord
        from evidenceforge.evaluation.pillars.causality import CausalityScorer

        scorer = CausalityScorer()
        scorer._spillage_gt = {
            "xsurf": {
                "values": ["EvidenceForgeFake_U"],
                "records": [{"value": "EvidenceForgeFake_U", "expected_sources": ["web_access"]}],
            }
        }
        syslog_trace = ParsedRecord(
            source_format="syslog",
            raw="<13>1 ... EvidenceForgeFake_U",
            fields={"hostname": "APP-SRV-01", "message": "app: leaked EvidenceForgeFake_U"},
            timestamp=None,
        )
        web_trace = ParsedRecord(
            source_format="web_access",
            raw="...",
            fields={"hostname": "WEB-01", "path": "/x?token=EvidenceForgeFake_U", "referer": "-"},
            timestamp=None,
        )
        ev = SimpleNamespace(storyline_id="xsurf", event_types={"spillage"})
        # value present only in the WRONG surface (syslog) -> not satisfied
        ev.traces = [syslog_trace]
        assert scorer._all_spillage_values_traced(ev) is False
        # value present in the RIGHT surface (web_access) -> satisfied
        ev.traces = [web_trace]
        assert scorer._all_spillage_values_traced(ev) is True


# --- Validation ----------------------------------------------------------------


def _app_web_zeek_network():
    return {
        "segments": [
            {
                "name": "lab",
                "cidr": "192.168.20.0/24",
                "exposure": "internal",
                "systems": ["APP-SRV-01", "WEB-01"],
            }
        ],
        "sensors": [
            {
                "name": "zeek-lab",
                "type": "network",
                "placement": "span",
                "monitoring_segments": ["lab"],
                "direction": "bidirectional",
                "log_formats": ["zeek"],
            }
        ],
    }


def _linux_scenario(
    events,
    *,
    logs=None,
    actor="nina",
    same_time=False,
    web_server=False,
    actor_os="Ubuntu 22.04 LTS",
    web_server_hostname="WEB-01",
    web_server_services=None,
    web_server_roles=None,
    network=None,
):
    logs = logs or [{"format": "bash_history"}, {"format": "syslog"}, {"format": "ecar"}]
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
                "hostname": web_server_hostname,
                "ip": "192.168.20.40",
                "os": "Ubuntu 22.04 LTS",
                "type": "server",
                "roles": web_server_roles or ["web_server"],
                "services": web_server_services or [],
            }
        )
    environment = {
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
    }
    if network is not None:
        environment["network"] = network

    return {
        "version": "1.0",
        "name": "spillage-validate",
        "description": "validation harness",
        "environment": environment,
        "time_window": {"start": "2024-03-18T14:00:00Z", "duration": "1h"},
        "baseline_activity": {"description": "x", "intensity": "low", "variation": "low"},
        "output": {"logs": logs, "destination": "./output", "compression": False},
        "storyline": [
            {
                "id": f"e{i}",
                "time": "+20m" if same_time else f"+{10 * (i + 1)}m",
                "actor": actor,
                "system": "APP-SRV-01",
                "activity": "spillage",
                "events": [ev],
            }
            for i, ev in enumerate(events)
        ],
    }


def _errors(scenario_dict):
    v = ScenarioValidator(Scenario(**scenario_dict))
    v.validate()
    return [i.message for i in v.issues if i.severity == "error"]


class TestSpillageValidation:
    def test_good_fixture_validates_clean(self, scenarios_dir):
        v = ScenarioValidator(Scenario(**load_yaml(scenarios_dir / "spillage.yaml")))
        v.validate()
        assert not v.has_errors()

    def test_unknown_family_is_error(self):
        errs = _errors(
            _linux_scenario([{"type": "spillage", "surface": "shell_history", "family": "nope"}])
        )
        assert any("Unknown spillage family" in m for m in errs)

    def test_unsafe_literal_is_error(self):
        errs = _errors(
            _linux_scenario(
                [{"type": "spillage", "surface": "syslog_message", "value": "AKIAREALKEY12345678"}]
            )
        )
        assert any("Unsafe spillage value" in m for m in errs)

    def test_safe_literal_validates_clean(self):
        assert not _errors(
            _linux_scenario(
                [{"type": "spillage", "surface": "syslog_message", "value": "EvidenceForgeFake_T"}]
            )
        )

    def test_missing_surface_format_is_error(self):
        errs = _errors(
            _linux_scenario(
                [{"type": "spillage", "surface": "shell_history", "family": "aws_iam"}],
                logs=[{"format": "syslog"}],
            )
        )
        assert any("needs output format 'bash_history'" in m for m in errs)

    @pytest.mark.parametrize("surface", ["shell_history", "syslog_message"])
    @pytest.mark.parametrize("actor_os", ["macOS 14", "FreeBSD 14", "Windows 10"])
    def test_linux_only_surface_on_non_linux_host_rejected(self, actor_os, surface):
        # Regression: the Linux-only-surface gate must reject ANY non-Linux host (Windows OR
        # an unknown OS such as macOS/BSD), not just Windows — else shell_history/syslog on a
        # macOS/BSD actor validates clean but is dropped at emit (a phantom positive). A Linux
        # host is present so the bash_history format has a valid home.
        scenario = _linux_scenario(
            [{"type": "spillage", "surface": surface, "family": "aws_iam"}],
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

    def test_noninteractive_actor_is_error(self):
        errs = _errors(
            _linux_scenario(
                [{"type": "spillage", "surface": "shell_history", "family": "aws_iam"}],
                actor="www-data",
            )
        )
        assert any("non-interactive service account" in m for m in errs)

    def test_http_surface_without_web_server_is_error(self):
        errs = _errors(
            _linux_scenario(
                [{"type": "spillage", "surface": "http_request_url", "family": "gcp_api_key"}],
                logs=[{"format": "web_access"}],
            )
        )
        assert any("role 'web_server'" in m for m in errs)

    def test_http_surface_with_web_server_validates_clean(self):
        assert not _errors(
            _linux_scenario(
                [{"type": "spillage", "surface": "http_referrer", "family": "jwt"}],
                logs=[{"format": "web_access"}],
                web_server=True,
            )
        )

    def test_http_scheme_to_https_only_web_server_is_error(self):
        errs = _errors(
            _linux_scenario(
                [
                    {
                        "type": "spillage",
                        "surface": "http_request_url",
                        "family": "gcp_api_key",
                        "scheme": "http",
                    }
                ],
                logs=[{"format": "web_access"}],
                web_server=True,
                web_server_services=["https"],
            )
        )
        assert any("compatible with scheme 'http'" in m for m in errs)

    def test_https_scheme_to_http_only_web_server_is_error(self):
        errs = _errors(
            _linux_scenario(
                [
                    {
                        "type": "spillage",
                        "surface": "http_referrer",
                        "family": "jwt",
                        "scheme": "https",
                    }
                ],
                logs=[{"format": "web_access"}],
                web_server=True,
                web_server_services=["http"],
            )
        )
        assert any("compatible with scheme 'https'" in m for m in errs)

    def test_generic_web_server_supports_http_and_https_spillage(self):
        assert not _errors(
            _linux_scenario(
                [
                    {
                        "type": "spillage",
                        "surface": "http_request_url",
                        "family": "gcp_api_key",
                        "scheme": "http",
                    },
                    {
                        "type": "spillage",
                        "surface": "http_referrer",
                        "family": "jwt",
                        "scheme": "https",
                    },
                ],
                logs=[{"format": "web_access"}],
                web_server=True,
                web_server_services=["nginx"],
            )
        )


class TestSpillageValidateCLI:
    def test_good_fixture_exit_zero(self, scenarios_dir):
        result = runner.invoke(app, ["validate", str(scenarios_dir / "spillage.yaml")])
        assert result.exit_code == 0

    def test_bad_spillage_exit_two(self, tmp_path):
        import yaml

        bad = tmp_path / "bad.yaml"
        bad.write_text(
            yaml.safe_dump(
                _linux_scenario(
                    [{"type": "spillage", "surface": "shell_history", "family": "nope"}]
                )
            )
        )
        assert runner.invoke(app, ["validate", str(bad)]).exit_code == 2

    def test_no_web_server_suggestion_keeps_bracketed_role(self, tmp_path):
        # The fix-it suggestion contains "roles: [web_server]"; Rich must not parse
        # the bracket token as markup and silently drop it.
        import yaml

        bad = tmp_path / "no_web.yaml"
        bad.write_text(
            yaml.safe_dump(
                _linux_scenario(
                    [{"type": "spillage", "surface": "http_request_url", "family": "gcp_api_key"}],
                    logs=[{"format": "web_access"}],
                )
            )
        )
        result = runner.invoke(app, ["validate", str(bad)])
        assert result.exit_code == 2
        assert "[web_server]" in result.output
