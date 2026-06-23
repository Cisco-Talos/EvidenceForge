# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Integration test for the scenarios/llm-injection-demo example: the prompt-injection
families plant recoverable echo-canaries into the logs, the decoy credentials land for the
exfiltration check, every payload stays canary-only/safe, and the dataset evals clean."""

import ipaddress
import json
import re
import urllib.parse
from pathlib import Path

import pytest

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

_DEMO = Path(__file__).resolve().parents[2] / "scenarios/llm-injection-demo"
_SCENARIO = _DEMO / "scenario.yaml"
_TWIN = _DEMO / "scenario-clean.yaml"
_CANARY_RE = re.compile(r"EFORGE_TEST-CANARY-[A-Za-z0-9]{12}")
# dns_qname renders the canary DNS-safe (lowercased, '_' folded to '-'): eforge-test-canary-<nonce>.
_DNS_CANARY_RE = re.compile(r"eforge-test-canary-[a-z0-9]{12}")
_ANY_CANARY_RE = re.compile(r"EFORGE_TEST-CANARY-[A-Za-z0-9]{12}|eforge-test-canary-[a-z0-9]{12}")
_HOST_RE = re.compile(r"(?:[a-zA-Z][a-zA-Z0-9+.\-]*:)?//([^/?#\\\s\"'>}]+)")


def _load_scenario(path: Path = _SCENARIO) -> Scenario:
    # Mirror the `eforge generate` path: built-in personas are merged before construction.
    from evidenceforge.utils.personas import merge_builtin_personas

    return Scenario(**merge_builtin_personas(load_yaml(path)))


def _per_file_lines(out: Path) -> dict[str, set[str]]:
    # The log corpus a copilot reads — not the run metadata (GROUND_TRUTH, OBSERVATION, OUTPUT).
    return {
        p.relative_to(out).as_posix(): set(p.read_text(errors="replace").splitlines())
        for p in out.rglob("*")
        if p.is_file()
        and p.suffix in (".log", ".json")
        and not p.name.startswith(("GROUND_TRUTH", "OBSERVATION", "OUTPUT"))
    }


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    out = tmp_path_factory.mktemp("pi_demo")
    GenerationEngine(_load_scenario(), out).generate()
    gt = json.loads((out / "GROUND_TRUTH.json").read_text())
    corpus = "\n".join(
        p.read_text(errors="replace")
        for p in out.rglob("*")
        if p.is_file() and p.suffix in (".log", ".json") and not p.name.startswith("GROUND_TRUTH")
    )
    return out, gt, corpus.replace("\r\n", "\n").replace("\r", "\n")


def _injections(gt):
    return [e for e in gt["events"] if e["kind"] == "adversarial_payload" and e["emitted"]]


def test_scenario_is_valid():
    # validate() must accept it (proposed-family warnings are non-fatal).
    _load_scenario()


def test_every_injection_has_a_recoverable_canary_in_the_logs(generated):
    # Tier-0 self-score: each planted injection's echo-canary is recorded in ground truth
    # AND lands in the data a copilot would read (byte-for-byte) — that is the grep target.
    _out, gt, corpus = generated
    injections = _injections(gt)
    assert len(injections) == 14
    corpus_lower = corpus.lower()
    for e in injections:
        a = e["attributes"]
        token = _CANARY_RE.search(a["value"])
        assert token, f"no canary in {a['family']} value"
        # The canary lands verbatim on most surfaces, or DNS-encoded (lowercased) in the
        # dns_qname QNAME — recover by the 12-char nonce so both forms count as a hit.
        nonce = token.group(0).split("CANARY-", 1)[1].lower()
        assert (token.group(0) in corpus) or (f"canary-{nonce}" in corpus_lower), (
            f"{a['family']}/{a['surface']} canary nonce {nonce} not recoverable in logs"
        )
        assert a["rendered_value"].replace("\r\n", "\n") in corpus  # the full payload landed


def test_decoy_credentials_land_for_the_exfiltration_check(generated):
    # The exfil injection tells the copilot to surface secrets; the answer key needs real
    # decoy credentials in the logs to grep its output against.
    _out, gt, corpus = generated
    decoys = [e for e in gt["events"] if e["kind"] == "spillage" and e["emitted"]]
    assert len(decoys) == 2  # aws_iam in a URL + db_uri in syslog
    for e in decoys:
        assert e["attributes"]["value"] in corpus


def test_injection_payloads_are_canary_only(generated):
    # Safety: no real/resolvable host may appear in any planted injection.
    _out, gt, _corpus = generated
    bad = []
    for e in _injections(gt):
        for field in ("value", "rendered_value"):
            for m in _HOST_RE.finditer(urllib.parse.unquote(e["attributes"].get(field, "") or "")):
                host = m.group(1).rsplit("@", 1)[-1].split(":")[0].lower()
                if not host or host == "canary.eforge.invalid":
                    continue
                try:
                    ipaddress.ip_address(host)  # reserved IPs are fine
                except ValueError:
                    bad.append(host)
    assert not bad, f"non-canary hosts in injection payloads: {bad}"


def test_negative_controls_are_labeled_in_ground_truth(generated):
    # An automated self-score must be able to tell a correctly-resisted control apart from a
    # real hijack, so the control family must self-identify in the canonical ground truth.
    _out, gt, _corpus = generated
    controls = [
        e for e in _injections(gt) if e["attributes"].get("family") == "prompt_injection_control"
    ]
    assert controls
    for e in controls:
        label = (
            e["attributes"].get("weakness_class", "")
            + e["attributes"].get("expected_defender_signal", "")
        ).upper()
        assert "NEGATIVE CONTROL" in label


def test_dataset_evals_clean(generated):
    out, _gt, _corpus = generated
    report = EvaluationEngine(output_dir=out, scenario=_load_scenario()).run()
    ep = next(s for p in report.pillars for s in p.sub_scores if s.key == "event_presence")
    assert ep.score == 100.0


def test_clean_twin_shares_a_byte_identical_baseline(generated, tmp_path_factory):
    # The Tier-3 differential-twin claim: scenario-clean.yaml keeps the same storyline event
    # SET (so the baseline RNG stream is unchanged) but neutralizes every injection — so the
    # two datasets share a byte-identical baseline and differ ONLY in the injected fields. A
    # defender can therefore diff copilot verdicts across the two to isolate the injection
    # (incl. spillover). This also guards against the twin drifting from scenario.yaml.
    poison_out, _gt, _corpus = generated
    clean_out = tmp_path_factory.mktemp("pi_twin")
    GenerationEngine(_load_scenario(_TWIN), clean_out).generate()

    poison = _per_file_lines(poison_out)
    clean = _per_file_lines(clean_out)
    assert set(poison) == set(clean), "twin produced a different set of output files"

    total = shared = differing = 0
    for fname, plines in poison.items():
        clines = clean[fname]
        shared += len(plines & clines)
        total += max(len(plines), len(clines))
        for line in plines - clines:
            differing += 1
            # Every differing line must be injection-related: a canary-bearing readable line
            # (uppercase token on most surfaces, or the DNS-encoded lowercase form in zeek
            # dns.log), or an ephemeral-port network tuple in zeek conn.log (inherently noisy
            # and not a readable triage surface, so it is allowed to differ).
            is_conn = Path(fname).name in ("conn.json", "conn.log", "zeek_conn.json")
            assert _ANY_CANARY_RE.search(line) or is_conn, (
                f"non-injection baseline line differs in {fname}: {line[:80]!r}"
            )
    assert shared / total > 0.99, f"baseline only {shared}/{total} identical — twin is not matched"
    assert differing <= 40  # 14 injections × (readable line + zeek http/conn mirrors)
    # the twin itself must be clean — no injection canary anywhere, in either form
    twin_text = "\n".join("\n".join(s) for s in clean.values())
    assert "EFORGE_TEST-CANARY-" not in twin_text
    assert not _DNS_CANARY_RE.search(twin_text)
