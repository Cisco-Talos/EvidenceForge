"""Regression controls for source attribution, transition identity and literal commands."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.evaluation.ground_truth_agreement import (
    _email_recipients_match,
    _fields_match,
    _RecordIndex,
)
from evidenceforge.evaluation.parsers import ParsedRecord, get_parser
from evidenceforge.evaluation.process_commands import process_commands_agree
from evidenceforge.events.contexts import NetworkTransactionDraft
from evidenceforge.events.evidence_projection import candidate_formats, native_requirements
from evidenceforge.models.scenario import EmailDistributionGroup, EmailMessageEventSpec
from tests.integration.test_ground_truth_reconciliation import _scenario


@pytest.mark.parametrize("group_address", ["finance@example.org", "alice@example.org"])
def test_email_requested_headers_and_expanded_mailboxes_remain_distinct(group_address: str) -> None:
    group = EmailDistributionGroup(address=group_address, members=["alice@example.org"])
    spec = EmailMessageEventSpec(to=[group_address], bcc=["security@example.org"])
    email = {
        "to": [f"Finance <{group_address}>"],
        "cc": [],
        "bcc": ["security@example.org"],
        "expanded_rcptto": ["alice@example.org", "security@example.org"],
    }
    assert _email_recipients_match(spec, email, [group])
    assert not _email_recipients_match(
        spec, {**email, "expanded_rcptto": ["alice@example.org"]}, [group]
    )
    assert not _email_recipients_match(spec, {**email, "to": ["other@example.org"]}, [group])
    assert not _email_recipients_match(
        spec, {**email, "to": [group_address, "security@example.org"], "bcc": []}, [group]
    )
    if group_address != "alice@example.org":
        assert not _email_recipients_match(spec, email, [])
    else:
        assert _email_recipients_match(spec, email, [])


@pytest.mark.parametrize(
    "fmt,suffix,body",
    [
        ("zsh_history", "zsh_history", ": 1792501200:0;whoami\n"),
        ("bash_history", "bash_history", "#1792501200\nwhoami\n"),
    ],
)
def test_history_owners_survive_format_subdirectories(
    tmp_path: Path, fmt: str, suffix: str, body: str
) -> None:
    scenario = _scenario(tmp_path, [])
    for host in ("CLIENT-01", "OTHER"):
        path = tmp_path / host / fmt / f"alice.{suffix}"
        path.parent.mkdir(parents=True)
        path.write_text(body)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    assert {r.source_instance for r in records[fmt]} == {"CLIENT-01", "OTHER"}
    assert {r.source_host for r in records[fmt]} == {"CLIENT-01", "OTHER"}
    assert not any(r.parse_errors for r in records[fmt])


@pytest.mark.parametrize(
    "authored,actual,os_category,expected",
    [
        ('find /tmp -name "*.pdf"', "find /tmp -name '*.pdf'", "macos", True),
        ('find /tmp -name "*.pdf"', "find /tmp -name '*.txt'", "macos", False),
        ('echo "$HOME"', "echo '$HOME'", "linux", False),
        ("echo a | cat", "echo a|cat", "linux", False),
        ("echo a{b,c}", "echo 'a{b,c}'", "linux", False),
        ("FOO=bar command", "'FOO=bar' command", "linux", False),
        ('echo "hello"', "echo 'hello'", "windows", False),
        ("find /tmp -name *.pdf", "find /tmp -name '*.pdf'", "linux", False),
    ],
)
def test_only_literal_posix_argument_equivalence_is_accepted(
    authored: str, actual: str, os_category: str, expected: bool
) -> None:
    assert process_commands_agree(authored, actual, os_category) is expected


@pytest.mark.parametrize("date", ["Oct 20", "Jan 20"])
def test_asa_generated_clock_is_aware_utc(tmp_path: Path, date: str) -> None:
    path = tmp_path / "2026" / "cisco_asa.log"
    path.parent.mkdir()
    path.write_text(
        f"<166>{date} 13:50:22 gateway %ASA-6-302013: Built outbound TCP connection 12 for outside:198.51.100.1/443 (198.51.100.1/443) to inside:10.0.0.1/50000 (10.0.0.1/50000)\n"
    )
    record = next(get_parser("cisco_asa").parse_file(path))
    assert record.timestamp is not None
    assert record.timestamp.hour == 13
    assert record.timestamp.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "operation", ["exec", "audit_bind", "privilege_drop", "service_drop", "job_control"]
)
def test_process_contract_identifies_the_exact_operation_and_execution(operation: str) -> None:
    facts = {
        "process": {"pid": 42, "image": "/bin/zsh", "command_line": "zsh"},
        "subject_identity": {"object_id": "process-42"},
        "process_transition": {
            "operation": operation,
            "execution_id": "activation-2",
            "previous_execution_id": "activation-1",
        },
    }
    requirement = native_requirements("ecar", "process_" + operation, facts, {}, "host")[0]
    record = ParsedRecord(
        source_format="ecar", raw="", fields={**requirement.selector, **requirement.required}
    )
    assert requirement.selector["operation"] == operation
    assert requirement.selector["execution_id"] == "activation-2"
    assert _fields_match(record, requirement.selector)
    record.fields["execution_id"] = "activation-3"
    assert not _fields_match(record, requirement.selector)
    record.fields["execution_id"] = "activation-2"
    record.fields["image_path"] = "/wrong/image"
    assert _fields_match(record, requirement.selector)
    assert not _fields_match(record, requirement.required)


@pytest.mark.parametrize(
    "src,dst,overhead", [("10.0.0.1", "10.0.0.2", 28), ("2001:db8::1", "2001:db8::2", 48)]
)
def test_udp_accounting_is_finalized_before_capture(src: str, dst: str, overhead: int) -> None:
    at = datetime(2026, 10, 20, tzinfo=UTC)
    draft = NetworkTransactionDraft(
        src_ip=src,
        dst_ip=dst,
        src_port=50001,
        dst_port=53,
        protocol="udp",
        source_visible_start_time=at,
        orig_bytes=62,
        resp_bytes=50,
        orig_pkts=1,
        resp_pkts=1,
        orig_ip_bytes=114,
        resp_ip_bytes=102,
    )
    plan = draft.finalize_transaction("dns-transaction")
    assert plan.orig_ip_bytes == 62 + overhead
    assert plan.resp_ip_bytes == 50 + overhead
    draft.validate_finalized_transaction()


def test_ssh_logoff_contract_does_not_require_syslog_without_its_context() -> None:
    host = {"hostname": "linux", "os_category": "linux"}
    facts = {"dst_host": host, "auth": {"logon_id": "42"}}
    assert "syslog" not in candidate_formats("logoff", facts)
    assert "syslog" in candidate_formats("logoff", {**facts, "syslog": {"app_name": "sshd"}})


@pytest.mark.parametrize("observation_delay", [0.0, 0.353186])
@pytest.mark.parametrize(
    "phase,policy",
    [
        ("process_fork", "source.ecar_process_create"),
        ("process_create", "source.ecar_process_create"),
        ("process_exec", "source.ecar_dependent_after_process_create"),
        ("process_terminate", "source.ecar_process_terminate"),
    ],
)
def test_timing_proof_requires_the_real_predecessor_and_bounded_delay(
    tmp_path: Path, phase: str, policy: str, observation_delay: float
) -> None:
    from evidenceforge.evaluation.source_timing_proof import verify_process_timing
    from evidenceforge.events.ground_truth_occurrence import (
        GroundTruthOccurrence,
        GroundTruthSourceExpectation,
    )

    at = datetime(2026, 10, 20, tzinfo=UTC)
    parent_time = at + timedelta(seconds=3)
    native = parent_time + timedelta(milliseconds=20)
    facts = {
        "process": {"object_id": "child", "execution_id": "child-exec"},
        "actor_process": {"object_id": "parent"},
    }
    row = GroundTruthOccurrence(
        occurrence_id="child-occurrence",
        action_id="action",
        intent_id="intent",
        storyline_id="story",
        section="storyline",
        kind=phase,
        time=at,
        facts=facts,
    )
    proof = {
        "version": 1,
        "phase": phase,
        "object_id": "child",
        "execution_id": "child-exec",
        "canonical_time": at.isoformat(),
        "native_time": native.isoformat(),
        "policy": policy,
        "anchors": [
            {"kind": "parent_create", "identity": "parent", "time": parent_time.isoformat()}
        ],
    }
    exp = GroundTruthSourceExpectation(
        expectation_id="expectation",
        source_instance="ecar:client-01",
        source_host="CLIENT-01",
        family="ecar",
        format="ecar",
        role="host",
        phase=phase,
        expected="present",
        expected_time=native,
        provenance={
            "timing": proof,
            "window": {"source_delay_seconds": observation_delay},
        },
    )
    parent = ParsedRecord(
        source_format="ecar",
        raw="",
        timestamp=parent_time,
        source_instance="CLIENT-01",
        fields={"objectID": "parent", "object": "PROCESS", "action": "CREATE"},
    )
    index = _RecordIndex({"ecar": [parent]}, _scenario(tmp_path, []))
    assert verify_process_timing(row, exp, index, {}) == []
    altered = exp.model_copy(update={"expected_time": native + timedelta(seconds=1)})
    assert "process_timing_identity_disagreement" in verify_process_timing(row, altered, index, {})
    proof = exp.provenance["timing"]
    assert "unverifiable_timing_dependency" in verify_process_timing(
        row, exp, _RecordIndex({}, _scenario(tmp_path, [])), {}
    )
    proof["anchors"][0]["identity"] = "unrelated-process"
    assert "invalid_timing_dependency_identity" in verify_process_timing(row, exp, index, {})
    proof["anchors"][0]["identity"] = "parent"
    proof["anchors"][0]["time"] = native.isoformat()
    assert "invalid_timing_dependency_order" in verify_process_timing(row, exp, index, {})
    proof["anchors"][0]["time"] = parent_time.isoformat()
    proof["native_time"] = (at + timedelta(seconds=30)).isoformat()
    assert "unjustified_source_time" in verify_process_timing(row, exp, index, {})


def test_representative_diagnostics_include_later_failure_families() -> None:
    from evidenceforge.evaluation.finding_samples import FindingSamples

    samples = FindingSamples()
    for number in range(1000):
        samples.add("missing", "ecar", {"number": number, "family": "missing"})
    samples.add("timing", "ecar", {"family": "timing"})
    samples.add("facts", "zeek_conn", {"family": "facts"})
    examples = samples.examples()
    assert len(examples) == 100
    assert {item["family"] for item in examples} == {"missing", "timing", "facts"}
    assert examples == samples.examples()


def test_multiple_history_commands_are_not_duplicates(tmp_path: Path) -> None:
    scenario = _scenario(tmp_path, [])
    at = datetime(2026, 10, 20, tzinfo=UTC)
    facts = {"shell": {"command": "whoami"}, "process": {"username": "alice"}}
    requirement = native_requirements("zsh_history", "shell_command", facts, {}, "host")[0]
    records = [
        ParsedRecord(
            source_format="zsh_history",
            raw=command,
            timestamp=at,
            source_instance="CLIENT-01",
            fields={"username": user, "command": command},
        )
        for user, command in [("alice", "whoami"), ("alice", "hostname"), ("bob", "whoami")]
    ]
    assert sum(_fields_match(record, requirement.selector) for record in records) == 1
    records.append(records[0].model_copy(deep=True))
    assert sum(_fields_match(record, requirement.selector) for record in records) == 2
    assert _RecordIndex({"zsh_history": records}, scenario).host("CLIENT-01") == "client-01"


def test_process_frontier_can_be_its_child_but_not_an_unrelated_process(tmp_path: Path) -> None:
    from evidenceforge.evaluation.source_timing_proof import verify_process_timing
    from evidenceforge.events.ground_truth_occurrence import (
        GroundTruthOccurrence,
        GroundTruthSourceExpectation,
    )

    at = datetime(2026, 10, 20, tzinfo=UTC)
    frontier = at + timedelta(seconds=3)
    native = frontier + timedelta(milliseconds=2)
    row = GroundTruthOccurrence(
        occurrence_id="parent-next-exec",
        action_id="action",
        intent_id="intent",
        storyline_id="story",
        section="storyline",
        kind="process_exec",
        time=at,
        facts={"process": {"pid": 42, "object_id": "parent", "execution_id": "parent-next"}},
    )
    exp = GroundTruthSourceExpectation(
        expectation_id="expectation",
        source_instance="ecar:client-01",
        source_host="CLIENT-01",
        family="ecar",
        format="ecar",
        role="host",
        phase="process_exec",
        expected="present",
        expected_time=native,
        provenance={
            "timing": {
                "version": 1,
                "phase": "process_exec",
                "object_id": "parent",
                "execution_id": "parent-next",
                "canonical_time": at.isoformat(),
                "native_time": native.isoformat(),
                "policy": "source.ecar_dependent_after_process_create",
                "anchors": [
                    {"kind": "process_frontier", "identity": "parent", "time": frontier.isoformat()}
                ],
            }
        },
    )
    child = ParsedRecord(
        source_format="ecar",
        raw="",
        timestamp=frontier,
        source_instance="CLIENT-01",
        fields={
            "object": "PROCESS",
            "action": "CREATE",
            "objectID": "child",
            "pid": 43,
            "ppid": 42,
        },
    )
    scenario = _scenario(tmp_path, [])
    assert verify_process_timing(row, exp, _RecordIndex({"ecar": [child]}, scenario), {}) == []
    child.fields["ppid"] = 999
    errors = verify_process_timing(row, exp, _RecordIndex({"ecar": [child]}, scenario), {})
    assert "unverifiable_timing_dependency" in errors
    assert "unjustified_source_time" in errors


def test_source_timing_witness_clone_is_detached() -> None:
    from evidenceforge.generation.source_timing import SourceTimingPlan

    plan = SourceTimingPlan(
        canonical_timestamp=datetime(2026, 10, 20, tzinfo=UTC),
        validation_receipts={"ecar:host": {"anchors": [{"identity": "parent"}]}},
    )
    clone = plan._clone()
    clone.validation_receipts["ecar:host"]["anchors"][0]["identity"] = "changed"
    assert plan.validation_receipts["ecar:host"]["anchors"][0]["identity"] == "parent"
