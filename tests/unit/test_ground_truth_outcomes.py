"""Prevention reflects the enforcing mechanism, independently of collection."""

import pytest

from evidenceforge.generation.ground_truth_ledger import _outcome


@pytest.mark.parametrize(
    ("facts", "result", "mechanism"),
    [
        ({"firewall": {"action": "deny"}}, "prevented", "firewall_policy"),
        ({"proxy": {"cache_result": "DENIED"}}, "prevented", "proxy_policy"),
        ({"auth": {"result": "failure"}}, "prevented", "authentication_rejected"),
        ({"smb": {"result": "access_denied"}}, "prevented", "authorization"),
        ({"smb": {"result": "not_found"}}, "failed", None),
        ({"smb": {"result": "sharing_violation"}}, "failed", None),
        ({"email": {"mail_action": "quarantine"}}, "prevented", "mail_policy"),
        ({"email": {"mail_action": "reject"}}, "prevented", "mail_policy"),
        ({"email": {"mail_action": "strip_attachment"}}, "partial", "mail_policy"),
        ({"email": {"mail_action": "deliver", "outcome": "bounced"}}, "failed", None),
        ({"application_control": {"reason": "policy_refused"}}, "prevented", "application_control"),
        ({"http": {"status_code": 403}}, "prevented", "origin_authorization"),
        ({"http": {"status_code": 404}}, "failed", None),
        ({"http": {"status_code": 500}}, "failed", None),
        ({"dns": {"rcode": "NXDOMAIN"}}, "failed", None),
        ({"dns": {"rcode": "SERVFAIL"}}, "failed", None),
        ({"dns": {"rcode": "REFUSED"}}, "prevented", "dns_request_refused"),
        ({"network": {"conn_state": "S0"}}, "failed", None),
        ({"network": {"conn_state": "SF"}, "http": {"status_code": 200}}, "completed", None),
    ],
)
def test_outcomes_distinguish_control_prevention_from_ordinary_failure(
    facts: dict,
    result: str,
    mechanism: str | None,
) -> None:
    outcome = _outcome(facts)
    assert outcome.result == result
    assert outcome.mechanism == mechanism
