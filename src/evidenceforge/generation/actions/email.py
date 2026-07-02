# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

"""Email action bundles."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from evidenceforge.models.scenario import EmailMessageEventSpec, System, User


@dataclass(frozen=True, slots=True)
class EmailDeliveryRequest:
    """Intent for one SMTP email delivery activity."""

    spec: EmailMessageEventSpec
    actor: User
    system: System
    time: datetime
    activity: str = ""
    storyline_id: str = ""


@dataclass(frozen=True, slots=True)
class EmailDeliveryResult:
    """Generated email delivery summary for ground truth and artifacts."""

    artifact_id: str
    message_id: str
    sender: str
    recipients: list[str]
    subject: str
    outcome: str
    artifact_path: str = ""
    smtp_uids: list[str] = field(default_factory=list)
    route: list[dict[str, str]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class EmailAccessRequest:
    """Intent for one lightweight mailbox access session."""

    user: User
    system: System
    server: System
    time: datetime
    platform: str = "generic_smtp"
    protocol: str = ""
    duration: float | None = None
    user_agent: str = ""
    message_ids: tuple[str, ...] = ()


class EmailDeliveryExecutor(Protocol):
    """Adapter implemented by ActivityGenerator."""

    def _execute_email_delivery_bundle(self, request: EmailDeliveryRequest) -> EmailDeliveryResult:
        """Expand one email message into SMTP delivery evidence."""
        ...


class EmailAccessExecutor(Protocol):
    """Adapter implemented by ActivityGenerator."""

    def _execute_email_access_bundle(self, request: EmailAccessRequest) -> str:
        """Expand one email read/access session into opaque TLS network evidence."""
        ...


class EmailDeliveryActionBundle:
    """Coordinate SMTP delivery evidence for one message."""

    def __init__(self, executor: EmailDeliveryExecutor, request: EmailDeliveryRequest) -> None:
        self._executor = executor
        self._request = request

    def execute(self) -> EmailDeliveryResult:
        return self._executor._execute_email_delivery_bundle(self._request)


class EmailAccessActionBundle:
    """Coordinate opaque mailbox read/access evidence."""

    def __init__(self, executor: EmailAccessExecutor, request: EmailAccessRequest) -> None:
        self._executor = executor
        self._request = request

    def execute(self) -> str:
        return self._executor._execute_email_access_bundle(self._request)
