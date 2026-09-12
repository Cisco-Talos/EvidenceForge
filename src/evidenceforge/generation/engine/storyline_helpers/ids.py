# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Storyline IDS helpers without coordinator dependencies."""

import random
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from evidenceforge.generation.actions import IdsAlertActionBundle, IdsAlertRequest
from evidenceforge.models.ids import IdsAlertAttachmentSpec


def _build_ids_alert_contexts(
    attachments: Sequence[IdsAlertAttachmentSpec],
    *,
    time: datetime,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str,
    rng: random.Random,
    source: str,
) -> list[Any]:
    """Resolve authored SID references into canonical IDS contexts."""

    if not attachments:
        return []
    from evidenceforge.generation.activity.ids_signatures import signature_by_sid

    contexts = []
    for attachment in attachments:
        signature = signature_by_sid(attachment.sid)
        if signature is None:
            raise ValueError(
                f"Unknown IDS signature SID {attachment.sid}; add it to ids_signatures.yaml"
            )
        contexts.append(
            IdsAlertActionBundle(
                IdsAlertRequest(
                    signature=signature,
                    time=time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    proto=proto,
                    rng=rng,
                    source=source,
                    direction=str(signature.get("direction", "")),
                    policy=attachment.policy,
                    origin="authored_attachment",
                )
            ).execute()
        )
    return contexts


def _ids_attachment_ground_truth(
    attachments: Sequence[IdsAlertAttachmentSpec],
) -> list[dict[str, Any]]:
    """Describe effective attachment policies before sensor totals are finalized."""
    from evidenceforge.generation.activity.ids_signatures import (
        effective_alert_policy,
        signature_by_sid,
    )

    result = []
    for attachment in attachments:
        signature = signature_by_sid(attachment.sid)
        if signature is None:
            continue
        policy = effective_alert_policy(signature, attachment.policy)
        result.append(
            {
                "sid": attachment.sid,
                "effective_policy": (
                    "every" if policy is None else policy.model_dump(mode="json", exclude_none=True)
                ),
                "candidate": 0,
                "emitted": 0,
                "policy_filtered": 0,
            }
        )
    return result
