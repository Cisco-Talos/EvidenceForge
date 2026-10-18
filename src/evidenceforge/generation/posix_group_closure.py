# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact transient proof for a State/service process-group terminal transaction."""

import hmac
from dataclasses import dataclass

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.job_control import PosixGroupIdentity
from evidenceforge.generation.lifecycle_registry import LifecycleServiceProcessClosureReceipt
from evidenceforge.generation.state_manager import ProcessTerminationMaterializationPlan


@dataclass(frozen=True, slots=True)
class PosixGroupServiceClosureReceipt:
    """Bind every terminated incarnation and source plan to the same service receipt."""

    group: PosixGroupIdentity
    processes: tuple[ProcessIdentity, ...]
    process_plan_tokens: tuple[str, ...]
    service_receipt: LifecycleServiceProcessClosureReceipt
    prior_version: int
    committed_version: int
    _integrity: str

    def _payload(self) -> bytes:
        return repr(
            (
                "posix-group-service-close-v1",
                self.group,
                self.processes,
                self.process_plan_tokens,
                self.service_receipt,
                self.prior_version,
                self.committed_version,
            )
        ).encode("utf-8")

    @classmethod
    def issue(
        cls,
        *,
        secret: bytes,
        group: PosixGroupIdentity,
        plans: tuple[ProcessTerminationMaterializationPlan, ...],
        service_receipt: LifecycleServiceProcessClosureReceipt,
        prior_version: int,
        committed_version: int,
    ) -> "PosixGroupServiceClosureReceipt":
        """Issue only after both owners have committed their admitted primitives."""
        from dataclasses import replace

        receipt = cls(
            group,
            tuple(plan.identity for plan in plans),
            tuple(plan.publication_token for plan in plans),
            service_receipt,
            prior_version,
            committed_version,
            "",
        )
        return replace(receipt, _integrity=hmac.digest(secret, receipt._payload(), "sha256").hex())

    def authenticates(self, secret: bytes) -> bool:
        """Reject modified nested proof contents as well as another owner's receipt."""
        try:
            expected = hmac.digest(secret, self._payload(), "sha256").hex()
            return type(self._integrity) is str and hmac.compare_digest(self._integrity, expected)
        except (RecursionError, TypeError, ValueError):
            return False
