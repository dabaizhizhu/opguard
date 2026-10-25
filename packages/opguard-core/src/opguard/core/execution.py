"""Execution node. A tool call without a gateway permit is refused.

The default adapter records the permit and does not run shell, SQL, or HTTP.
Hosts supply their own ExecutionAdapter behind this node.
"""

from __future__ import annotations

from typing import Any, Protocol

from opguard.audit import AuditLog, blank_jev, blank_sandbox, preview, stamp
from opguard.base.clock import Clock, SystemClock
from opguard.base.config import OpGuardConfig
from opguard.base.errors import BareCallRejected, GatewayRejected
from opguard.core.gateway import Gateway
from opguard.policy import action_text
from opguard.base.types import ExecPermit, IntentTicket, ToolCall


class ExecutionAdapter(Protocol):
    """Host hook for a side effect. This package's default does not perform one."""

    def execute(self, call: ToolCall, permit: ExecPermit) -> dict[str, Any]:
        """Perform the already-permitted call."""


class DryRunAdapter:
    """Records an accepted permit. Does not invoke a shell, database, or network."""

    name = "dry-run"

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, call: ToolCall, permit: ExecPermit) -> dict[str, Any]:
        self.calls += 1
        return {
            "accepted": True,
            "adapter": self.name,
            "args_hash": call.fingerprint(),
            "dry_run": True,
            "permit_id": permit.permit_id,
            "tool": call.tool,
        }


class ExecutionNode:
    def __init__(
        self,
        gateway: Gateway,
        audit: AuditLog,
        config: OpGuardConfig,
        adapter: ExecutionAdapter | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.gateway = gateway
        self.audit = audit
        self.config = config
        self.adapter = adapter or DryRunAdapter()
        self.clock = clock or SystemClock()

    def execute(self, ticket: IntentTicket | None, call: ToolCall, permit: ExecPermit | None) -> dict[str, Any]:
        if permit is None:
            self._reject(ticket, call, "执行层拒绝裸 tool call", permit=None)
            raise BareCallRejected("执行层拒绝裸 tool call")
        try:
            self.gateway.verify_permit(ticket, call, permit)
        except GatewayRejected as exc:
            self._reject(ticket, call, str(exc), permit=permit)
            raise
        return self.adapter.execute(call, permit)

    def _reject(self, ticket: IntentTicket | None, call: ToolCall, reason: str, *, permit: ExecPermit | None) -> None:
        record = {
            "ts": stamp(self.clock.now()),
            "event": "bypass_rejected",
            "ticket_id": ticket.ticket_id if ticket else "",
            "parent_ticket_id": ticket.parent_ticket_id if ticket else None,
            "agent_id": ticket.agent_id if ticket else "",
            "tool": call.tool,
            "kind": call.kind.value,
            "args_hash": call.fingerprint(),
            "action_preview": preview(action_text(call)),
            "layer": "gateway",
            "decision": "deny",
            "reason": reason,
            "capabilities": list(ticket.capabilities) if ticket else [],
            "resources": list(ticket.resources) if ticket else [],
            "vector_score": None,
            "vector_band": "skipped",
            "jev": blank_jev(),
            "sandbox": blank_sandbox(),
            "verdict_id": permit.verdict.verdict_id if permit else None,
            "permit_id": None,
            "hmac_alg": "HMAC-SHA256",
            "hitl_enabled": self.config.hitl_enabled,
            "policy_version": self.config.policy_version,
            "elapsed_ms": 0.0,
            "trace": [{"elapsed_ms": 0.0, "layer": "gateway", "outcome": "deny", "reason": reason}],
            "executed": False,
            "nodes": ["execution"],
        }
        self.audit.write(record)
