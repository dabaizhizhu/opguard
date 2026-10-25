"""Gateway node. Verifies a signed verdict and, only then, issues an execution permit."""

from __future__ import annotations

import uuid
from typing import Callable

from opguard.base.clock import Clock, SystemClock
from opguard.base.config import OpGuardConfig
from opguard.base.crypto import sign, signatures_equal
from opguard.policy.embedding import EmbeddingProvider, max_similarity
from opguard.base.errors import GatewayRejected
from opguard.policy import PolicyPlugin, action_text, scope_allows
from opguard.base.types import Decision, ExecPermit, IntentTicket, SignedVerdict, ToolCall, ToolKind


class Gateway:
    def __init__(
        self,
        config: OpGuardConfig,
        policy: PolicyPlugin,
        embedding: EmbeddingProvider,
        *,
        clock: Clock | None = None,
        ids: Callable[[str], str] | None = None,
    ) -> None:
        self.config = config
        self.policy = policy
        self.embedding = embedding
        self.clock = clock or SystemClock()
        self.ids = ids or (lambda prefix: f"{prefix}-{uuid.uuid4().hex[:12]}")

    def review(self, ticket: IntentTicket | None, call: ToolCall, verdict: SignedVerdict) -> ExecPermit | None:
        self.verify_verdict(ticket, call, verdict)
        if verdict.decision != Decision.ALLOW.value:
            return None
        return self._issue(verdict)

    def verify_permit(self, ticket: IntentTicket | None, call: ToolCall, permit: ExecPermit) -> None:
        self.verify_verdict(ticket, call, permit.verdict)
        expected = sign("permit", permit.signing_payload(), self.config.hmac_secret)
        if not signatures_equal(expected, permit.hmac):
            raise GatewayRejected("permit hmac invalid")
        if self.clock.now() > permit.expires_at:
            raise GatewayRejected("permit expired")
        if permit.verdict.decision != Decision.ALLOW.value:
            raise GatewayRejected("permit is not an allow")
        if permit.verdict.args_hash != call.fingerprint() or permit.verdict.tool != call.tool:
            raise GatewayRejected("permit does not bind this call")

    def verify_verdict(self, ticket: IntentTicket | None, call: ToolCall, verdict: SignedVerdict) -> None:
        expected = sign("verdict", verdict.signing_payload(), self.config.hmac_secret)
        if not verdict.hmac or not signatures_equal(expected, verdict.hmac):
            raise GatewayRejected("verdict hmac invalid")
        if verdict.expired(self.clock.now()):
            raise GatewayRejected("verdict expired")
        if verdict.args_hash != call.fingerprint() or verdict.tool != call.tool or verdict.kind != call.kind.value:
            raise GatewayRejected("verdict does not bind this call")
        if ticket is None:
            if verdict.ticket_id != "" or verdict.decision != Decision.DENY.value:
                raise GatewayRejected("missing ticket")
            return
        if verdict.ticket_id != ticket.ticket_id:
            raise GatewayRejected("verdict ticket mismatch")
        if verdict.decision != Decision.ALLOW.value:
            return
        ticket_mac = sign("ticket", ticket.signing_payload(), self.config.hmac_secret)
        if not ticket.signature or not signatures_equal(ticket_mac, ticket.signature):
            raise GatewayRejected("ticket signature invalid")
        if ticket.expired(self.clock.now()):
            raise GatewayRejected("ticket expired")
        classification = self.policy.classify(
            call,
            workspace_roots=self.config.workspace_roots,
            resources=ticket.resources,
        )
        if classification.hard_deny:
            raise GatewayRejected(f"gateway hard deny: {classification.hard_deny}")
        if classification.capability and classification.capability not in ticket.capabilities:
            raise GatewayRejected("gateway intent drift")
        if not scope_allows(ticket.resources, classification.targets):
            raise GatewayRejected("gateway resource scope")
        if self.config.vector_enabled:
            score = max_similarity(action_text(call), self.policy.prototypes(), self.embedding)
            # 自然语言意图（MCP）高相似不在此直接拒绝，与 decision 层保持一致。
            if score >= self.config.vector_high and call.kind is not ToolKind.MCP:
                raise GatewayRejected("gateway vector high similarity")

    def _issue(self, verdict: SignedVerdict) -> ExecPermit:
        now = self.clock.now()
        permit_id = self.ids("permit")
        expires_at = min(now + self.config.permit_ttl_s, verdict.issued_at + verdict.ttl_s)
        unsigned = {
            "args_hash": verdict.args_hash,
            "expires_at": expires_at,
            "permit_id": permit_id,
            "ticket_id": verdict.ticket_id,
            "tool": verdict.tool,
            "verdict_hmac": verdict.hmac,
            "verdict_id": verdict.verdict_id,
        }
        return ExecPermit(
            permit_id=permit_id,
            verdict=verdict,
            expires_at=expires_at,
            hmac=sign("permit", unsigned, self.config.hmac_secret),
        )
