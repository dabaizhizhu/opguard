"""Signed intent tickets. The destroy capability cannot be issued."""

from __future__ import annotations

import uuid

from opguard.base.clock import Clock, SystemClock
from opguard.base.config import DEV_HMAC_SECRET
from opguard.base.crypto import sign, signatures_equal
from opguard.base.errors import TicketRejected
from opguard.policy import resource_covers
from opguard.base.types import ALLOWED_CAPABILITIES, IntentTicket


def _normalize_capabilities(capabilities: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for capability in capabilities:
        raw = getattr(capability, "value", capability)
        text = str(raw)
        if text == "destroy":
            raise TicketRejected("destroy 不能进入票据")
        if text not in ALLOWED_CAPABILITIES:
            raise TicketRejected(f"capability not allowed: {text}")
        if text not in normalized:
            normalized.append(text)
    if not normalized:
        raise TicketRejected("ticket requires a capability")
    return tuple(normalized)


def _normalize_resources(resources: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(str(resource) for resource in resources if str(resource)))
    if not normalized:
        raise TicketRejected("ticket requires a resource scope")
    return normalized


class TicketIssuer:
    """Issues HMAC-signed tickets and child tickets bound to a parent."""

    def __init__(self, secret: bytes = DEV_HMAC_SECRET, clock: Clock | None = None) -> None:
        self.secret = secret
        self.clock = clock or SystemClock()

    def issue(
        self,
        *,
        agent_id: str,
        capabilities: tuple[str, ...] | list[str],
        resources: tuple[str, ...] | list[str],
        intent: str,
        ttl_s: float = 600.0,
        parent_ticket_id: str | None = None,
        ticket_id: str | None = None,
    ) -> IntentTicket:
        if ttl_s <= 0:
            raise TicketRejected("ttl must be positive")
        if not agent_id or not intent.strip():
            raise TicketRejected("agent and intent are required")
        unsigned = IntentTicket(
            ticket_id=ticket_id or f"tkt-{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            capabilities=_normalize_capabilities(capabilities),
            resources=_normalize_resources(resources),
            intent=intent.strip(),
            issued_at=self.clock.now(),
            ttl_s=ttl_s,
            parent_ticket_id=parent_ticket_id,
            signature="",
        )
        return IntentTicket(
            ticket_id=unsigned.ticket_id,
            agent_id=unsigned.agent_id,
            capabilities=unsigned.capabilities,
            resources=unsigned.resources,
            intent=unsigned.intent,
            issued_at=unsigned.issued_at,
            ttl_s=unsigned.ttl_s,
            parent_ticket_id=unsigned.parent_ticket_id,
            signature=sign("ticket", unsigned.signing_payload(), self.secret),
        )

    def verify(self, ticket: IntentTicket) -> None:
        expected = sign("ticket", ticket.signing_payload(), self.secret)
        if not ticket.signature or not signatures_equal(expected, ticket.signature):
            raise TicketRejected("ticket signature")
        if ticket.expired(self.clock.now()):
            raise TicketRejected("ticket expired")
        _normalize_capabilities(ticket.capabilities)
        _normalize_resources(ticket.resources)

    def issue_child(
        self,
        parent: IntentTicket,
        *,
        agent_id: str,
        capabilities: tuple[str, ...] | list[str],
        resources: tuple[str, ...] | list[str],
        intent: str,
        ttl_s: float = 300.0,
    ) -> IntentTicket:
        self.verify(parent)
        child_caps = _normalize_capabilities(capabilities)
        child_resources = _normalize_resources(resources)
        if not set(child_caps) <= set(parent.capabilities):
            raise TicketRejected("子票能力不能超过父票")
        widened = [
            resource
            for resource in child_resources
            if not any(resource_covers(granted, resource) for granted in parent.resources)
        ]
        if widened:
            raise TicketRejected("子票资源不能超过父票")
        remaining = parent.issued_at + parent.ttl_s - self.clock.now()
        if remaining <= 0:
            raise TicketRejected("parent ticket expired")
        return self.issue(
            agent_id=agent_id,
            capabilities=child_caps,
            resources=child_resources,
            intent=intent,
            ttl_s=min(ttl_s, remaining),
            parent_ticket_id=parent.ticket_id,
        )
