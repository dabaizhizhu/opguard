"""Ticket issuance, tampering, expiry, and child-ticket capability scoping."""

from __future__ import annotations

import dataclasses
import secrets

import pytest

from opguard import OpGuard, OpGuardConfig, TicketRejected
from opguard.base.clock import ManualClock
from opguard.core.ticket import TicketIssuer

GOOD = dict(
    agent_id="a1",
    capabilities=("read", "mutate_scoped"),
    resources=("sql:orders", "fs:/workspace"),
    intent="运营维护",
)


def test_issue_ticket_produces_signed_verifiable_ticket(secret, clock):
    issuer = TicketIssuer(secret, clock)
    ticket = issuer.issue(**GOOD)
    assert ticket.signature and len(ticket.signature) == 64
    assert ticket.ticket_id.startswith("tkt-")
    issuer.verify(ticket)  # must not raise


def test_guard_issue_ticket_and_verify(secret, clock, tmp_path):
    guard = OpGuard(
        config=OpGuardConfig(hmac_secret=secret),
        audit_path=tmp_path / "audit.jsonl",
        clock=clock,
    )
    ticket = guard.issue_ticket(**GOOD)
    assert ticket.ticket_id.startswith("tkt-")
    guard.tickets.verify(ticket)


def test_destroy_capability_cannot_be_issued(secret, clock):
    issuer = TicketIssuer(secret, clock)
    with pytest.raises(TicketRejected) as exc:
        issuer.issue(agent_id="a", capabilities=("destroy",), resources=("sql:orders",), intent="x")
    assert "destroy" in str(exc.value)


def test_unknown_capability_cannot_be_issued(secret, clock):
    issuer = TicketIssuer(secret, clock)
    with pytest.raises(TicketRejected):
        issuer.issue(agent_id="a", capabilities=("sudo",), resources=("sql:orders",), intent="x")


def test_empty_resource_scope_cannot_be_issued(secret, clock):
    issuer = TicketIssuer(secret, clock)
    with pytest.raises(TicketRejected):
        issuer.issue(agent_id="a", capabilities=("read",), resources=(), intent="x")


def test_expired_ticket_is_rejected(secret, clock):
    issuer = TicketIssuer(secret, clock)
    ticket = issuer.issue(**GOOD, ttl_s=10.0)
    clock.advance(11.0)
    with pytest.raises(TicketRejected) as exc:
        issuer.verify(ticket)
    assert "expired" in str(exc.value)


def test_tampered_hmac_is_rejected(secret, clock):
    issuer = TicketIssuer(secret, clock)
    ticket = issuer.issue(**GOOD)
    bad = dataclasses.replace(ticket, signature="f" * 64)
    with pytest.raises(TicketRejected):
        issuer.verify(bad)


def test_tampered_content_is_rejected(secret, clock):
    issuer = TicketIssuer(secret, clock)
    ticket = issuer.issue(**GOOD)
    bad = dataclasses.replace(ticket, resources=("sql:other",))
    with pytest.raises(TicketRejected):
        issuer.verify(bad)


def test_issue_child_keeps_scope_subset_and_clamps_ttl(secret, clock):
    issuer = TicketIssuer(secret, clock)
    parent = issuer.issue(**GOOD, ttl_s=100.0)
    child = issuer.issue_child(
        parent,
        agent_id="c1",
        capabilities=("read",),
        resources=("sql:orders",),
        intent="只读",
        ttl_s=300.0,
    )
    assert set(child.capabilities) <= set(parent.capabilities)
    assert set(child.resources) <= set(parent.resources)
    assert child.parent_ticket_id == parent.ticket_id
    # Child TTL is clamped to the parent remaining time.
    assert child.ttl_s == pytest.approx(100.0)

    clock.advance(60.0)
    child2 = issuer.issue_child(
        parent,
        agent_id="c2",
        capabilities=("read",),
        resources=("sql:orders",),
        intent="只读",
        ttl_s=300.0,
    )
    assert child2.ttl_s == pytest.approx(40.0)


def test_issue_child_capability_overscope_is_rejected(secret, clock):
    issuer = TicketIssuer(secret, clock)
    parent = issuer.issue(**GOOD)
    with pytest.raises(TicketRejected) as exc:
        issuer.issue_child(
            parent,
            agent_id="c",
            capabilities=("create_user",),
            resources=("sql:orders",),
            intent="x",
        )
    assert "能力" in str(exc.value)


def test_issue_child_resource_overscope_is_rejected(secret, clock):
    issuer = TicketIssuer(secret, clock)
    parent = issuer.issue(**GOOD)
    with pytest.raises(TicketRejected) as exc:
        issuer.issue_child(
            parent,
            agent_id="c",
            capabilities=("read",),
            resources=("sql:other",),
            intent="x",
        )
    assert "资源" in str(exc.value)


def test_cross_project_shared_secret_verifies_and_foreign_secret_rejects(secret, tmp_path):
    guard_a = OpGuard(config=OpGuardConfig(hmac_secret=secret), audit_path=tmp_path / "a.jsonl")
    ticket = guard_a.issue_ticket(**GOOD)

    # Another guard in another "project" with the SAME secret accepts the ticket.
    guard_b = OpGuard(config=OpGuardConfig(hmac_secret=secret), audit_path=tmp_path / "b.jsonl")
    guard_b.tickets.verify(ticket)

    # A guard with a different secret rejects it.
    guard_c = OpGuard(
        config=OpGuardConfig(hmac_secret=secrets.token_bytes(32)),
        audit_path=tmp_path / "c.jsonl",
    )
    with pytest.raises(TicketRejected):
        guard_c.tickets.verify(ticket)