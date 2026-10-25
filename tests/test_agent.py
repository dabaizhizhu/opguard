"""Guarded agent factory: mandatory attachment, guarded calls, child scoping."""

from __future__ import annotations

import pytest

from conftest import CountingEmbedding

from opguard import (
    GuardAttachmentError,
    TicketRejected,
    build_call,
    create_deep_agent,
    guarded_agent_factory,
)


def _base_ticket(guard, issue_standard):
    return issue_standard(
        guard,
        capabilities=("read", "mutate_scoped"),
        resources=("sql:orders", "fs:/workspace"),
    )


def test_create_deep_agent_without_guard_or_ticket_rejects(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = _base_ticket(guard, issue_standard)
    with pytest.raises(GuardAttachmentError):
        create_deep_agent(name="a", ticket=ticket, guard=None)
    with pytest.raises(GuardAttachmentError):
        create_deep_agent(name="a", ticket=None, guard=guard.chain)


def test_guarded_agent_factory_without_chain_rejects(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = _base_ticket(guard, issue_standard)
    with pytest.raises(GuardAttachmentError):
        guarded_agent_factory(name="a", ticket=ticket, chain=None)
    with pytest.raises(GuardAttachmentError):
        guarded_agent_factory(name="a", ticket=ticket, chain=guard.chain, middleware_attached=False)


def test_call_tool_routes_through_guard_chain(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl", embedding=CountingEmbedding())
    ticket = _base_ticket(guard, issue_standard)
    agent = create_deep_agent(name="ops", ticket=ticket, guard=guard.chain)

    danger = agent.call_tool(build_call("sql", "DROP TABLE orders"))
    assert danger.decision == "deny"
    assert danger.layer == "L1"

    safe = agent.call_tool(build_call("sql", "SELECT id FROM orders WHERE id = 1"))
    assert safe.decision == "allow"
    assert safe.executed is True


def test_spawn_child_scope_is_clamped_to_parent(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = _base_ticket(guard, issue_standard)
    agent = create_deep_agent(name="ops", ticket=ticket, guard=guard.chain)

    child = agent.spawn("stats", capabilities=("read",), resources=("sql:orders",), intent="只读统计", ttl_s=300.0)
    assert child.ticket.capabilities == ("read",)
    assert child.ticket.resources == ("sql:orders",)
    assert child.ticket.parent_ticket_id == ticket.ticket_id

    with pytest.raises(TicketRejected):
        agent.spawn("bad", capabilities=("create_user",), resources=("sql:orders",), intent="越权")
    with pytest.raises(TicketRejected):
        agent.spawn("bad", capabilities=("read",), resources=("sql:salaries",), intent="越界")