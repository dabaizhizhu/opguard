"""Execution layer: bare calls refused, dry-run zero side-effects, custom adapters."""

from __future__ import annotations

import dataclasses

import pytest

from opguard import BareCallRejected, DryRunAdapter, GatewayRejected, build_call


def _allow_ticket(guard, issue_standard):
    return issue_standard(guard, resources=("sql:orders",), capabilities=("read",))


def test_bare_execution_node_call_is_rejected_and_audited(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = _allow_ticket(guard, issue_standard)
    call = build_call("sql", "SELECT id FROM orders WHERE id = 1")
    with pytest.raises(BareCallRejected):
        guard.execution.execute(ticket, call, None)
    rows = guard.audit.read()
    assert rows[-1]["event"] == "bypass_rejected"


def test_dry_run_adapter_has_zero_side_effects(make_guard, issue_standard, tmp_path):
    adapter = DryRunAdapter()
    guard = make_guard(tmp_path / "audit.jsonl", adapter=adapter)
    ticket = _allow_ticket(guard, issue_standard)
    call = build_call("sql", "SELECT id FROM orders WHERE id = 1")
    result = guard.handle(ticket, call)
    assert result.decision == "allow"
    assert result.executed is True
    assert result.output["dry_run"] is True
    assert result.output["permit_id"] == result.permit.permit_id
    assert adapter.calls == 1


def test_custom_adapter_receives_exec_permit_and_runs(make_guard, issue_standard, tmp_path):
    received = {}

    class HostAdapter:
        def execute(self, call, permit):
            received["call"] = call
            received["permit"] = permit
            return {"executed": True, "permit_id": permit.permit_id, "action": call.args["statement"]}

    guard = make_guard(tmp_path / "audit.jsonl", adapter=HostAdapter())
    ticket = _allow_ticket(guard, issue_standard)
    call = build_call("sql", "SELECT id FROM orders WHERE id = 1")
    result = guard.handle(ticket, call)
    assert result.executed is True
    assert received["permit"].permit_id == result.permit.permit_id
    assert received["call"].tool == call.tool
    assert result.output == {"executed": True, "permit_id": result.permit.permit_id, "action": "SELECT id FROM orders WHERE id = 1"}


def test_tampered_permit_is_rejected_and_audited(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = _allow_ticket(guard, issue_standard)
    call = build_call("sql", "SELECT id FROM orders WHERE id = 1")
    result = guard.handle(ticket, call)
    permit = result.permit
    bad = dataclasses.replace(permit, hmac="0" * 64)
    with pytest.raises(GatewayRejected):
        guard.execution.execute(ticket, call, bad)
    rows = guard.audit.read()
    assert rows[-1]["event"] == "bypass_rejected"