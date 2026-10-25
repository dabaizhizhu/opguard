"""JSONL audit trail: fixed field schema, jev/sandbox objects, bypass records."""

from __future__ import annotations

import pytest

from conftest import CountingEmbedding

from opguard import BareCallRejected, build_call
from opguard.audit import AUDIT_FIELDS, JEV_FIELDS, SANDBOX_FIELDS, audit_schema_errors


def test_handle_writes_full_deny_and_allow_audit_records(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl", embedding=CountingEmbedding())
    ticket = issue_standard(guard, resources=("sql:orders",), capabilities=("read", "mutate_scoped"))

    deny = guard.handle(ticket, build_call("sql", "DROP TABLE orders"))
    allow = guard.handle(ticket, build_call("sql", "SELECT id FROM orders WHERE id = 1"))

    assert deny.decision == "deny"
    assert allow.decision == "allow"
    assert allow.executed is True

    rows = guard.audit.read()
    assert len(rows) == 2
    decisions = {row["decision"] for row in rows}
    assert decisions == {"deny", "allow"}

    for row in rows:
        assert row["event"] == "guard"
        # Every fixed field is present, no schema gaps.
        for field in AUDIT_FIELDS:
            assert field in row
        assert audit_schema_errors(row) == []
        # jev and sandbox objects always exist and carry their fixed sub-fields.
        assert isinstance(row["jev"], dict)
        assert isinstance(row["sandbox"], dict)
        for key in JEV_FIELDS:
            assert key in row["jev"]
        for key in SANDBOX_FIELDS:
            assert key in row["sandbox"]


def test_allow_record_has_permit_id_and_executed(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl", embedding=CountingEmbedding())
    ticket = issue_standard(guard, resources=("sql:orders",), capabilities=("read",))
    result = guard.handle(ticket, build_call("sql", "SELECT id FROM orders WHERE id = 1"))
    row = guard.audit.read()[-1]
    assert result.permit is not None
    assert row["permit_id"] == result.permit.permit_id
    assert row["executed"] is True
    assert row["decision"] == "allow"


def test_bypass_rejected_event_is_persisted(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard, resources=("sql:orders",), capabilities=("read",))
    call = build_call("sql", "SELECT id FROM orders WHERE id = 1")
    with pytest.raises(BareCallRejected):
        guard.execution.execute(ticket, call, None)
    rows = guard.audit.read()
    bypass = [r for r in rows if r["event"] == "bypass_rejected"]
    assert len(bypass) == 1
    assert bypass[0]["decision"] == "deny"
    # A bypass record follows the same fixed schema.
    assert audit_schema_errors(bypass[0]) == []