"""Gateway verification: verdict/permit signatures, binding, expiry, re-check."""

from __future__ import annotations

import dataclasses

import pytest

from opguard import GatewayRejected, OpGuardConfig, build_call
from opguard.base.crypto import sign
from opguard.base.types import SignedVerdict


def _allow_call(guard, ticket):
    call = build_call("sql", "SELECT id FROM orders WHERE id = 1")
    result = guard.handle(ticket, call)
    assert result.decision == "allow"
    return call, result.verdict, result.permit


def _forge_verdict(ticket, call, secret, *, decision="allow", reason="x", ttl_s=30.0, issued_at=1_700_000_000.0):
    verdict = SignedVerdict(
        verdict_id="v-forged",
        tool=call.tool,
        kind=call.kind.value,
        args_hash=call.fingerprint(),
        ticket_id=ticket.ticket_id,
        layer="L3",
        decision=decision,
        reason=reason,
        ttl_s=ttl_s,
        issued_at=issued_at,
        hmac="",
    )
    return dataclasses.replace(verdict, hmac=sign("verdict", verdict.signing_payload(), secret))


def test_tampered_verdict_signature_is_rejected(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard, resources=("sql:orders",), capabilities=("read",))
    call, verdict, _ = _allow_call(guard, ticket)
    bad = dataclasses.replace(verdict, hmac="0" * 64)
    with pytest.raises(GatewayRejected) as exc:
        guard.gateway.verify_verdict(ticket, call, bad)
    assert "hmac invalid" in str(exc.value)


def test_verdict_args_hash_mismatch_is_rejected(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard, resources=("sql:orders",), capabilities=("read",))
    call, verdict, _ = _allow_call(guard, ticket)
    other_call = build_call("sql", "SELECT id FROM orders WHERE id = 2")
    with pytest.raises(GatewayRejected) as exc:
        guard.gateway.verify_verdict(ticket, other_call, verdict)
    assert "does not bind this call" in str(exc.value)


def test_expired_verdict_is_rejected(make_guard, issue_standard, secret, clock, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard, resources=("sql:orders",), capabilities=("read",))
    call = build_call("sql", "SELECT id FROM orders WHERE id = 1")
    verdict = _forge_verdict(ticket, call, secret, ttl_s=5.0, issued_at=clock.now())
    guard.gateway.verify_verdict(ticket, call, verdict)  # OK now
    clock.advance(6.0)
    with pytest.raises(GatewayRejected) as exc:
        guard.gateway.verify_verdict(ticket, call, verdict)
    assert "verdict expired" in str(exc.value)


def test_expired_permit_ttl_is_rejected(make_guard, issue_standard, secret, clock, tmp_path):
    # Permit TTL (5s) must expire before the verdict TTL (default 30s) so the
    # "permit expired" branch is the first expiry to trip.
    guard = make_guard(tmp_path / "audit.jsonl", config=OpGuardConfig(hmac_secret=secret, permit_ttl_s=5.0))
    ticket = issue_standard(guard, resources=("sql:orders",), capabilities=("read",))
    call = build_call("sql", "SELECT id FROM orders WHERE id = 1")
    verdict = _forge_verdict(ticket, call, secret, ttl_s=30.0, issued_at=clock.now())
    permit = guard.gateway.review(ticket, call, verdict)
    assert permit is not None
    guard.gateway.verify_permit(ticket, call, permit)  # OK now
    clock.advance(permit.expires_at - clock.now() + 0.01)
    with pytest.raises(GatewayRejected) as exc:
        guard.gateway.verify_permit(ticket, call, permit)
    assert "permit expired" in str(exc.value)


def test_gateway_rechecks_l1_hard_deny_on_forged_allow_verdict(
    make_guard, issue_standard, secret, tmp_path
):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard, resources=("sql:*",))
    call = build_call("sql", "DROP TABLE orders")
    verdict = _forge_verdict(ticket, call, secret, issued_at=guard.clock.now())
    with pytest.raises(GatewayRejected) as exc:
        guard.gateway.review(ticket, call, verdict)
    assert "gateway hard deny" in str(exc.value)


def test_gateway_rejects_deny_verdict_and_returns_no_permit(make_guard, issue_standard, secret, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard, resources=("sql:orders",), capabilities=("read",))
    call = build_call("sql", "DELETE FROM orders")
    verdict = _forge_verdict(ticket, call, secret, decision="deny", reason="nope", issued_at=guard.clock.now())
    assert guard.gateway.review(ticket, call, verdict) is None