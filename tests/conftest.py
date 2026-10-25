"""Shared fixtures for the opguard-core test suite.

Every guard built here carries a fresh, random HMAC secret and a manual clock so
that signature and expiry behaviour are deterministic and isolated from the
wall clock.  No network is ever touched except ``localhost`` in the L2 tests.
"""

from __future__ import annotations

import secrets

import pytest

from opguard import OpGuard, OpGuardConfig
from opguard.base.clock import ManualClock
from opguard.policy.jev import JevRequest, JevResponse


@pytest.fixture
def secret() -> bytes:
    """A fresh random HMAC secret — never the development secret."""
    return secrets.token_bytes(32)


@pytest.fixture
def clock() -> ManualClock:
    """A manual clock so ticket/verdict/permit expiry is fully deterministic."""
    return ManualClock()


@pytest.fixture
def make_guard(secret, clock):
    """Build an :class:`OpGuard` bound to a fresh secret and a manual clock."""

    def _make(audit_path, *, config=None, embedding=None, jev=None, sandbox=None, adapter=None):
        cfg = config if config is not None else OpGuardConfig(hmac_secret=secret)
        # 测试默认用确定性哈希向量，隔离 torch 依赖；生产默认已改为真语义。
        if embedding is None:
            from opguard.policy.embedding import HashingEmbedding

            embedding = HashingEmbedding()
        return OpGuard(
            config=cfg,
            embedding=embedding,
            jev=jev,
            sandbox=sandbox,
            adapter=adapter,
            audit_path=audit_path,
            clock=clock,
        )

    return _make


@pytest.fixture
def issue_standard():
    """Issue a broad-but-benign ticket that passes the L0 structural checks."""

    def _issue(
        guard,
        *,
        capabilities=("read", "mutate_scoped"),
        resources=("sql:*", "fs:/workspace", "mcp:*", "http:*", "shell:workspace"),
        intent="运营维护",
        ttl_s=600.0,
        agent_id="a1",
    ):
        return guard.issue_ticket(
            agent_id=agent_id,
            capabilities=capabilities,
            resources=resources,
            intent=intent,
            ttl_s=ttl_s,
        )

    return _issue


class CountingJev:
    """Counting L2 double. Tracks whether the decision node reached L2."""

    def __init__(self, decision="allow", reason="mock jev", audit_id="mock-jev"):
        self.decision = decision
        self.reason = reason
        self.audit_id = audit_id
        self.calls = 0
        self.requests: list[JevRequest] = []

    def audit(self, request: JevRequest, timeout_s: float) -> JevResponse:
        self.calls += 1
        self.requests.append(request)
        return JevResponse(self.decision, self.reason, self.audit_id, 200, 0.0)


class CountingEmbedding:
    """Counting L1.5 double backed by a scripted cosine against the default prototypes."""

    def __init__(self, scores=None, *, default=0.0):
        from opguard.policy import DefaultPolicy
        from opguard.policy.embedding import ScriptedEmbedding

        self._inner = ScriptedEmbedding(scores or {}, prototypes=DefaultPolicy().prototypes(), default=default)
        self.calls = 0

    def embed(self, text):
        self.calls += 1
        return self._inner.embed(text)