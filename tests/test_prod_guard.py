"""Production assembly (build_prod_guard): fail fast on missing/mock components."""

from __future__ import annotations

import pytest

from opguard import build_prod_guard
from opguard.core.execution import DryRunAdapter
from opguard.policy.embedding import HashingEmbedding
from opguard.policy.jev import DemoJevAuditor, HttpJevAuditor
from opguard.policy.sandbox import ClassifyingSandbox
from opguard.policy.semantic import LLMJevAuditor, RemoteEmbedding

_SECRET = "s" * 64


def test_missing_hmac_secret_raises(tmp_path):
    with pytest.raises(ValueError, match="OPGUARD_HMAC_SECRET"):
        build_prod_guard(tmp_path / "audit.jsonl", env={})


def test_explicit_demo_jev_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="DemoJevAuditor"):
        build_prod_guard(
            tmp_path / "audit.jsonl",
            env={"OPGUARD_HMAC_SECRET": _SECRET},
            jev=DemoJevAuditor(),
        )


def test_explicit_hashing_embedding_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="HashingEmbedding"):
        build_prod_guard(
            tmp_path / "audit.jsonl",
            env={"OPGUARD_HMAC_SECRET": _SECRET, "OPENAI_API_KEY": "sk-test"},
            embedding=HashingEmbedding(),
        )


def test_jev_url_assembles_http_jev_auditor(tmp_path):
    guard = build_prod_guard(
        tmp_path / "audit.jsonl",
        env={
            "OPGUARD_HMAC_SECRET": _SECRET,
            "OPGUARD_JEV_URL": "http://localhost:9000/v1/audit",
            "OPGUARD_EMBEDDING": "local",
        },
        sandbox=ClassifyingSandbox(),
        adapter=DryRunAdapter(),
    )
    assert isinstance(guard.decision.jev, HttpJevAuditor)


def test_openai_api_key_assembles_llm_jev_and_remote_embedding(tmp_path):
    guard = build_prod_guard(
        tmp_path / "audit.jsonl",
        env={"OPGUARD_HMAC_SECRET": _SECRET, "OPENAI_API_KEY": "sk-test"},
        sandbox=ClassifyingSandbox(),
        adapter=DryRunAdapter(),
    )
    assert isinstance(guard.decision.jev, LLMJevAuditor)
    assert isinstance(guard.embedding, RemoteEmbedding)