"""Optional semantic upgrades for the embedding and jev slots.

The core library stays zero-dependency: :class:`HashingEmbedding` and
:class:`DemoJevAuditor` remain the offline defaults. This module provides
production-grade replacements behind lazy imports, so importing ``opguard``
never requires torch, transformers, or network access.

* :class:`SemanticEmbedding`  -- sentence-transformers model (needs ``pip install
  "opguard-core[embeddings]"``); loads lazily and raises a clear error if absent.
* :class:`RemoteEmbedding`    -- OpenAI-compatible ``/v1/embeddings`` endpoint, so a
  local Ollama or any hosted model works without torch.
* :class:`HybridEmbedding`    -- semantic when available, hashing as automatic fallback.
* :class:`LLMJevAuditor`      -- OpenAI-compatible chat endpoint as the L2 reviewer,
  strictly parsed and fail-closed like :class:`HttpJevAuditor`.

All classes implement the existing protocols; drop one into ``OpGuard(...)`` and
nothing else in the framework changes.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Sequence

from opguard.policy.embedding import HashingEmbedding
from opguard.base.errors import JevParseError, JevTimeout, JevTransportError
from opguard.policy.jev import DECISIONS, JevRequest, JevResponse

_SEMANTIC_HINT = (
    'semantic embedding is unavailable. Install the optional extra: '
    'pip install "opguard-core[embeddings]"'
)

# For multilingual intent (Chinese + English) a small multilingual model is the
# pragmatic default. Swap in any sentence-transformers compatible model.
_DEFAULT_SEMANTIC_MODEL = "paraphrase-multilingual-MiniLM-L12-v2"


class SemanticEmbedding:
    """Sentence-transformers backed embedder. Lazily imports the heavy dependency."""

    def __init__(self, model: str = _DEFAULT_SEMANTIC_MODEL) -> None:
        self.model = model
        self._encoder = None

    def _load(self):
        if self._encoder is None:
            try:
                from sentence_transformers import SentenceTransformer  # lazy: heavy dep
            except ImportError as exc:
                raise ImportError(_SEMANTIC_HINT) from exc
            self._encoder = SentenceTransformer(self.model)
        return self._encoder

    def embed(self, text: str) -> list[float]:
        return [float(value) for value in self._load().encode([text])[0]]


class RemoteEmbedding:
    """OpenAI-compatible embeddings endpoint (works with Ollama, vLLM, OpenAI...)."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "text-embedding-3-small",
        timeout_s: float = 5.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s
        if not self.api_key:
            raise ValueError(
                "RemoteEmbedding requires an API key (set OPENAI_API_KEY or pass api_key=)"
            )

    def embed(self, text: str) -> list[float]:
        body = json.dumps({"input": text, "model": self.model}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/embeddings",
            data=body,
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise ConnectionError(str(exc.reason)) from exc
        try:
            return [float(value) for value in data["data"][0]["embedding"]]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ValueError(f"unexpected embedding response: {data!r}") from exc


class HybridEmbedding:
    """Semantic vectors when a model is available, hashing vectors otherwise."""

    def __init__(self, model: str = _DEFAULT_SEMANTIC_MODEL) -> None:
        self.model = model
        self._semantic: SemanticEmbedding | None = None
        self._hashing = HashingEmbedding()

    def _try_semantic(self) -> SemanticEmbedding | None:
        if self._semantic is None:
            try:
                self._semantic = SemanticEmbedding(model=self.model)
                self._semantic.embed("probe")  # fail eagerly if the dep is missing
            except ImportError:
                self._semantic = None
        return self._semantic

    def embed(self, text: str) -> list[float]:
        semantic = self._try_semantic()
        if semantic is not None:
            return semantic.embed(text)
        return self._hashing.embed(text)

    @property
    def using_semantic(self) -> bool:
        return self._try_semantic() is not None


class LLMJevAuditor:
    """LLM reviewer for the L2 slot, speaking OpenAI-compatible chat APIs.

    Works with OpenAI, a local Ollama instance (``ollama run llama3.2``), or any
    compatible endpoint. Parsed strictly; every failure mode fails closed with the
    same exception types the core already handles.
    """

    SYSTEM_PROMPT = (
        "You are a security reviewer for agent tool calls. "
        "Classify the call as 'allow', 'gray', or 'deny' based only on whether it "
        "destroys data, escalates privilege, or breaks out of its declared scope. "
        "Respond with JSON only: {\"decision\": \"allow|gray|deny\", "
        "\"reason\": \"short justification\", \"audit_id\": \"any string id\"}."
    )

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str = "gpt-4o-mini",
        timeout_s: float = 10.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.model = model
        self.timeout_s = timeout_s
        if not self.api_key:
            raise ValueError(
                "LLMJevAuditor requires an API key (set OPENAI_API_KEY or pass api_key=)"
            )

    def audit(self, request: JevRequest, timeout_s: float) -> JevResponse:
        prompt = (
            f"Tool: {request.tool}\nKind: {request.kind}\n"
            f"Action: {request.action_text}\n"
            f"Vector score: {request.vector_score:.3f} ({request.vector_band} band)\n"
            f"Ticket: {request.ticket_id[:12]}...\n"
            "Judge now."
        )
        body = json.dumps(
            {
                "model": self.model,
                "temperature": 0.0,
                "messages": [
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        started = time.perf_counter()
        box: dict[str, object] = {}

        def target() -> None:
            try:
                with urllib.request.urlopen(req, timeout=timeout_s) as response:
                    box["value"] = response.read()
            except Exception as exc:  # fail closed on any transport fault
                box["error"] = exc

        worker = threading.Thread(target=target, daemon=True)
        worker.start()
        worker.join(timeout_s)
        latency_ms = (time.perf_counter() - started) * 1000.0
        if worker.is_alive():
            raise JevTimeout("llm jev timed out", latency_ms=latency_ms)
        if "error" in box:
            error = box["error"]
            if isinstance(error, TimeoutError):
                raise JevTimeout(str(error), latency_ms=latency_ms)
            raise JevTransportError(str(error), latency_ms=latency_ms)

        try:
            data = json.loads(box["value"])  # type: ignore[arg-type]
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise JevParseError("unexpected llm response shape", latency_ms=latency_ms) from exc
        return self._parse(content, latency_ms)

    @staticmethod
    def _parse(content: str, latency_ms: float) -> JevResponse:
        text = content.strip()
        if text.startswith("```"):
            text = text.strip("`").removeprefix("json").strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise JevParseError("llm returned invalid json", latency_ms=latency_ms) from exc
        decision = data.get("decision") if isinstance(data, dict) else None
        if decision not in DECISIONS:
            raise JevParseError("llm returned missing or unknown decision", latency_ms=latency_ms)
        reason = data.get("reason")
        audit_id = data.get("audit_id")
        if not isinstance(reason, str):
            reason = ""
        if not isinstance(audit_id, str) or not audit_id:
            audit_id = "llm"
        return JevResponse(decision, reason, audit_id, 200, latency_ms)


def combined_max_similarity(
    text: str, prototypes: Sequence[str], *embedders
) -> float:
    """Conservative fusion: the highest cosine across all embedders wins.

    Used when a host wants semantic + hashing signals at once; the max keeps
    the guard conservative (any one signal screaming is enough).
    """

    from opguard.policy.embedding import max_similarity

    return max((max_similarity(text, prototypes, embedder) for embedder in embedders), default=0.0)