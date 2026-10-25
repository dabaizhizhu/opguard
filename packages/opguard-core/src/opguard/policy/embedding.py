"""Embedding providers and cosine bands.

The default provider is an offline hashing embedder. Tests and the lab inject
:class:`ScriptedEmbedding`, which pins a cosine so the three bands are deterministic.
Prototype strings describe destructive intent. They are not commands to run.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol, Sequence

from opguard.base.config import OpGuardConfig
from opguard.base.types import VectorBand

_TOKEN = re.compile(r"[a-z0-9_\u4e00-\u9fff]+")


class EmbeddingProvider(Protocol):
    """Maps text to a vector. Hosts may swap in a remote model."""

    def embed(self, text: str) -> Sequence[float]:
        """Return a dense vector for ``text``."""


def cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right) or not left:
        raise ValueError("vectors must be the same non-zero length")
    dot = 0.0
    norm_l = 0.0
    norm_r = 0.0
    for a, b in zip(left, right, strict=True):
        dot += a * b
        norm_l += a * a
        norm_r += b * b
    if norm_l == 0.0 or norm_r == 0.0:
        return 0.0
    return dot / math.sqrt(norm_l * norm_r)


def band_for(score: float, config: OpGuardConfig) -> VectorBand:
    if score >= config.vector_high:
        return VectorBand.HIGH
    if score >= config.vector_mid:
        return VectorBand.MID
    return VectorBand.LOW


def max_similarity(text: str, prototypes: Sequence[str], embedder: EmbeddingProvider) -> float:
    if not prototypes:
        return 0.0
    current = embedder.embed(text)
    return max(cosine(current, embedder.embed(prototype)) for prototype in prototypes)


class HashingEmbedding:
    """Local hashing embedder. No network and no model download."""

    def __init__(self, dims: int = 128) -> None:
        if dims < 16:
            raise ValueError("dims must be at least 16")
        self.dims = dims

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dims
        tokens = _TOKEN.findall(text.casefold())
        grams = list(tokens)
        grams.extend(f"{a}_{b}" for a, b in zip(tokens, tokens[1:], strict=False))
        compact = "".join(tokens)
        grams.extend(compact[i : i + 3] for i in range(max(0, len(compact) - 2)))
        if not grams:
            grams.append("")
        for gram in grams:
            digest = hashlib.sha256(gram.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self.dims
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(value * value for value in vector)) or 1.0
        return [value / norm for value in vector]


class ScriptedEmbedding:
    """Test and lab double. Exact action strings map to a cosine against prototypes.

    Prototype texts sit on axis 0. Any other text is placed so its cosine with
    that axis equals the scripted score (default 0, the low band).
    """

    def __init__(self, scores: dict[str, float] | None = None, *, prototypes: Sequence[str] = (), default: float = 0.0) -> None:
        self.scores = dict(scores or {})
        self.prototypes = frozenset(prototypes)
        self.default = default

    def embed(self, text: str) -> list[float]:
        if text in self.prototypes:
            return [1.0, 0.0]
        score = self.scores.get(text, self.default)
        score = max(-1.0, min(1.0, float(score)))
        # Keep the vector on the unit circle so cosine with [1, 0] is `score`.
        other = math.sqrt(max(0.0, 1.0 - score * score))
        return [score, other]
