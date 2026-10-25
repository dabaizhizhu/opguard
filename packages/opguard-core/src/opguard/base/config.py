"""Runtime knobs. Human approval is off unless a host builds something else.

This package never waits for a person. ``hitl_enabled`` is recorded in the
audit log and does not pause the pipeline.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Local default only. Hosts set OPGUARD_HMAC_SECRET outside this repository.
DEV_HMAC_SECRET = b"opguard-dev-not-for-production"

POLICY_VERSION = "opguard-v3"
VERSION = "0.3.0"


def _secret_from_env() -> bytes:
    raw = os.environ.get("OPGUARD_HMAC_SECRET")
    if not raw:
        return DEV_HMAC_SECRET
    return raw.encode("utf-8")


@dataclass(frozen=True)
class OpGuardConfig:
    """Thresholds and deadlines for one guard chain.

    Vector bands (inclusive on the lower edge of the stricter band):

    - score >= ``vector_high`` → deny immediately (no L2, no sandbox)
    - ``vector_mid`` <= score < ``vector_high`` → L2 jev (deny 拦 / allow 放 / gray 进沙箱)
    - score < ``vector_mid`` → 未拦截直接放行（不进沙箱）
    """

    hmac_secret: bytes = DEV_HMAC_SECRET
    vector_high: float = 0.85
    vector_mid: float = 0.55
    vector_enabled: bool = True
    l2_enabled: bool = True
    l2_timeout_s: float = 0.8
    sandbox_enabled: bool = True
    sandbox_timeout_s: float = 2.0
    # 未拦截（低相似）直接放行，不进沙箱。设为 True 则低相似候选进沙箱实证。
    sandbox_sample_low: bool = False
    # Jev 判 allow 直接放行，不进沙箱。设为 True 则 L2 放行候选进沙箱复核。
    sandbox_on_l2_allow: bool = False
    hitl_enabled: bool = False
    permit_ttl_s: float = 30.0
    verdict_ttl_s: float = 30.0
    workspace_roots: tuple[str, ...] = ("/workspace",)
    policy_version: str = POLICY_VERSION

    def __post_init__(self) -> None:
        if not 0.0 <= self.vector_mid < self.vector_high <= 1.0:
            raise ValueError("vector thresholds must satisfy 0 <= mid < high <= 1")
        if self.l2_timeout_s <= 0 or self.sandbox_timeout_s <= 0:
            raise ValueError("timeouts must be positive")
        if self.permit_ttl_s <= 0 or self.verdict_ttl_s <= 0:
            raise ValueError("ttls must be positive")

    @classmethod
    def from_env(cls) -> OpGuardConfig:
        return cls(hmac_secret=_secret_from_env())
