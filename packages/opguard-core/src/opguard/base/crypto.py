"""Domain-separated HMAC-SHA256 for tickets, verdicts, and permits."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def args_hash(tool: str, kind: str, args: Mapping[str, Any]) -> str:
    body = canonical_json({"args": dict(args), "kind": kind, "tool": tool})
    return hashlib.sha256(body).hexdigest()


def sign(domain: str, payload: Mapping[str, Any], secret: bytes) -> str:
    mac = hmac.new(secret, domain.encode("utf-8") + b"\0" + canonical_json(payload), hashlib.sha256)
    return mac.hexdigest()


def signatures_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
