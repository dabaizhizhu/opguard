"""JSONL audit log. Every record carries the same field set, including jev and sandbox."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

AUDIT_FIELDS = (
    "ts",
    "event",
    "ticket_id",
    "parent_ticket_id",
    "agent_id",
    "tool",
    "kind",
    "args_hash",
    "action_preview",
    "layer",
    "decision",
    "reason",
    "capabilities",
    "resources",
    "vector_score",
    "vector_band",
    "jev",
    "sandbox",
    "verdict_id",
    "permit_id",
    "hmac_alg",
    "hitl_enabled",
    "policy_version",
    "elapsed_ms",
    "trace",
    "executed",
    "nodes",
)

JEV_FIELDS = (
    "called",
    "outcome",
    "audit_id",
    "latency_ms",
    "http_status",
    "error",
)

SANDBOX_FIELDS = (
    "entered",
    "clean",
    "effects",
    "timed_out",
    "elapsed_ms",
)

JEV_OUTCOMES = frozenset({"skipped", "allow", "deny", "gray", "timeout", "parse_error", "transport_error"})
LAYERS = frozenset({"L0", "L1", "L1.5", "L2", "L3", "gateway"})
BANDS = frozenset({"high", "mid", "low", "skipped"})
EVENTS = frozenset({"guard", "bypass_rejected"})


def blank_jev() -> dict[str, Any]:
    return {
        "called": False,
        "outcome": "skipped",
        "audit_id": None,
        "latency_ms": None,
        "http_status": None,
        "error": None,
    }


def blank_sandbox() -> dict[str, Any]:
    return {
        "entered": False,
        "clean": None,
        "effects": [],
        "timed_out": False,
        "elapsed_ms": None,
    }


def preview(text: str, limit: int = 160) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"


def audit_schema_errors(record: Mapping[str, Any]) -> list[str]:
    """Return human-readable gaps. An empty list means the record is complete."""

    errors: list[str] = []
    for key in AUDIT_FIELDS:
        if key not in record:
            errors.append(f"missing {key}")
    if errors:
        return errors
    if not isinstance(record["ts"], str) or not record["ts"]:
        errors.append("ts")
    if record["event"] not in EVENTS:
        errors.append("event")
    if not isinstance(record["ticket_id"], str):
        errors.append("ticket_id")
    if record["parent_ticket_id"] is not None and not isinstance(record["parent_ticket_id"], str):
        errors.append("parent_ticket_id")
    if not isinstance(record["agent_id"], str):
        errors.append("agent_id")
    for key in ("tool", "kind", "args_hash", "action_preview", "reason", "policy_version"):
        if not isinstance(record[key], str):
            errors.append(key)
    if record["layer"] not in LAYERS:
        errors.append("layer")
    if record["decision"] not in {"allow", "deny"}:
        errors.append("decision")
    if not isinstance(record["capabilities"], list) or not isinstance(record["resources"], list):
        errors.append("scope lists")
    score = record["vector_score"]
    if score is not None and not isinstance(score, (int, float)):
        errors.append("vector_score")
    if isinstance(score, bool):
        errors.append("vector_score bool")
    if record["vector_band"] not in BANDS:
        errors.append("vector_band")
    jev = record["jev"]
    if not isinstance(jev, dict):
        errors.append("jev")
    else:
        for key in JEV_FIELDS:
            if key not in jev:
                errors.append(f"jev.{key}")
        if isinstance(jev, dict) and jev.get("outcome") not in JEV_OUTCOMES:
            errors.append("jev.outcome")
        if isinstance(jev, dict) and not isinstance(jev.get("called"), bool):
            errors.append("jev.called")
    sandbox = record["sandbox"]
    if not isinstance(sandbox, dict):
        errors.append("sandbox")
    else:
        for key in SANDBOX_FIELDS:
            if key not in sandbox:
                errors.append(f"sandbox.{key}")
        if isinstance(sandbox, dict):
            if not isinstance(sandbox.get("entered"), bool) or not isinstance(sandbox.get("timed_out"), bool):
                errors.append("sandbox flags")
            if not isinstance(sandbox.get("effects"), list):
                errors.append("sandbox.effects")
            if sandbox.get("clean") is not None and not isinstance(sandbox.get("clean"), bool):
                errors.append("sandbox.clean")
    if record["verdict_id"] is not None and not isinstance(record["verdict_id"], str):
        errors.append("verdict_id")
    if record["permit_id"] is not None and not isinstance(record["permit_id"], str):
        errors.append("permit_id")
    if record["hmac_alg"] != "HMAC-SHA256":
        errors.append("hmac_alg")
    if not isinstance(record["hitl_enabled"], bool):
        errors.append("hitl_enabled")
    if not isinstance(record["elapsed_ms"], (int, float)) or isinstance(record["elapsed_ms"], bool):
        errors.append("elapsed_ms")
    if not isinstance(record["trace"], list) or not isinstance(record["nodes"], list):
        errors.append("trace")
    if not isinstance(record["executed"], bool):
        errors.append("executed")
    return errors


def stamp(clock_now: float) -> str:
    return datetime.fromtimestamp(clock_now, timezone.utc).isoformat()


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: Mapping[str, Any]) -> dict[str, Any]:
        errors = audit_schema_errors(record)
        if errors:
            raise RuntimeError("incomplete audit record: " + ", ".join(errors))
        stored = dict(record)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(stored, ensure_ascii=False, sort_keys=True) + "\n")
        return stored

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows
