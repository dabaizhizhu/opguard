"""Shared records. A signed verdict is the only thing the gateway will turn into a permit."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping

from opguard.base.crypto import args_hash


class Capability(StrEnum):
    READ = "read"
    CREATE_USER = "create_user"
    MUTATE_SCOPED = "mutate_scoped"


class ToolKind(StrEnum):
    SQL = "sql"
    SHELL = "shell"
    HTTP = "http"
    FS = "fs"
    MCP = "mcp"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class VectorBand(StrEnum):
    HIGH = "high"
    MID = "mid"
    LOW = "low"
    SKIPPED = "skipped"


# Destroy is not a capability. Ticket issuance rejects the string before this tuple is used.
ALLOWED_CAPABILITIES = frozenset(c.value for c in Capability)


@dataclass(frozen=True)
class ToolCall:
    tool: str
    kind: ToolKind
    args: Mapping[str, Any]

    @property
    def kind_value(self) -> str:
        return self.kind.value

    def fingerprint(self) -> str:
        return args_hash(self.tool, self.kind.value, self.args)


def build_call(kind: str | ToolKind, action: str, *, tool: str | None = None) -> ToolCall:
    """Build a tool call from a fixture string. The string is not executed."""

    parsed = ToolKind(kind)
    if parsed is ToolKind.SQL:
        return ToolCall(tool or "sql.query", parsed, {"statement": action})
    if parsed is ToolKind.SHELL:
        return ToolCall(tool or "shell.exec", parsed, {"command": action})
    if parsed is ToolKind.HTTP:
        method, url = action.split(" ", 1)
        return ToolCall(tool or "http.request", parsed, {"method": method.upper(), "url": url})
    if parsed is ToolKind.FS:
        op, path = action.split(" ", 1)
        return ToolCall(tool or f"fs.{op}", parsed, {"op": op, "path": path, "content": ""})
    if parsed is ToolKind.MCP:
        return ToolCall(tool or "mcp.tool", parsed, {"command": action})
    raise ValueError(f"unsupported kind {kind}")


@dataclass(frozen=True)
class IntentTicket:
    ticket_id: str
    agent_id: str
    capabilities: tuple[str, ...]
    resources: tuple[str, ...]
    intent: str
    issued_at: float
    ttl_s: float
    parent_ticket_id: str | None = None
    signature: str = ""

    def signing_payload(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "capabilities": list(self.capabilities),
            "intent": self.intent,
            "issued_at": self.issued_at,
            "parent_ticket_id": self.parent_ticket_id,
            "resources": list(self.resources),
            "ticket_id": self.ticket_id,
            "ttl_s": self.ttl_s,
        }

    def expired(self, now: float) -> bool:
        return now > self.issued_at + self.ttl_s


@dataclass(frozen=True)
class SignedVerdict:
    verdict_id: str
    tool: str
    kind: str
    args_hash: str
    ticket_id: str
    layer: str
    decision: str
    reason: str
    ttl_s: float
    issued_at: float
    hmac: str

    def signing_payload(self) -> dict[str, Any]:
        return {
            "args_hash": self.args_hash,
            "decision": self.decision,
            "issued_at": self.issued_at,
            "kind": self.kind,
            "layer": self.layer,
            "reason": self.reason,
            "ticket_id": self.ticket_id,
            "tool": self.tool,
            "ttl_s": self.ttl_s,
            "verdict_id": self.verdict_id,
        }

    def expired(self, now: float) -> bool:
        return now > self.issued_at + self.ttl_s


@dataclass(frozen=True)
class ExecPermit:
    permit_id: str
    verdict: SignedVerdict
    expires_at: float
    hmac: str

    def signing_payload(self) -> dict[str, Any]:
        return {
            "args_hash": self.verdict.args_hash,
            "expires_at": self.expires_at,
            "permit_id": self.permit_id,
            "ticket_id": self.verdict.ticket_id,
            "tool": self.verdict.tool,
            "verdict_hmac": self.verdict.hmac,
            "verdict_id": self.verdict.verdict_id,
        }


@dataclass(frozen=True)
class EffectReport:
    sandbox_id: str
    effects: tuple[str, ...]
    clean: bool
    timed_out: bool
    elapsed_ms: float
    detail: str


@dataclass
class HandleResult:
    decision: str
    layer: str
    reason: str
    verdict: SignedVerdict | None
    permit: ExecPermit | None
    executed: bool
    output: dict[str, Any] | None
    nodes: tuple[str, ...]
    audit: dict[str, Any]
    elapsed_ms: float


@dataclass
class Evaluation:
    """Final decision plus the trace a test or the lab can inspect."""

    verdict: SignedVerdict
    trace: list[dict[str, Any]] = field(default_factory=list)
    vector_score: float | None = None
    vector_band: str = VectorBand.SKIPPED.value
    jev: dict[str, Any] = field(default_factory=dict)
    sandbox: dict[str, Any] = field(default_factory=dict)
    capabilities: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    parent_ticket_id: str | None = None
    agent_id: str | None = None
    ticket_id: str | None = None
