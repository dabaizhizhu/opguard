"""L2 jev auditor.

Only the mid vector band calls this layer. Timeout, transport failure, and
unparseable bodies are fail-closed. The HTTP client posts an audit request;
it does not run the tool call.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from opguard.base.errors import JevParseError, JevTimeout, JevTransportError

DECISIONS = frozenset({"allow", "deny", "gray"})


@dataclass(frozen=True)
class JevRequest:
    ticket_id: str
    tool: str
    kind: str
    args_hash: str
    action_text: str
    vector_score: float
    vector_band: str

    def to_json(self) -> dict[str, object]:
        return {
            "action_text": self.action_text,
            "args_hash": self.args_hash,
            "kind": self.kind,
            "ticket_id": self.ticket_id,
            "tool": self.tool,
            "vector_band": self.vector_band,
            "vector_score": self.vector_score,
        }


@dataclass(frozen=True)
class JevResponse:
    decision: str
    reason: str
    audit_id: str
    http_status: int | None = None
    latency_ms: float = 0.0


class JevTransport(Protocol):
    def post(self, url: str, body: bytes, headers: dict[str, str], timeout_s: float) -> tuple[int, bytes]:
        """Return HTTP status and raw body, or raise on transport failure."""


class JevAuditor(Protocol):
    def audit(self, request: JevRequest, timeout_s: float) -> JevResponse:
        """Review one mid-band call. Raise JevTimeout or JevParseError to fail closed."""


class UrllibTransport:
    """Stdlib HTTP transport. Hosts point it at their own auditor URL."""

    def post(self, url: str, body: bytes, headers: dict[str, str], timeout_s: float) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout_s) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            return exc.code, payload
        except TimeoutError as exc:
            raise TimeoutError(str(exc)) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise TimeoutError(str(exc.reason)) from exc
            raise ConnectionError(str(exc.reason)) from exc


class HttpJevAuditor:
    """POST a jev audit request and require a JSON decision."""

    def __init__(self, url: str, transport: JevTransport | None = None) -> None:
        if not url:
            raise ValueError("jev url is required")
        self.url = url
        self.transport = transport or UrllibTransport()

    def audit(self, request: JevRequest, timeout_s: float) -> JevResponse:
        body = json.dumps(request.to_json(), ensure_ascii=False).encode("utf-8")
        headers = {"content-type": "application/json", "accept": "application/json"}
        started = time.perf_counter()
        box: dict[str, object] = {}

        def target() -> None:
            try:
                box["value"] = self.transport.post(self.url, body, headers, timeout_s)
            except Exception as exc:  # noqa: BLE001 — fail closed on any transport fault
                box["error"] = exc

        worker = threading.Thread(target=target, daemon=True)
        worker.start()
        worker.join(timeout_s)
        latency_ms = (time.perf_counter() - started) * 1000.0
        if worker.is_alive():
            raise JevTimeout("jev timed out", latency_ms=latency_ms)
        if "error" in box:
            error = box["error"]
            if isinstance(error, TimeoutError):
                raise JevTimeout(str(error), latency_ms=latency_ms)
            raise JevTransportError(str(error), latency_ms=latency_ms)
        status, payload = box["value"]  # type: ignore[misc]
        return self._parse(status, payload, latency_ms)

    @staticmethod
    def _parse(status: int, payload: bytes, latency_ms: float) -> JevResponse:
        try:
            data = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JevParseError("invalid json", http_status=status, latency_ms=latency_ms) from exc
        if not isinstance(data, dict):
            raise JevParseError("response is not an object", http_status=status, latency_ms=latency_ms)
        decision = data.get("decision")
        if decision not in DECISIONS:
            raise JevParseError("missing or unknown decision", http_status=status, latency_ms=latency_ms)
        audit_id = data.get("audit_id")
        if not isinstance(audit_id, str) or not audit_id:
            raise JevParseError("missing audit_id", http_status=status, latency_ms=latency_ms)
        reason = data.get("reason")
        if not isinstance(reason, str):
            reason = ""
        return JevResponse(decision, reason, audit_id, status, latency_ms)


class DemoJevAuditor:
    """Offline stand-in used by the lab and the default guard.

    Keyword replies are a mock auditor, not a second policy engine and not an
    instruction to perform the described action.
    """

    def audit(self, request: JevRequest, timeout_s: float) -> JevResponse:
        del timeout_s
        text = request.action_text.casefold()
        if "session cache" in text:
            return JevResponse("deny", "jev flagged destructive cleanup", "demo-deny", 200, 0.0)
        if "archive index" in text:
            return JevResponse("gray", "jev left the call in the gray zone", "demo-gray", 200, 0.0)
        return JevResponse("allow", "jev found no destructive signal", "demo-allow", 200, 0.0)
