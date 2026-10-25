"""Decision node. L0 → L1 → L1.5 → L2 → L3, short-circuit, then a signed verdict.

The node never executes a tool and never waits for a person.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Callable

from opguard.audit import blank_jev, blank_sandbox
from opguard.base.clock import Clock, SystemClock
from opguard.base.config import OpGuardConfig
from opguard.base.crypto import sign
from opguard.policy.embedding import EmbeddingProvider, band_for, max_similarity
from opguard.base.errors import JevParseError, JevTimeout, JevTransportError
from opguard.policy.jev import DemoJevAuditor, JevAuditor, JevRequest
from opguard.policy import PolicyPlugin, action_text, intent_is_malicious, scope_allows
from opguard.policy.sandbox import ClassifyingSandbox, SandboxBackend, run_with_deadline
from opguard.core.ticket import TicketIssuer
from opguard.base.types import ALLOWED_CAPABILITIES, Decision, Evaluation, IntentTicket, SignedVerdict, ToolCall, ToolKind, VectorBand


def _step(layer: str, outcome: str, reason: str, started: float) -> dict[str, Any]:
    return {
        "elapsed_ms": (time.perf_counter() - started) * 1000.0,
        "layer": layer,
        "outcome": outcome,
        "reason": reason,
    }


class DecisionNode:
    def __init__(
        self,
        config: OpGuardConfig,
        policy: PolicyPlugin,
        embedding: EmbeddingProvider,
        *,
        jev: JevAuditor | None = None,
        sandbox: SandboxBackend | None = None,
        clock: Clock | None = None,
        ids: Callable[[str], str] | None = None,
    ) -> None:
        self.config = config
        self.policy = policy
        self.embedding = embedding
        self.jev = jev or DemoJevAuditor()
        self.sandbox = sandbox or ClassifyingSandbox(config.workspace_roots)
        self.clock = clock or SystemClock()
        self.ids = ids or (lambda prefix: f"{prefix}-{uuid.uuid4().hex[:12]}")
        self.tickets = TicketIssuer(config.hmac_secret, self.clock)

    def evaluate(self, ticket: IntentTicket | None, call: ToolCall) -> Evaluation:
        trace: list[dict[str, Any]] = []
        jev_info = blank_jev()
        sandbox_info = blank_sandbox()
        score: float | None = None
        band = VectorBand.SKIPPED

        started = time.perf_counter()
        structural = self._structural(ticket)
        if structural is not None:
            trace.append(_step("L0", "deny", structural, started))
            return self._finish(Decision.DENY, "L0", structural, trace, jev_info, sandbox_info, ticket, call, score, band)
        assert ticket is not None
        trace.append(_step("L0", "pass", "ticket ok", started))

        started = time.perf_counter()
        try:
            classification = self.policy.classify(
                call,
                workspace_roots=self.config.workspace_roots,
                resources=ticket.resources,
            )
        except Exception as exc:  # noqa: BLE001 — 宿主插件故障一律 fail-closed
            reason = f"policy component error fail-closed: {exc}"
            trace.append(_step("L1", "deny", reason, started))
            return self._finish(Decision.DENY, "L1", reason, trace, jev_info, sandbox_info, ticket, call, score, band)
        if classification.hard_deny:
            trace.append(_step("L1", "deny", classification.hard_deny, started))
            return self._finish(
                Decision.DENY,
                "L1",
                classification.hard_deny,
                trace,
                jev_info,
                sandbox_info,
                ticket,
                call,
                score,
                band,
            )
        if classification.capability:
            trace.append(_step("L1", "candidate", classification.capability, started))
        else:
            trace.append(_step("L1", "abstain", "no hard pattern", started))

        started = time.perf_counter()
        if not scope_allows(ticket.resources, classification.targets):
            reason = "resource outside ticket scope"
            trace.append(_step("L0", "deny", reason, started))
            return self._finish(Decision.DENY, "L0", reason, trace, jev_info, sandbox_info, ticket, call, score, band)
        if classification.capability and classification.capability not in ticket.capabilities:
            reason = f"intent drift: call needs {classification.capability}"
            trace.append(_step("L0", "deny", reason, started))
            return self._finish(Decision.DENY, "L0", reason, trace, jev_info, sandbox_info, ticket, call, score, band)
        trace.append(_step("L0", "pass", "scope and capability", started))

        state = "candidate" if classification.capability else "gray"
        if self.config.vector_enabled:
            started = time.perf_counter()
            try:
                score = max_similarity(action_text(call), self.policy.prototypes(), self.embedding)
            except Exception as exc:  # noqa: BLE001 — 向量服务故障一律 fail-closed
                reason = f"embedding error fail-closed: {exc}"
                trace.append(_step("L1.5", "deny", reason, started))
                return self._finish(Decision.DENY, "L1.5", reason, trace, jev_info, sandbox_info, ticket, call, score, band)
            band = band_for(score, self.config)
            # 自然语言意图（MCP prose）高相似不直接拦，降级为灰度交给 Jev 二次判断；
            # 只有结构化操作（sql / shell / http / fs）的高相似才直接拦截。
            if band is VectorBand.HIGH and call.kind is ToolKind.MCP:
                band = VectorBand.MID
            if band is VectorBand.HIGH:
                reason = f"vector high similarity {score:.3f}"
                trace.append(_step("L1.5", "deny", reason, started))
                return self._finish(Decision.DENY, "L1.5", reason, trace, jev_info, sandbox_info, ticket, call, score, band)
            if band is VectorBand.MID:
                trace.append(_step("L1.5", "mid", f"vector mid similarity {score:.3f}", started))
                if not self.config.l2_enabled:
                    state = "gray"
                    trace.append(_step("L2", "skip", "l2 disabled", started))
                else:
                    state, jev_reason = self._run_jev(ticket, call, score, band, jev_info)
                    trace.append(_step("L2", state if state != "candidate" else "allow", jev_reason, started))
                    if state == "deny":
                        return self._finish(
                            Decision.DENY,
                            "L2",
                            jev_reason,
                            trace,
                            jev_info,
                            sandbox_info,
                            ticket,
                            call,
                            score,
                            band,
                        )
            else:
                state = "candidate"
                trace.append(_step("L1.5", "low", f"vector low similarity {score:.3f}", started))
        else:
            trace.append(_step("L1.5", "skip", "vector disabled", time.perf_counter()))

        return self._sandbox_or_allow(state, band, trace, jev_info, sandbox_info, ticket, call, score)

    def _run_jev(
        self,
        ticket: IntentTicket,
        call: ToolCall,
        score: float,
        band: VectorBand,
        jev_info: dict[str, Any],
    ) -> tuple[str, str]:
        request = JevRequest(
            ticket_id=ticket.ticket_id,
            tool=call.tool,
            kind=call.kind.value,
            args_hash=call.fingerprint(),
            action_text=action_text(call),
            vector_score=score,
            vector_band=band.value,
        )
        jev_info["called"] = True
        try:
            response = self.jev.audit(request, self.config.l2_timeout_s)
        except JevTimeout as exc:
            jev_info.update(outcome="timeout", latency_ms=exc.latency_ms, error="timeout", http_status=None, audit_id=None)
            return "deny", "jev timeout fail-closed"
        except JevParseError as exc:
            jev_info.update(
                outcome="parse_error",
                latency_ms=exc.latency_ms,
                error=str(exc),
                http_status=exc.http_status,
                audit_id=None,
            )
            return "deny", "jev parse failure fail-closed"
        except JevTransportError as exc:
            jev_info.update(
                outcome="transport_error",
                latency_ms=exc.latency_ms,
                error=str(exc),
                http_status=None,
                audit_id=None,
            )
            return "deny", "jev transport failure fail-closed"
        except Exception as exc:  # noqa: BLE001 — 审查器故障一律 fail-closed
            jev_info.update(outcome="transport_error", latency_ms=0, error=str(exc), http_status=None, audit_id=None)
            return "deny", f"jev component error fail-closed: {exc}"
        jev_info.update(
            outcome=response.decision,
            latency_ms=response.latency_ms,
            error=None,
            http_status=response.http_status,
            audit_id=response.audit_id,
        )
        if response.decision == "deny":
            return "deny", response.reason or "jev deny"
        if response.decision == "gray":
            return "gray", response.reason or "jev gray"
        return "candidate", response.reason or "jev allow"

    def _sandbox_or_allow(
        self,
        state: str,
        band: VectorBand,
        trace: list[dict[str, Any]],
        jev_info: dict[str, Any],
        sandbox_info: dict[str, Any],
        ticket: IntentTicket,
        call: ToolCall,
        score: float | None,
    ) -> Evaluation:
        enter = False
        if state == "gray":
            if not self.config.sandbox_enabled:
                reason = "sandbox disabled, gray fail-closed"
                trace.append(_step("L3", "deny", reason, time.perf_counter()))
                return self._finish(Decision.DENY, "L3", reason, trace, jev_info, sandbox_info, ticket, call, score, band)
            enter = True
        elif state == "candidate":
            if band is VectorBand.LOW:
                enter = self.config.sandbox_enabled and self.config.sandbox_sample_low
            elif band is VectorBand.MID:
                enter = self.config.sandbox_enabled and self.config.sandbox_on_l2_allow
            else:
                enter = self.config.sandbox_enabled
        if not enter:
            layer = "L1.5" if band is not VectorBand.SKIPPED else "L1"
            if band is VectorBand.MID:
                layer = "L2"
            reason = "candidate allow"
            trace.append(_step("L3", "skip", "sandbox not required", time.perf_counter()))
            return self._finish(Decision.ALLOW, layer, reason, trace, jev_info, sandbox_info, ticket, call, score, band)

        started = time.perf_counter()
        try:
            report = run_with_deadline(
                self.sandbox,
                call,
                timeout_s=self.config.sandbox_timeout_s,
                resources=ticket.resources,
            )
        except Exception as exc:  # noqa: BLE001 — 沙箱故障一律 fail-closed
            reason = f"sandbox error fail-closed: {exc}"
            sandbox_info.update(entered=True, clean=False, effects=[], timed_out=False, elapsed_ms=None)
            trace.append(_step("L3", "deny", reason, started))
            return self._finish(Decision.DENY, "L3", reason, trace, jev_info, sandbox_info, ticket, call, score, band)
        sandbox_info.update(
            entered=True,
            clean=report.clean and not report.timed_out and not report.effects,
            effects=list(report.effects),
            timed_out=report.timed_out,
            elapsed_ms=report.elapsed_ms,
        )
        if report.timed_out or report.effects or not report.clean:
            reason = "sandbox timeout fail-closed" if report.timed_out else f"sandbox observed {', '.join(report.effects) or report.detail}"
            trace.append(_step("L3", "deny", reason, started))
            return self._finish(Decision.DENY, "L3", reason, trace, jev_info, sandbox_info, ticket, call, score, band)
        trace.append(_step("L3", "allow", "sandbox clean", started))
        return self._finish(Decision.ALLOW, "L3", "sandbox clean", trace, jev_info, sandbox_info, ticket, call, score, band)

    def _structural(self, ticket: IntentTicket | None) -> str | None:
        if ticket is None:
            return "missing ticket"
        expected = sign("ticket", ticket.signing_payload(), self.config.hmac_secret)
        from opguard.base.crypto import signatures_equal

        if not ticket.signature or not signatures_equal(expected, ticket.signature):
            return "ticket signature invalid"
        if ticket.expired(self.clock.now()):
            return "ticket expired"
        if not ticket.capabilities or not ticket.resources:
            return "empty ticket scope"
        if any(capability not in ALLOWED_CAPABILITIES for capability in ticket.capabilities):
            return "capability not allowed"
        if intent_is_malicious(ticket.intent):
            return "malicious ticket intent"
        return None

    def _finish(
        self,
        decision: Decision,
        layer: str,
        reason: str,
        trace: list[dict[str, Any]],
        jev_info: dict[str, Any],
        sandbox_info: dict[str, Any],
        ticket: IntentTicket | None,
        call: ToolCall,
        score: float | None,
        band: VectorBand,
    ) -> Evaluation:
        issued_at = self.clock.now()
        verdict_id = self.ids("verdict")
        payload = {
            "args_hash": call.fingerprint(),
            "decision": decision.value,
            "issued_at": issued_at,
            "kind": call.kind.value,
            "layer": layer,
            "reason": reason,
            "ticket_id": ticket.ticket_id if ticket else "",
            "tool": call.tool,
            "ttl_s": self.config.verdict_ttl_s,
            "verdict_id": verdict_id,
        }
        verdict = SignedVerdict(
            verdict_id=verdict_id,
            tool=call.tool,
            kind=call.kind.value,
            args_hash=call.fingerprint(),
            ticket_id=payload["ticket_id"],
            layer=layer,
            decision=decision.value,
            reason=reason,
            ttl_s=self.config.verdict_ttl_s,
            issued_at=issued_at,
            hmac=sign("verdict", payload, self.config.hmac_secret),
        )
        return Evaluation(
            verdict=verdict,
            trace=trace,
            vector_score=score,
            vector_band=band.value,
            jev=dict(jev_info),
            sandbox=dict(sandbox_info),
            capabilities=tuple(ticket.capabilities) if ticket else (),
            resources=tuple(ticket.resources) if ticket else (),
            parent_ticket_id=ticket.parent_ticket_id if ticket else None,
            agent_id=ticket.agent_id if ticket else "",
            ticket_id=ticket.ticket_id if ticket else "",
        )
