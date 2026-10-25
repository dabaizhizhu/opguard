"""Wires decision → gateway → execution and writes one JSONL audit record."""

from __future__ import annotations

import time
import warnings
from pathlib import Path

from opguard.audit import AuditLog, preview, stamp
from opguard.base.clock import Clock, SystemClock
from opguard.base.config import DEV_HMAC_SECRET, OpGuardConfig
from opguard.core.decision import DecisionNode
from opguard.policy.embedding import EmbeddingProvider, ScriptedEmbedding
from opguard.base.errors import GatewayRejected
from opguard.core.execution import DryRunAdapter, ExecutionAdapter, ExecutionNode
from opguard.core.factory import GuardChain, GuardedAgent, guarded_agent_factory
from opguard.core.gateway import Gateway
from opguard.policy.jev import DemoJevAuditor, JevAuditor
from opguard.policy import DefaultPolicy, PolicyPlugin, action_text
from opguard.policy.sandbox import ClassifyingSandbox, SandboxBackend
from opguard.base.types import HandleResult, IntentTicket, ToolCall


class OpGuard:
    """Single entry point. Agents call ``handle``; they do not call tools directly."""

    def __init__(
        self,
        *,
        config: OpGuardConfig | None = None,
        policy: PolicyPlugin | None = None,
        embedding: EmbeddingProvider | None = None,
        jev: JevAuditor | None = None,
        sandbox: SandboxBackend | None = None,
        adapter: ExecutionAdapter | None = None,
        audit_path: str | Path = "opguard-audit.jsonl",
        clock: Clock | None = None,
    ) -> None:
        self.config = config or OpGuardConfig()
        self.policy = policy or DefaultPolicy()
        # 默认走真语义嵌入：未显式注入时使用 SemanticEmbedding，绝不用字面哈希兜底。
        # 语义依赖缺失时首次 embed 会抛出带安装提示的错误（fail-closed），不会静默降级。
        if embedding is None:
            from opguard.policy.semantic import SemanticEmbedding

            embedding = SemanticEmbedding()
        self.embedding = embedding
        self.clock = clock or SystemClock()
        self.audit = AuditLog(audit_path)
        self.decision = DecisionNode(
            self.config,
            self.policy,
            self.embedding,
            jev=jev,
            sandbox=sandbox,
            clock=self.clock,
        )
        self.gateway = Gateway(self.config, self.policy, self.embedding, clock=self.clock)
        self.execution = ExecutionNode(
            self.gateway,
            self.audit,
            self.config,
            adapter=adapter or DryRunAdapter(),
            clock=self.clock,
        )
        self.tickets = self.decision.tickets
        self.chain = GuardChain(
            decision=self.decision,
            gateway=self.gateway,
            execution=self.execution,
            tickets=self.tickets,
            handle=self.handle,
        )

    def handle(self, ticket: IntentTicket | None, call: ToolCall) -> HandleResult:
        started = time.perf_counter()
        evaluation = self.decision.evaluate(ticket, call)
        nodes = ["decision", "gateway"]
        permit = None
        output = None
        executed = False
        verdict = evaluation.verdict
        try:
            permit = self.gateway.review(ticket, call, verdict)
        except GatewayRejected as exc:
            elapsed = (time.perf_counter() - started) * 1000.0
            record = self._record(
                evaluation,
                call,
                permit=None,
                executed=False,
                nodes=nodes,
                elapsed_ms=elapsed,
                layer="gateway",
                decision="deny",
                reason=str(exc),
            )
            try:
                self.audit.write(record)
            except OSError as exc:  # 审计落盘故障不中断流水线，但必须留下告警
                warnings.warn(f"audit write failed: {exc}", stacklevel=2)
            return HandleResult(
                decision="deny",
                layer="gateway",
                reason=str(exc),
                verdict=verdict,
                permit=None,
                executed=False,
                output=None,
                nodes=tuple(nodes),
                audit=record,
                elapsed_ms=elapsed,
            )
        if permit is not None:
            nodes.append("execution")
            output = self.execution.execute(ticket, call, permit)
            executed = True
        elapsed = (time.perf_counter() - started) * 1000.0
        record = self._record(
            evaluation,
            call,
            permit=permit,
            executed=executed,
            nodes=nodes,
            elapsed_ms=elapsed,
            layer=verdict.layer,
            decision=verdict.decision,
            reason=verdict.reason,
        )
        try:
            self.audit.write(record)
        except OSError as exc:  # 审计落盘故障不中断流水线，但必须留下告警
            warnings.warn(f"audit write failed: {exc}", stacklevel=2)
        return HandleResult(
            decision=verdict.decision,
            layer=verdict.layer,
            reason=verdict.reason,
            verdict=verdict,
            permit=permit,
            executed=executed,
            output=output,
            nodes=tuple(nodes),
            audit=record,
            elapsed_ms=elapsed,
        )

    def issue_ticket(
        self,
        *,
        agent_id: str,
        capabilities: tuple[str, ...] | list[str],
        resources: tuple[str, ...] | list[str],
        intent: str,
        ttl_s: float = 600.0,
    ) -> IntentTicket:
        """Convenience wrapper around :meth:`TicketIssuer.issue` bound to this guard."""
        return self.tickets.issue(
            agent_id=agent_id,
            capabilities=capabilities,
            resources=resources,
            intent=intent,
            ttl_s=ttl_s,
        )

    def agent(self, ticket: IntentTicket, *, name: str = "agent", tools: tuple[str, ...] | list[str] = ()) -> GuardedAgent:
        return guarded_agent_factory(name=name, ticket=ticket, chain=self.chain, tools=tools, middleware_attached=True)

    def _record(
        self,
        evaluation,
        call: ToolCall,
        *,
        permit,
        executed: bool,
        nodes: list[str],
        elapsed_ms: float,
        layer: str,
        decision: str,
        reason: str,
    ) -> dict:
        return {
            "ts": stamp(self.clock.now()),
            "event": "guard",
            "ticket_id": evaluation.ticket_id or "",
            "parent_ticket_id": evaluation.parent_ticket_id,
            "agent_id": evaluation.agent_id or "",
            "tool": call.tool,
            "kind": call.kind.value,
            "args_hash": call.fingerprint(),
            "action_preview": preview(action_text(call)),
            "layer": layer,
            "decision": decision,
            "reason": reason,
            "capabilities": list(evaluation.capabilities),
            "resources": list(evaluation.resources),
            "vector_score": evaluation.vector_score,
            "vector_band": evaluation.vector_band,
            "jev": evaluation.jev,
            "sandbox": evaluation.sandbox,
            "verdict_id": evaluation.verdict.verdict_id,
            "permit_id": permit.permit_id if permit else None,
            "hmac_alg": "HMAC-SHA256",
            "hitl_enabled": self.config.hitl_enabled,
            "policy_version": self.config.policy_version,
            "elapsed_ms": elapsed_ms,
            "trace": evaluation.trace,
            "executed": executed,
            "nodes": list(nodes),
        }


def build_lab_guard(
    audit_path: str | Path,
    *,
    config: OpGuardConfig | None = None,
    clock: Clock | None = None,
) -> OpGuard:
    """Lab and acceptance wiring: scripted mock embedding, demo jev, classifying sandbox.

    Policy code is the core default plugin. The lab does not carry a second ruleset.
    """

    from opguard.policy.catalog import FIXTURES

    policy = DefaultPolicy()
    scores = {fixture.action: fixture.similarity for fixture in FIXTURES}
    embedding = ScriptedEmbedding(scores, prototypes=policy.prototypes(), default=0.0)
    return OpGuard(
        config=config
        or OpGuardConfig(hmac_secret=DEV_HMAC_SECRET, hitl_enabled=False, sandbox_sample_low=True),
        policy=policy,
        embedding=embedding,
        jev=DemoJevAuditor(),
        sandbox=ClassifyingSandbox(),
        audit_path=audit_path,
        clock=clock,
    )
