"""Guarded agent factory. A spawn without the guard chain fails closed."""

from __future__ import annotations

import os as _os
import warnings
from dataclasses import dataclass
from typing import Any, Callable

from opguard.base.errors import GuardAttachmentError
from opguard.core.execution import ExecutionNode
from opguard.core.gateway import Gateway
from opguard.core.ticket import TicketIssuer
from opguard.base.types import HandleResult, IntentTicket, ToolCall


@dataclass
class GuardChain:
    """The three nodes every main and child agent must carry."""

    decision: Any
    gateway: Gateway
    execution: ExecutionNode
    tickets: TicketIssuer
    handle: Callable[[IntentTicket | None, ToolCall], HandleResult]


class GuardedAgent:
    """An agent whose tool calls and children go through one guard chain."""

    def __init__(
        self,
        *,
        name: str,
        ticket: IntentTicket,
        chain: GuardChain | None,
        tools: tuple[str, ...] | list[str] = (),
        middleware_attached: bool = True,
    ) -> None:
        if not middleware_attached or chain is None:
            raise GuardAttachmentError("漏挂守卫，拒绝创建")
        if chain.gateway is None or chain.decision is None or chain.execution is None:
            raise GuardAttachmentError("漏挂守卫，拒绝创建")
        self.name = name
        self.ticket = ticket
        self.chain = chain
        self.tools = tuple(tools)
        self.middleware_attached = True

    def call_tool(self, call: ToolCall) -> HandleResult:
        return self.chain.handle(self.ticket, call)

    def spawn(
        self,
        name: str,
        *,
        capabilities: tuple[str, ...] | list[str],
        resources: tuple[str, ...] | list[str],
        intent: str,
        ttl_s: float = 300.0,
        tools: tuple[str, ...] | list[str] | None = None,
    ) -> GuardedAgent:
        child = self.chain.tickets.issue_child(
            self.ticket,
            agent_id=name,
            capabilities=capabilities,
            resources=resources,
            intent=intent,
            ttl_s=ttl_s,
        )
        return guarded_agent_factory(
            name=name,
            ticket=child,
            chain=self.chain,
            tools=self.tools if tools is None else tools,
            middleware_attached=True,
        )


def guarded_agent_factory(
    *,
    name: str,
    ticket: IntentTicket,
    chain: GuardChain | None,
    tools: tuple[str, ...] | list[str] = (),
    middleware_attached: bool = True,
) -> GuardedAgent:
    """Create a main or child agent. Missing middleware or gateway is a hard failure."""

    return GuardedAgent(
        name=name,
        ticket=ticket,
        chain=chain,
        tools=tools,
        middleware_attached=middleware_attached,
    )


def build_prod_guard(
    audit_path,
    *,
    config=None,
    policy=None,
    embedding=None,
    jev=None,
    sandbox=None,
    adapter=None,
    clock=None,
    env=None,
):
    """生产装配：配置环境变量即可得到带真实语义与真实 L2 审查的完整 guard。

    必需配置：
    - ``OPGUARD_HMAC_SECRET``：票据/裁决/许可的共享 HMAC 密钥（``openssl rand -hex 32``），
      缺失时直接报错，绝不回退开发密钥。
    - L2 审查器二选一：``OPENAI_API_KEY``（OpenAI 兼容 LLM 审查）或
      ``OPGUARD_JEV_URL``（自建 /v1/audit 审查服务），缺失时报错并提示补什么。
    - 语义向量二选一：``OPENAI_API_KEY``（远程语义嵌入）或
      ``OPGUARD_EMBEDDING=local``（本地语义模型）。字面哈希向量与 DemoJevAuditor
      默认实现在生产装配中一律报错拒启——同义改写必须由语义件拦截。

    可选配置：``OPENAI_BASE_URL``（兼容端点/Ollama）、``OPGUARD_LLM_MODEL``、
    ``OPGUARD_EMBEDDING_MODEL``、``OPGUARD_HITL=1``（仅记录人工审批标记）。

    默认实现（带 warnings.warn 提醒）：L3 用 ClassifyingSandbox 仅做静态分类，
    执行器用 DryRunAdapter 仅记录放行决策；注入 ``sandbox=`` / ``adapter=`` 参数接真实后端。
    其中 L3 默认实现不执行调用、不兑现"沙箱执行+执行后检测"语义，评估真实
    检测链路可用 opguard SubprocessSandbox（白名单真执行）。

    调用前会先 ``load_dotenv()``（不覆盖已有环境变量）：复制 ``.env.example`` 为
    ``.env`` 并填入 URL/key 即可，无需再手 export。
    """
    from opguard.base.envfile import load_dotenv
    from opguard.core.runtime import OpGuard
    from opguard.policy import DefaultPolicy
    from opguard.policy.embedding import HashingEmbedding
    from opguard.policy.jev import DemoJevAuditor, HttpJevAuditor
    from opguard.policy.sandbox import ClassifyingSandbox

    # Fill missing keys from .env before reading the process environment.
    load_dotenv()
    environment = dict(_os.environ) if env is None else dict(env)

    secret = environment.get("OPGUARD_HMAC_SECRET", "").strip()
    if not secret:
        raise ValueError(
            "生产装配缺少 OPGUARD_HMAC_SECRET（票据/裁决共享 HMAC 密钥）。"
            "请生成一次并注入所有信任方：openssl rand -hex 32"
        )

    if jev is None:
        jev_url = environment.get("OPGUARD_JEV_URL", "").strip()
        api_key = environment.get("OPENAI_API_KEY", "").strip()
        if jev_url:
            jev = HttpJevAuditor(jev_url)
        elif api_key:
            from opguard.policy.semantic import LLMJevAuditor

            jev = LLMJevAuditor(
                api_key=api_key,
                base_url=environment.get("OPENAI_BASE_URL") or None,
                model=environment.get("OPGUARD_LLM_MODEL", "gpt-4o-mini"),
                timeout_s=float(environment.get("OPGUARD_LLM_TIMEOUT_S", "10")),
            )
        else:
            raise ValueError(
                "生产装配缺少真实 L2 审查器：设置 OPENAI_API_KEY（OpenAI 兼容 LLM 审查）"
                "或 OPGUARD_JEV_URL（自建审查服务），两者至少其一"
            )

    if isinstance(jev, DemoJevAuditor):
        raise ValueError(
            "生产装配拒绝 DemoJevAuditor（内置轻量审查器，不提供语义审查）："
            "请设置 OPENAI_API_KEY（LLMJevAuditor）或 OPGUARD_JEV_URL（HttpJevAuditor），"
            "或显式传入自建 JevAuditor 实现"
        )

    if embedding is None:
        api_key = environment.get("OPENAI_API_KEY", "").strip()
        mode = environment.get("OPGUARD_EMBEDDING", "").strip().lower()
        if api_key and mode != "off":
            from opguard.policy.semantic import RemoteEmbedding

            embedding = RemoteEmbedding(
                api_key=api_key,
                base_url=environment.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
                model=environment.get("OPGUARD_EMBEDDING_MODEL", "text-embedding-3-small"),
                timeout_s=float(environment.get("OPGUARD_EMBEDDING_TIMEOUT_S", "5")),
            )
        elif mode == "local":
            from opguard.policy.semantic import SemanticEmbedding

            embedding = SemanticEmbedding(
                model=environment.get("OPGUARD_EMBEDDING_MODEL", "paraphrase-multilingual-MiniLM-L12-v2")
            )
        else:
            raise ValueError(
                "生产装配缺少语义向量：字面哈希向量不提供语义匹配，生产必须注入语义嵌入件。"
                "请设置 OPENAI_API_KEY（远程语义嵌入）或 OPGUARD_EMBEDDING=local（本地模型），"
                "或显式传入 SemanticEmbedding / RemoteEmbedding / HybridEmbedding 实现"
            )

    if isinstance(embedding, HashingEmbedding):
        raise ValueError(
            "生产装配拒绝 HashingEmbedding 字面哈希向量（不提供语义匹配）："
            "请注入语义嵌入件 SemanticEmbedding / RemoteEmbedding / HybridEmbedding，"
            "或设置 OPENAI_API_KEY / OPGUARD_EMBEDDING=local（见使用手册第 8 节）"
        )

    if sandbox is None:
        sandbox = ClassifyingSandbox()
        warnings.warn(
            "L3 使用默认 ClassifyingSandbox：不执行调用、不兑现 L3 实证验证语义（沙箱执行+执行后检测）；"
            "评估真实检测链路请注入 SubprocessSandbox()（见 opguard.policy.sandbox）"
            "或宿主隔离沙箱：build_prod_guard(sandbox=your_backend)",
            stacklevel=2,
        )

    if adapter is None:
        from opguard.core.execution import DryRunAdapter

        adapter = DryRunAdapter()
        warnings.warn(
            "默认 DryRunAdapter 仅记录放行决策；如需真实执行请注入自定义 ExecutionAdapter："
            "build_prod_guard(adapter=your_adapter)",
            stacklevel=2,
        )

    if config is None:
        from opguard.base.config import OpGuardConfig

        config = OpGuardConfig(
            hmac_secret=secret.encode("utf-8"),
            hitl_enabled=environment.get("OPGUARD_HITL", "").strip().lower() == "1",
        )

    return OpGuard(
        config=config,
        policy=policy,
        embedding=embedding,
        jev=jev,
        sandbox=sandbox,
        adapter=adapter,
        audit_path=audit_path,
        clock=clock,
    )
