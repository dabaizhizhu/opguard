"""Protection layer for agent tool calls: decision, gateway, execution.

This package does not run shell, SQL, or HTTP side effects. Hosts bring an
ExecutionAdapter if they need one. Destroy is not a ticket capability.

目录结构：``base`` 协议与基础件，``core`` 决策主链路，``policy`` L1-L3
防护组件（扩展点），``audit`` 审计与取证。
"""

from opguard.audit import AUDIT_FIELDS, JEV_FIELDS, SANDBOX_FIELDS, audit_schema_errors
from opguard.base.config import POLICY_VERSION, VERSION, OpGuardConfig
from opguard.base.errors import (
    BareCallRejected,
    GatewayRejected,
    GuardAttachmentError,
    JevParseError,
    JevTimeout,
    JevTransportError,
    OpGuardError,
    TicketRejected,
)
from opguard.base.types import (
    Capability,
    ExecPermit,
    HandleResult,
    IntentTicket,
    SignedVerdict,
    ToolCall,
    ToolKind,
    build_call,
)
from opguard.policy import DefaultPolicy, PolicyPlugin
from opguard.policy.catalog import FIXTURES
from opguard.policy.embedding import EmbeddingProvider, HashingEmbedding, ScriptedEmbedding
from opguard.policy.jev import DemoJevAuditor, HttpJevAuditor, JevAuditor
from opguard.policy.sandbox import ClassifyingSandbox, SandboxBackend, SubprocessSandbox
from opguard.core.execution import DryRunAdapter, ExecutionAdapter
from opguard.core.factory import GuardChain, build_prod_guard, create_deep_agent, guarded_agent_factory
from opguard.core.runtime import OpGuard, build_lab_guard

__version__ = VERSION

__all__ = [
    "AUDIT_FIELDS",
    "BareCallRejected",
    "Capability",
    "ClassifyingSandbox",
    "DefaultPolicy",
    "DemoJevAuditor",
    "DryRunAdapter",
    "EmbeddingProvider",
    "ExecPermit",
    "ExecutionAdapter",
    "FIXTURES",
    "GatewayRejected",
    "GuardChain",
    "GuardAttachmentError",
    "HandleResult",
    "HashingEmbedding",
    "HttpJevAuditor",
    "IntentTicket",
    "JEV_FIELDS",
    "JevAuditor",
    "JevParseError",
    "JevTimeout",
    "JevTransportError",
    "OpGuard",
    "OpGuardConfig",
    "OpGuardError",
    "POLICY_VERSION",
    "PolicyPlugin",
    "SANDBOX_FIELDS",
    "SandboxBackend",
    "ScriptedEmbedding",
    "SignedVerdict",
    "SubprocessSandbox",
    "TicketRejected",
    "ToolCall",
    "ToolKind",
    "VERSION",
    "__version__",
    "audit_schema_errors",
    "build_call",
    "build_lab_guard",
    "build_prod_guard",
    "create_deep_agent",
    "guarded_agent_factory",
]