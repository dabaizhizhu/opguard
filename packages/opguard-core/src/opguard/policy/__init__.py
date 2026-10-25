"""L1-L3 防护组件包。

- ``rules``：L1 规则与默认真件（DefaultPolicy / PolicyPlugin）
- ``embedding``：L1.5 向量判定（含语义真件的协议）
- ``semantic``：可选语义嵌入与 LLM 审查器（需第三方依赖）
- ``jev``：L2 审查器协议与内置实现
- ``sandbox``：L3 沙箱协议与分类实现
- ``catalog``：意图与夹具目录
"""

from .rules import (
    Classification,
    DefaultPolicy,
    PolicyPlugin,
    action_text,
    collect_effects,
    intent_is_malicious,
    resource_covers,
    scope_allows,
)

__all__ = [
    "Classification",
    "DefaultPolicy",
    "PolicyPlugin",
    "action_text",
    "collect_effects",
    "intent_is_malicious",
    "resource_covers",
    "scope_allows",
]