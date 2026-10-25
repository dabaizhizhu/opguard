"""从 .env 装配生产 guard 并打一条 handle（仅记录放行决策的 DryRun）。

用法（仓库根）：
  cp .env.example .env   # 填 OPGUARD_HMAC_SECRET + JEV_URL 或 OPENAI_API_KEY
  python packages/opguard-core/examples/run_prod_from_env.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from opguard import build_call, build_prod_guard  # noqa: E402
from opguard.core.execution import DryRunAdapter  # noqa: E402
from opguard.policy.sandbox import ClassifyingSandbox  # noqa: E402


def main() -> None:
    guard = build_prod_guard(
        "opguard-audit.jsonl",
        sandbox=ClassifyingSandbox(),
        adapter=DryRunAdapter(),
    )
    ticket = guard.issue_ticket(
        agent_id="env-demo",
        capabilities=("read", "mutate_scoped"),
        resources=("sql:orders",),
        intent="带范围内查询与变更",
    )
    denied = guard.handle(ticket, build_call("sql", "DELETE FROM orders"))
    print("deny path:", denied.decision, denied.layer, getattr(denied, "reason", ""))
    allowed = guard.handle(ticket, build_call("sql", "SELECT id FROM orders LIMIT 1"))
    print("allow path:", allowed.decision, allowed.permit is not None)


if __name__ == "__main__":
    main()
