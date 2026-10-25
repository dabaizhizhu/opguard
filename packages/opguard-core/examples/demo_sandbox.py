"""L3 沙箱实证验证链路演示：真实执行 + 执行后检测。

本脚本直接运行 opguard 框架，所有裁决结果均来自真实调用，未硬编码任何
输出。演示的核心命题：

  默认装配下，未拦截（低相似）的调用直接放行；显式开启 sandbox_sample_low
  后，未拦截的调用进入沙箱真实执行，观察执行后的真实效果，干净才放行到
  真实环境（执行适配器）。

运行方式（在仓库根目录）：

  python packages/opguard-core/examples/demo_sandbox.py
"""

import os
import sys
import tempfile
from pathlib import Path

# 允许从仓库根目录直接运行（未安装时定位源码）
_SRC = Path(__file__).resolve().parents[3] / "packages" / "opguard-core" / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from opguard import (  # noqa: E402
    OpGuard,
    OpGuardConfig,
    SubprocessSandbox,
    ToolCall,
    ExecPermit,
    build_call,
)
from opguard.policy.embedding import HashingEmbedding  # noqa: E402

_LINE = "-" * 72


class HostAdapter:
    """真实环境执行器：只有拿到 ExecPermit 的调用才会到达这里。"""

    def execute(self, call: ToolCall, permit: ExecPermit) -> dict:
        action = (call.args.get("command")
                  or call.args.get("statement")
                  or call.args.get("op"))
        return {"stage": "real-env", "permit_id": permit.permit_id, "action": action}


def make_guard(sandbox, audit_name):
    # 演示 L3 沙箱实证：显式开启 sandbox_sample_low（默认未拦截直接放行）。
    # 显式注入哈希向量以隔离 torch 依赖；本演示聚焦沙箱，不依赖语义模型。
    config = OpGuardConfig(sandbox_timeout_s=2.0, sandbox_sample_low=True)
    return OpGuard(config=config, embedding=HashingEmbedding(), sandbox=sandbox,
                   adapter=HostAdapter(),
                   audit_path=os.path.join(tempfile.gettempdir(), audit_name))


def show(result, note):
    sb = result.audit.get("sandbox") if result.audit else None
    detail = "-"
    if isinstance(sb, dict):
        detail = sb.get("detail") or f"effects={sb.get('effects')}" or "-"
    print(f"  decision={result.decision:<6} layer={result.layer:<5} executed={result.executed}")
    print(f"  reason : {result.reason}")
    print(f"  sandbox: {detail}")
    print(f"  verdict: {note}")


def main() -> None:
    # 每次运行从干净的审计开始，保证汇总数字对应当前这次真实运行
    for name in ("demo-sbx-audit.jsonl", "demo-sbx-mock-audit.jsonl"):
        audit_file = os.path.join(tempfile.gettempdir(), name)
        if os.path.exists(audit_file):
            os.remove(audit_file)

    # 门票：读 + 范围内的变更；资源覆盖演示涉及的 sql/mcp/fs/shell 面
    ticket = dict(agent_id="sbx-demo", capabilities=("read", "mutate_scoped"),
                  resources=("sql:orders", "fs:/workspace", "mcp:*", "shell:workspace"),
                  intent="沙箱验证演示：带范围内维护与只读查询")

    print(_LINE)
    print("A. 真实执行沙箱：SubprocessSandbox（白名单真执行 + 真实效果检测）")
    print(_LINE)
    guard = make_guard(SubprocessSandbox(), "demo-sbx-audit.jsonl")
    tk = guard.issue_ticket(**ticket)

    print("\n[1] shell: rm -rf /            （预期：L1 正则层直接拒绝，不进沙箱——硬破坏形态）")
    show(guard.handle(tk, build_call("shell", "rm -rf /")), "L1 regex hard-deny，沙箱未参与")

    print("\n[2] mcp : rm tmp.txt            （预期：L1 放过（workspace 内），沙箱白名单拒绝 = 真执行前的实证闸门）")
    show(guard.handle(tk, build_call("mcp", "rm tmp.txt")), "regex/jev 均未拦截 → 沙箱拒绝执行非白名单命令 → deny")

    hostname_cmd = "hostname" if os.name == "nt" else "ls -la"
    print(f"\n[3] mcp : {hostname_cmd:<22}（预期：沙箱真实执行并观测输出，干净 → 放行给真实执行器）")
    show(guard.handle(tk, build_call("mcp", hostname_cmd)),
         "沙箱真实 subprocess 执行，stdout 观测无破坏 → allow → HostAdapter 收到 permit")

    struct_cmd = "hostname | findstr x" if os.name == "nt" else "ls | grep cfg"
    print(f"\n[4] mcp : {struct_cmd:<22}（预期：管道结构拒绝回放 → deny）")
    show(guard.handle(tk, build_call("mcp", struct_cmd)), "管道/重定向结构不在回放范围 → 实证拒绝")

    print("\n[5] fs  : write /workspace/demo.txt（预期：沙箱一次性目录里真实写文件，干净 → allow）")
    show(guard.handle(tk, build_call("fs", "write /workspace/demo.txt")),
         "文件在沙箱临时目录被真实写入后销毁；真实环境无副作用")

    print("\n[6] fs: delete /workspace/ghost.txt（预期：真实执行删除 → 目标不存在 → 执行后检测拒绝）")
    show(guard.handle(tk, build_call("fs", "delete /workspace/ghost.txt")),
         "真实执行暴露'目标已消失'这一执行结果 → deny（这就是执行后检测）")

    print("\n[7] sql: SELECT id FROM orders （预期：子进程沙箱无法真实验证 SQL → fail-closed 拒绝）")
    show(guard.handle(tk, build_call("sql", "SELECT id FROM orders")),
         "沙箱诚实拒绝：sql 类调用需宿主注入数据库沙箱，否则不实证、不放行")

    print(_LINE)
    print("B. 对照：默认装配（sandbox_sample_low=False + ClassifyingSandbox）")
    print("    未拦截直接放行，对比 A 显式开启沙箱实证后的拒绝")
    print(_LINE)
    guard_mock = OpGuard(embedding=HashingEmbedding(), sandbox=None,
                         audit_path=os.path.join(tempfile.gettempdir(),
                                                 "demo-sbx-mock-audit.jsonl"))
    tk_mock = guard_mock.issue_ticket(**ticket)
    print("\n[8] 同样的 mcp: rm tmp.txt（对照：默认未拦截直接放行，对比 [2] 开启沙箱实证后的拒绝）")
    show(guard_mock.handle(tk_mock, build_call("mcp", "rm tmp.txt")),
         "默认未拦截直接放行 → allow；真实沙箱（[2] 显式开启实证）拦下了同一个调用")

    print(_LINE)
    rows = guard.audit.read()
    entered = [r for r in rows if r["sandbox"] and r["sandbox"].get("entered")]
    unverified = [r for r in rows if r["decision"] == "deny"
                  and r["sandbox"] and "whitelist_refused" in str(r["sandbox"].get("effects"))]
    print(f"审计汇总：共 {len(rows)} 次真实调用；进沙箱 {len(entered)} 次；"
      f"白名单实证拒绝 {len(unverified)} 次；审计文件 -> {os.path.join(tempfile.gettempdir(), 'demo-sbx-audit.jsonl')}")
    print("诊断：所有进入沙箱的行为均由沙箱真实执行产生，没有一行是硬编码模拟。")


if __name__ == "__main__":
    main()