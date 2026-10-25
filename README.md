# opguard-core

**Agent 工具调用的可插拔防护中间件**：票据 → 多层裁决 → 签名执行许可 → JSONL 审计。

版本 **0.3.0** · Python 3.11+ · MIT · 核心零依赖，默认语义向量可选装

---

## 定位（一句话说清）

你的 Agent 照旧在自己的框架里跑；危险工具调用必须先过守卫，才能触达真实世界。类比 Linux PAM 之于登录、Express middleware 之于 Web。

| 是 | 不是 |
| --- | --- |
| 挂在**工具执行路径**上的旁路库 | Agent 框架本身 |
| 票据 / 裁决 / 许可三层 HMAC 域分离 | 操作系统沙箱（容器 / seccomp / nsjail 由宿主提供） |
| 可插拔中间件，框架无关 | 与特定 Agent 框架绑定的插件 |

---

## 快速开始

```bash
pip install -e "packages/opguard-core[test]"   # 本仓库开发安装
# 或发布后：pip install opguard-core
```

```python
from opguard import OpGuard, build_call

guard = OpGuard(audit_path="opguard-audit.jsonl")  # 默认语义向量（需 pip install "opguard-core[embeddings]"）
ticket = guard.issue_ticket(
    agent_id="main",
    capabilities=("read", "mutate_scoped"),  # destroy 不在能力表，签不出去
    resources=("sql:orders", "fs:/workspace"),
    intent="读取订单并做带范围内的变更",
)

denied = guard.handle(ticket, build_call("sql", "DELETE FROM orders"))
print(denied.decision, denied.layer)  # deny L1 ...

allowed = guard.handle(ticket, build_call("sql", "SELECT id FROM orders"))
print(allowed.decision, allowed.permit is not None)  # allow True
```

更完整的链路、三层签名与接入姿势见 [使用手册.md](使用手册.md)。  
威胁模型与已知限制见 [SECURITY.md](SECURITY.md)。  
沙箱实证演示见 [packages/opguard-core/examples/demo_sandbox.py](packages/opguard-core/examples/demo_sandbox.py)。

---

## 三种装配怎么选

| 方式 | 适合 | 说明 |
| --- | --- | --- |
| `OpGuard()` | 本地开发、单测、跑通链路 | 默认语义向量 + 内置 L2 审查器；缺 `[embeddings]` 时 fail-closed 报错；**不是生产配置** |
| `build_prod_guard()` | 要真实密钥 / 语义 / L2 的部署 | 缺 `OPGUARD_HMAC_SECRET`、真实语义或 L2 时**拒启**；不回退开发默认实现 |
| 宿主注入隔离 | 需要真隔离执行 | 本库不自带 Docker/nsjail；通过 `sandbox=` / `adapter=` 注入；评估链路可用 `SubprocessSandbox` |

**生产 Jev（填 URL/key 即用）：**

```bash
cp .env.example .env   # 或 packages/opguard-core/.env.example
# 编辑 .env：填 OPGUARD_HMAC_SECRET +（OPGUARD_JEV_URL 或 OPENAI_API_KEY）
# 仅 JEV_URL 时还需语义向量：OPENAI_API_KEY 或 OPGUARD_EMBEDDING=local
```

```python
from opguard import build_prod_guard

# build_prod_guard 会自动 load_dotenv()，无需再手 export
guard = build_prod_guard(audit_path="opguard-audit.jsonl")
```

---

## 真亮点（可指到代码）

1. **三层域分离 HMAC**：`ticket` / `verdict` / `permit` 各用独立签名域，缺一或篡改即拒。
2. **Fail-closed**：决策层默认拒绝；L2/语义/沙箱故障按拒绝处理，不炸穿调用链。
3. **网关二次复核**：裁决通过后仍验票、验范围、验硬拒绝，再签 30 秒短命 `ExecPermit`。
4. **裸调用必拒**：执行层无许可就拒绝并写审计；漏挂守卫抛 `GuardAttachmentError`。
5. **子票 ⊆ 父票**：子代理能力和资源不能比父票更宽；`destroy` 在签发阶段就被挡住。
6. **生产装配要求生产组件**：`build_prod_guard` 拒绝开发用哈希向量与 Demo L2，要求注入生产组件。

---

## 文档

- [使用手册](使用手册.md) — 机制、接入姿势、生产装配、扩展点
- [SECURITY.md](SECURITY.md) — 威胁模型、已知限制、如何报告问题
- [包内 README](packages/opguard-core/README.md) — PyPI / 安装向说明（口径与本文一致）
- [demo_sandbox.py](packages/opguard-core/examples/demo_sandbox.py) — L3 沙箱执行后检测演示

## 开发与测试

```bash
pip install -e "packages/opguard-core[test]"
python -m pytest tests -q
```

## 许可证

[MIT](LICENSE)

## 仓库

- Homepage / Source: https://github.com/dabaizhizhu/opguard-core
- Issues: https://github.com/dabaizhizhu/opguard-core/issues
