# opguard-core

> 仓库级说明（定位、默认 vs 生产、威胁模型入口）见根目录 [README.md](../../README.md) 与 [SECURITY.md](../../SECURITY.md)。口径以根 README 为准：本包是可插拔防护中间件，不是 Agent 框架、不是 OS 沙箱。


版本 0.3.0。给 Agent 工具调用加一层防护：**决策层**产出 `SignedVerdict`，**网关**验签、验票、验范围后签发 `ExecPermit`，**执行层**只接受这份许可。裸 tool call 会被拒绝并写入审计。

本包不执行 shell、SQL 或 HTTP 副作用。默认适配器只记录“已许可”。测试夹具是字符串，不会真的删除任何东西。

## 安装

```bash
python -m pip install opguard-core
```

Python 3.11+。核心无第三方依赖；默认语义向量需 `[embeddings]` extra。

## 挂到代理

```python
from opguard import OpGuard

guard = OpGuard(audit_path="opguard-audit.jsonl")
ticket = guard.tickets.issue(
    agent_id="main",
    capabilities=("read", "mutate_scoped"),
    resources=("sql:orders", "fs:/workspace"),
    intent="读取订单并做带范围的变更",
)
agent = guard.agent(ticket, name="main")
```

子代理走 `agent.spawn(...)`。漏挂 middleware 或 gateway 会抛 `GuardAttachmentError`。子票的能力和资源不能超过父票。`destroy` 在签发时就被拒绝。

`hitl_enabled` 默认为关。打开它也只是记在审计里，流水线不会停下来等人。

## 流水线

1. **L0** 票据完整性、恶意意图、资源范围、能力漂移。没有票就拒绝。
2. **L1** 明确破坏形态：删库、TRUNCATE、无 WHERE 或恒真 WHERE 的删改、系统路径删除或写入、卸载系统包、系统 jar、集合级 DELETE、生产主机上的破坏性方法。命中后不进向量、不进 jev、不进沙箱。
3. **L1.5** 与破坏意图原型做余弦相似度。结构化操作（sql/shell/http/fs）`>= 0.85` 立即拒绝；自然语言（MCP）高相似降级进 L2 二次判断；`0.55–0.85` 进 L2；`< 0.55` 作为放行候选。阈值在 `OpGuardConfig` 里改。
4. **L2** 只处理中档。HTTP 审计客户端是 `HttpJevAuditor`。超时、传输失败、JSON 解析失败都是拒绝。
5. **L3** Jev 判灰（gray）的候选进沙箱**实际执行验证**；低相似默认不进沙箱直接放行（`sandbox_sample_low` 可开）。观察到破坏效果、超时或无法实证验证则拒绝——放进沙箱的命令真实执行，从执行后的真实结果做检测。硬拒绝永远不进来。
6. 网关复核硬拒绝、漂移、范围和高相似，通过后签名许可。执行层再次验许可。

审计是 JSONL。每条记录都带 `jev` 和 `sandbox` 对象，字段见 `opguard.audit.AUDIT_FIELDS`。

## 扩展点

| 协议 | 作用 |
| --- | --- |
| `PolicyPlugin` | 正则族、原型短语、效果标签 |
| `EmbeddingProvider` | `embed(text)`，本地语义或远端模型 |
| `JevAuditor` | 中档审计。可用 `HttpJevAuditor` |
| `SandboxBackend` | `run -> EffectReport`。仓库附 `SubprocessSandbox`（白名单真实执行 + 执行后检测）与 `ScriptedSandbox`（测试替身）；生产隔离（Docker/nsjail）由宿主注入 |
| `ExecutionAdapter` | 网关放行之后的宿主执行器。本仓库不提供会真正跑命令的实现 |

## 生产装配（配置即运行）

复制 `.env.example` 为 `.env`，填 URL/key 后一行装配真实语义向量 + 真实 L2 审查（`build_prod_guard` 自动 `load_dotenv`，不覆盖已有环境变量；勿提交 `.env`）：

```bash
cp .env.example .env
# 编辑 .env：
#   OPGUARD_HMAC_SECRET=...          # 必填；openssl rand -hex 32
#   OPGUARD_JEV_URL=...              # 方案 A：自建审查 → HttpJevAuditor
#   # 或 OPENAI_API_KEY=sk-...       # 方案 B：LLM 审查 → LLMJevAuditor（兼远程嵌入）
# 仅设 JEV_URL 时语义向量还需 OPENAI_API_KEY 或 OPGUARD_EMBEDDING=local
```

```python
from opguard import build_prod_guard

guard = build_prod_guard(audit_path="opguard-audit.jsonl")
```

也可继续用 `export` / PowerShell `$env:` 注入同一批变量；已存在的环境变量优先于 `.env`。

- 缺少 `OPGUARD_HMAC_SECRET`、真实 L2 审查或语义向量配置时启动即报错并提示补哪项；`HashingEmbedding` 字面哈希向量与 `DemoJevAuditor` 默认实现在生产装配中一律拒启——同义改写必须由语义件拦截，绝不回退开发默认实现。
- 组件故障（向量、L2、沙箱异常）按 fail-closed 拒绝，不炸穿调用链；审计落盘失败只告警不中断。
- L3 沙箱与执行器默认实现并发出警告；接真实后端传 `sandbox=` / `adapter=`。评估"沙箱执行+执行后检测"真实链路可用 `sandbox=SubprocessSandbox()`，实证演示见 `examples/demo_sandbox.py`。

攻击逻辑不在这个仓库里实现。能力只有 `read`、`create_user`、`mutate_scoped`。

## 开发与测试

```bash
pip install -e ".[test]"   # 在仓库根目录运行：pip install -e "packages/opguard-core[test]"
python -m pytest tests -q  # 测试套件位于仓库根目录 tests/
```

CI 在 push 与 PR 时于 Ubuntu / Windows、Python 3.11–3.13 全矩阵运行同一套测试；推送 `v*` 标签触发 PyPI 可信发布（见 `.github/workflows/`）。
