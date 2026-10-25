# 安全策略（Security Policy）

## 支持的版本

| 版本 | 状态 |
| --- | --- |
| 0.3.x | 支持 |

## 威胁模型

opguard-core 保护的是 **agent 工具调用通道**：每一次工具调用都是一次申请，必须持有有效票据、通过多层裁决并拿到签名执行许可，才能触达真实世界。

该模型成立的前提是：**这条通道是 agent 触碰真实世界的唯一出口**。以下情形不在本库的防护边界内：

- agent 持有任意代码执行权（可直接 `os.system` 等）——那是 OS 沙箱（容器 / seccomp / nsjail）的职责，本库不替代；
- 宿主自行实现的 `ExecutionAdapter` 内部逻辑；
- 对称 HMAC 密钥（`OPGUARD_HMAC_SECRET`）的物理保管、分发与轮换。

## 已知限制

接入前请确认以下边界与你的预期一致：

- **L1 基于规则匹配**，识别固定破坏形态；同义改写的语义攻击由 L1.5 语义向量（默认 `SemanticEmbedding`）与 L2 审查共同覆盖。`HashingEmbedding` 字面哈希向量面向离线/测试场景，不提供语义匹配能力；
- **默认实现面向开发与测试**：embedding 默认已接入真语义（`SemanticEmbedding`）；L2 审查、L3 沙箱与执行器的默认实现（`DemoJevAuditor`、`ClassifyingSandbox`、`DryRunAdapter`）仅用于本地开发与链路验证，生产装配 `build_prod_guard` 会拒绝 `HashingEmbedding` 与 `DemoJevAuditor` 并要求注入生产组件；
- **`SubprocessSandbox` 不构成隔离边界**：它以宿主账户执行白名单命令，用于评估"执行 + 执行后检测"链路；生产隔离需宿主注入 Docker / nsjail / Firecracker 后端；
- **`HttpJevAuditor` 不携带鉴权头**：自建审查服务请部署在受信网络，或在网关层自行加鉴权；
- **`hitl_enabled` 仅写入审计标记**：本库不暂停流水线等待人工审批；需要审批流的场景请在宿主执行器侧实现；
- **自然语言与结构化操作采用不同拦截策略**：L1.5 语义相似度的高相似（≥0.85）直接拦截仅对结构化操作（sql/shell/http/fs）生效；自然语言意图（MCP）高相似不直接拦，降级进 L2 由审查器二次判断；
- 所有组件故障（向量 / L2 审查 / 沙箱）一律 fail-closed 拒绝，可能带来可用性影响——这是设计取向，不是缺陷。

## 报告安全问题

请提交 GitHub Issue 并标注 security（或其他约定的报告渠道）。请勿在公开 Issue 中附带可直接利用的 payload 或生产环境密钥。