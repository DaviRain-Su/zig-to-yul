• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- EOF Prague 指令未实现（5.1）
  - 总体实现规划（5.1）：
    - 指令清单：按 EIP/EOF 规范建立缺失指令矩阵
    - 解析与 AST：扩展 Yul builtin/IR 支持 Prague 指令
    - 代码生成：Yul→EVM bytecode 支持新 opcode
    - Gas/执行语义：补充 gas table 与语义规则
    - 测试：对齐上游向量与单元测试
- SDK 主线（方向C）：
  - Zig SDK：支持调用已部署的 Solidity 合约（ABI/encoding + RPC 调用）（已完成基础调用）
  - 总体实现规划（SDK）：
    - RPC：统一 JSON-RPC 客户端与重试/超时策略（已完成基础调用）
    - ABI：生成/解析 ABI JSON，与 ethers/Foundry 兼容（已完成基础编码）
    - 交易：支持 EIP-1559/Legacy 参数与签名
    - SDK：提供高层调用封装与类型映射
    - 测试：本地 Anvil/Foundry 集成测试
- 优化研究：对比 https://github.com/Vectorized/solady
  - 总体实现规划（优化）：
    - 选基准：确定 Solady/参考合约与基准指标
    - Profiling：对齐 gas/size/部署成本
    - 优化点：映射、scratch 复用、SLOAD/SSTORE 合并
    - 回归测试：确保语义一致与指标提升
- 生态整合：
  - JSON-RPC 兼容（Anvil/Hardhat/Foundry/Alchemy/Infura/QuickNode）
  - ABI JSON 输出（ethers.js/Foundry/Hardhat 兼容）
  - EIP-1559 交易参数支持（maxFee/maxPriority）
  - keystore/私钥签名兼容
  - SourceMap 格式对齐 solidity 生态
  - 总体实现规划（生态）：
    - RPC：覆盖常见 provider 兼容性差异
    - ABI：输出 schema 与字段排序一致性
    - 交易：EIP-1559 与签名/nonce 处理
    - SourceMap：对齐 Solidity map 格式与工具链

如果你想继续：建议优先推进 5.3 端到端测试 → 5.1 EOF Prague → SDK/生态。

- 文档同步：
  - `docs/ROADMAP.md`
  - `docs/stories/v0.1.0-runtime-profile.md`
