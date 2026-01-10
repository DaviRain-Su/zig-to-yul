• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- EOF Prague 指令未实现（5.1）
  - 总体实现规划（5.1）：
    - 指令清单：按 EIP/EOF 规范建立缺失指令矩阵
    - 解析与 AST：扩展 Yul builtin/IR 支持 Prague 指令
    - 代码生成：Yul→EVM bytecode 支持新 opcode
    - Gas/执行语义：补充 gas table 与语义规则
    - 测试：对齐上游向量与单元测试
- 优化研究：对比 https://github.com/Vectorized/solady
  - 总体实现规划（优化）：
    - 选基准：确定 Solady/参考合约与基准指标
    - Profiling：对齐 gas/size/部署成本
    - 优化点：映射、scratch 复用、SLOAD/SSTORE 合并
    - 回归测试：确保语义一致与指标提升
- 生态整合：
  - JSON-RPC 兼容（已覆盖 Hardhat/Alchemy/Infura/QuickNode 基础差异）
  - ABI JSON 输出（已补全 stateMutability/tuple components）
  - keystore/私钥签名兼容
  - SourceMap 格式对齐 solidity 生态（已完成）
  - 总体实现规划（生态）：
    - RPC：覆盖常见 provider 兼容性差异
    - ABI：输出 schema 与字段排序一致性（已完成）
    - SourceMap：对齐 Solidity map 格式与工具链（已完成）

如果你想继续：建议优先推进 5.1 EOF Prague → SDK/生态。

- 文档同步：
  - `docs/ROADMAP.md`
  - `docs/stories/v0.1.0-runtime-profile.md`
