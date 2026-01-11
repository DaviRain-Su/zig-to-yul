# ROADMAP

> Source of truth for planned work. Status: ⏳ In Progress

## v0.1.0 - Runtime Profile & Gas Estimation

- Status: ⏳
- Goals:
  - 完成 5.3 动态 gas 估算（基于运行时 profile）
  - 完成 6.5 SourceLocation 完整覆盖
  - 完成 5.1 EOF Prague 指令支持

### Scope
- 5.3 Runtime Profile
  - 插桩：branch/switch/loop 计数
  - 采集：本地 VM + RPC
  - 多轮聚合：runs 统计与权重
  - 估算：profile overrides 应用（已完成）
  - 端到端测试：插桩→采集→聚合→估算（已完成：z2y profile-test）

- 6.5 SourceLocation
  - AST/Transformer 完整标注
  - printer/sourcemap 输出对齐（已完成）
  - Yul trace 注释输出（已完成）

- 语言体验（语法糖/可读性）
  - self.otherMethod() 方法互调（已完成）
  - @as 基础类型转换（Address <-> u256）（已完成）
  - -= / *= 等复合赋值运算（已完成）
  - while (cond) : (i += 1) 语法（已完成）
  - const/var 基本推导的安全报错提示

- 5.1 EOF Prague
  - 指令清单与语义实现
  - gas 表更新
  - 测试向量对齐

- CLI/SDK 主线（方向C）
  - CLI：build/deploy/call/profile/abi-gen（已完成）
  - SDK：storage/abi/event/precompile（已完成基础导出）
  - ABI 导出与 Solidity 交互（已完成 ABI JSON + z2y call）
  - RPC profiles（name→RPC+chainId）（已完成：profiles.json）
  - SDK Solidity 调用（已完成基础调用 + abi-gen）
  - EIP-1559 交易参数与签名

- 优化研究（Solady 对比）
  - 基准合约与指标定义
  - gas/size/部署成本对齐
  - mapping/scratch/sload/sstore 优化

- 生态整合
  - JSON-RPC 兼容（Anvil/Hardhat/Foundry/Alchemy/Infura/QuickNode）
  - ABI JSON 输出兼容
  - keystore/私钥签名兼容
  - SourceMap 格式对齐

### Related Docs
- `docs/libyul-comparison.md`
- `docs/gas-optimization-roadmap.md`
- `todo.md`
