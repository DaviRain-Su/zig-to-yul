• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- Gas 估算仍缺完整动态因素（动态路径执行次数精确建模已部分完成，仍需基于运行时 profile）（5.3）
- EOF Prague 指令未实现（5.1）
- CLI/SDK 主线（方向C）：
  - CLI：`build` / `deploy` / `call` / `profile`
  - SDK：storage / abi / event / precompile
  - ABI 导出：`abi-export` 供前端调用
  - 网络 profiles：name → RPC + chainId（deploy/call 直接用 name）
  - CLI `call` 支持与 Solidity 合约交互
  - Zig SDK：支持调用已部署的 Solidity 合约（ABI/encoding + RPC 调用）
- 优化研究：对比 https://github.com/Vectorized/solady
- 生态整合：
  - JSON-RPC 兼容（Anvil/Hardhat/Foundry/Alchemy/Infura/QuickNode）
  - ABI JSON 输出（ethers.js/Foundry/Hardhat 兼容）
  - EIP-1559 交易参数支持（maxFee/maxPriority）
  - keystore/私钥签名兼容
  - SourceMap 格式对齐 solidity 生态
如果你想继续：建议按 5.3（工具特性）→ 6.5（SourceLocation）→ 5.1（EOF Prague 指令）的优先级推进。
