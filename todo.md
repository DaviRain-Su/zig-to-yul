• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- EOF Prague 指令未实现（5.1）【未来规划，当前未使用】
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

下面是针对 Solady 的优化策略调研结果，已提炼成 可落地 的优化清单，并标注优先级与风险，方便你决定接下来要实现哪一类。
可直接落地的优化清单（按优先级）
P0（低风险，高收益）
1) 自定义错误（4 字节 selector）【已完成】  
   - 替换 require("...") 字符串  
   - 部署体积显著下降，revert 成本下降  
2) 事件签名常量化【已完成】  
   - 将 keccak256("Transfer(address,address,uint256)") 编译时计算  
3) 地址/整型位清理【已完成】  
   - 自动插入 shr(96, shl(96, addr)) 等位清理  
   - 避免高位污染
P1（中风险，中等复杂度）
4) Scratch Space 复用（0x00-0x3f）  
   - 合并临时 mstore/mload，减少内存开销  
5) 无分支条件优化  
   - 简单条件替换为位操作/算术  
   - 例如 z := mul(gt(x,y), sub(x,y))
P2（高收益，高复杂度）
6) 批量 SLOAD/SSTORE 合并  
   - 同一 slot 多次读写 -> 单次 SLOAD + 位操作 + 单次 SSTORE  
7) Storage Slot Packing  
   - 多字段打包到一个 slot，节省大量 SSTORE  
8) Identity 预编译 copy  
   - 大块内存复制使用 staticcall(0x04)，节省 gas
---
建议的落地路径
第一步做 P0：实现成本低、风险低、收益高。  
然后选择 Scratch Space 复用 + 无分支条件优化。  
P2 需要做静态分析与生命周期跟踪，应该单独设计优化 pass。
---
你可以选的下一步
1) 现在直接做 P0：自定义错误 + 事件签名常量化 + 位清理  
2) 先做 Scratch Space 复用（P1）  
3) 先建立优化 pass 基础框架（为 P2 做准备）
你想先实现哪一项？我可以直接开始落地。


- 文档同步：
  - `docs/ROADMAP.md`
  - `docs/stories/v0.1.0-runtime-profile.md`
