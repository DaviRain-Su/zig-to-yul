• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- EOF Prague 指令未实现（5.1）【未来规划，当前未使用】
  - 总体实现规划（5.1）：
    - 指令清单：按 EIP/EOF 规范建立缺失指令矩阵
    - 解析与 AST：扩展 Yul builtin/IR 支持 Prague 指令
    - 代码生成：Yul→EVM bytecode 支持新 opcode
    - Gas/执行语义：补充 gas table 与语义规则
    - 测试：对齐上游向量与单元测试
    

- 优化研究：对比 https://github.com/Vectorized/solady


未完成清单（按你给的列表）：
阶段 1
- const/var 基本推导的安全报错提示（未做）
阶段 2
- evm.Array(T) storage 动态数组（未做）
- ABI 自动序列化/反序列化封装（未做）
阶段 3
- 更精确错误定位提示（未做）
- debug/trace 辅助（Yul 注释 / SourceMap）（未做）
- 约束报告（如 mapping value 动态类型提示）（未做）
并行补齐
- Iterator.forEach 小封装（未做）
- valuePtrAt 动态 value 语义说明（未做）
- transformer 输出测试（getPtr/getOrPutPtr + removeOrNull）（未做）
文档同步
- docs/ROADMAP.md（未做）
- docs/stories/v0.1.0-runtime-profile.md（未做）
