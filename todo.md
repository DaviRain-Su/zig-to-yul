• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- EOF Prague 指令未实现（5.1）【未来规划，当前未使用】
  - 总体实现规划（5.1）：
    - 指令清单：按 EIP/EOF 规范建立缺失指令矩阵
    - 解析与 AST：扩展 Yul builtin/IR 支持 Prague 指令
    - 代码生成：Yul→EVM bytecode 支持新 opcode
    - Gas/执行语义：补充 gas table 与语义规则
    - 测试：对齐上游向量与单元测试
    

- 优化研究：对比 https://github.com/Vectorized/solady


目前还未完成的（已把已完成项剔除）：
阶段 2
- evm.Array(T) storage 动态数组
阶段 3
- 更精确错误定位提示
文档同步
- docs/ROADMAP.md
- docs/stories/v0.1.0-runtime-profile.md
并行补齐三项已经完成：Iterator.forEach、valuePtrAt 语义说明、transformer 输出测试。
已完成：ABI 自动序列化/反序列化封装、debug/trace 辅助（Yul 注释 / SourceMap）、约束报告（如 mapping value 动态类型提示）。

还缺一些“类似 Map 的体验/安全性”功能，主要是这些：
缺的功能/语义
- 边界检查：get/set/remove/pop 没有越界/空数组提示（当前实现会在 Yul 里直接读写）。
- 稳定删除：remove 语义是 swap‑last，不提供“保持顺序”的删除方式。
- 指针/引用 API：没有 getPtr / valuePtrAt 这类“直接引用元素”的接口。
- 扩展操作：没有 insert(index, value)、swapRemove（显式）、resize(new_len)、clearAndZero 等变体。
- 迭代器：没有 iterator()/forEach() 这类数组级迭代 API（目前只能自己写 for）。
已有限制（实现里明确报错）
- 不支持嵌套数组 / 数组元素为 mapping（会报错）。
如果你想补齐哪一类，我可以按优先级逐项完善。

可以实现，但需要你确认范围：
1) 支持嵌套数组（如 Array(Array(T))）  
2) 支持数组元素为 mapping（如 Array(Mapping(K,V))）  
3) resize 增长时自动清零（等价于 Solidity 语义）
你想先做哪一项？如果全都要，也可以做，但实现量会明显增加。
