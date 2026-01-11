• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- EOF Prague 指令未实现（5.1）【未来规划，当前未使用】
  - 总体实现规划（5.1）：
    - 指令清单：按 EIP/EOF 规范建立缺失指令矩阵
    - 解析与 AST：扩展 Yul builtin/IR 支持 Prague 指令
    - 代码生成：Yul→EVM bytecode 支持新 opcode
    - Gas/执行语义：补充 gas table 与语义规则
    - 测试：对齐上游向量与单元测试
    

可以考虑这些“链上友好”的数据结构，能显著提升开发体验（不一定全部要实现）：
- Set：基于 Mapping<T,bool> + Array<T> 的可枚举集合（含 add/remove/contains/values）。
- Queue/Deque：环形队列（push/pop、pushFront/popFront），适合任务队列。
- Stack：LIFO，语义简单，gas 可控。
- Optional：Option<T> 类型，明确“存在/不存在”语义。
- BytesBuilder/StringBuilder：可扩展字节数组（append/slice），用于拼装 calldata/日志。
- EnumMap：以 enum 作为 key 的紧凑映射（避免 hash/slot 开销）。
- PackedStruct：自动打包/解包小字段，减少 storage 槽位。
如果要优先做，我建议顺序：Set → Queue → BytesBuilder。你想先从哪一个开始？
