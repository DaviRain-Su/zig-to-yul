• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- EOF Prague 指令未实现（5.1）【未来规划，当前未使用】
  - 总体实现规划（5.1）：
    - 指令清单：按 EIP/EOF 规范建立缺失指令矩阵
    - 解析与 AST：扩展 Yul builtin/IR 支持 Prague 指令
    - 代码生成：Yul→EVM bytecode 支持新 opcode
    - Gas/执行语义：补充 gas table 与语义规则
    - 测试：对齐上游向量与单元测试
    

- 优化研究：对比 https://github.com/Vectorized/solady


阶段 1：语法糖/可读性
- 支持 self.otherMethod() 方法互调  
- 支持 @as 基础类型转换（u256 <-> Address 等）
- 支持 -=、*= 等赋值运算
- 支持 while (cond) : (i += 1) 语法
- 支持 const/var 基本推导的安全报错提示
阶段 2：数据结构抽象
- evm.Mapping(K,V) 做到像 Zig 容器一样用  
  - get/set/contains（语义清晰）
  - 支持嵌套 mapping 与 struct 值
- evm.Array(T) 对应 storage 动态数组（length + data）
- ABI 自动序列化/反序列化封装
阶段 3：开发体验
- 更精确的错误定位（比如 “self.data.field 不支持”的提示）
- debug/trace 辅助（生成 Yul 注释 / SourceMap）
- 约束报告（比如 “mapping value 目前不能是动态类型”）
如果你希望“更像 Zig”，建议优先做：  
方法互调 + @as + -= + while :，这是写起来最自然的部分。

- 文档同步：
  - `docs/ROADMAP.md`
  - `docs/stories/v0.1.0-runtime-profile.md`
