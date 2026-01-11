• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- EOF Prague 指令未实现（5.1）【未来规划，当前未使用】
  - 总体实现规划（5.1）：
    - 指令清单：按 EIP/EOF 规范建立缺失指令矩阵
    - 解析与 AST：扩展 Yul builtin/IR 支持 Prague 指令
    - 代码生成：Yul→EVM bytecode 支持新 opcode
    - Gas/执行语义：补充 gas table 与语义规则
    - 测试：对齐上游向量与单元测试
    

结论：基本是的，目前 zig_to_yul 的语义子集比 Solidity 窄，遇到不支持的语法就需要改写代码。
针对你列的三点：
1. @panic 不支持：目前不会生成 Yul 的 revert/invalid，所以需要改成显式的错误返回或 require 风格的手动判断（如果我们提供了对应 helper）。
2. inline if 表达式不支持：只能用普通 if 语句先赋值变量，再继续使用。
3. 嵌套 Mapping 访问：需要按照 arr[index].get(key) / map.get(key) 这类 API 走，不能直接 map[key1][key2]。
“错误处理不完善”这一点你说得对：目前只覆盖了部分常见路径，离 Solidity 的 revert/require 体验还有差距。
如果你愿意，我可以补这块：
- 加一个 require/assert helper（直接生成 revert）
- 把 @panic 映射到 revert（保留 message 或者仅用 selector）
- 在编译期给出更明确的诊断提示和替代写法
