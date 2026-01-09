• 目前的 TODO 主要集中在 docs/libyul-comparison.md 的“未实现特性/限制”部分：

  - ABI 编解码：动态类型、动态数组、结构体参数、多返回值（6.4）
  - SourceLocation 未填充（6.5）
  - 工具特性：Source Maps、事件解码、Gas 估算、Yul 优化器（5.3）
  - EOF Prague 相关指令（5.1）
  - 预编译合约封装（5.2）
  - 调试辅助：ObjectDebugData、Object::Structure（5.4）

  另外还有一个代码里明确的 TODO：src/evm/types.zig 里 keccak256 还没实现。

  如果你想继续：我们可以按 6.4（ABI 编解码）→ 6.5（SourceLocation）→ 5.3（工具特性）的优先级推进。
  （顺带提醒：当前有未提交的测试改动在 src/compiler.zig 和 src/yul/transformer.zig。）
