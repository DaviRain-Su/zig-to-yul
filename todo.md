• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- 预编译合约封装未实现（5.2：0x01-0x0a）
- Gas 估算仅静态估算（5.3）
- Yul 优化器仅 peephole 基础实现（5.3）
- 迭代 slice/数组/指针（for (arr) |v, i| {}）
- for 的自定义步进/反向（非 +1）
- for-else 分支
- for 中复杂 payload 解构
- 数组索引仅部分支持（6.3）
- 结构体字面量仅部分支持（6.3）
- 事件编码仅部分支持（6.4）
- SourceLocation 仅 AST 路径填充（6.5）
- ObjectDebugData 未实现（2.3/5.4）
- Object::Structure 未实现（2.3/5.4）
- EOF Prague 指令未实现（5.1）

如果你想继续：建议按 5.2（预编译合约封装）→ 5.4（调试辅助）→ 5.1（EOF Prague 指令）的优先级推进。
