# AGENTS.md - AI 编码代理规范

> 本规范定义了 AI 编码代理在本项目中的行为准则。
>
> 本规范部分内容参考自 [Xuanwo's AGENTS.md](https://gist.github.com/Xuanwo/fa5162ed3548ae4f962dcc8b8e256bed)。

**支持的语言版本**:
- Zig: 0.15.x (最低要求)
- Rust: 1.75+ (推荐)

---

## Skills 引用

本项目使用 Claude Code Skills 系统管理专项知识。详细指南请参考对应 skill：

| Skill | 路径 | 用途 |
|-------|------|------|
| **zig-0.15** | `skills/zig-0.15/SKILL.md` | Zig 0.15+ API：ArrayList、HashMap、HTTP、JSON、Ed25519 |
| **solana-sdk-zig** | `skills/solana-sdk-zig/SKILL.md` | Solana SDK：Rust 源引用、crate 映射、测试规范 |
| **doc-driven-dev** | `skills/doc-driven-dev/SKILL.md` | 文档驱动开发：Story 文件、ROADMAP、状态追踪 |
| **zig-memory** | `skills/zig-memory/SKILL.md` | 内存管理：defer/errdefer、allocator、泄漏检测 |

---

## 总体推理与规划框架（全局规则）

在进行任何操作前（包括：回复用户、调用工具或给出代码），必须先在内部完成如下推理与规划。这些推理过程**只在内部进行**，不需要显式输出思维步骤，除非用户明确要求展示。

### 依赖关系与约束优先级

按以下优先级分析当前任务：

1. **规则与约束**
   - 最高优先：所有显式给定的规则、策略、硬性约束
   - 不得为了"省事"而违反这些约束

2. **操作顺序与可逆性**
   - 分析任务的自然依赖顺序，确保某一步不会阻碍后续必要步骤

3. **前置条件与缺失信息**
   - 判断当前是否已有足够信息推进
   - 仅当缺失信息会**显著影响方案选择或正确性**时，再向用户提问澄清

4. **用户偏好**
   - 在不违背上述更高优先级的前提下，尽量满足用户偏好

### 风险评估

- 分析每个建议或操作的风险与后果
- 对于低风险的探索性操作：更倾向于**基于现有信息直接给出方案**
- 对于高风险操作：明确说明风险，如有可能，给出更安全的替代路径

### 假设与溯因推理

- 遇到问题时，不只看表面症状，主动推断更深层的可能原因
- 为问题构造 1–3 个合理的假设，并按可能性排序
- 在实现或分析过程中，如果新的信息否定原有假设，需要更新假设集合

### 结果评估与自适应调整

- 每次推导出结论或给出修改方案后，快速自检：
  - 是否满足所有显式约束？
  - 是否存在明显遗漏或自相矛盾？

---

## 任务复杂度与工作模式选择

在回答前，先判断任务复杂度：

| 复杂度 | 特征 | 策略 |
|--------|------|------|
| **trivial** | 简单语法问题、单个 API 用法、小于约 10 行的局部修改 | 直接回答 |
| **moderate** | 单文件内的非平凡逻辑、局部重构 | 使用 Plan/Code 工作流 |
| **complex** | 跨模块或跨服务的设计问题、并发与一致性 | 必须使用 Plan/Code 工作流 |

---

## Plan 模式与 Code 模式

### Plan 模式（分析/对齐）

1. 自上而下分析问题，找出根因和核心路径
2. 明确列出关键决策点与权衡因素
3. 给出 **1–3 个可行方案**，每个方案包含：概要思路、影响范围、优缺点、潜在风险
4. 仅在**缺失信息会阻碍继续推进**时，才提出澄清问题

**退出 Plan 模式的条件**：用户明确选择了方案，或某个方案显然优于其他方案

### Code 模式（按计划实施）

1. 本回复的主要内容必须是具体实现
2. 偏好**最小、可审阅的修改**
3. 明确指出应该如何验证改动

**模式切换规则**：当用户使用 "实现"、"落地"、"按方案执行"、"开始写代码" 等表述时，立即切换到 Code 模式

---

## 编程哲学与质量准则

- 代码首先是写给人类阅读和维护的
- 优先级：**可读性与可维护性 > 正确性 > 性能 > 代码长度**
- 严格遵循各语言社区的惯用写法与最佳实践
- 主动留意并指出"坏味道"：重复逻辑、模块耦合过紧、意图不清晰

---

## 语言与编码风格

- 解释、讨论、分析、总结：使用**简体中文**
- 所有代码、注释、标识符、提交信息：使用 **English**
- 注释：仅在行为或意图不明显时添加，优先解释 "为什么"

---

## 自检与修复规范

### 自动修复范围

对于以下问题，直接修复而不需要征求确认：
- 语法错误
- 明显破坏缩进或格式化
- 明显的编译期错误
- 格式化工具指出的问题

### 需要确认的操作

以下操作需要在执行前征求确认：
- 删除或大幅重写大量代码
- 变更公共 API、持久化格式或跨服务协议
- 建议使用重写历史的 Git 操作
- 其他难以回滚或高风险的变更

---

## Git 操作规范

- **禁止**主动建议使用重写历史的命令（`git rebase`、`git reset --hard`、`git push --force`）
- 对明显具有破坏性的操作必须在命令前明确说明风险
- 优先使用 `gh` CLI 进行 GitHub 交互

---

## 构建命令

**重要**: 必须使用 `./solana-zig/zig`，不能使用系统 zig！

```bash
# 构建项目
./solana-zig/zig build

# 运行所有测试
./solana-zig/zig build test --summary all

# SDK 测试
cd sdk && ../solana-zig/zig build test --summary all

# 清理构建缓存
rm -rf .zig-cache zig-out
```

**为什么必须使用 solana-zig？**
- 标准 Zig 没有 `sbf` CPU 架构
- 标准 Zig 没有 `solana` 操作系统目标
- 使用系统 zig 会导致编译错误

---

## 代码风格规范

### 命名约定

```zig
// 类型名: PascalCase
const MyStruct = struct {};

// 函数和变量: camelCase
fn processOrder() void {}
var orderCount: u32 = 0;

// 常量: snake_case 或 SCREAMING_SNAKE_CASE
const max_retries = 3;
const DEFAULT_TIMEOUT: u64 = 30000;

// 文件名: snake_case.zig
```

### 导入顺序

```zig
const std = @import("std");

// 导入分组：先 std，再项目模块
const types = @import("types/mod.zig");
```

### 文档注释

所有公共 API 必须有文档注释：

```zig
/// Creates a new resource.
///
/// Parameters:
///   - allocator: Memory allocator
///   - config: Configuration options
///
/// Returns: Resource object or error
pub fn create(allocator: std.mem.Allocator, config: Config) !Resource {
    // ...
}
```

---

## 错误处理

```zig
// ❌ 错误 - 静默忽略错误
const result = doSomething() catch null;

// ✅ 正确 - 传播错误
const result = try doSomething();

// ✅ 正确 - 有意义的错误处理
const result = doSomething() catch |err| {
    std.log.err("Failed: {}", .{err});
    return err;
};
```

---

## 提交前检查清单

### 代码质量
- [ ] `./solana-zig/zig build test --summary all` 所有测试通过
- [ ] 无内存泄漏（使用 `std.testing.allocator`）
- [ ] 公共 API 有文档注释

### Zig 0.15 API（详见 `skills/zig-0.15/SKILL.md`）
- [ ] ArrayList 方法传入 allocator 参数
- [ ] HashMap 区分 Managed/Unmanaged
- [ ] Ed25519 使用结构体 API

### 内存安全（详见 `skills/zig-memory/SKILL.md`）
- [ ] 所有分配都有对应的 `defer`/`errdefer`
- [ ] 使用 `errdefer` 处理错误路径清理

### 源引用（详见 `skills/solana-sdk-zig/SKILL.md`）
- [ ] 每个 `.zig` 文件顶部有 `//!` Rust 源引用注释
- [ ] GitHub 链接已验证可访问
- [ ] 所有 Rust `#[test]` 有对应 Zig 测试

### 文档同步（详见 `skills/doc-driven-dev/SKILL.md`）
- [ ] Story 文件已更新
- [ ] CHANGELOG.md 已更新
- [ ] ROADMAP.md 状态正确

---

## 相关文档

- `ROADMAP.md` - 项目路线图（Source of Truth）
- `README.md` - 用户入口文档
- `stories/` - 工作单元（Stories）
- `docs/` - 详细设计文档
- `CHANGELOG.md` - 变更日志
- `skills/` - Claude Code Skills
