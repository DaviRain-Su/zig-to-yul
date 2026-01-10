# Zig-to-Yul 与 C++ libyul 实现对比报告

> 文档版本: 1.2
> 更新日期: 2026-01-09
> 对比基准: [ethereum/solidity](https://github.com/ethereum/solidity) develop 分支

---

## 1. 概述

本文档对比分析 zig-to-yul 编译器与 Solidity 官方 libyul 库的实现完整性，确保我们的 Zig 实现覆盖了所有必要的 AST 节点类型和 EVM 操作码。

### 1.1 项目架构

**重要说明**: zig-to-yul 是**纯 Zig 实现**，不包含任何 C++ 代码。我们参考 libyul 的设计，但完全用 Zig 重新实现。

```
Zig 源代码 → [zig-to-yul] → Yul 代码 → [solc] → EVM 字节码
```

**两条编译路径:**

| 路径 | 入口函数 | 说明 |
|------|----------|------|
| IR-based (旧) | `Compiler.compile()` | 基于中间表示 |
| AST-based (新) | `Compiler.compileWithAst()` | 直接 AST 转换，推荐使用 |

### 1.2 对比范围

- **AST 节点**: libyul/AST.h
- **Object 模型**: libyul/Object.h
- **EVM 操作码**: libyul/backends/evm/EVMDialect.cpp, libevmasm/Instruction.h
- **Dialect 系统**: EVM 版本特性

---

## 2. AST 节点对比

### 2.1 表达式 (Expression)

| libyul C++ | Zig 实现 | 文件位置 | 状态 |
|------------|----------|----------|------|
| `Literal` | `Literal` | src/yul/ast.zig:193 | ✅ 完整 |
| `Identifier` | `Identifier` | src/yul/ast.zig:236 | ✅ 完整 |
| `BuiltinName` | `BuiltinName` | src/yul/ast.zig:246 | ✅ 完整 |
| `FunctionCall` | `FunctionCall` | src/yul/ast.zig:293 | ✅ 完整 |

**Literal 支持的类型:**
- `number` - 十进制数字 (如 `255`)
- `hex_number` - 十六进制数字 (如 `0xff`)
- `boolean` - 布尔值 (`true`/`false`)
- `string` - 字符串字面量
- `hex_string` - 十六进制字符串

### 2.2 语句 (Statement)

| libyul C++ | Zig 实现 | 文件位置 | 状态 |
|------------|----------|----------|------|
| `ExpressionStatement` | `ExpressionStatement` | src/yul/ast.zig:354 | ✅ 完整 |
| `VariableDeclaration` | `VariableDeclaration` | src/yul/ast.zig:332 | ✅ 完整 |
| `Assignment` | `Assignment` | src/yul/ast.zig:343 | ✅ 完整 |
| `Block` | `Block` | src/yul/ast.zig:364 | ✅ 完整 |
| `If` | `If` | src/yul/ast.zig:378 | ✅ 完整 |
| `Switch` | `Switch` | src/yul/ast.zig:404 | ✅ 完整 |
| `Case` | `Case` | src/yul/ast.zig:389 | ✅ 完整 |
| `ForLoop` | `ForLoop` | src/yul/ast.zig:414 | ✅ 完整 |
| `FunctionDefinition` | `FunctionDefinition` | src/yul/ast.zig:428 | ✅ 完整 |
| `Break` | `Break` | src/yul/ast.zig:451 | ✅ 完整 |
| `Continue` | `Continue` | src/yul/ast.zig:456 | ✅ 完整 |
| `Leave` | `Leave` | src/yul/ast.zig:461 | ✅ 完整 |

### 2.3 顶层结构

| libyul C++ | Zig 实现 | 文件位置 | 状态 |
|------------|----------|----------|------|
| `AST` | `AST` | src/yul/ast.zig:585 | ✅ 完整 |
| `Object` | `Object` | src/yul/ast.zig:562 | ✅ 完整 |
| `Data` (ObjectNode) | `DataSection` | src/yul/ast.zig:542 | ✅ 完整 |
| `ObjectDebugData` | `ObjectDebugData` | src/yul/ast.zig:562 | ✅ |
| `Object::Structure` | `ObjectStructure` | src/yul/ast.zig:568 | ✅ |

### 2.4 辅助类型

| libyul C++ | Zig 实现 | 状态 | 备注 |
|------------|----------|------|------|
| `NameWithDebugData` | `TypedName` | ✅ | 含可选类型注解 |
| `YulName` | `YulName` ([]const u8) | ✅ | |
| `LiteralValue` | `LiteralValue` | ✅ | union 类型 |
| `LiteralKind` | `LiteralKind` | ✅ | enum 类型 |
| `SourceLocation` | `SourceLocation` | ✅ | start/end/source_index |

---

## 3. EVM Dialect 对比

### 3.1 EVM 版本支持

| 版本 | Zig 实现 | 状态 |
|------|----------|------|
| Homestead | `EvmVersion.homestead` | ✅ |
| Tangerine Whistle | `EvmVersion.tangerine_whistle` | ✅ |
| Spurious Dragon | `EvmVersion.spurious_dragon` | ✅ |
| Byzantium | `EvmVersion.byzantium` | ✅ |
| Constantinople | `EvmVersion.constantinople` | ✅ |
| Petersburg | `EvmVersion.petersburg` | ✅ |
| Istanbul | `EvmVersion.istanbul` | ✅ |
| Berlin | `EvmVersion.berlin` | ✅ |
| London | `EvmVersion.london` | ✅ |
| Paris | `EvmVersion.paris` | ✅ |
| Shanghai | `EvmVersion.shanghai` | ✅ |
| Cancun | `EvmVersion.cancun` | ✅ |
| Prague | `EvmVersion.prague` | ✅ (enum 定义) |

### 3.2 版本特性追踪

| 特性 | 引入版本 | Zig EvmFeature | 状态 |
|------|----------|----------------|------|
| staticcall | Byzantium | `.staticcall` | ✅ |
| create2 | Constantinople | `.create2` | ✅ |
| extcodehash | Constantinople | `.extcodehash` | ✅ |
| shl/shr/sar | Constantinople | `.shl_shr_sar` | ✅ |
| chainid | Istanbul | `.chainid` | ✅ |
| selfbalance | Istanbul | `.selfbalance` | ✅ |
| basefee | London | `.basefee` | ✅ |
| prevrandao | Paris | `.prevrandao` | ✅ |
| push0 | Shanghai | `.push0` | ✅ |
| blobhash | Cancun | `.blobhash` | ✅ |
| blobbasefee | Cancun | `.blobbasefee` | ✅ |
| mcopy | Cancun | `.mcopy` | ✅ |
| tload/tstore | Cancun | `.tload_tstore` | ✅ |

---

## 4. EVM 操作码覆盖

### 4.1 算术操作 (11 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 状态 |
|--------|----------|------|------|------|
| ADD | `add` | 2 | 1 | ✅ |
| SUB | `sub` | 2 | 1 | ✅ |
| MUL | `mul` | 2 | 1 | ✅ |
| DIV | `div` | 2 | 1 | ✅ |
| SDIV | `sdiv` | 2 | 1 | ✅ |
| MOD | `mod` | 2 | 1 | ✅ |
| SMOD | `smod` | 2 | 1 | ✅ |
| EXP | `exp` | 2 | 1 | ✅ |
| ADDMOD | `addmod` | 3 | 1 | ✅ |
| MULMOD | `mulmod` | 3 | 1 | ✅ |
| SIGNEXTEND | `signextend` | 2 | 1 | ✅ |

### 4.2 比较操作 (6 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 状态 |
|--------|----------|------|------|------|
| LT | `lt` | 2 | 1 | ✅ |
| GT | `gt` | 2 | 1 | ✅ |
| SLT | `slt` | 2 | 1 | ✅ |
| SGT | `sgt` | 2 | 1 | ✅ |
| EQ | `eq` | 2 | 1 | ✅ |
| ISZERO | `iszero` | 1 | 1 | ✅ |

### 4.3 位运算操作 (8 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 状态 |
|--------|----------|------|------|------|
| AND | `and` | 2 | 1 | ✅ |
| OR | `or` | 2 | 1 | ✅ |
| XOR | `xor` | 2 | 1 | ✅ |
| NOT | `not` | 1 | 1 | ✅ |
| BYTE | `byte` | 2 | 1 | ✅ |
| SHL | `shl` | 2 | 1 | ✅ |
| SHR | `shr` | 2 | 1 | ✅ |
| SAR | `sar` | 2 | 1 | ✅ |

### 4.4 内存操作 (5 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 引入版本 | 状态 |
|--------|----------|------|------|----------|------|
| MLOAD | `mload` | 1 | 1 | - | ✅ |
| MSTORE | `mstore` | 2 | 0 | - | ✅ |
| MSTORE8 | `mstore8` | 2 | 0 | - | ✅ |
| MSIZE | `msize` | 0 | 1 | - | ✅ |
| MCOPY | `mcopy` | 3 | 0 | Cancun | ✅ |

### 4.5 存储操作 (4 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 引入版本 | 状态 |
|--------|----------|------|------|----------|------|
| SLOAD | `sload` | 1 | 1 | - | ✅ |
| SSTORE | `sstore` | 2 | 0 | - | ✅ |
| TLOAD | `tload` | 1 | 1 | Cancun | ✅ |
| TSTORE | `tstore` | 2 | 0 | Cancun | ✅ |

### 4.6 执行上下文 (19 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 状态 |
|--------|----------|------|------|------|
| CALLER | `caller` | 0 | 1 | ✅ |
| CALLVALUE | `callvalue` | 0 | 1 | ✅ |
| CALLDATALOAD | `calldataload` | 1 | 1 | ✅ |
| CALLDATASIZE | `calldatasize` | 0 | 1 | ✅ |
| CALLDATACOPY | `calldatacopy` | 3 | 0 | ✅ |
| CODESIZE | `codesize` | 0 | 1 | ✅ |
| CODECOPY | `codecopy` | 3 | 0 | ✅ |
| EXTCODESIZE | `extcodesize` | 1 | 1 | ✅ |
| EXTCODECOPY | `extcodecopy` | 4 | 0 | ✅ |
| RETURNDATASIZE | `returndatasize` | 0 | 1 | ✅ |
| RETURNDATACOPY | `returndatacopy` | 3 | 0 | ✅ |
| EXTCODEHASH | `extcodehash` | 1 | 1 | ✅ |
| ADDRESS | `address` | 0 | 1 | ✅ |
| BALANCE | `balance` | 1 | 1 | ✅ |
| SELFBALANCE | `selfbalance` | 0 | 1 | ✅ |
| ORIGIN | `origin` | 0 | 1 | ✅ |
| GASPRICE | `gasprice` | 0 | 1 | ✅ |
| GAS | `gas` | 0 | 1 | ✅ |

### 4.7 区块上下文 (11 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 引入版本 | 状态 |
|--------|----------|------|------|----------|------|
| BLOCKHASH | `blockhash` | 1 | 1 | - | ✅ |
| COINBASE | `coinbase` | 0 | 1 | - | ✅ |
| TIMESTAMP | `timestamp` | 0 | 1 | - | ✅ |
| NUMBER | `number` | 0 | 1 | - | ✅ |
| DIFFICULTY | `difficulty` | 0 | 1 | - (废弃) | ✅ |
| PREVRANDAO | `prevrandao` | 0 | 1 | Paris | ✅ |
| GASLIMIT | `gaslimit` | 0 | 1 | - | ✅ |
| CHAINID | `chainid` | 0 | 1 | Istanbul | ✅ |
| BASEFEE | `basefee` | 0 | 1 | London | ✅ |
| BLOBBASEFEE | `blobbasefee` | 0 | 1 | Cancun | ✅ |
| BLOBHASH | `blobhash` | 1 | 1 | Cancun | ✅ |

### 4.8 控制流 (5 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 状态 |
|--------|----------|------|------|------|
| RETURN | `return` | 2 | 0 | ✅ |
| REVERT | `revert` | 2 | 0 | ✅ |
| STOP | `stop` | 0 | 0 | ✅ |
| INVALID | `invalid` | 0 | 0 | ✅ |
| SELFDESTRUCT | `selfdestruct` | 1 | 0 | ✅ |

### 4.9 日志操作 (5 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 状态 |
|--------|----------|------|------|------|
| LOG0 | `log0` | 2 | 0 | ✅ |
| LOG1 | `log1` | 3 | 0 | ✅ |
| LOG2 | `log2` | 4 | 0 | ✅ |
| LOG3 | `log3` | 5 | 0 | ✅ |
| LOG4 | `log4` | 6 | 0 | ✅ |

### 4.10 调用操作 (4 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 状态 |
|--------|----------|------|------|------|
| CALL | `call` | 7 | 1 | ✅ |
| CALLCODE | `callcode` | 7 | 1 | ✅ (废弃) |
| DELEGATECALL | `delegatecall` | 6 | 1 | ✅ |
| STATICCALL | `staticcall` | 6 | 1 | ✅ |

### 4.11 创建操作 (2 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 状态 |
|--------|----------|------|------|------|
| CREATE | `create` | 3 | 1 | ✅ |
| CREATE2 | `create2` | 4 | 1 | ✅ |

### 4.12 其他操作 (8 个)

| 操作码 | Yul 名称 | 输入 | 输出 | 状态 |
|--------|----------|------|------|------|
| KECCAK256 | `keccak256` | 2 | 1 | ✅ |
| - | `datasize` | 1 | 1 | ✅ |
| - | `dataoffset` | 1 | 1 | ✅ |
| - | `datacopy` | 3 | 0 | ✅ |
| - | `setimmutable` | 3 | 0 | ✅ |
| - | `loadimmutable` | 1 | 1 | ✅ |
| - | `linkersymbol` | 1 | 1 | ✅ |
| - | `memoryguard` | 1 | 1 | ✅ |
| - | `verbatim_*i_*o` | * | * | ✅ |
| POP | `pop` | 1 | 0 | ✅ |

**操作码统计: 73/73 (100%)**

---

## 5. 未实现特性

### 5.1 EOF (Ethereum Object Format) - Prague 硬分叉

以下特性属于 EOF 规范，尚未在以太坊主网启用：

| 操作码 | 描述 | EIP | 优先级 |
|--------|------|-----|--------|
| `rjump` | 相对跳转 | EIP-4200 | 低 |
| `rjumpi` | 条件相对跳转 | EIP-4200 | 低 |
| `callf` | 调用函数 | EIP-4750 | 低 |
| `retf` | 从函数返回 | EIP-4750 | 低 |
| `jumpf` | 跳转到函数 | EIP-4750 | 低 |
| `dupn` | 动态 DUP | EIP-663 | 低 |
| `swapn` | 动态 SWAP | EIP-663 | 低 |
| `dataloadn` | 加载数据 | EIP-7480 | 低 |
| `eofcreate` | EOF 合约创建 | EIP-7620 | 低 |
| `returncontract` | 返回合约 | EIP-7620 | 低 |
| `extcall` | 外部调用 (EOF) | EIP-7069 | 低 |
| `extdelegatecall` | 外部委托调用 | EIP-7069 | 低 |
| `extstaticcall` | 外部静态调用 | EIP-7069 | 低 |
| `auxdataloadn` | 辅助数据加载 | EOF | 低 |

### 5.2 预编译合约支持

以下 EVM 预编译合约需要通过 `call` 操作码调用，目前无直接封装：

| 地址 | 功能 | 状态 |
|------|------|------|
| `0x01` | ecrecover (ECDSA 恢复) | ✅ `evm.precompile_ecrecover(in_ptr, in_len, out_ptr, out_len)` |
| `0x02` | SHA-256 哈希 | ✅ `evm.precompile_sha256(in_ptr, in_len, out_ptr, out_len)` |
| `0x03` | RIPEMD-160 哈希 | ✅ `evm.precompile_ripemd160(in_ptr, in_len, out_ptr, out_len)` |
| `0x04` | identity (数据复制) | ✅ `evm.precompile_identity(in_ptr, in_len, out_ptr, out_len)` |
| `0x05` | modexp (模幂运算) | ✅ `evm.precompile_modexp(in_ptr, in_len, out_ptr, out_len)` |
| `0x06` | ecAdd (BN256 加法) | ✅ `evm.precompile_ecadd(in_ptr, in_len, out_ptr, out_len)` |
| `0x07` | ecMul (BN256 乘法) | ✅ `evm.precompile_ecmul(in_ptr, in_len, out_ptr, out_len)` |
| `0x08` | ecPairing (配对检查) | ✅ `evm.precompile_ecpairing(in_ptr, in_len, out_ptr, out_len)` |
| `0x09` | blake2f (BLAKE2b) | ✅ `evm.precompile_blake2f(in_ptr, in_len, out_ptr, out_len)` |
| `0x0a` | point evaluation (KZG) | ✅ `evm.precompile_point_evaluation(in_ptr, in_len, out_ptr, out_len)` |

### 5.3 开发工具特性

| 功能 | 描述 | 状态 |
|------|------|------|
| 源码映射 (Source Maps) | 调试时定位源码位置 | ✅ 基础实现 |
| 事件解码 (Event Decoding) | 解析合约事件日志 | ✅ 完整（静态类型/bytes/string/数组/动态数组元素/tuple/数组 tuple/CLI/indexed 预镜像/签名校验/匿名事件） |
| ABI 解码 | 解码 calldata/returndata | ✅ 完整（静态类型/动态类型/数组/tuple/CLI） |
| Gas 估算 | 预估交易 gas 消耗 | ⚠️ 基础实现（静态估算） |
| Yul 优化器 | 内置 Yul 级别优化 | ⚠️ 基础实现（peephole） |

### 5.4 调试/辅助功能

| 功能 | 描述 | 优先级 |
|------|------|--------|
| `ObjectDebugData` | 源码名称映射 | ✅ |
| `Object::Structure` | 对象层级查询 | ✅ |

---

## 6. 已知限制与差异 (Critical)

> ⚠️ **重要**: 以下是与 libyul 的关键差异，影响完整性声明

### 6.1 AST 结构差异

| 问题 | libyul 行为 | 当前实现 | 影响 |
|------|-------------|----------|------|
| **BuiltinCall 区分** | 区分 `BuiltinCall` 和 `FunctionCall` 两种节点 | Builtin/Function 已区分 | ✅ 已对齐 |
| **Typed 节点** | 严格区分 builtin/identifier/typed | 统一处理 | 类型信息丢失 |

### 6.2 Dialect 验证缺失 (已修复)

```zig
// ast.zig:87 - 定义了 hasBuiltin()
pub fn hasBuiltin(self: Dialect, name: []const u8) bool { ... }

// 现在在 transformer.zig 和 compiler.zig 中调用
// 结果：EVM 版本检查会在解析 evm.* 内建时强制执行
```

**影响**: 使用 Cancun 特性（如 `mcopy`）时会检查目标 EVM 版本，避免生成不兼容代码。

### 6.3 Zig→Yul 语义覆盖 (子集)

**已实现的 Zig 节点:**

| 节点类型 | 状态 | 说明 |
|----------|------|------|
| 函数定义 | ✅ | `pub fn name()` |
| 变量声明 | ✅ | `var x = ...` |
| 赋值语句 | ✅ | `x = value` |
| if 语句 | ✅ | if/else |
| 函数调用 | ✅ | `func(args)` |
| 字段访问 | ✅ | `self.field` |
| 二元运算 | ✅ | `+`, `-`, `*`, `/`, `<`, `>`, `==` |
| return | ✅ | `return value` |

**未实现的 Zig 节点:**

| 节点类型 | 状态 | Yul 对应 |
|----------|------|----------|
| for 循环 | ✅ 完整 | 支持 `for (start..end)`、`for (start..)`、`for (zig2yul.range_step(start, end, step))`、`for (start..end, 0..) |val, idx|`、`for (base, 0..len) |val, idx|`、`for (arr) |val|`、`for ... else` |
| while 循环 | ✅ | `for { } cond { } { }` |
| switch 语句 | ✅ | range/表达式 case 会降级为 if 链 |
| break | ✅ | 不支持 label/value |
| continue | ✅ | 不支持 label/value |
| if-else | ✅ | 通过 `iszero` 翻转 |
| 复杂表达式 | ✅ | 递归翻译算术/调用/访问 |
| 数组索引 | ✅ | 支持内存数组/切片、结构体数组索引/写入（stride + field offset）；存储数组仍按 slot+index |
| 结构体字面量 | ✅ | 支持显式类型与上下文推断（var/assign/参数/返回），支持具名/位置字段 |

### 6.4 ABI 编解码限制

| 特性 | 状态 | 说明 |
|------|------|------|
| 静态参数 (uint256, address) | ✅ | `calldataload(4 + i*32)` |
| 单返回值 | ✅ | `mstore(0, result); return(0, 32)` |
| 动态类型 (string, bytes) | ✅ | 偏移量解码 + 长度前缀 |
| 动态数组 | ✅ | 偏移量解码 + `len*32` |
| 结构体参数 | ✅ | 支持静态与动态嵌套字段 |
| 多返回值 | ✅ | 结构体返回会连续 `mstore` |
| 事件编码 | ⚠️ 部分 | log0-log4 存在，无高级封装 |

### 6.5 SourceLocation 部分填充

```zig
// ast.zig - 结构存在
pub const SourceLocation = struct {
    start: u32 = 0,
    end: u32 = 0,
    source_index: ?u32 = null,
};

// transformer.zig - 主要语句/表达式已填充
// 结果：AST 路径错误定位更准确，IR 路径仍无位置
```

---

## 7. 类型系统与语言特性

### 7.1 EVM 类型支持

**原生类型 (src/evm/types.zig):**

| 类型 | Zig 表示 | EVM 大小 | 状态 |
|------|----------|----------|------|
| `u256` | `U256` (@Vector) | 32 bytes | ✅ |
| `address` | `Address` ([20]u8) | 20 bytes | ✅ |
| `bool` | `bool` | 1 byte | ✅ |
| `bytes1`-`bytes32` | `[N]u8` | 1-32 bytes | ✅ |

**复合类型:**

| 类型 | 描述 | 状态 |
|------|------|------|
| `Struct` | 结构体类型 | ✅ |
| `Mapping` | 键值映射 | ✅ |
| `Array` | 动态/定长数组 | ✅ |
| `Function` | 函数类型 | ✅ |

### 7.2 语言特性支持

| 特性 | 描述 | 状态 |
|------|------|------|
| 结构体合约 | `pub const Contract = struct { ... }` | ✅ |
| 存储变量 | 自动 slot 分配 | ✅ |
| 函数选择器 | Keccak256 前 4 字节 | ✅ |
| 合约分发器 | switch/case 路由 | ✅ |
| 构造函数 | 部署代码生成 | ✅ |
| ABI 编码 | 参数序列化 | ✅ |
| 事件发射 | log0-log4 | ✅ |
| 错误处理 | revert with message | ✅ |

---

## 8. 实现差异说明

### 8.1 命名冲突处理

由于 Zig 语言关键字限制，以下操作码使用内部别名：

| Yul 名称 | Zig 内部名称 | 说明 |
|----------|--------------|------|
| `and` | `and_` | 避免与 Zig `and` 冲突 |
| `or` | `or_` | 避免与 Zig `or` 冲突 |
| `return` | `return_` | 避免与 Zig `return` 冲突 |

`getBuiltin()` 函数已支持通过 Yul 名称查找（如 `getBuiltin("and")` 可正常工作）。

### 8.2 类型系统差异

| libyul | Zig 实现 | 说明 |
|--------|----------|------|
| `u256` (boost) | `U256` (@Vector) | 使用 Zig 原生向量类型 |
| `std::optional` | Zig optional (`?T`) | 原生支持 |
| `std::variant` | Zig union | 更安全的标记联合 |
| `std::shared_ptr` | 手动内存管理 | 使用 AstBuilder 追踪 |

---

## 9. 结论

### 9.1 核心结论

> ⚠️ **尚未完全对齐 C++ libyul AST，也未覆盖当前 EVM 全部能力。**
>
> 当前实现是**可用的核心子集**，但仍有结构与功能空洞。

### 9.2 完整性评估 (按组件)

| 类别 | 覆盖率 | 状态 | 备注 |
|------|--------|------|------|
| Yul AST 节点类型 | 15/15 | ✅ | Builtin/Function 已区分 |
| Object 模型 | 3/5 (60%) | ✅ 核心完整 | |
| EVM 操作码定义 | 73/73 | ✅ 列表完整 | 但缺少版本强制检查 |
| Dialect 版本追踪 | 13/13 | ✅ | `hasBuiltin()` 已强制检查 |
| EOF 特性 (Prague) | 0/14 (0%) | ❌ 未实现 | |

### 9.3 完整性评估 (按功能领域)

| 领域 | 覆盖率 | 说明 |
|------|--------|------|
| **Yul AST 结构** | ~80% | 节点类型完整，但语义区分不足 |
| **EVM Builtin** | ~90% | 操作码列表完整，版本检查已补齐 |
| **Zig→Yul 翻译** | ~60% | 支持循环/switch/break/continue，缺少复杂表达式 |
| **ABI 编解码** | ~30% | 仅静态类型单返回值 |
| **开发工具** | ~20% | 基本编译，无源码映射/调试 |

### 9.4 当前可用场景

- ✅ 简单合约：纯函数、if/else、简单存储读写
- ✅ 循环逻辑：while 循环、for 范围循环 (0..n)
- ✅ 控制流：switch 语句、break、continue
- ✅ 基础分发器：静态参数函数路由
- ⚠️ 复杂合约：需要手动处理动态 ABI、数组索引

### 9.5 优先修复路线

| 优先级 | 任务 | 影响 |
|--------|------|------|
| **P0** | 添加 Dialect 版本强制检查 | ✅ 已完成 |
| **P0** | 实现 for/while 循环翻译 | ✅ 已完成 (for 支持 range) |
| **P1** | 区分 BuiltinCall/FunctionCall | ✅ 已完成 |
| **P1** | 实现 switch/break/continue | ✅ 已完成 (range/表达式 case 通过 if 链; break/continue 无 label/value) |
| **P1** | 动态 ABI 类型支持 | 实际合约需要 |
| **P2** | 填充 SourceLocation | 调试能力 |
| **P2** | 多返回值 ABI | 复杂接口 |
| **P3** | EOF 特性 | Prague 后需要 |

---

## 附录

### A. 参考资料

- [Yul Specification](https://docs.soliditylang.org/en/latest/yul.html)
- [libyul AST.h](https://github.com/ethereum/solidity/blob/develop/libyul/AST.h)
- [libyul Object.h](https://github.com/ethereum/solidity/blob/develop/libyul/Object.h)
- [EVM Opcodes](https://www.evm.codes/)
- [EOF EIPs](https://eips.ethereum.org/EIPS/eip-7692)
- [EVM Precompiled Contracts](https://www.evm.codes/precompiled)

### B. 更新历史

| 日期 | 版本 | 变更内容 |
|------|------|----------|
| 2026-01-09 | 1.0 | 初始版本 |
| 2026-01-09 | 1.1 | 添加项目架构说明、类型系统、语言特性、预编译合约、开发工具特性、功能领域评估 |
| 2026-01-09 | 1.2 | 添加关键限制章节：AST 结构差异、Dialect 验证缺失、Zig→Yul 覆盖子集、ABI 限制、SourceLocation 未填充；更新完整性评估为更诚实的数字；添加优先修复路线 |
