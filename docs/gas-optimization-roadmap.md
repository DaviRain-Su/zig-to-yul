# Gas 优化路线图：达到 Solady 级别效率

## 当前状态 vs 目标

```
当前:  Zig → 简单 Yul → solc → 字节码 (Gas: ~100%)
目标:  Zig → 优化 Yul → solc → 字节码 (Gas: ~60-70%)
极致:  Zig → 手写级 Yul → solc → 字节码 (Gas: ~50-60%)
```

## Phase 1: 存储布局优化

### 1.1 Mapping 的正确实现

Solady 使用 keccak256 计算 mapping slot：

```yul
// Solady 风格
mstore(0x00, key)
mstore(0x20, baseSlot)
let slot := keccak256(0x00, 0x40)
let value := sload(slot)
```

**需要修改**:
- `src/yul/transformer.zig` - 添加 mapping slot 计算
- `src/evm/types.zig` - 添加 StorageLayout 结构

```zig
// 新增: src/evm/storage.zig
pub const StorageLayout = struct {
    /// 计算 mapping slot: keccak256(key ++ baseSlot)
    pub fn mappingSlot(key: u256, base_slot: u256) Expression {
        return .{ .function_call = .{
            .name = "keccak256",
            .args = &.{
                // mstore(0, key), mstore(32, baseSlot), keccak256(0, 64)
            },
        }};
    }

    /// 计算嵌套 mapping: mapping(a => mapping(b => v))
    pub fn nestedMappingSlot(keys: []const u256, base: u256) Expression {
        // keccak256(b ++ keccak256(a ++ base))
    }

    /// 打包多个小变量到一个 slot
    pub fn packSlot(values: []const PackedValue) Expression {
        // or(shl(offset1, v1), or(shl(offset2, v2), v3))
    }
};
```

### 1.2 存储打包 (Storage Packing)

Solady 的关键技巧 - 多个变量打包到一个 256-bit slot：

```zig
// Zig 源码
pub const Token = struct {
    owner: Address,      // 20 bytes
    approved: bool,      // 1 byte
    balance: u64,        // 8 bytes
    // 总共 29 bytes，可以打包到 1 个 slot
};

// 应生成的 Yul
function getOwner() -> o {
    o := and(sload(0), 0xffffffffffffffffffffffffffffffffffffffff)
}
function getApproved() -> a {
    a := and(shr(160, sload(0)), 0xff)
}
function getBalance() -> b {
    b := shr(168, sload(0))
}
```

**需要修改**:
- `src/sema/analyzer.zig` - 分析结构体布局
- 新增 `src/optimizer/storage_packer.zig`

### 1.3 冷/热存储访问优化

```zig
// 新增: 存储访问分析器
pub const StorageAccessOptimizer = struct {
    /// 检测同一 slot 的多次访问，合并为单次 sload
    pub fn optimizeAccess(stmts: []Statement) []Statement {
        // balance1 = sload(slot)
        // balance2 = sload(slot)  // 删除，复用 balance1
    }

    /// 检测 sload 后立即 sstore 同一 slot，使用 dup 而非重新 load
    pub fn optimizeLoadStore(stmts: []Statement) []Statement {
        // ...
    }
};
```

## Phase 2: 内存布局优化

### 2.1 Scratch Space 使用

Solady 大量使用 0x00-0x40 作为临时内存：

```yul
// Solady 风格 - 复用 scratch space
mstore(0x00, value1)
mstore(0x20, value2)
let hash := keccak256(0x00, 0x40)

// 当前生成 - 浪费内存
let ptr := mload(0x40)  // free memory pointer
mstore(ptr, value1)
mstore(add(ptr, 32), value2)
mstore(0x40, add(ptr, 64))  // 更新 free pointer
let hash := keccak256(ptr, 64)
```

**需要修改**:
- 新增 `src/optimizer/memory_optimizer.zig`

```zig
pub const MemoryOptimizer = struct {
    /// 分析内存生命周期，复用 scratch space
    scratch_available: bool = true,

    pub fn allocate(size: u32) MemoryRegion {
        if (size <= 64 and self.scratch_available) {
            return .{ .offset = 0, .is_scratch = true };
        }
        // 使用 free memory pointer
    }
};
```

### 2.2 Event 日志优化

```yul
// Solady 风格 - 直接使用 log
mstore(0x00, amount)
log3(0x00, 0x20, TRANSFER_TOPIC, from, to)

// 当前可能生成 - 低效
let ptr := mload(0x40)
mstore(ptr, amount)
mstore(0x40, add(ptr, 0x20))
log3(ptr, 0x20, TRANSFER_TOPIC, from, to)
```

## Phase 3: 控制流优化

### 3.1 条件分支优化

```zig
// Zig 源码
if (a > b) {
    return a;
} else {
    return b;
}

// 当前生成
if gt(a, b) { result := a leave }
result := b

// 优化后 (使用 select 模式)
result := xor(b, mul(xor(a, b), gt(a, b)))
```

**新增**:
```zig
// src/optimizer/branch_optimizer.zig
pub const BranchOptimizer = struct {
    /// 将简单 if-else 转换为无分支算术
    pub fn optimizeSimpleBranch(if_stmt: IfStatement) ?Expression {
        if (isSimpleReturn(if_stmt.then_body) and isSimpleReturn(if_stmt.else_body)) {
            // 使用 xor + mul 模式
        }
    }
};
```

### 3.2 循环展开

```zig
// Zig: 固定次数循环
for (0..4) |i| {
    sum += arr[i];
}

// 展开为
sum := add(sum, sload(0))
sum := add(sum, sload(1))
sum := add(sum, sload(2))
sum := add(sum, sload(3))
```

## Phase 4: ABI 编码优化

### 4.1 Calldata 直接读取

```yul
// 当前 - 可能生成冗余代码
let param1 := calldataload(4)
let param2 := calldataload(36)

// Solady 风格 - 内联到使用处
sstore(slot, calldataload(4))  // 直接使用，不存临时变量
```

### 4.2 Return 数据优化

```yul
// 当前
mstore(0x00, result)
return(0x00, 0x20)

// Solady (多返回值打包)
mstore(0x00, or(shl(96, addr), balance))
return(0x00, 0x20)
```

## Phase 5: Zig 编译期优化

### 5.1 利用 comptime 预计算

```zig
// Zig 源码
const TRANSFER_SELECTOR = comptime keccak256("transfer(address,uint256)")[0..4];

// 编译时计算，直接内联到 Yul
// 不需要运行时计算 selector
```

### 5.2 泛型特化

```zig
// 通用 ERC20
pub fn ERC20(comptime decimals: u8) type {
    return struct {
        // 根据 decimals 生成不同的优化代码
    };
}
```

## Phase 6: 高级优化 (可选)

### 6.1 直接生成 EVM 字节码

跳过 Yul，直接生成优化的 EVM：

```
Zig → [zig-to-evm] → EVM 字节码
```

这需要：
- 实现 EVM 操作码生成器
- 实现 jump 目标解析
- 实现代码大小优化

### 6.2 跨函数优化

```zig
// 识别相似代码模式，提取公共子程序
fn transfer() { ... common_check() ... }
fn transferFrom() { ... common_check() ... }

// 生成共享的内部函数
function __common_check() { ... }
```

## 实现优先级

| 优先级 | 功能 | 预期 Gas 节省 | 复杂度 |
|--------|------|--------------|--------|
| P0 | Mapping slot 正确计算 | 必须 | 中 |
| P0 | Scratch space 复用 | 10-15% | 低 |
| P1 | 存储打包 | 20-30% | 高 |
| P1 | sload/sstore 合并 | 5-10% | 中 |
| P2 | 无分支条件 | 3-5% | 中 |
| P2 | 循环展开 | 变化大 | 低 |
| P3 | 直接 EVM 生成 | 10-20% | 极高 |

## 示例：优化前后对比

### ERC20 Transfer

**当前输出**:
```yul
function transfer(to, amount) -> success {
    let sender := caller()
    let balance := sload(0)  // 错误: 应该是 mapping slot
    if lt(balance, amount) {
        success := 0
        leave
    }
    sstore(0, sub(balance, amount))
    // ... 更新 to 余额
    success := 1
}
```

**目标输出 (Solady 级别)**:
```yul
function transfer(to, amount) -> success {
    // 计算 sender 的 balance slot
    mstore(0x00, caller())
    mstore(0x20, _BALANCE_SLOT)
    let fromSlot := keccak256(0x00, 0x40)
    let fromBal := sload(fromSlot)

    // 检查 + 扣减 (单次 sstore)
    if iszero(lt(fromBal, amount)) {
        sstore(fromSlot, sub(fromBal, amount))

        // 计算 to 的 balance slot (复用 scratch space)
        mstore(0x00, to)
        // 0x20 已经是 _BALANCE_SLOT
        let toSlot := keccak256(0x00, 0x40)
        sstore(toSlot, add(sload(toSlot), amount))

        // Event
        mstore(0x00, amount)
        log3(0x00, 0x20, _TRANSFER_EVENT, caller(), to)

        success := 1
        leave
    }
    // success 默认是 0
}
```

## 下一步行动

1. **立即开始**: 实现正确的 mapping slot 计算
2. **本周**: 添加 scratch space 内存优化
3. **下周**: 实现存储打包分析
4. **后续**: 根据 benchmark 结果决定优先级

## Benchmark 计划

创建对比测试：
```bash
# 编译同一逻辑
solc --yul solady-transfer.yul -o solady.bin
zig-to-yul examples/transfer.zig | solc --yul - -o zig.bin

# 对比 Gas
forge test --gas-report
```
