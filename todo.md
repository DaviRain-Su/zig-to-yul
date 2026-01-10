• 目前的 TODO 清单（汇总自 docs/libyul-comparison.md 的未完成/部分实现项）：

- EOF Prague 指令未实现（5.1）【未来规划，当前未使用】
  - 总体实现规划（5.1）：
    - 指令清单：按 EIP/EOF 规范建立缺失指令矩阵
    - 解析与 AST：扩展 Yul builtin/IR 支持 Prague 指令
    - 代码生成：Yul→EVM bytecode 支持新 opcode
    - Gas/执行语义：补充 gas table 与语义规则
    - 测试：对齐上游向量与单元测试
    

- 优化研究：对比 https://github.com/Vectorized/solady
  - 总体实现规划（优化）：
    - 选基准：确定 Solady/参考合约与基准指标
    - Profiling：对齐 gas/size/部署成本
    - 优化点：映射、scratch 复用、SLOAD/SSTORE 合并
    - 回归测试：确保语义一致与指标提升


基于 Solady 的优化建议

  已实现的优化 ✅
  ┌────────────────────────────────┬──────┬──────────────────┐
  │              优化              │ 状态 │       来源       │
  ├────────────────────────────────┼──────┼──────────────────┤
  │ Scratch space 重用 (0x00-0x3f) │ ✅   │ EfficientHashLib │
  ├────────────────────────────────┼──────┼──────────────────┤
  │ 地址清理 (shr 96 bits)         │ ✅   │ SafeTransferLib  │
  ├────────────────────────────────┼──────┼──────────────────┤
  │ 自定义错误选择器               │ ✅   │ 通用模式         │
  ├────────────────────────────────┼──────┼──────────────────┤
  ├────────────────────────────────┼──────┼──────────────────┤
  │ 常量折叠                       │ ✅   │ 基础优化         │
  └────────────────────────────────┴──────┴──────────────────┘
  可新增的优化建议

  P0 - 高优先级（显著 gas 节省）

  1. EIP-1153 瞬态存储支持
  // 当前: sstore 成本 ~20000 gas (cold)
  sstore(slot, value)

  // 优化: tstore 仅需 ~100 gas
  tstore(slot, value)
  tload(slot)
  适用场景：重入锁、临时状态、单交易内的跨函数数据传递

  2. 无分支条件计算 (LibBit 模式)
  // 当前: 使用 if 语句
  if iszero(x) { result := 0 }
  if x { result := 1 }

  // 优化: 无分支归一化
  result := iszero(iszero(x))  // 保证返回 0 或 1

  3. Calldata 直接哈希 (EfficientHashLib)
  // 当前: 可能拷贝到内存再哈希
  let data := calldataload(offset)
  mstore(0x00, data)
  let hash := keccak256(0x00, 0x20)

  // 优化: 对于大数据，使用 calldatacopy 到临时缓冲区
  calldatacopy(0x00, offset, length)
  let hash := keccak256(0x00, length)

  P1 - 中优先级

  4. 预定位内存布局 (SafeTransferLib 模式)
  // 优化 ERC20 调用参数布局
  mstore(0x60, amount)       // 第三个参数
  mstore(0x40, recipient)    // 第二个参数
  mstore(0x2c, shl(96, sender)) // 第一个参数 (地址左移)
  mstore(0x0c, selector)     // 函数选择器

  // 单次 call，无需重新布局
  call(gas(), token, 0, 0x1c, 0x64, 0x00, 0x20)

  5. 饱和算术运算 (FixedPointMathLib)
  // 饱和乘法，溢出时返回 max 而非 revert
  function saturatingMul(x, y) -> result {
      result := mul(x, y)
      if iszero(eq(div(result, x), y)) {
          result := not(0)  // type(uint256).max
      }
  }

  6. De Bruijn 位操作查找表 (LibBit)
  // 快速找到最低有效位位置
  function ffs(x) -> r {
      // 使用魔法常数进行 O(1) 查找
      r := shl(2, shr(250, mul(and(x, sub(0, x)),
          0xb6db6db6ddddddddd34d34d349249249210842108c6318c639ce739cffffffff)))
  }

  P2 - 低优先级

  7. 模算术避免溢出检查
  // 使用 mulmod/addmod 原生支持
  let result := mulmod(a, b, mod)
  let result := addmod(a, b, mod)

  8. Gas Stipend 常量化
  // SafeTransferLib 模式
  let GAS_STIPEND_NO_STORAGE := 2300
  let GAS_STIPEND_NO_GRIEF := 100000

  9. 返回值验证模式
  // ERC20 兼容性检查
  if iszero(and(eq(mload(0x00), 1), success)) {
      revert(0, 0)
  }

  优化器增强建议

  1. sload/sstore 合并 - 合并对同一 slot 的多次读写
  2. 内联小函数 - 减少 JUMP 开销
  3. 循环展开 - 对已知边界的小循环
  4. 尾调用优化 - 减少栈使用
  5. returndata 缓冲区优化 - 重用 call 返回数据区域

  1) EIP-1153 瞬态存储支持（P0）  
  2) 无分支归一化（iszero(iszero(x)) 等）（P0）  
  3) Calldata 直接哈希（P0）  
  4) 预定位内存布局（P1，针对 ERC20 调用模式）

- 文档同步：
  - `docs/ROADMAP.md`
  - `docs/stories/v0.1.0-runtime-profile.md`
