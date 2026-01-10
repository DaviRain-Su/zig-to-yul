//! IDE-only stubs for EVM builtins.
//! These are NOT used by zig-to-yul codegen.

const types = @import("types.zig");

pub const U256 = types.U256;
pub const Address = types.Address;

// Arithmetic
pub fn add(_: U256, _: U256) U256 {
    return 0;
}
pub fn sub(_: U256, _: U256) U256 {
    return 0;
}
pub fn mul(_: U256, _: U256) U256 {
    return 0;
}
pub fn div(_: U256, _: U256) U256 {
    return 0;
}
pub fn sdiv(_: U256, _: U256) U256 {
    return 0;
}
pub fn mod(_: U256, _: U256) U256 {
    return 0;
}
pub fn smod(_: U256, _: U256) U256 {
    return 0;
}
pub fn exp(_: U256, _: U256) U256 {
    return 0;
}
pub fn addmod(_: U256, _: U256, _: U256) U256 {
    return 0;
}
pub fn mulmod(_: U256, _: U256, _: U256) U256 {
    return 0;
}
pub fn signextend(_: U256, _: U256) U256 {
    return 0;
}

// Comparison
pub fn lt(_: U256, _: U256) U256 {
    return 0;
}
pub fn gt(_: U256, _: U256) U256 {
    return 0;
}
pub fn slt(_: U256, _: U256) U256 {
    return 0;
}
pub fn sgt(_: U256, _: U256) U256 {
    return 0;
}
pub fn eq(_: U256, _: U256) U256 {
    return 0;
}
pub fn iszero(_: U256) U256 {
    return 0;
}

// Bitwise
pub fn and_(_: U256, _: U256) U256 {
    return 0;
}
pub fn or_(_: U256, _: U256) U256 {
    return 0;
}
pub fn xor(_: U256, _: U256) U256 {
    return 0;
}
pub fn not(_: U256) U256 {
    return 0;
}
pub fn byte(_: U256, _: U256) U256 {
    return 0;
}
pub fn shl(_: U256, _: U256) U256 {
    return 0;
}
pub fn shr(_: U256, _: U256) U256 {
    return 0;
}
pub fn sar(_: U256, _: U256) U256 {
    return 0;
}

// Memory
pub fn mload(_: U256) U256 {
    return 0;
}
pub fn mstore(_: U256, _: U256) void {}
pub fn mstore8(_: U256, _: U256) void {}
pub fn msize() U256 {
    return 0;
}
pub fn mcopy(_: U256, _: U256, _: U256) void {}

// Storage
pub fn sload(_: U256) U256 {
    return 0;
}
pub fn sstore(_: U256, _: U256) void {}
pub fn tload(_: U256) U256 {
    return 0;
}
pub fn tstore(_: U256, _: U256) void {}

pub fn ffs(_: U256) U256 {
    return 0;
}

// Execution context
pub fn caller() Address {
    return 0;
}
pub fn callvalue() U256 {
    return 0;
}
pub fn calldataload(_: U256) U256 {
    return 0;
}
pub fn calldatasize() U256 {
    return 0;
}
pub fn calldatacopy(_: U256, _: U256, _: U256) void {}
pub fn codesize() U256 {
    return 0;
}
pub fn codecopy(_: U256, _: U256, _: U256) void {}
pub fn extcodesize(_: Address) U256 {
    return 0;
}
pub fn extcodecopy(_: Address, _: U256, _: U256, _: U256) void {}
pub fn returndatasize() U256 {
    return 0;
}
pub fn returndatacopy(_: U256, _: U256, _: U256) void {}
pub fn extcodehash(_: Address) U256 {
    return 0;
}
pub fn address() Address {
    return 0;
}
pub fn balance(_: Address) U256 {
    return 0;
}
pub fn selfbalance() U256 {
    return 0;
}
pub fn origin() Address {
    return 0;
}
pub fn gasprice() U256 {
    return 0;
}
pub fn gas() U256 {
    return 0;
}

// Block context
pub fn blockhash(_: U256) U256 {
    return 0;
}
pub fn coinbase() Address {
    return 0;
}
pub fn timestamp() U256 {
    return 0;
}
pub fn number() U256 {
    return 0;
}
pub fn difficulty() U256 {
    return 0;
}
pub fn prevrandao() U256 {
    return 0;
}
pub fn gaslimit() U256 {
    return 0;
}
pub fn chainid() U256 {
    return 0;
}
pub fn basefee() U256 {
    return 0;
}
pub fn blobbasefee() U256 {
    return 0;
}
pub fn blobhash(_: U256) U256 {
    return 0;
}

// Control flow
pub fn return_(_: U256, _: U256) void {}
pub fn revert(_: U256, _: U256) void {}
pub fn stop() void {}
pub fn invalid() void {}
pub fn selfdestruct(_: Address) void {}

// Logging
pub fn log0(_: U256, _: U256) void {}
pub fn log1(_: U256, _: U256, _: U256) void {}
pub fn log2(_: U256, _: U256, _: U256, _: U256) void {}
pub fn log3(_: U256, _: U256, _: U256, _: U256, _: U256) void {}
pub fn log4(_: U256, _: U256, _: U256, _: U256, _: U256, _: U256) void {}

// Calls
pub fn call(_: U256, _: Address, _: U256, _: U256, _: U256, _: U256, _: U256) U256 {
    return 0;
}
pub fn callcode(_: U256, _: Address, _: U256, _: U256, _: U256, _: U256, _: U256) U256 {
    return 0;
}
pub fn delegatecall(_: U256, _: Address, _: U256, _: U256, _: U256, _: U256) U256 {
    return 0;
}
pub fn staticcall(_: U256, _: Address, _: U256, _: U256, _: U256, _: U256) U256 {
    return 0;
}

// Create
pub fn create(_: U256, _: U256, _: U256) U256 {
    return 0;
}
pub fn create2(_: U256, _: U256, _: U256, _: U256) U256 {
    return 0;
}

// Other
pub fn keccak256(_: U256, _: U256) U256 {
    return 0;
}
pub fn datasize(_: U256) U256 {
    return 0;
}
pub fn dataoffset(_: U256) U256 {
    return 0;
}
pub fn datacopy(_: U256, _: U256, _: U256) void {}
pub fn setimmutable(_: U256, _: U256, _: U256) void {}
pub fn loadimmutable(_: U256) U256 {
    return 0;
}
pub fn linkersymbol(_: U256) U256 {
    return 0;
}
pub fn memoryguard(_: U256) U256 {
    return 0;
}
pub fn verbatim() void {}
pub fn pop(_: U256) void {}
