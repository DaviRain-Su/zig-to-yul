//! Event encoding helpers for EVM logs.
//! Provides basic ABI-style encoding for event data.

const types = @import("types.zig");

pub const U256 = types.U256;
pub const Address = types.Address;

// Declare EVM builtins as extern to satisfy Zig typing.
const evm = struct {
    pub extern fn mload(addr: U256) U256;
    pub extern fn mstore(addr: U256, value: U256) void;
    pub extern fn keccak256(ptr: U256, len: U256) U256;
    pub extern fn log0(ptr: U256, len: U256) void;
    pub extern fn log1(ptr: U256, len: U256, t0: U256) void;
    pub extern fn log2(ptr: U256, len: U256, t0: U256, t1: U256) void;
    pub extern fn log3(ptr: U256, len: U256, t0: U256, t1: U256, t2: U256) void;
    pub extern fn log4(ptr: U256, len: U256, t0: U256, t1: U256, t2: U256, t3: U256) void;
};

pub const EventData = struct {
    ptr: U256,
    len: U256,
};

pub fn start() EventData {
    return .{ .ptr = evm.mload(0x40), .len = 0 };
}

pub fn finish(data: *EventData) void {
    evm.mstore(0x40, data.ptr + data.len);
}

pub fn topicFromBytes(ptr: U256, len: U256) U256 {
    return evm.keccak256(ptr, len);
}

pub fn pushWord(data: *EventData, value: U256) void {
    evm.mstore(data.ptr + data.len, value);
    data.len += 32;
}

pub fn pushAddress(data: *EventData, value: Address) void {
    pushWord(data, value);
}

pub fn pushBool(data: *EventData, value: U256) void {
    pushWord(data, value);
}

pub fn pushBytes(data: *EventData, src: U256, len: U256) void {
    evm.mstore(data.ptr + data.len, len);
    const dst = data.ptr + data.len + 32;
    copyMemory(dst, src, len);
    const padded = (len + 31) & ~@as(U256, 31);
    data.len += 32 + padded;
}

pub fn emit0(data: *EventData) void {
    evm.log0(data.ptr, data.len);
    finish(data);
}

pub fn emit1(t0: U256, data: *EventData) void {
    evm.log1(data.ptr, data.len, t0);
    finish(data);
}

pub fn emit2(t0: U256, t1: U256, data: *EventData) void {
    evm.log2(data.ptr, data.len, t0, t1);
    finish(data);
}

pub fn emit3(t0: U256, t1: U256, t2: U256, data: *EventData) void {
    evm.log3(data.ptr, data.len, t0, t1, t2);
    finish(data);
}

pub fn emit4(t0: U256, t1: U256, t2: U256, t3: U256, data: *EventData) void {
    evm.log4(data.ptr, data.len, t0, t1, t2, t3);
    finish(data);
}

fn copyMemory(dest: U256, src: U256, len: U256) void {
    var i: U256 = 0;
    const padded = (len + 31) & ~@as(U256, 31);
    while (i < padded) : (i += 32) {
        const word = evm.mload(src + i);
        evm.mstore(dest + i, word);
    }
}
