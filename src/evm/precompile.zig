//! Precompile addresses per Ethereum execution specs.

const types = @import("types.zig");

pub const Address = types.Address;

pub const ecrecover: Address = 0x01;
pub const sha256: Address = 0x02;
pub const ripemd160: Address = 0x03;
pub const identity: Address = 0x04;
pub const modexp: Address = 0x05;
pub const bn128_add: Address = 0x06;
pub const bn128_mul: Address = 0x07;
pub const bn128_pairing: Address = 0x08;
pub const blake2f: Address = 0x09;
// EIP-4844 point evaluation (precompile 0x0a on mainnet).
pub const point_evaluation: Address = 0x0a;
