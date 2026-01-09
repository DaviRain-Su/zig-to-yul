//! Simple Counter Contract
//! Demonstrates basic state management in a smart contract

const evm = @import("evm");

/// Simple counter contract with increment/decrement functionality
pub const Counter = struct {
    /// Current counter value
    value: evm.u256,

    /// Increment the counter by 1
    pub fn increment(self: *Counter) void {
        self.value = self.value + 1;
    }

    /// Decrement the counter by 1
    pub fn decrement(self: *Counter) void {
        if (self.value > 0) {
            self.value = self.value - 1;
        }
    }

    /// Get current value
    pub fn get(self: *Counter) evm.u256 {
        return self.value;
    }

    /// Set value (only owner)
    pub fn set(self: *Counter, new_value: evm.u256) void {
        self.value = new_value;
    }
};
