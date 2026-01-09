//! Example: Simple ERC20-like Token Contract
//! This demonstrates how to write a smart contract in Zig
//! that compiles to Yul intermediate language.

const evm = @import("evm");

/// Simple token contract with balance tracking
pub const Token = struct {
    /// Mapping of addresses to balances
    balances: evm.Mapping(evm.Address, evm.u256),
    /// Total supply of tokens
    total_supply: evm.u256,
    /// Contract owner
    owner: evm.Address,

    /// Initialize the contract with initial supply
    pub fn init(self: *Token, initial_supply: evm.u256) void {
        const sender = evm.caller();
        self.total_supply = initial_supply;
        self.balances.set(sender, initial_supply);
        self.owner = sender;
    }

    /// Get balance of an address
    pub fn balanceOf(self: *Token, account: evm.Address) evm.u256 {
        return self.balances.get(account);
    }

    /// Transfer tokens to another address
    pub fn transfer(self: *Token, to: evm.Address, amount: evm.u256) bool {
        const sender = evm.caller();
        const sender_balance = self.balances.get(sender);

        // Check sufficient balance
        if (sender_balance < amount) {
            return false;
        }

        // Update balances
        self.balances.set(sender, sender_balance - amount);
        self.balances.set(to, self.balances.get(to) + amount);

        return true;
    }

    /// Get total supply
    pub fn totalSupply(self: *Token) evm.u256 {
        return self.total_supply;
    }
};
