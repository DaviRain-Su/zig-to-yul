# zig-to-yul

A compiler that translates Zig smart contracts to Yul intermediate language for the Ethereum Virtual Machine (EVM).

```
Zig Source Code → [zig-to-yul] → Yul Code → [solc] → EVM Bytecode
```

## Features

- **Zig to Yul Compilation**: Write smart contracts in Zig, compile to Yul IR
- **Direct Bytecode Generation**: Compile directly to EVM bytecode using solc
- **Struct-based Contracts**: Define contracts as Zig structs with storage variables and methods
- **EVM Built-ins**: Access EVM opcodes through the `evm` namespace
- **Gas Estimation**: Estimate gas usage with optional profile overrides
- **Profiling (Yul)**: Generate instrumented Yul and aggregate counts
- **Cross-platform**: Runs on Linux, macOS, and Windows

## Installation

### From Source

Requirements:
- [Zig 0.15.x](https://ziglang.org/download/)
- [solc](https://docs.soliditylang.org/en/latest/installing-solidity.html) (for bytecode generation)

```bash
git clone https://github.com/example/zig-to-yul.git
cd zig-to-yul
zig build -Doptimize=ReleaseSafe
```

The binary will be at `./zig-out/bin/zig_to_yul`.

### From Releases

Download pre-built binaries from the [Releases](https://github.com/DaviRain-Su/zig-to-yul/releases) page.

One-line installer (Linux/macOS, installs `z2y` + `zig_to_yul` to `~/.local/bin`):

```bash
curl -fsSL https://raw.githubusercontent.com/DaviRain-Su/zig-to-yul/v0.1.0/scripts/install.sh | bash
```

Ensure Zig 0.15.2 is installed separately (required by `z2y`).

## Usage

### Compile to Yul

```bash
# Output to stdout
zig-to-yul compile contract.zig

# Output to file
zig-to-yul compile contract.zig -o contract.yul

# Emit ABI JSON
zig-to-yul compile contract.zig -o contract.yul --abi out/Contract.abi.json

# Use project build.zig root module
zig-to-yul compile --project . -o contract.yul --abi out/Contract.abi.json

# Emit source map (Solidity-compatible entries: start:length:source)
zig-to-yul compile contract.zig -o contract.yul --sourcemap
```

### Build to EVM Bytecode

Requires `solc` in PATH.

```bash
# Output to stdout (with 0x prefix)
zig-to-yul build contract.zig

# Output to file
zig-to-yul build contract.zig -o contract.bin

# With solc optimizer
zig-to-yul build -O contract.zig -o contract.bin
```

### Commands

| Command | Description |
|---------|-------------|
| `compile` | Compile Zig to Yul intermediate language |
| `build` | Compile Zig to EVM bytecode (requires solc) |
| `estimate` | Estimate gas usage (supports profile overrides) |
| `profile` | Instrument Yul and aggregate profile counts |
| `version` | Print version information |
| `help` | Print help message |

### SDK Surface

Only the `evm` module is intended for contract code (other modules are internal and not stable):

```zig
const evm = @import("zig_to_yul").evm;
```

Available namespaces:
- `evm.types`
- `evm.storage`
- `evm.event` (alias for `evm.event_encode`/`evm.event_decode`)
- `evm.abi`
- `evm.precompile`
- `evm.rpc`
- `evm.contract`
- `evm.tx` (legacy tx signing)
- `evm.builtins_stub` (IDE-only)

### Scaffold Project (z2y)

```bash
# Build the z2y tool
cd tools/z2y && zig build

# Install prerequisites (prints commands)
./tools/z2y/zig-out/bin/z2y install

# Check tool availability (zig, zig-to-yul, solc, anvil, forge, cast)
./tools/z2y/zig-out/bin/z2y info

# Build bytecode into out/Contract.bin
./tools/z2y/zig-out/bin/z2y build

# Generate ABI + Yul into out/
./tools/z2y/zig-out/bin/z2y build-abi

# Run local test (starts anvil, deploys, calls set/get)
./tools/z2y/zig-out/bin/z2y test

# Deploy to remote RPC (reads PRIVATE_KEY env)
./tools/z2y/zig-out/bin/z2y deploy --rpc-url https://rpc.example

# Call a Solidity-compatible function
./tools/z2y/zig-out/bin/z2y call --address 0xabc... --sig "get()(uint256)"

# Generate on-chain ABI wrapper (static types only)
./tools/z2y/zig-out/bin/z2y abi-gen --abi out/Contract.abi.json --out src/ContractAbi.zig --name ExternalContract

# Call using ABI + function name
./tools/z2y/zig-out/bin/z2y call --address 0xabc... --abi out/Contract.abi.json --func get

# Use a named profile from profiles.json
./tools/z2y/zig-out/bin/z2y call --profile local --address 0xabc... --sig "get()(uint256)"

# End-to-end profile test (instrument -> collect -> estimate)
./tools/z2y/zig-out/bin/z2y profile-test

# Initialize a new contract project (current directory)
./tools/z2y/zig-out/bin/z2y init .

# Or create a new directory
./tools/z2y/zig-out/bin/z2y init my-contract
```

Example `profiles.json`:

```json
{
  "local": {
    "rpc_url": "http://127.0.0.1:8545",
    "chain_id": 31337,
    "private_key_env": "PRIVATE_KEY"
  }
}
```

SDK example (call a Solidity function off-chain):

```zig
const evm = @import("zig_to_yul").evm;

const result_hex = try evm.contract.call(
    allocator,
    "http://127.0.0.1:8545",
    "0x1234...",
    "balanceOf(address)",
    &.{ .{ .address = some_address } },
);
```

SDK example (sign legacy transaction):

```zig
const evm = @import("zig_to_yul").evm;

const raw = try evm.tx.signLegacy(allocator, .{
    .nonce = 0,
    .gas_price = 1_000_000_000,
    .gas_limit = 21000,
    .to = 0x1234,
    .value = 0,
    .data = &.{},
    .chain_id = 1,
}, "0x<private_key>");
```

SDK example (sign EIP-1559 transaction):

```zig
const evm = @import("zig_to_yul").evm;

const raw = try evm.tx.signEip1559(allocator, .{
    .chain_id = 1,
    .nonce = 0,
    .max_priority_fee_per_gas = 1_000_000_000,
    .max_fee_per_gas = 2_000_000_000,
    .gas_limit = 21000,
    .to = 0x1234,
    .value = 0,
    .data = &.{},
    .access_list = &.{},
}, "0x<private_key>");
```

SDK example (sign from keystore):

```zig
const evm = @import("zig_to_yul").evm;

const keystore_json = try std.fs.cwd().readFileAlloc(allocator, "wallet.json", 1024 * 1024);
defer allocator.free(keystore_json);

const raw = try evm.tx.signEip1559Keystore(allocator, .{
    .chain_id = 1,
    .nonce = 0,
    .max_priority_fee_per_gas = 1_000_000_000,
    .max_fee_per_gas = 2_000_000_000,
    .gas_limit = 21000,
    .to = 0x1234,
    .value = 0,
    .data = &.{},
    .access_list = &.{},
}, keystore_json, "password");
```

On-chain wrapper example (generated):

```zig
const evm = @import("evm");
const ExternalContract = @import("ContractAbi.zig").ExternalContract;

pub fn readBalance(token: evm.Address, owner: evm.Address) evm.U256 {
    var contract = ExternalContract.init(token);
    return contract.balanceOf(owner);
}
```

### Gas Estimation

```bash
# Estimate gas
zig-to-yul estimate contract.zig

# Estimate with profile overrides
zig-to-yul estimate contract.zig --profile profile.json
```

### Profiling (Yul)

```bash
# Emit instrumented Yul and map
zig-to-yul profile contract.zig -o contract.profile.yul --map profile.map.json

# Aggregate raw counter runs into profile.json
zig-to-yul profile contract.zig --map profile.map.json \
  --counts run1.counts.json --counts run2.counts.json \
  --profile-out profile.json

# Collect via Anvil RPC (deploy + eth_call)
zig-to-yul profile contract.zig --rpc-url http://127.0.0.1:8545 \
  --call-data 0x1234 --runs 5 --profile-out profile.json
```

### Options

| Option | Description |
|--------|-------------|
| `-o, --output <file>` | Write output to file |
| `-O, --optimize` | Enable solc optimizer (build only) |
| `--project <dir>` | Use build.zig root module |
| `--abi <file>` | Write ABI JSON (compile/estimate/profile) |
| `--profile <file>` | Profile counts JSON (estimate only) |
| `--evm-version <name>` | EVM version (estimate only) |
| `--rpc-url <url>` | Collect profile via JSON-RPC (profile only) |
| `--contract <addr>` | Use deployed contract address (profile only) |
| `--call-data <hex|@file>` | Calldata hex for eth_call (profile only) |
| `--runs <n>` | Repeat eth_call n times (profile only) |
| `--no-deploy` | Skip deployment (profile only) |
| `--return-counts` | Force return count payload (profile only) |
| `-h, --help` | Print help |
| `-v, --version` | Print version |

## Writing Contracts

### Basic Contract Structure

```zig
// contracts/token.zig
const evm = @import("evm");

pub const Token = struct {
    // Storage variables
    total_supply: u256,
    balances: evm.Mapping(evm.Address, u256),

    // Contract functions
    pub fn transfer(self: *Token, to: evm.Address, amount: u256) bool {
        const sender = evm.caller();
        const sender_balance = self.balances.get(sender);

        if (sender_balance < amount) {
            return false;
        }

        self.balances.set(sender, sender_balance - amount);
        self.balances.set(to, self.balances.get(to) + amount);
        return true;
    }

    pub fn balanceOf(self: *Token, account: evm.Address) u256 {
        return self.balances.get(account);
    }
};
```

### Mapping Iteration

```zig
pub fn totalBalance(self: *Token) u256 {
    var sum: u256 = 0;
    var it = self.balances.iterator();
    while (it.next()) |entry| {
        sum += entry.value;
    }
    return sum;
}

pub fn totalBalancePtr(self: *Token) u256 {
    var sum: u256 = 0;
    var it = self.balances.iteratorPtr();
    while (it.next()) |entry| {
        sum += entry.value_ptr.*;
    }
    return sum;
}
```

Notes:
- Iteration order is not stable after removals (swap-with-last storage).
- `iteratorPtr()` iterates over snapshot arrays from `keys()`/`values()`.

### Mapping Entry References

```zig
pub fn bumpBalance(self: *Token, owner: evm.Address, delta: u256) void {
    var ref = self.balances.getOrPutPtr(owner, 0);
    const current = ref.get();
    ref.set(current + delta);

    if (ref.wasInserted()) {
        // optional bookkeeping when a new entry is created
    }
}
```

Notes:
- `getPtr`/`getOrPutPtr`/`fetchPutPtr`/`putNoClobberPtr` return a storage-backed ref with `get`/`set`/`exists`.
- `getKey()`/`getSlot()` expose the key/slot stored in the ref.
- `valuePtrAt(index)` returns a ref for the entry at `index` (dynamic values use `Ref.get/set`).
- `keyPtrAt(index)` is the same as `keyAt(index)` for fixed keys.
- `removeOrNull` returns zero when the key is missing.
- `removeOrNullInfo` returns a `RemoveRef` with `removed()` and `getValue()` for "bool + value" semantics.
- `ensureCapacity`/`shrinkToFit` are no-ops for mappings.

### EVM Built-in Functions

```zig
const evm = @import("evm");

// Context
evm.caller()           // msg.sender
evm.callvalue()        // msg.value
evm.calldataload(pos)  // Load calldata

// Storage
evm.sload(slot)        // Load from storage
evm.sstore(slot, val)  // Store to storage

// Memory
evm.mload(offset)      // Load from memory
evm.mstore(offset, val) // Store to memory

// Control flow
evm.revert(offset, size)  // Revert transaction
evm.return_(offset, size) // Return data
```

## Examples

See the [`examples/`](./examples) directory:

- [`simple.zig`](./examples/simple.zig) - Minimal contract
- [`counter.zig`](./examples/counter.zig) - Counter with increment/decrement
- [`token.zig`](./examples/token.zig) - ERC20-like token

## Testing Locally

### Run Unit Tests

```bash
zig build test --summary all
```

### Foundry SDK Test (Anvil + Cast)

Requires [Foundry](https://getfoundry.sh/) (anvil, cast). The test spawns `anvil`, deploys a minimal contract with `cast`, then calls it via the SDK.

```bash
# Optionally override Foundry binaries
export ANVIL_BIN=anvil
export CAST_BIN=cast

zig build test --summary all
```

### JSON-RPC Compatibility Check

Use any RPC provider (Anvil/Hardhat/Alchemy) to verify baseline methods.

```bash
export RPC_URL=http://127.0.0.1:8545

curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}'

curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'

curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"net_version","params":[]}'
```

You can also run the optional compatibility test with multiple providers:

```bash
export RPC_URL=http://127.0.0.1:8545
export RPC_URL_HARDHAT=http://127.0.0.1:8545
export RPC_URL_ALCHEMY=https://eth-mainnet.g.alchemy.com/v2/<key>
export RPC_URL_INFURA=https://mainnet.infura.io/v3/<key>
export RPC_URL_QUICKNODE=https://<name>.quiknode.pro/<key>

zig build test --summary all
```

### Deploy to Local Testnet

Requires [Foundry](https://getfoundry.sh/) (anvil, cast).

```bash
# Run the deployment test script
./scripts/test-deploy.sh

# Or test a specific contract
./scripts/test-deploy.sh examples/token.zig
```

### Manual Deployment

```bash
# 1. Start local testnet
anvil

# 2. Compile to bytecode
./zig-out/bin/zig_to_yul build contract.zig -o bytecode.txt

# 3. Deploy
cast send --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --rpc-url http://127.0.0.1:8545 \
  --create $(cat bytecode.txt)
```

## Project Structure

```
zig-to-yul/
├── src/
│   ├── main.zig          # CLI entry point
│   ├── compiler.zig      # Main compiler logic
│   ├── ast/
│   │   └── parser.zig    # Zig AST parsing
│   ├── sema/
│   │   ├── symbols.zig   # Symbol table
│   │   └── types.zig     # Type system
│   ├── yul/
│   │   ├── ir.zig        # Yul IR definitions
│   │   └── codegen.zig   # Yul code generation
│   └── evm/
│       ├── types.zig     # EVM types (u256, Address, etc.)
│       └── builtins.zig  # EVM opcode wrappers
├── examples/             # Example contracts
├── scripts/              # Utility scripts
└── .github/workflows/    # CI configuration
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     zig-to-yul Compiler                     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐  │
│  │  Lexer  │ →  │ Parser  │ →  │  Sema   │ →  │ CodeGen │  │
│  │(std.zig)│    │(std.zig)│    │         │    │  (Yul)  │  │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘  │
│       ↓              ↓              ↓              ↓        │
│    Tokens          AST          Yul IR        Yul Code     │
└─────────────────────────────────────────────────────────────┘
```

## Documentation

| 文档 | 说明 |
|------|------|
| [AUDIT-REPORT.md](docs/AUDIT-REPORT.md) | 项目功能完整性审查报告 |
| [ROADMAP.md](docs/ROADMAP.md) | 版本路线图与开发计划 |
| [libyul-comparison.md](docs/libyul-comparison.md) | 与 Solidity libyul 功能对比 |
| [gas-optimization-roadmap.md](docs/gas-optimization-roadmap.md) | Gas 优化计划 |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | 故障排除指南 |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`zig build test`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Zig Programming Language](https://ziglang.org/)
- [Solidity/Yul](https://docs.soliditylang.org/en/latest/yul.html)
- [Foundry](https://getfoundry.sh/)
