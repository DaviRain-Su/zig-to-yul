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

Download pre-built binaries from the [Releases](https://github.com/example/zig-to-yul/releases) page.

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

# End-to-end profile test (instrument -> collect -> estimate)
./tools/z2y/zig-out/bin/z2y profile-test

# Initialize a new contract project (current directory)
./tools/z2y/zig-out/bin/z2y init .

# Or create a new directory
./tools/z2y/zig-out/bin/z2y init my-contract
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
