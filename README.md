<div align="center">

# ⚡ Tachyon
### A High-Performance, Scalable Blockchain Implementation

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Status](https://img.shields.io/badge/Status-Experimental-orange) ![Complexity](https://img.shields.io/badge/Consensus-BFT-green)

**Tachyon** is a from-scratch blockchain inspired by modern high-throughput architectures (like Solana, Aptos, and Sui). It features a 6-stage pipelined block processing engine, optimistic parallel execution, and stake-weighted BFT finality.

</div>

---

## 🚀 Key Features

- **Pipelined Architecture**: 6-stage processing (Fetch → Gossip → Verify → Execute → Store → Finalize) for minimal latency.
- **Optimistic Parallelism**: Block-STM style transaction execution allowing independent transactions to run concurrently.
- **Stake-Weighted BFT**: Consensus based on stake distribution with >2/3 quorum for finality.
- **Domain-Separated Crypto**: Pure Python Ed25519 (RFC 8032) with custom hashing to prevent type confusion.
- **EIP-1559 Fee Market**: Dynamic base fee adjustment based on network utilization.

---

## 📅 Development Timeline

Tachyon's development is structured into two main phases. We have successfully completed the foundational architecture and are now focused on scaling and enhancing performance.

### ✅ Phase 1: Core Architecture (Achieved)
We have built a fully functional, from-scratch blockchain that implements modern consensus and cryptographic patterns:

- [x] **Cryptographic Foundation**: Implemented pure Python Ed25519 with RFC 8032 compliance and precomputed base-point tables for speed.
- [x] **State Management**: Developed a production-grade Sparse Merkle Tree (SMT) for efficient state commitments and compact proofs.
- [x] **Consensus Engine**: Built a stake-weighted BFT finality engine (>2/3 quorum) with a 6-stage pipelined block processor.
- [x] **Transaction Management**: Integrated a priority-based transaction pool (mempool) and dynamic EIP-1559 style fee market.
- [x] **Performance Benchmarking**: Validated the architecture with multi-node simulations, achieving ~1,500 TPS in controlled environments.

### 🚧 Phase 2: Scaling & Optimization (In Progress)
Our next milestones focus on real-world applicability and extreme performance:

- [ ] **VRF-based Leader Election**: Moving beyond round-robin to Verifiable Random Function (VRF) for secure, unpredictable slot assignment.
- [ ] **Network Optimizations**: Implementing gossip protocol enhancements for sub-100ms block propagation across distributed nodes.
- [ ] **Smart Contract Support**: Defining a safe, sandboxed execution environment for custom programs (WASM or Python bytecode).
- [ ] **Cross-Chain Compatibility**: Exploring interoperability bridges with existing BFT chains.

---

## 📊 Performance Benchmarks

*(Results from `scripts/benchmark.py`)*

| Validators | Throughput (TPS) | Scalability |
|:----------:|:----------------:|:-----------:|
| 2 Nodes    | **1,561**        | ████████████████████████████ |
| 4 Nodes    | **1,402**        | █████████████████████████    |
| 8 Nodes    | **1,272**        | ██████████████████████       |
| 16 Nodes   | **1,203**        | ██████████████████           |

*Note: Throughput remains high despite increasing validator count due to efficient gossip and pre-computed cryptographic tables.*

---

## 🛠️ Getting Started

### Prerequisites
- Python 3.10+
- No external dependencies (Standard Library only)

### Installation
```bash
git clone https://github.com/kp-pc/Tachyon-blockchain.git
cd Tachyon-blockchain
```

### Running the Simulation
To see the blockchain in action:
```bash
python -m tachyon.simulation
```

### Performance Testing
```bash
python scripts/benchmark.py
```

---

## 📂 Project Structure

```text
├── tachyon/
│   ├── chain.py       # Core consensus & data structures
│   ├── crypto.py      # Ed25519 & Base58 encoding
│   ├── smt.py         # Sparse Merkle Tree state
│   ├── pipeline.py    # 6-stage block processing
│   ├── executor.py    # Optimistic parallel execution
│   ├── mempool.py     # Priority transaction pool
│   ├── election.py    # Stake-weighted leader rotation
│   ├── networking.py  # P2P gossip protocol
│   └── rpc.py         # JSON-RPC API
├── scripts/
│   └── benchmark.py   # Throughput visualization
└── tests/
    └── test_crypto.py # RFC 8032 verification
```

---

## 🤝 Contributing

Tachyon is currently in the **experimental** phase. Contributions, suggestions, and bug reports are welcome!

> **Security Note**: This is an educational implementation. Do not use for production financial value transfer.

---

<div align="center">

**Built with 💜 by Agent Zero**

</div>
