<div align="center">

# 🟪 Tachyon
### A From-Scratch High-Performance Blockchain

![Python](https://img.shields.io/badge/Python-3.12+-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Status](https://img.shields.io/badge/Status-Experimental-orange)

Tachyon is a pure-Python, dependency-free blockchain implementation that explores high-throughput consensus designs inspired by **Solana**, **Aptos**, and **Tendermint**.

</div>

---

## 🚀 Features

Tachyon implements several advanced consensus and state management patterns from scratch:

| Feature | Description | Inspiration |
|---------|-------------|-------------|
| **⚡ High-Throughput Pipelining** | 6-stage block processing pipeline (Fetch → Gossip → Verify → Execute → Store → Finalize). | Solana |
| **🔒 Cryptographic Identity** | Pure-Python Ed25519 (RFC 8032) with precomputed base-point tables (~0.5ms sign). | Modern BFT |
| **🌲 Sparse Merkle Tree** | Production-grade state commitment for 256-bit keys with compact (≈8KB) inclusion/exclusion proofs. | Zcash/Cosmos |
| **⚖️ Stake-Weighted BFT** | Deterministic leader election and quorum-based finality (>2/3 stake). | Tendermint |
| **💸 Dynamic Fee Market** | EIP-1559 style base fee adjustment based on block utilization. | Ethereum |
| **🏃 Optimistic Parallel Execution** | Block-STM style speculative execution with dependency tracking. | Aptos/Sui |

---

## 📊 Performance Benchmarks

Tachyon maintains >1,200 TPS in simulated multi-validator networks, showcasing the efficiency of the pipelined architecture.

```
Transactions Per Second (TPS) by Validator Count:
------------------------------------------------------------
 2 Validators:  1467.43 TPS ████████████████████████████████████████|
 4 Validators:  1327.25 TPS ████████████████████████████████████    |
 8 Validators:  1221.36 TPS █████████████████████████████████       |
16 Validators:  1204.82 TPS ████████████████████████████████        |
------------------------------------------------------------
```

---

## 🛠️ Getting Started

### Prerequisites
- Python 3.12+
- No third-party dependencies (Standard Library only)

### Installation
Since there are no external dependencies, you can run the project directly from the source:

```bash
git clone https://github.com/kp-pc/Tachyon-blockchain.git
cd Tachyon-blockchain
```

### Running the Simulation
To see Tachyon in action, run the multi-node simulation with SMT state and leader election:

```bash
python -m tachyon.simulation
```

### Performance Benchmarking
To visualize throughput vs. validator count:

```bash
python scripts/benchmark.py
```

### Crypto Verification
Verify the Ed25519 implementation against official RFC 8032 test vectors:

```bash
python tests/test_crypto.py
```

---

## 📂 Project Structure

The Tachyon codebase is modular, separating cryptographic primitives, consensus logic, and networking:

```text
├── tachyon/
│   ├── crypto.py      # Ed25519 & Base58
│   ├── smt.py         # Sparse Merkle Tree
│   ├── chain.py       # BFT Consensus Core
│   ├── pipeline.py    # 6-Stage Processing Pipe
│   ├── mempool.py     # Priority Transaction Pool
│   └── election.py    # Leader Election
├── scripts/
│   └── benchmark.py   # Performance Analysis
└── tests/
    └── test_crypto.py # RFC 8032 Verification
```

---

## ⚠️ Security Disclaimer
This project is built for educational and research purposes. The consensus and cryptographic implementations are not audited and should **not** be used for production value transmission.

---

## 🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request for improvements, bug fixes, or additional features.

---

<div align="center">

**Tachyon** — Built from scratch with pure Python. 🟪

</div>
